# -*- coding: utf_8 -*-
"""iOS Analysis."""
import logging
from pathlib import Path

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal

from django.conf import settings
from django.shortcuts import render

from mobsf.MobSF.utils import (
    append_scan_status,
    file_size,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerIOS,
)
from mobsf.StaticAnalyzer.views.ios.appstore import app_search
from mobsf.StaticAnalyzer.views.ios.binary_analysis import (
    binary_analysis,
)
from mobsf.StaticAnalyzer.views.common.binary.lib_analysis import (
    library_analysis,
)
from mobsf.StaticAnalyzer.views.ios.code_analysis import ios_source_analysis
from mobsf.StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry,
    save_get_ctx,
)
from mobsf.StaticAnalyzer.views.ios.file_analysis import ios_list_files
from mobsf.StaticAnalyzer.views.ios.icon_analysis import (
    get_icon_from_ipa,
    get_icon_source,
)
from mobsf.StaticAnalyzer.views.ios.plist_analysis import (
    get_plist_secrets,
    plist_analysis,
)
from mobsf.StaticAnalyzer.views.ios.strings import (
    get_strings_metadata,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    get_avg_cvss,
    hash_gen,
    strings_and_entropies,
    unzip,
)
from mobsf.StaticAnalyzer.views.common.firebase import (
    firebase_analysis,
)
from mobsf.StaticAnalyzer.views.common.appsec import (
    get_ios_dashboard,
)
from mobsf.StaticAnalyzer.views.common.async_task import (
    async_analysis,
    mark_task_completed,
    mark_task_started,
)
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import (
    MalwareDomainCheck,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    has_permission,
)

logger = logging.getLogger(__name__)

# -------------------------------
# TEST FILTERS: URL + SECRETS
# -------------------------------
import re 

TOKEN_AUTH_RX = re.compile(
    r"(?i)(?:\S*(?:token|auth)\w*\s*[:=]\s*['\"`]?([\w\-=\.]+)['\"`]?|<[^>]*(?:token|auth)[^>]*>([^<]+)<|{{\s*[\w\.]*(?:token|auth)\w*\s*}})"
)

SBER_URL_RX_STRICT = re.compile(
    r"\bhttps?:\/\/[\w.-]*(?:sberbank|sber|sbrf|sigma|delta|ci\d+|ift|majorcheck|majorgo)[^\s\"'<]*",
    re.IGNORECASE,
)



def _extract_text_from_secret_item(item) -> str:
    """
    Универсально вытаскиваем текст из элемента секрета (str/dict/любое).
    Подходит и для app_dic['secrets'], и для code_dict['secrets'].
    """
    if isinstance(item, str):
        return item
    if not isinstance(item, dict):
        return str(item)

    for k in ("value", "match", "secret", "string", "line", "text", "evidence", "details"):
        v = item.get(k)
        if v:
            return str(v)

    for k in ("title", "description", "issue", "message"):
        v = item.get(k)
        if v:
            return str(v)

    return str(item)

def _filter_secrets_list(secrets: list) -> list:
    """Оставляем только те элементы, где есть совпадение с TOKEN_AUTH_RX."""
    if not isinstance(secrets, list):
        return secrets
    out = []
    for it in secrets:
        txt = _extract_text_from_secret_item(it)
        if TOKEN_AUTH_RX.search(txt):
            out.append(it)
    return out

def _filter_secrets_in_code_dic(code_dic: dict):
    """
    Режем секреты в code_dic:
    - code_dic['secrets'] (если есть)
    - code_dic['findings'] (если секреты представлены как findings)
    """
    if not isinstance(code_dic, dict):
        return

    secrets = code_dic.get("secrets")
    if isinstance(secrets, list):
        before = len(secrets)
        code_dic["secrets"] = _filter_secrets_list(secrets)
        after = len(code_dic["secrets"])
        logger.warning("SECRET FILTER: code_dic['secrets'] %d -> %d", before, after)

    findings = code_dic.get("findings")
    if isinstance(findings, list):
        filtered = []
        dropped = 0

        for f in findings:
            if not isinstance(f, dict):
                filtered.append(f)
                continue

            title = str(f.get("title") or "")
            issue = str(f.get("issue") or "")
            desc  = str(f.get("description") or f.get("details") or "")

            looks_like_secret_finding = (
                "secret" in title.lower()
                or "secret" in issue.lower()
                or ("hardcoded" in title.lower() and "key" in title.lower())
            )

            if looks_like_secret_finding:
                blob = " ".join([title, issue, desc, _extract_text_from_secret_item(f)])
                if TOKEN_AUTH_RX.search(blob):
                    filtered.append(f)
                else:
                    dropped += 1
            else:
                filtered.append(f)

        code_dic["findings"] = filtered
        if dropped:
            logger.warning("SECRET FILTER: dropped %d secret-like findings", dropped)

def _filter_urls_in_code_dic(code_dic: dict):
    """
    Фильтруем URL на уровне итогового code_dic:
    - сохраняем ВСЕ источники (path) отдельно (не схлопываем resources vs code)
    - urls_list делаем плоским уникальным списком того, что реально показываем/сканим
    """
    if not isinstance(code_dic, dict):
        return

    uf_before = code_dic.get("urls") or []
    filtered_groups = []
    flat_order = []
    seen_flat = set()

    if isinstance(uf_before, list):
        for item in uf_before:
            if not isinstance(item, dict):
                continue
            path = (item.get("path") or "").strip() or "Unknown"
            urls_in_item = item.get("urls") or []
            if not isinstance(urls_in_item, (list, tuple)):
                continue

            group_seen = set()
            group_urls = []
            for u in urls_in_item:
                s = str(u).strip()
                if not s:
                    continue
                if not SBER_URL_RX_STRICT.search(s):
                    continue

                if s not in group_seen:
                    group_seen.add(s)
                    group_urls.append(s)

                if s not in seen_flat:
                    seen_flat.add(s)
                    flat_order.append(s)

            if group_urls:
                filtered_groups.append({"path": path, "urls": group_urls})

    ul_before = code_dic.get("urls_list") or []
    ul_filtered = []
    if isinstance(ul_before, list):
        for u in ul_before:
            s = str(u).strip()
            if s and SBER_URL_RX_STRICT.search(s) and s not in seen_flat:
                seen_flat.add(s)
                ul_filtered.append(s)

    code_dic["urls"] = filtered_groups
    code_dic["urls_list"] = flat_order or ul_filtered

    logger.warning(
        "URL FILTER: urls_groups=%d urls_list=%d",
        len(code_dic.get("urls") or []),
        len(code_dic.get("urls_list") or []),
    )

def apply_post_filters_ios(app_dic: dict, code_dict: dict):
    """
    Удобный хелпер: прогнать фильтры одним вызовом.
    Для iOS дополнительно режем app_dic['secrets'] (plist secrets), если нужно.
    """
    _filter_secrets_in_code_dic(code_dict)
    _filter_urls_in_code_dic(code_dict)

    if isinstance(app_dic, dict) and isinstance(app_dic.get("secrets"), list):
        before = len(app_dic["secrets"])
        app_dic["secrets"] = _filter_secrets_list(app_dic["secrets"])
        after = len(app_dic["secrets"])
        logger.warning("SECRET FILTER: app_dic['secrets'] %d -> %d", before, after)


def initialize_app_dic(app_dic, file_ext):
    """Initialize App Dictionary."""
    checksum = app_dic['md5_hash']
    app_dic['app_file'] = f'{checksum}.{file_ext}'
    app_dic['app_path'] = (app_dic['app_dirp'] / app_dic['app_file']).as_posix()
    return checksum


def get_size_and_hashes(app_dic):
    app_dic['size'] = str(file_size(app_dic['app_path'])) + 'MB'
    app_dic['sha1'], app_dic['sha256'] = hash_gen(
        app_dic['md5_hash'], app_dic['app_path'])


def extract_and_check_ipa(checksum, app_dic):
    """Extract and Check IPA."""
    # EXTRACT IPA
    msg = 'Extracting IPA'
    logger.info(msg)
    append_scan_status(checksum, msg)
    unzip(
        checksum,
        app_dic['app_path'],
        app_dic['app_dir'])
    # Identify Payload directory
    dirs = app_dic['app_dirp'].glob('**/*')
    for _dir in dirs:
        if 'payload' in _dir.as_posix().lower():
            app_dic['bin_dir'] = app_dic['app_dirp'] / _dir
            break
    else:
        return False
    app_dic['bin_dir'] = app_dic['bin_dir'].as_posix() + '/'
    return True


def common_analysis(scan_type, app_dic, checksum):
    """Common Analysis for ipa and zip."""
    location = app_dic['app_dir']
    if scan_type == 'ipa':
        location = app_dic['bin_dir']
    # Get Files
    app_dic['all_files'] = ios_list_files(
        checksum,
        location,
        scan_type)
    # Plist files are converted to xml/readable for ipa
    app_dic['infoplist'] = plist_analysis(
        checksum,
        location,
        scan_type)
    app_dic['appstore'] = app_search(
        checksum,
        app_dic['infoplist'].get('id'))
    app_dic['secrets'] = get_plist_secrets(
        checksum,
        location)


def common_firebase_and_trackers(code_dict, app_dic, checksum):
    """Common Firebase and Trackers."""
    # Firebase Analysis
    code_dict['firebase'] = firebase_analysis(
        checksum,
        code_dict)
    # Extract Trackers from Domains
    trk = Trackers.Trackers(
        checksum,
        None,
        app_dic['tools_dir'])
    code_dict['trackers'] = trk.get_trackers_domains_or_deps(
        code_dict['domains'], [])


def get_scan_subject(app_dic, bin_dict):
    """Get Scan Subject."""
    app_name = None
    pkg_name = None
    subject = 'iOS App'
    if bin_dict.get('bin_path'):
        app_name = bin_dict['bin_path'].name if bin_dict['bin_path'] else None
    if app_dic.get('infoplist'):
        pkg_name = app_dic['infoplist'].get('id')

    if app_name and pkg_name:
        subject = f'{app_name} ({pkg_name})'
    elif pkg_name:
        subject = pkg_name
    elif app_name:
        subject = app_name
    if subject == 'Failed':
        subject = f'({subject})'
    return subject


def ipa_analysis_task(checksum, app_dic, rescan, queue=False):
    """IPA Analysis Task."""
    context = None
    try:
        if queue:
            settings.ASYNC_ANALYSIS = True
            mark_task_started(checksum)
        append_scan_status(checksum, 'init')
        msg = 'iOS Binary (IPA) Analysis Started'
        logger.info(msg)
        append_scan_status(checksum, msg)
        get_size_and_hashes(app_dic)

        if not extract_and_check_ipa(checksum, app_dic):
            msg = ('IPA is malformed! MobSF cannot find Payload directory')
            append_scan_status(checksum, 'IPA is malformed', msg)
            if queue:
                return mark_task_completed(
                    checksum, 'Failed', msg)
            return context, msg

        # Common Analysis
        common_analysis('ipa', app_dic, checksum)
        # IPA Binary Analysis
        bin_dict = binary_analysis(
            checksum,
            app_dic['bin_dir'],
            app_dic['tools_dir'],
            app_dic['app_dir'],
            app_dic['infoplist'].get('bin'))
        # Analyze dylibs and frameworks
        lb = library_analysis(
            checksum,
            app_dic['bin_dir'],
            'macho')
        bin_dict['dylib_analysis'] = lb['macho_analysis']
        bin_dict['framework_analysis'] = lb['framework_analysis']
        # Extract String metadata from binary
        code_dict = get_strings_metadata(
            app_dic,
            bin_dict,
            app_dic['all_files'],
            lb['macho_strings'])
        # Domain Extraction and Malware Check
        code_dict['domains'] = MalwareDomainCheck().scan(
            checksum,
            code_dict['urls_list'])
        # Get Icon
        get_icon_from_ipa(app_dic)
        # Firebase and Trackers
        common_firebase_and_trackers(code_dict, app_dic, checksum)

        code_dict['api'] = {}
        code_dict['code_anal'] = {}
        context = save_get_ctx(
            app_dic,
            code_dict,
            bin_dict,
            rescan)
        if queue:
            subject = get_scan_subject(app_dic, bin_dict)
            return mark_task_completed(
                checksum, subject, 'Success')
        return context, None
    except Exception as exp:
        if queue:
            return mark_task_completed(
                checksum, 'Failed', repr(exp))
        return context, repr(exp)


def generate_dynamic_context(request, app_dic, context, checksum, api):
    """Generate Dynamic Context."""
    context['virus_total'] = None
    if settings.VT_ENABLED:
        vt = VirusTotal.VirusTotal(checksum)
        context['virus_total'] = vt.get_result(app_dic['app_path'])
    context['appsec'] = get_ios_dashboard(context, True)
    context['average_cvss'] = get_avg_cvss(context['binary_analysis'])
    template = 'static_analysis/ios_binary_analysis.html'
    return context if api else render(request, template, context)


def ipa_analysis(request, app_dic, rescan, api):
    """IPA Analysis."""
    checksum = initialize_app_dic(app_dic, 'ipa')
    ipa_db = StaticAnalyzerIOS.objects.filter(MD5=checksum)
    if ipa_db.exists() and not rescan:
        context = get_context_from_db_entry(ipa_db)
        return generate_dynamic_context(request, app_dic, context, checksum, api)
    else:
        # IPA Analysis
        if not has_permission(request, Permissions.SCAN, api):
            return print_n_send_error_response(request, 'Permission Denied', False)
        if settings.ASYNC_ANALYSIS:
            return async_analysis(
                checksum,
                api,
                app_dic.get('file_name', ''),
                ipa_analysis_task, checksum, app_dic, rescan)
        context, err = ipa_analysis_task(checksum, app_dic, rescan)
        if err:
            return print_n_send_error_response(request, err, api)
        return generate_dynamic_context(request, app_dic, context, checksum, api)


def ios_analysis_task(checksum, app_dic, rescan, queue=False):
    """IOS Analysis Task."""
    context = None
    try:
        if queue:
            settings.ASYNC_ANALYSIS = True
            mark_task_started(checksum)
        logger.info('iOS Source Code Analysis Started')
        get_size_and_hashes(app_dic)

        # ANALYSIS BEGINS - Already Unzipped
        # append_scan_status init done in android static analyzer
        common_analysis('zip', app_dic, checksum)

        # IOS Source Code Analysis
        code_dict = ios_source_analysis(
            checksum,
            app_dic['app_dir'])
        # Extract Strings and entropies from source code
        ios_strs = strings_and_entropies(
            checksum,
            Path(app_dic['app_dir']),
            ['.swift', '.m', '.h', '.plist', '.json'])
        if ios_strs['secrets']:
            app_dic['secrets'].extend(list(ios_strs['secrets']))
        # Get App Icon
        get_icon_source(app_dic)
        # Firebase and Trackers
        common_firebase_and_trackers(code_dict, app_dic, checksum)

        bin_dict = {
            'checksec': {},
            'libraries': [],
            'bin_code_analysis': {},
            'strings': list(ios_strs['strings']),
            'bin_info': {},
            'bin_type': code_dict['source_type'],
            'dylib_analysis': {},
            'framework_analysis': {},
        }
        context = save_get_ctx(
            app_dic,
            code_dict,
            bin_dict,
            rescan)
        if queue:
            subject = get_scan_subject(app_dic, bin_dict)
            return mark_task_completed(
                checksum, subject, 'Success')
    except Exception as exp:
        if queue:
            return mark_task_completed(
                checksum, 'Failed', repr(exp))
    return context


def generate_dynamic_ios_context(request, context, api):
    """Generate Dynamic Context for IOS."""
    context['appsec'] = get_ios_dashboard(context, True)
    context['average_cvss'] = get_avg_cvss(context['code_analysis'])
    template = 'static_analysis/ios_source_analysis.html'
    return context if api else render(request, template, context)


def ios_analysis(request, app_dic, rescan, api):
    """IOS Source Code Analysis."""
    checksum = initialize_app_dic(app_dic, 'zip')
    ios_zip_db = StaticAnalyzerIOS.objects.filter(MD5=checksum)
    if ios_zip_db.exists() and not rescan:
        context = get_context_from_db_entry(ios_zip_db)
        return generate_dynamic_ios_context(request, context, api)
    else:
        # IOS Source Analysis
        if not has_permission(request, Permissions.SCAN, api):
            return print_n_send_error_response(request, 'Permission Denied', False)
        if settings.ASYNC_ANALYSIS:
            return async_analysis(
                checksum,
                api,
                app_dic.get('file_name', ''),
                ios_analysis_task, checksum, app_dic, rescan)
        context = ios_analysis_task(checksum, app_dic, rescan)
        return generate_dynamic_ios_context(request, context, api)
