# -*- coding: utf_8 -*-
"""Android APK and Source Analysis."""
import logging
import shutil
from pathlib import Path
import re

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal
from mobsf.MalwareAnalyzer.views.android import (
    apkid,
    permissions,
)
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import MalwareDomainCheck

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render

from mobsf.MobSF.utils import (
    append_scan_status,
    file_size,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)
from mobsf.StaticAnalyzer.views.common.binary.lib_analysis import (
    library_analysis,
)
from mobsf.StaticAnalyzer.views.android.app import (
    aapt_parse,
    androguard_parse,
    get_apk_name,
)
from mobsf.StaticAnalyzer.views.android.cert_analysis import (
    cert_info,
    get_hardcoded_cert_keystore,
)
from mobsf.StaticAnalyzer.views.android.code_analysis import code_analysis
from mobsf.StaticAnalyzer.views.android.converter import (
    apk_2_java,
    dex_2_smali,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry,
    save_get_ctx,
)
from mobsf.StaticAnalyzer.views.android.icon_analysis import (
    get_icon_apk,
    get_icon_from_src,
)
from mobsf.StaticAnalyzer.views.android.manifest_analysis import (
    manifest_analysis,
)
from mobsf.StaticAnalyzer.views.android.manifest_utils import (
    extract_manifest_data,
    get_parsed_manifest,
)
from mobsf.StaticAnalyzer.views.android.playstore import (
    get_app_details,
)
from mobsf.StaticAnalyzer.views.android.strings import (
    get_strings_metadata,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    get_avg_cvss,
    hash_gen,
    unzip,
)
from mobsf.StaticAnalyzer.views.common.firebase import (
    firebase_analysis,
)
from mobsf.StaticAnalyzer.views.common.appsec import (
    get_android_dashboard,
)
from mobsf.StaticAnalyzer.views.common.async_task import (
    async_analysis,
    mark_task_completed,
    mark_task_started,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    has_permission,
)

logger = logging.getLogger(__name__)

SBER_URL_RX_STRICT = re.compile(
    r'\bhttps?:\/\/[\w.-]*(?:sberbank|sber|sbrf|sigma|delta|ci\d+|ift|majorcheck|majorgo)[^\s"\'<]*',
    re.IGNORECASE,
)
import re

TOKEN_AUTH_RX = re.compile(r"(?i)(?:\S*(?:token|auth)\w*\s*[:=]\s*['\"`]?([\w\-=\.]+)['\"`]?|<[^>]*(?:token|auth)[^>]*>([^<]+)<|{{\s*[\w\.]*(?:token|auth)\w*\s*}})")

KEY_RX = re.compile(
    r"(['\"]?\w*key\w*['\"]?\s*[:=\s>\-]?\s*['\"]?\s*[a-zA-Z0-9_\s].*)|(\.\w*key\w*\s*\([^)]*\))",
    re.IGNORECASE,
)

def _extract_text_from_secret_item(item) -> str:
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
    out = []
    for it in secrets:
        txt = _extract_text_from_secret_item(it)
        if (TOKEN_AUTH_RX.search(txt) or KEY_RX.search(txt)):
            out.append(it)
    return out

def _filter_secrets_in_code_dic(code_dic: dict):
    secrets = code_dic.get("secrets")
    if isinstance(secrets, list):
        code_dic["secrets"] = _filter_secrets_list(secrets)

    findings = code_dic.get("findings")
    if isinstance(findings, list):
        filtered = []
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
                or "hardcoded" in title.lower()
                and "key" in title.lower()
            )

            if looks_like_secret_finding:
                blob = " ".join([title, issue, desc, _extract_text_from_secret_item(f)])
                if (TOKEN_AUTH_RX.search(blob) or KEY_RX.search(blob)):
                    filtered.append(f)
            else:
                filtered.append(f)

        code_dic["findings"] = filtered


def _is_noise_path(p: str) -> bool:
    p = (p or "").strip().lower()
    return (not p) or (p in ("android string resource", "unknown", "none"))

def _pick_better_path(old_path: str, new_path: str) -> str:
    """
    Выбираем "лучший" path для одного и того же URL.
    Хотим предпочитать реальный исходник (.java/.kt/...) вместо "Android String Resource".
    """
    old_path = (old_path or "").strip()
    new_path = (new_path or "").strip()
    if _is_noise_path(old_path) and not _is_noise_path(new_path):
        return new_path
    if not old_path:
        return new_path
    return old_path

def _filter_urls_in_code_dic(code_dic):
    uf_before = code_dic.get("urls") or []

    filtered_groups = []
    flat_order = [] 
    seen_flat = set()

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
    for u in ul_before:
        s = str(u).strip()
        if s and SBER_URL_RX_STRICT.search(s):
            if s not in seen_flat:
                seen_flat.add(s)
                ul_filtered.append(s)

    code_dic["urls"] = filtered_groups
    code_dic["urls_list"] = flat_order or ul_filtered

def initialize_app_dic(app_dic, file_ext):
    checksum = app_dic['md5']
    app_dic['app_file'] = f'{checksum}.{file_ext}'
    app_dic['app_path'] = (app_dic['app_dir'] / app_dic['app_file']).as_posix()
    app_dic['app_dir'] = app_dic['app_dir'].as_posix() + '/'
    return checksum


def get_size_and_hashes(app_dic):
    app_dic['size'] = str(file_size(app_dic['app_path'])) + 'MB'
    app_dic['sha1'], app_dic['sha256'] = hash_gen(app_dic['md5'], app_dic['app_path'])


def get_manifest_data(app_dic):
    """Get Manifest Data."""
    get_parsed_manifest(app_dic)
    man_data_dic = extract_manifest_data(app_dic)
    man_analysis = manifest_analysis(app_dic, man_data_dic)
    return man_data_dic, man_analysis


def print_scan_subject(app_dic, man_data):
    """Log scan subject."""
    checksum = app_dic['md5']
    app_name = app_dic.get('real_name')
    pkg_name = man_data.get('packagename')
    pkg_name2 = app_dic.get('apk_features', {}).get('package')
    if not pkg_name:
        pkg_name = pkg_name2
    subject = 'Android App'
    if app_name and pkg_name:
        subject = f'{app_name} ({pkg_name})'
    elif pkg_name:
        subject = pkg_name
    elif app_name:
        subject = app_name
    msg = f'Performing Static Analysis on: {subject}'
    logger.info(msg)
    append_scan_status(checksum, msg)
    if subject == 'Failed':
        subject = f'({subject})'
    app_dic['subject'] = subject


def clean_up(app_dic):
    """Clean up for pickling."""
    app_dic['androguard_apk'] = None
    app_dic['androguard_apk_resources'] = None


def apk_analysis_task(checksum, app_dic, rescan, queue=False):
    """APK Analysis Task."""
    context = None
    try:
        if queue:
            settings.ASYNC_ANALYSIS = True
            mark_task_started(checksum)
        append_scan_status(checksum, 'init')
        get_size_and_hashes(app_dic)
        msg = 'Extracting APK'
        logger.info(msg)
        append_scan_status(checksum, msg)
        app_dic['zipped'] = 'apk'

        app_dic['files'] = unzip(checksum, app_dic['app_path'], app_dic['app_dir'])

        androguard_parse(app_dic)
        aapt_parse(app_dic)
        get_hardcoded_cert_keystore(app_dic)

        man_data_dic, man_analysis = get_manifest_data(app_dic)
        get_apk_name(app_dic)
        print_scan_subject(app_dic, man_data_dic)
        get_app_details(app_dic, man_data_dic)

        mal_perms = permissions.check_malware_permission(checksum, man_data_dic['perm'])
        man_analysis['malware_permissions'] = mal_perms

        get_icon_apk(app_dic)

        elf_dict = library_analysis(checksum, app_dic['app_dir'], 'elf')
        cert_dic = cert_info(app_dic, man_data_dic)
        apkid_results = apkid.apkid_analysis(checksum, app_dic['app_path'])

        trackers = Trackers.Trackers(checksum, app_dic['app_dir'], app_dic['tools_dir']).get_trackers()

        apk_2_java(checksum, app_dic['app_path'], app_dic['app_dir'], settings.DOWNLOADED_TOOLS_DIR)
        dex_2_smali(checksum, app_dic['app_dir'], app_dic['tools_dir'])

        code_an_dic = code_analysis(
            checksum,
            app_dic['app_dir'],
            app_dic['zipped'],
            app_dic['manifest_file'],
            man_data_dic['perm'])

        get_strings_metadata(app_dic, elf_dict['elf_strings'], ['.java'], code_an_dic)

        code_an_dic['firebase'] = firebase_analysis(checksum, code_an_dic)
        _filter_secrets_in_code_dic(code_an_dic)
        _filter_urls_in_code_dic(code_an_dic)

        code_an_dic['domains'] = MalwareDomainCheck().scan(checksum, code_an_dic['urls_list'])

        context = save_get_ctx(
            app_dic,
            man_data_dic,
            man_analysis,
            code_an_dic,
            cert_dic,
            elf_dict['elf_analysis'],
            apkid_results,
            trackers,
            rescan,
        )
        if queue:
            return mark_task_completed(checksum, app_dic['subject'], 'Success')
        return context, None
    except Exception as exp:
        if queue:
            return mark_task_completed(checksum, 'Failed', repr(exp))
        return context, repr(exp)
    finally:
        clean_up(app_dic)


def generate_dynamic_context(request, app_dic, checksum, context, api):
    """Generate Dynamic Context."""
    context['appsec'] = get_android_dashboard(context, True)
    context['average_cvss'] = get_avg_cvss(context['code_analysis']['findings'])
    logcat_file = Path(app_dic['app_dir']) / 'logcat.txt'
    context['dynamic_analysis_done'] = logcat_file.exists()
    context['virus_total'] = None
    if settings.VT_ENABLED:
        vt = VirusTotal.VirusTotal(checksum)
        context['virus_total'] = vt.get_result(app_dic['app_path'])
    template = 'static_analysis/android_binary_analysis.html'
    return context if api else render(request, template, context)


def apk_analysis(request, app_dic, rescan, api):
    """APK Analysis."""
    checksum = initialize_app_dic(app_dic, 'apk')
    db_entry = StaticAnalyzerAndroid.objects.filter(MD5=checksum)
    if db_entry.exists() and not rescan:
        context = get_context_from_db_entry(db_entry)
        return generate_dynamic_context(request, app_dic, checksum, context, api)
    else:
        if not has_permission(request, Permissions.SCAN, api):
            return print_n_send_error_response(request, 'Permission Denied', False)
        if settings.ASYNC_ANALYSIS:
            return async_analysis(
                checksum,
                api,
                app_dic.get('app_name', ''),
                apk_analysis_task, checksum, app_dic, rescan)
        context, err = apk_analysis_task(checksum, app_dic, rescan)
        if err:
            return print_n_send_error_response(request, err, api)
        return generate_dynamic_context(request, app_dic, checksum, context, api)


def src_analysis_task(checksum, app_dic, rescan, pro_type, queue=False):
    """Android ZIP Source Code Analysis Begins."""
    context = None
    try:
        if queue:
            settings.ASYNC_ANALYSIS = True
            mark_task_started(checksum)
        cert_dic = {
            'certificate_info': '',
            'certificate_status': '',
            'description': '',
        }
        app_dic['strings'] = []
        app_dic['secrets'] = []
        app_dic['zipped'] = pro_type

        get_hardcoded_cert_keystore(app_dic)

        man_data_dic, man_analysis = get_manifest_data(app_dic)
        get_apk_name(app_dic)
        print_scan_subject(app_dic, man_data_dic)
        get_app_details(app_dic, man_data_dic)

        mal_perms = permissions.check_malware_permission(checksum, man_data_dic['perm'])
        man_analysis['malware_permissions'] = mal_perms

        get_icon_from_src(app_dic, man_data_dic['icons'])

        code_an_dic = code_analysis(
            checksum,
            app_dic['app_dir'],
            app_dic['zipped'],
            app_dic['manifest_file'],
            man_data_dic['perm'])

        get_strings_metadata(app_dic, None, ['.java', '.kt'], code_an_dic)

        code_an_dic['firebase'] = firebase_analysis(checksum, code_an_dic)

        _filter_secrets_in_code_dic(code_an_dic)
        _filter_urls_in_code_dic(code_an_dic)

        code_an_dic['domains'] = MalwareDomainCheck().scan(checksum, code_an_dic['urls_list'])

        trackers = Trackers.Trackers(
            checksum, None, app_dic['tools_dir']
        ).get_trackers_domains_or_deps(code_an_dic['domains'], [])

        context = save_get_ctx(
            app_dic,
            man_data_dic,
            man_analysis,
            code_an_dic,
            cert_dic,
            [],
            {},
            trackers,
            rescan,
        )
        if queue:
            return mark_task_completed(checksum, app_dic['subject'], 'Success')
    except Exception as exp:
        if queue:
            return mark_task_completed(checksum, 'Failed', repr(exp))
    return context


def generate_dynamic_src_context(request, context, api):
    """Generate Dynamic Source Context."""
    context['appsec'] = get_android_dashboard(context, True)
    context['average_cvss'] = get_avg_cvss(context['code_analysis']['findings'])
    template = 'static_analysis/android_source_analysis.html'
    return context if api else render(request, template, context)


def src_analysis(request, app_dic, rescan, api):
    """Source Code Analysis."""
    checksum = initialize_app_dic(app_dic, 'zip')
    ret = f'/static_analyzer_ios/{checksum}/'
    db_entry = StaticAnalyzerAndroid.objects.filter(MD5=checksum)
    ios_db_entry = StaticAnalyzerIOS.objects.filter(MD5=checksum)

    if db_entry.exists() and not rescan:
        context = get_context_from_db_entry(db_entry)
        return generate_dynamic_src_context(request, context, api)
    elif ios_db_entry.exists() and not rescan:
        return {'type': 'ios'} if api else HttpResponseRedirect(ret)
    else:
        append_scan_status(checksum, 'init')
        get_size_and_hashes(app_dic)

        msg = 'Extracting ZIP'
        logger.info(msg)
        append_scan_status(checksum, msg)

        app_dic['files'] = unzip(checksum, app_dic['app_path'], app_dic['app_dir'])

        pro_type, valid = valid_source_code(checksum, app_dic['app_dir'])

        msg = f'Source code type - {pro_type}'
        logger.info(msg)
        append_scan_status(checksum, msg)

        if valid and pro_type == 'ios':
            msg = 'Redirecting to iOS Source Code Analyzer'
            logger.info(msg)
            append_scan_status(checksum, msg)
            ret = f'{ret}?rescan={str(int(rescan))}'
            return {'type': 'ios'} if api else HttpResponseRedirect(ret)

        if not has_permission(request, Permissions.SCAN, api):
            return print_n_send_error_response(request, 'Permission Denied', False)

        if valid and (pro_type in ['eclipse', 'studio']):
            if settings.ASYNC_ANALYSIS:
                return async_analysis(
                    checksum,
                    api,
                    app_dic.get('app_name', ''),
                    src_analysis_task, checksum, app_dic, rescan, pro_type)
            context = src_analysis_task(checksum, app_dic, rescan, pro_type)
            return generate_dynamic_src_context(request, context, api)
        else:
            msg = 'This ZIP Format is not supported'
            if api:
                return print_n_send_error_response(request, msg, True)
            else:
                print_n_send_error_response(request, msg, False)
                ctx = {
                    'title': 'Invalid ZIP archive',
                    'version': settings.MOBSF_VER,
                }
                template = 'general/zip.html'
                return render(request, template, ctx)


def is_android_source(app_path):
    """Detect Android Source and IDE Type."""
    man = app_path / 'AndroidManifest.xml'
    src = app_path / 'src'
    if man.is_file() and src.exists():
        return 'eclipse', True

    man = app_path / 'app' / 'src' / 'main' / 'AndroidManifest.xml'
    java = app_path / 'app' / 'src' / 'main' / 'java'
    kotlin = app_path / 'app' / 'src' / 'main' / 'kotlin'
    if man.is_file() and (java.exists() or kotlin.exists()):
        return 'studio', True

    return None, False


def move_to_parent(inside_path, app_path):
    """Move contents of inside to app dir."""
    for item in inside_path.iterdir():
        shutil.move(str(item), str(app_path))
    shutil.rmtree(inside_path)


def valid_source_code(checksum, app_dir):
    """Test if this is a valid source code zip."""
    try:
        msg = 'Detecting source code type'
        logger.info(msg)
        append_scan_status(checksum, msg)

        app_path = Path(app_dir)
        ide, is_and = is_android_source(app_path)

        if ide:
            return ide, is_and

        for subdir in app_path.iterdir():
            if subdir.is_dir() and subdir.exists():
                ide, is_and = is_android_source(subdir)
                if ide:
                    move_to_parent(subdir, app_path)
                    return ide, is_and

        xcode = [f for f in app_path.iterdir() if f.suffix == '.xcodeproj']
        if xcode:
            return 'ios', True

        for subdir in app_path.iterdir():
            if subdir.is_dir() and subdir.exists():
                if any(f.suffix == '.xcodeproj' for f in subdir.iterdir()):
                    return 'ios', True

        return '', False
    except Exception as exp:
        msg = 'Error identifying source code type from zip'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
        return '', False
