# -*- coding: utf_8 -*-

import json
import logging

from pathlib import Path

from mobsf.MobSF.utils import append_scan_status
from mobsf.StaticAnalyzer.views.common.secret_patterns import is_secret

logger = logging.getLogger(__name__)

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

def _flatten(data, prefix=''):
    pairs = []
    if isinstance(data, dict):
        for k, v in data.items():
            full = f'{prefix}.{k}' if prefix else str(k)
            if isinstance(v, (dict, list)):
                pairs.extend(_flatten(v, full))
            elif v is not None:
                pairs.append((full, str(v)))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            idx = f'{prefix}[{i}]'
            if isinstance(item, (dict, list)):
                pairs.extend(_flatten(item, idx))
            elif item is not None:
                pairs.append((idx, str(item)))
    return pairs

def _parse_json(file_path):
    try:
        data = json.loads(
            file_path.read_text(encoding='utf-8', errors='ignore'))
        return _flatten(data)
    except Exception:
        return []
 
 
def _parse_yaml(file_path):
    try:
        text = file_path.read_text(encoding='utf-8', errors='ignore')
        pairs = []
        for doc in yaml.safe_load_all(text):
            if isinstance(doc, (dict, list)):
                pairs.extend(_flatten(doc))
        return pairs
    except Exception:
        return []
 
def _parse_properties(file_path):
    pairs = []
    try:
        for line in file_path.read_text(encoding='utf8', errors='ignore').splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '!')):
                continue
            for sep in ('=',':'):
                idx = line.find(sep)
                if idx > 0:
                    pairs.append((line[:idx].strip(),line[idx+1:].strip()))
                    break
    except Exception:
        pass 
    return pairs


PARSERS = {
    '.json': _parse_json,
    '.yaml': _parse_yaml,
    '.yml': _parse_yaml,
    '.properties': _parse_properties,
}
 
_SKIP_NAMES = frozenset({
    'package.json', 'package-lock.json', 'composer.json',
    'build.gradle', 'settings.gradle',
    'google-services.json',
    'AndroidManifest.xml',
})
 
_SKIP_DIRS = frozenset({
    'node_modules', '.gradle', 'build', '__pycache__',
    '.git', '.svn', '.idea',
})
 
def _should_skip(fp):
    if fp.name in _SKIP_NAMES:
        return True
    return any(d in fp.parts for d in _SKIP_DIRS)

def scan_config_files(checksum,app_dir):
    msg = 'start scanning config files'
    logger.info(msg)

    secrets = []
    app_path = Path(app_dir) if not isinstance(app_dir, Path) else app_dir

    if not app_path.exists():
        return secrets
    
    try:
        for fp in app_path.rglob('*'):
            if not fp.is_file() or _should_skip(fp):
                continue

            parser = PARSERS.get(fp.suffix.lower())

            if not parser:
                continue

            for key_path,value in parser(fp):
                if is_secret(key_path):
                    secrets.append(f'"{key_path}" : "{value}"')


    except Exception as exp:
        msg = 'Failed to scan config files for secrets'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))

    msg = f'Config file scan: {len(secrets)} potential secrets'
    logger.info(msg)
    append_scan_status(checksum, msg)
    return secrets
