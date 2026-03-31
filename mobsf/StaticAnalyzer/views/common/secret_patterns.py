import re
 
_KEY_REGEXES = [
    re.compile(r'private(?:[_\-]?key)', re.I),
    re.compile(r'secret(?:[_\-]?key)?', re.I),
    re.compile(r'encrypt(?:ion)?(?:[_\-]?key)?', re.I),
    re.compile(r'protected(?:[_\-]?key)?', re.I),
    re.compile(r'(?:appsflyer|dev)?key', re.I),
]
 
_TOKEN_KEY_REGEXES = [
    re.compile(r'[\w\.]*token[\w\.]*', re.I),
    re.compile(r'sess(?:ion)?(?:[_\-]?(?:id|token))?', re.I),
    re.compile(r'registration(?:[_\-]?(?:id|token))?', re.I),
    re.compile(r'protected(?:[_\-]?token)?', re.I),
    re.compile(r'secret(?:[_\-]?token)?', re.I),
    re.compile(r'private(?:[_\-]?token)', re.I),
]
 
ALL_KEY_PATTERNS = _KEY_REGEXES + _TOKEN_KEY_REGEXES
 
_EXCLUDE_KEY_RE = re.compile(
    r'label_|_text|hint|msg_|create_|message|confirm|'
    r'activity_|forgot|dashboard_|current_|signup|'
    r'sign_in|signin|title_|welcome_|change_|'
    r'placeholder|invalid_|btn_|action_|prompt_|button|'
    r'lable|hide_|update|error|empty|txt_|lbl_',
    re.I,
)
 
JWT_RE = re.compile(
    r'(?:(?<=^)|(?<=[^\w]))'
    r'(eyJ[a-zA-Z0-9_=]{17,})'
    r'\.'
    r'([a-zA-Z0-9_=]{50,})'
    r'\.'
    r'([a-zA-Z0-9_\-\+\/=]*)',
)
 
_NOISE_VALUE_RE = re.compile(
    r'^(true|false|null|none|yes|no|on|off|\d+\.?\d*|'
    r'https?://schemas?\.|com\.google\.)$',
    re.I,
)
 
 
def _is_noise_value(val):
    if not val or len(val) < 4:
        return True
    if ' ' in val:
        return True
    if val.lower() in ('string', 'value', 'example', 'sample',
                        'placeholder', 'your_key_here',
                        'change_me', 'todo', 'xxx', 'dummy'):
        return True
    if _NOISE_VALUE_RE.match(val):
        return True
    return False
 
 
def match_secret_key(key):
    segments = key.replace('[', '.').replace(']', '').split('.')
    key_name = segments[-1] if segments else key
 
    if _EXCLUDE_KEY_RE.search(key_name):
        return None
 
    for pat in ALL_KEY_PATTERNS:
        if pat.search(key_name):
            return pat.pattern
    return None
 
 
def match_secret_value(value):
    if _is_noise_value(value):
        return None
    if JWT_RE.search(value):
        return 'jwt'
    return None
 
 
def is_secret(key, value):
    if _is_noise_value(value):
        return False
    return bool(match_secret_key(key) or match_secret_value(value))
 
