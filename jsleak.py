#!/usr/bin/env python3
"""
jsleak - JavaScript Secret & Endpoint Scanner
A portable, stdlib-only CLI tool for finding secrets, API endpoints and interesting
artifacts in JavaScript files, directories or remote JS URLs.

Usage:
  python3 jsleak.py <target>
  python3 jsleak.py path/to/app.js
  python3 jsleak.py ./src/
  python3 jsleak.py https://example.com/bundle.js --format json --mask

Authorised recon tool. Pure Python standard library.
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# -------------------- Configuration --------------------

SKIP_DIRS = {
    '.git', 'node_modules', 'vendor', 'dist', 'build', 'out', 'public', 'static',
    '__pycache__', '.next', '.nuxt', 'coverage', 'bower_components', 'jspm_packages',
    'target', 'bin', 'obj'
}

MAX_FILE_SIZE = 8 * 1024 * 1024  # 8 MiB safety limit

# -------------------- Regex Patterns --------------------

# Secrets - order matters for display priority somewhat
SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "regex": re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        "severity": "HIGH",
        "minlen": 20,
    },
    {
        "name": "AWS Secret Access Key",
        "regex": re.compile(r'(?i)(?:aws(?:_|\s|-)?(?:secret|access)?(?:_|\s|-)?(?:key|secret)|aws_secret_access_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
        "severity": "HIGH",
        "minlen": 40,
    },
    {
        "name": "Google API Key",
        "regex": re.compile(r'\b(AIza[0-9A-Za-z_-]{35})\b'),
        "severity": "HIGH",
        "minlen": 39,
    },
    {
        "name": "Stripe Secret Key",
        "regex": re.compile(r'\b(sk_(?:live|test)_[0-9a-zA-Z]{20,})\b'),
        "severity": "HIGH",
        "minlen": 24,
    },
    {
        "name": "Stripe Publishable Key",
        "regex": re.compile(r'\b(pk_(?:live|test)_[0-9a-zA-Z]{20,})\b'),
        "severity": "MEDIUM",
        "minlen": 24,
    },
    {
        "name": "Slack Token",
        "regex": re.compile(r'\b(xox[abprs]-[0-9A-Za-z-]{10,})\b'),
        "severity": "HIGH",
        "minlen": 15,
    },
    {
        "name": "Slack Webhook",
        "regex": re.compile(r'(https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+)'),
        "severity": "HIGH",
        "minlen": 50,
    },
    {
        "name": "GitHub Token",
        "regex": re.compile(r'\b(gh[opsu]_[0-9A-Za-z_]{36,})\b'),
        "severity": "HIGH",
        "minlen": 40,
    },
    {
        "name": "GitHub Fine-grained PAT",
        "regex": re.compile(r'\b(github_pat_[0-9A-Za-z_]{60,})\b'),
        "severity": "HIGH",
        "minlen": 70,
    },
    {
        "name": "GitLab PAT",
        "regex": re.compile(r'\b(glpat-[0-9A-Za-z_\-]{20,})\b'),
        "severity": "HIGH",
        "minlen": 26,
    },
    {
        "name": "OpenAI API Key",
        "regex": re.compile(r'\b(sk-(?!ant-)(?:proj-)?[0-9A-Za-z_\-]{20,})\b'),
        "severity": "HIGH",
        "minlen": 24,
    },
    {
        "name": "Anthropic API Key",
        "regex": re.compile(r'\b(sk-ant-[0-9A-Za-z_\-]{20,})\b'),
        "severity": "HIGH",
        "minlen": 28,
    },
    {
        "name": "Slack App-Level Token",
        "regex": re.compile(r'\b(xapp-[0-9]-[0-9A-Za-z_\-]{10,})\b'),
        "severity": "HIGH",
        "minlen": 20,
    },
    {
        "name": "npm Access Token",
        "regex": re.compile(r'\b(npm_[0-9A-Za-z]{36})\b'),
        "severity": "HIGH",
        "minlen": 40,
    },
    {
        "name": "SendGrid API Key",
        "regex": re.compile(r'\b(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})\b'),
        "severity": "HIGH",
        "minlen": 69,
    },
    {
        "name": "Twilio Account SID",
        "regex": re.compile(r'\b(AC[0-9a-fA-F]{32})\b'),
        "severity": "MEDIUM",
        "minlen": 34,
    },
    {
        "name": "JWT",
        "regex": re.compile(r'\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b'),
        "severity": "MEDIUM",
        "minlen": 32,
    },
    {
        "name": "Private Key Block",
        "regex": re.compile(r'-----BEGIN (?:[A-Za-z ]+?)?PRIVATE KEY-----[\s\S]{20,}?-----END (?:[A-Za-z ]+?)?PRIVATE KEY-----', re.IGNORECASE),
        "severity": "CRITICAL",
        "minlen": 50,
        "multiline": True,
    },
    {
        "name": "Firebase URL",
        "regex": re.compile(r'https?://[a-z0-9-]{3,}\.firebaseio\.com'),
        "severity": "MEDIUM",
        "minlen": 20,
    },
    {
        "name": "Database URI",
        "regex": re.compile(r'(?i)\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|sqlserver|oracle|jdbc:[a-z]+)://[^\s\'"<>`]{12,180}'),
        "severity": "HIGH",
        "minlen": 20,
    },
    {
        "name": "Generic API Secret",
        "regex": re.compile(r'(?i)\b(?:api[_-]?(?:key|secret|token)|secret[_-]?(?:key|token)|access[_-]?(?:key|token)|client[_-]?(?:id|secret)|private[_-]?key|app[_-]?(?:key|secret)|bearer[_-]?token)\s*[:=]\s*["\']?([A-Za-z0-9_\-\.\/+=~|]{12,})["\']?'),
        "severity": "MEDIUM",
        "minlen": 12,
    },
    {
        "name": "Password Assignment",
        "regex": re.compile(r'(?i)\b(?:pass(?:word)?|pwd)\s*[:=]\s*["\']([^"\s\'`]{6,64})["\']?'),
        "severity": "MEDIUM",
        "minlen": 6,
    },
]

# Endpoint patterns (LinkFinder-inspired)
ENDPOINT_REGEXES = [
    re.compile(r'https?://[^\s\'"`<>()\[\]{}]{4,300}', re.IGNORECASE),
    re.compile(r'["\'](/api/[^\s\'"`<>()\[\]{}]{2,200})["\']?', re.IGNORECASE),
    re.compile(r'["\'](/v[0-9]+/[^\s\'"`<>()\[\]{}]{1,200})["\']?', re.IGNORECASE),
    re.compile(r'(?:fetch|axios|request|http\.get|http\.post|\.get\(|\.post\(|\.put\(|\.delete\(|\.patch\()\s*["\']([^"\s\'`]{3,200})["\']', re.IGNORECASE),
    re.compile(r'["\'](/[a-zA-Z0-9_\-/]{3,80}(?:\?[^\s\'"`]{0,120})?)["\']', re.IGNORECASE),
]

# Interesting artifacts
EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
S3_RE = re.compile(r'(?:https?://)?([a-z0-9][a-z0-9.\-]{2,62})\.s3[.\-][a-z0-9\-]{2,}\.amazonaws\.com| s3://([a-z0-9][a-z0-9.\-]{2,62})', re.IGNORECASE)
GCS_RE = re.compile(r'(?:https?://)?(?:[a-z0-9.\-]{3,}\.)?storage\.googleapis\.com/[^\s\'"`]+|(?:[a-z0-9][a-z0-9.\-]{2,62})\.storage\.googleapis\.com', re.IGNORECASE)

BAD_ENDPOINT_EXTS = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.scss', '.less', '.map',
                     '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.webm', '.pdf')

# -------------------- Helpers --------------------

def supports_color():
    """Return True if we should emit ANSI color codes."""
    if os.environ.get('NO_COLOR'):
        return False
    if not sys.stdout.isatty():
        return False
    return True

ANSI = {
    'reset': '\033[0m',
    'bold': '\033[1m',
    'red': '\033[91m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'magenta': '\033[95m',
    'cyan': '\033[96m',
    'gray': '\033[90m',
}

SEV_COLOR = {
    'CRITICAL': ANSI['red'] + ANSI['bold'],
    'HIGH': ANSI['red'],
    'MEDIUM': ANSI['yellow'],
    'INFO': ANSI['cyan'],
}

CAT_COLOR = {
    'secret': ANSI['red'] + ANSI['bold'],
    'endpoint': ANSI['blue'],
    'interesting': ANSI['magenta'],
}

def c(text, code):
    if not supports_color() or not code:
        return text
    return f"{code}{text}{ANSI['reset']}"

def mask_value(value, typ, do_mask):
    """Mask a secret value for display."""
    if not do_mask or not value:
        return value
    v = str(value)
    if len(v) <= 6:
        return '****'
    if 'Private Key' in typ:
        return '-----BEGIN ... PRIVATE KEY ... (masked)-----'
    if 'JWT' in typ:
        try:
            p = v.split('.')
            if len(p) >= 3:
                return f"{p[0][:8]}***.{p[1][:4]}***.{p[2][-6:]}"
        except Exception:
            pass
        return v[:6] + '***' + v[-4:]
    # Generic secret masking: keep prefix + suffix
    prefix = 6
    if v.startswith(('AKIA', 'AIza', 'sk_', 'pk_', 'ghp_', 'gho_', 'ghs_', 'ghu_', 'xox')):
        prefix = min(8, len(v) - 5)
    elif any(x in typ.lower() for x in ('aws', 'google', 'stripe', 'slack', 'github')):
        prefix = min(7, len(v) - 5)
    return v[:prefix] + ('*' * max(4, len(v) - prefix - 4)) + v[-4:]

def is_false_positive(val, name):
    """Crude but effective FP filter."""
    if not val:
        return True
    v = val.lower()
    fp_tokens = (
        'example', 'sample', 'demo', 'placeholder', 'your_', 'xxx', 'xxxx',
        'fake', 'dummy', 'changeme', 'insert', 'replace', 'todo',
        'undefined', 'null', 'none', 'false', '0x000', 'redacted',
    )
    if any(t in v for t in fp_tokens):
        return True
    # Very short random strings that look generic
    if len(val) < 16 and name in ('Generic API Secret', 'Password Assignment'):
        return True
    return False

def is_internal_ip(ip):
    try:
        o = [int(x) for x in ip.split('.')]
        if o[0] == 10:
            return True
        if o[0] == 127:
            return True
        if o[0] == 192 and o[1] == 168:
            return True
        if o[0] == 172 and 16 <= o[1] <= 31:
            return True
        if o[0] == 169 and o[1] == 254:
            return True
        return False
    except Exception:
        return False

def clean_endpoint(val):
    """Strip obvious junk and normalize endpoint."""
    val = val.strip().strip('\'"`')
    if len(val) < 3:
        return None
    low = val.lower()
    if low.startswith(('data:', 'blob:', 'javascript:', 'vbscript:', 'about:')):
        return None
    if low.endswith(BAD_ENDPOINT_EXTS):
        # allow if it contains /api/ or looks like route
        if '/api/' not in low and '/v1/' not in low and '/v2/' not in low:
            return None
    if len(val) > 280:
        val = val[:280]
    return val

def get_location(source, lineno, col):
    """Format source:line:col string."""
    if ':' in source and source.startswith(('http://', 'https://')):
        # keep full url but trim for display? keep full
        base = source
    else:
        base = source
    if col is not None:
        return f"{base}:{lineno}:{col}"
    return f"{base}:{lineno}"

# -------------------- Core Scanner --------------------

def scan_content(content, source):
    """Return list of raw finding dicts from a single source."""
    hits = []
    if not content or len(content) > MAX_FILE_SIZE:
        return hits

    lines = content.splitlines()

    # --- Line-based secrets (most) ---
    for lineno, line in enumerate(lines, 1):
        for p in SECRET_PATTERNS:
            if p.get('multiline'):
                continue
            for m in p['regex'].finditer(line):
                val = m.group(0)
                if m.lastindex:
                    g1 = m.group(1)
                    if g1 and len(g1) >= p.get('minlen', 4):
                        val = g1
                if not val or len(val) < p.get('minlen', 4):
                    continue
                if is_false_positive(val, p['name']):
                    continue
                col = m.start() + 1
                loc = get_location(source, lineno, col)
                hits.append({
                    'category': 'secret',
                    'type': p['name'],
                    'value': val,
                    'location': loc,
                    'severity': p['severity'],
                    'line': lineno,
                })

        # Endpoints
        for rx in ENDPOINT_REGEXES:
            for m in rx.finditer(line):
                raw = m.group(1) if m.lastindex else m.group(0)
                cleaned = clean_endpoint(raw)
                if not cleaned:
                    continue
                col = m.start() + 1
                loc = get_location(source, lineno, col)
                hits.append({
                    'category': 'endpoint',
                    'type': 'URL/Path',
                    'value': cleaned,
                    'location': loc,
                    'severity': 'INFO',
                    'line': lineno,
                })

        # Emails
        for m in EMAIL_RE.finditer(line):
            val = m.group(0)
            loc = get_location(source, lineno, m.start() + 1)
            hits.append({
                'category': 'interesting',
                'type': 'Email',
                'value': val,
                'location': loc,
                'severity': 'INFO',
                'line': lineno,
            })

        # IPs
        for m in IP_RE.finditer(line):
            ip = m.group(0)
            typ = 'Internal IP' if is_internal_ip(ip) else 'IP Address'
            loc = get_location(source, lineno, m.start() + 1)
            hits.append({
                'category': 'interesting',
                'type': typ,
                'value': ip,
                'location': loc,
                'severity': 'INFO',
                'line': lineno,
            })

    # --- Full-content / multiline secrets ---
    for p in SECRET_PATTERNS:
        if not p.get('multiline'):
            continue
        for m in p['regex'].finditer(content):
            val = m.group(0)
            if not val or len(val) < p.get('minlen', 4):
                continue
            # Compute starting line
            start_pos = m.start()
            lineno = content.count('\n', 0, start_pos) + 1
            # For private keys, use first line (BEGIN) + marker for value
            if 'PRIVATE' in p['name'].upper():
                first_line = val.splitlines()[0] if '\n' in val else val[:70]
                display_val = first_line
            else:
                display_val = val[:140]
            loc = get_location(source, lineno, 1)
            hits.append({
                'category': 'secret',
                'type': p['name'],
                'value': display_val,
                'location': loc,
                'severity': p['severity'],
                'line': lineno,
            })

    # --- Bucket / storage references from full content (broader) ---
    for m in S3_RE.finditer(content):
        bucket = m.group(1) or m.group(2)
        if bucket:
            lineno = content.count('\n', 0, m.start()) + 1
            loc = get_location(source, lineno, m.start() + 1)
            hits.append({
                'category': 'interesting',
                'type': 'S3 Bucket',
                'value': bucket if not bucket.startswith('http') else bucket,
                'location': loc,
                'severity': 'MEDIUM',
                'line': lineno,
            })

    for m in GCS_RE.finditer(content):
        lineno = content.count('\n', 0, m.start()) + 1
        val = m.group(0)
        loc = get_location(source, lineno, m.start() + 1)
        hits.append({
            'category': 'interesting',
            'type': 'GCS Bucket',
            'value': val,
            'location': loc,
            'severity': 'MEDIUM',
            'line': lineno,
        })

    return hits

# -------------------- Output Formatters --------------------

def prepare_display(findings, mask, truncate=True):
    """Attach display_value and sort findings.

    truncate=True shortens long values for terminal-table width. Machine-readable
    outputs (JSON, Markdown) pass truncate=False so piped/automated consumers get
    the full value (a truncated JWT, DB URI or key is useless downstream).
    """
    out = []
    for f in findings:
        disp = mask_value(f['value'], f['type'], mask) if f['category'] == 'secret' else f['value']
        # Truncate overly long display for table friendliness only
        if truncate and len(disp) > 90:
            disp = disp[:87] + '...'
        nf = dict(f)
        nf['display_value'] = disp
        out.append(nf)

    # Sort: secrets (CRITICAL/HIGH first) then others
    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'INFO': 3}
    out.sort(key=lambda x: (0 if x['category'] == 'secret' else 1,
                            sev_order.get(x.get('severity', 'INFO'), 9),
                            x['type'],
                            x['location']))
    return out

def print_table(findings, mask):
    prepared = prepare_display(findings, mask)
    if not prepared:
        print(c("No findings.", ANSI['gray']))
        return

    # Compute column widths
    headers = ['SEVERITY', 'TYPE', 'VALUE', 'LOCATION']
    rows = []
    for f in prepared:
        sev = f.get('severity', 'INFO')
        rows.append([
            sev,
            f['type'],
            f['display_value'],
            f['location']
        ])

    col_widths = []
    for i in range(4):
        maxw = len(headers[i])
        for r in rows:
            maxw = max(maxw, min(len(r[i]), 88))
        col_widths.append(maxw)

    # Print header
    header_line = '  '.join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    print(c(header_line, ANSI['bold'] + ANSI['gray']))
    print(c('-' * (sum(col_widths) + 6), ANSI['gray']))

    for r in rows:
        sev = r[0]
        color = SEV_COLOR.get(sev, '')
        sev_str = c(sev.ljust(col_widths[0]), color)
        line = '  '.join([
            sev_str,
            r[1].ljust(col_widths[1]),
            r[2].ljust(col_widths[2]),
            c(r[3], ANSI['gray'])
        ])
        print(line)

    print(c(f"\nTotal: {len(prepared)} unique finding(s)", ANSI['gray']))

def print_json(findings, mask):
    prepared = prepare_display(findings, mask, truncate=False)
    clean = []
    for f in prepared:
        item = {
            'category': f['category'],
            'type': f['type'],
            'value': f['display_value'],
            'location': f['location'],
            'severity': f.get('severity', 'INFO'),
        }
        clean.append(item)
    print(json.dumps(clean, indent=2, sort_keys=False))

def print_md(findings, mask):
    prepared = prepare_display(findings, mask, truncate=False)
    if not prepared:
        print("No findings.")
        return

    print("| Severity | Type | Value | Location |")
    print("|----------|------|-------|----------|")
    for f in prepared:
        val = f['display_value'].replace('|', '\\|')
        loc = f['location'].replace('|', '\\|')
        print(f"| {f.get('severity','INFO')} | {f['type']} | `{val}` | {loc} |")

    print(f"\n**Total unique findings:** {len(prepared)}")

# -------------------- Fetch & File Handling --------------------

def fetch_url(url):
    if not url.lower().startswith(('http://', 'https://')):
        raise ValueError("URL must start with http:// or https://")
    req = urllib.request.Request(
        url,
        headers={
            'User-Agent': 'jsleak/1.0 (+https://github.com/ - authorised recon)',
            'Accept': 'application/javascript, text/javascript, */*;q=0.8',
        },
        method='GET'
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        charset = resp.headers.get_content_charset() or 'utf-8'
        data = resp.read()
        try:
            return data.decode(charset, errors='replace')
        except Exception:
            return data.decode('utf-8', errors='replace')

def collect_js_files(root_dir):
    files = []
    for dirpath, dirnames, filenames in os.walk(root_dir, followlinks=False):
        # prune
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(('.js', '.mjs', '.cjs')):
                full = os.path.join(dirpath, name)
                try:
                    if os.path.isfile(full) and os.path.getsize(full) <= MAX_FILE_SIZE:
                        files.append(full)
                except OSError:
                    pass
    return sorted(files)

def read_file_safe(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception as e:
        print(c(f"[!] Failed to read {path}: {e}", ANSI['red']), file=sys.stderr)
        return None

# -------------------- Main --------------------

def build_argparser():
    p = argparse.ArgumentParser(
        prog='jsleak',
        description='JavaScript secret & endpoint scanner (stdlib only)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 jsleak.py app.js
  python3 jsleak.py ./src/ --format md
  python3 jsleak.py https://cdn.site.com/app.js --mask --format json
  python3 jsleak.py bundle.js | grep -i aws
        """.strip()
    )
    p.add_argument('target',
                   help='Path to .js file, directory to scan recursively, or http(s) URL')
    p.add_argument('--format', '-f', choices=['table', 'json', 'md'], default='table',
                   help='Output format (default: table)')
    p.add_argument('--mask', '-m', action='store_true',
                   help='Mask secret values in the output (recommended for sharing)')
    p.add_argument('--no-color', action='store_true',
                   help='Disable ANSI colors even when stdout is a TTY')
    p.add_argument('--version', action='version', version='jsleak 1.1.0')
    return p

def print_banner():
    """CobraSEC branded banner — matches jwtforge. Shown only for interactive table output
    so JSON/MD and piped output stay clean."""
    use = supports_color()
    g  = ANSI['green'] if use else ''
    cy = ANSI['cyan'] if use else ''
    gr = ANSI['gray'] if use else ''
    b  = ANSI['bold'] if use else ''
    r  = ANSI['reset'] if use else ''
    print(
        f"{g}╾━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╼{r}\n"
        f"{b}{cy}    J S L E A K{r}   {g}▓▒░ CobraSEC ░▒▓{r}\n"
        f"{gr}    JS Secret & Endpoint Scanner · Attack to Defend{r}\n"
        f"{g}╾━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╼{r}"
    )


def main():
    parser = build_argparser()
    args = parser.parse_args()

    if args.no_color:
        os.environ['NO_COLOR'] = '1'

    if args.format == 'table' and sys.stdout.isatty():
        print_banner()

    target = args.target.strip()
    sources = []   # list of (source_id, content)

    if target.startswith(('http://', 'https://')):
        print(c(f"[*] Fetching {target}", ANSI['blue']))
        try:
            content = fetch_url(target)
            sources.append((target, content))
        except urllib.error.URLError as e:
            print(c(f"[!] Fetch error: {e}", ANSI['red']), file=sys.stderr)
            sys.exit(2)
        except Exception as e:
            print(c(f"[!] Error: {e}", ANSI['red']), file=sys.stderr)
            sys.exit(2)

    elif os.path.isfile(target):
        content = read_file_safe(target)
        if content is None:
            sys.exit(2)
        sources.append((target, content))

    elif os.path.isdir(target):
        js_files = collect_js_files(target)
        total = len(js_files)
        if total == 0:
            print(c(f"[!] No .js files found under {target}", ANSI['yellow']))
            sys.exit(0)
        print(c(f"[*] Found {total} JavaScript file(s) — scanning...", ANSI['blue']))
        for idx, path in enumerate(js_files, 1):
            rel = os.path.relpath(path, target)
            if total > 3:
                print(f"\r{c(f'[+] ({idx}/{total}) {rel[:70]}', ANSI['gray'])}", end='', flush=True)
            content = read_file_safe(path)
            if content:
                sources.append((path, content))
        if total > 3:
            print()  # finish progress line
    else:
        print(c(f"[!] Target not found: {target}", ANSI['red']), file=sys.stderr)
        sys.exit(2)

    # Scan all sources
    all_raw = []
    for src, content in sources:
        all_raw.extend(scan_content(content, src))

    # Deduplicate by (category, type, value)
    seen = set()
    deduped = []
    for h in all_raw:
        key = (h['category'], h['type'], h['value'])
        if key not in seen:
            seen.add(key)
            deduped.append(h)

    # Output
    fmt = args.format
    mask = args.mask

    secrets_found = any(f['category'] == 'secret' for f in deduped)

    if fmt == 'json':
        print_json(deduped, mask)
    elif fmt == 'md':
        print_md(deduped, mask)
    else:
        print_table(deduped, mask)

    # Exit code: nonzero when secrets discovered
    if secrets_found:
        sys.exit(1)
    sys.exit(0)

if __name__ == '__main__':
    main()
