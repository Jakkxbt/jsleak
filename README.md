# jsleak

A fast, portable, **single-file** JavaScript secret & endpoint scanner written in pure Python (standard library only).

- No dependencies
- Works on Python 3.6+
- Scans single `.js` files, directories (recursive), or live `http(s)` URLs
- Finds secrets, API endpoints/paths, and interesting artifacts
- Clean table / JSON / Markdown output
- Optional secret masking
- Non-zero exit status when secrets are discovered (CI friendly)
- JSON/Markdown output keeps full values (never truncated) for piping into other tools

## Installation

```bash
mkdir -p jsleak && cd jsleak
curl -o jsleak.py https://...   # or copy the script
chmod +x jsleak.py
```

Or just drop `jsleak.py` anywhere and run with `python3 jsleak.py`.

## Usage

```bash
python3 jsleak.py <target> [options]
```

**Targets**

- Single file: `python3 jsleak.py dist/app.js`
- Directory (recurses, skips `node_modules`, `.git`, `dist`, etc.): `python3 jsleak.py ./src/`
- Remote JS: `python3 jsleak.py https://example.com/static/bundle.js`

**Options**

| Flag            | Description                              |
|-----------------|------------------------------------------|
| `--format`, `-f` | `table` (default) \| `json` \| `md`     |
| `--mask`, `-m`   | Mask secret values (recommended)         |
| `--no-color`     | Disable ANSI colors                      |
| `--version`      | Show version                             |

## What it detects

### SECRETS (with severity)

| Type                    | Example pattern                     | Severity  |
|-------------------------|-------------------------------------|-----------|
| AWS Access Key ID       | `AKIA...`                           | HIGH      |
| AWS Secret Access Key   | long base64 assignment              | HIGH      |
| Google API Key          | `AIza...`                           | HIGH      |
| Stripe keys             | `sk_live_...`, `pk_live_...`        | HIGH/MED  |
| Slack Token / Webhook   | `xox...`, hooks.slack.com           | HIGH      |
| GitHub Token            | `ghp_...`, `gho_...`                | HIGH      |
| GitHub Fine-grained PAT | `github_pat_...`                    | HIGH      |
| GitLab PAT              | `glpat-...`                         | HIGH      |
| OpenAI API Key          | `sk-...`, `sk-proj-...`             | HIGH      |
| Anthropic API Key       | `sk-ant-...`                        | HIGH      |
| Slack App-Level Token   | `xapp-...`                          | HIGH      |
| npm Access Token        | `npm_...`                           | HIGH      |
| SendGrid API Key        | `SG.xxx.yyy`                        | HIGH      |
| Twilio Account SID      | `AC...`                             | MEDIUM    |
| JWT                     | `eyJ...`                            | MEDIUM    |
| Private Key Block       | `-----BEGIN ... PRIVATE KEY-----`   | CRITICAL  |
| Firebase URL            | `*.firebaseio.com`                  | MEDIUM    |
| Database URI            | `postgres://`, `mongodb://`, etc.   | HIGH      |
| Generic secrets         | `api_key=`, `client_secret=`, `password=` | MEDIUM |

### ENDPOINTS

- Absolute `https?://...`
- Relative API paths: `/api/...`, `/v1/...`, `/v2/...`
- Common fetch/axios patterns
- Other quoted paths that look like routes

### INTERESTING

- Emails
- IP addresses (highlights Internal IPs: 10/8, 172.16/12, 192.168/16, 127)
- S3 buckets (`*.s3.*.amazonaws.com`, `s3://...`)
- GCS buckets (`storage.googleapis.com`, `*.storage.googleapis.com`)

All results are **deduplicated** across files.

## Exit codes

- `0` — no secrets found
- `1` — one or more secrets found
- `2` — usage / fetch / read error

## Examples

### Basic scan of a file

```bash
python3 jsleak.py app.js
```

### Scan directory + Markdown report

```bash
python3 jsleak.py ./webapp/ --format md > findings.md
```

### Scan remote bundle, mask secrets, JSON output

```bash
python3 jsleak.py https://static.example.com/main.3f4a2b.js --mask --format json
```

### Pipe-friendly

```bash
python3 jsleak.py dist/*.js --mask | jq '.[] | select(.severity=="HIGH")'
```

### CI example (fail build on secrets)

```yaml
- name: Scan JS for secrets
  run: |
    python3 jsleak/jsleak.py ./dist --format json --mask || exit 1
```

## Sample output (table)

```
SEVERITY  TYPE                  VALUE                                      LOCATION
---------  --------------------  -----------------------------------------  --------------------
CRITICAL  Private Key Block     -----BEGIN RSA PRIVATE KEY ...             src/config.js:12:4
HIGH      AWS Access Key ID     AKIA****************                      dist/app.js:284:18
HIGH      Stripe Secret Key     sk_live_************************           src/payments.js:41:9
MEDIUM    JWT                   eyJhbG***.***.abc123                       public/app.js:19:33
INFO      URL/Path              /api/v2/users/profile                      dist/app.js:102:27
INFO      Internal IP           10.42.13.7                                 config.js:7:22
INFO      Email                 admin@company.internal                     src/auth.js:55:11
INFO      S3 Bucket             my-prod-assets                             assets.js:3:1
```

## Notes / Limitations

- Only `.js`, `.mjs`, `.cjs` files are scanned in directory mode.
- Large files (>8 MiB) are skipped for safety.
- Regexes try to balance recall vs noise; false positives are still possible.
- The tool is intended for **authorised** security testing and reconnaissance only.

## License

Public domain / CC0 — use freely for authorised work.
