# 🛡️ BAC Hunter — Broken Access Control Bug Bounty Suite

<p align="center">
  <img src="https://img.shields.io/badge/version-v3.0.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/OWASP-A01%3A2021-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/python-3.10%2B-yellow?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Bug%20Bounty-Ready-orange?style=for-the-badge" />
</p>

> **For authorised penetration testing and bug bounty programs ONLY.**
> Only run against systems you own or have explicit written permission to test.
> Unauthorised use is illegal and unethical.

---

## 📖 What is BAC Hunter?

**BAC Hunter** is a focused, low-noise Python tool for detecting **Broken Access Control** vulnerabilities — the #1 threat in the OWASP Top 10 (A01:2021). It is purpose-built for bug bounty hunters and penetration testers who need a reliable, stealthy, and readable scanner that covers a wide range of real-world BAC attack patterns.

Unlike bloated all-in-one scanners, BAC Hunter does one thing and does it well — finding access control flaws across 20 distinct test categories, with built-in stealth controls for responsible disclosure workflows.

---

## ✨ Features

- ✅ **20 test categories** covering OWASP A01:2021 in depth
- 🥷 **Stealth mode** — UA rotation, randomised jitter, automatic rate-limit backoff
- 🔒 **Passive mode** — skips all destructive PoC actions (safe for production targets)
- 📄 **JSON report output** — structured findings with severity levels
- 🎯 **Selective testing** — run only the tests you need with `--test`
- 🔁 **Retry logic** — exponential backoff on connection errors
- 🌐 **Proxy support** — plug straight into Burp Suite
- 🏷️ **Severity tagging** — Critical / High / Medium / Low on every finding

---

## 🧪 Tests Covered

| # | Test | Severity |
|---|------|----------|
| 01 | Unprotected Admin Panel (predictable paths) | Critical/High |
| 02 | Admin Path Disclosed in Page Source / JS | High |
| 03 | Cookie-Based Bypass (`Admin=true`, `role=admin`, …) | Critical/High |
| 04 | Role ID Privilege Escalation via JSON / Form body | High |
| 05 | X-Original-URL / X-Rewrite-URL / Forwarded Header Override | Critical/High |
| 06 | HTTP Method Bypass (GET on POST-only endpoints) | Medium |
| 07 | IDOR — Horizontal Escalation (`?id=`, `?userId=`) | High |
| 08 | IDOR — GUID / UUID Leaked in Page | High |
| 09 | IDOR — Sensitive Data in 302 Redirect Body | High |
| 10 | IDOR — Admin Password Extraction | Critical |
| 11 | IDOR — Insecure File Download (predictable filenames) | High |
| 12 | Missing Function-Level Access Control (POST / DELETE) | High |
| 13 | Referer-Based Access Control Bypass | Medium |
| 14 | IP Spoofing / Forwarding Headers Bypass | Critical/High |
| 15 | Path Normalisation / Encoding Bypass | High |
| 16 | HTTP Verb Tampering (HEAD, OPTIONS, TRACE, PATCH) | Medium |
| 17 | Mass Assignment (extra privilege fields) | High |
| 18 | HTTP Parameter Pollution (duplicate params) | Medium |
| 19 | HTTP Method Switching (GET→POST→DELETE on restricted endpoints) | High |
| 20 | Authorization Parameter Fuzzing (`?admin=true`, `&role=admin`, …) | Medium |

---

## 🚀 Installation

```bash
git clone https://github.com/TheMursalin/bachunter.git
cd bachunter
pip install -r requirements.txt
```

### Requirements

```
requests
beautifulsoup4
urllib3
lxml
```

Or install directly:

```bash
pip install requests beautifulsoup4 urllib3 lxml
```

---

## 🔧 Usage

```
python3 bac_hunter.py <target_url> [options]
```

### Basic Examples

```bash
# Run all 20 tests with stealth mode and no destructive actions
python3 bac_hunter.py https://target.com --stealth --passive

# Run specific tests only
python3 bac_hunter.py https://target.com --test 1 5 14 19 20 --stealth

# Save findings to JSON report (great for writeups)
python3 bac_hunter.py https://target.com --output findings.json

# Use with Burp Suite proxy
python3 bac_hunter.py https://target.com --proxy http://127.0.0.1:8080

# Custom credentials + no proxy
python3 bac_hunter.py https://target.com --creds admin:hunter2 --no-proxy

# Adjust timeout for slow targets
python3 bac_hunter.py https://target.com --timeout 30 --stealth
```

### All Options

| Flag | Description | Default |
|------|-------------|---------|
| `url` | Target base URL | *(required)* |
| `--test N [N ...]` | Run specific test numbers (1–20) | all tests |
| `--stealth` | UA rotation + longer jitter + rate-limit backoff | off |
| `--passive` | Skip all destructive / mutating PoC actions | off |
| `--delay MIN MAX` | Custom jitter window in seconds | `0.3–1.0` (or `0.8–2.5` in stealth) |
| `--proxy URL` | Proxy URL | `http://127.0.0.1:8080` |
| `--no-proxy` | Disable proxy entirely | — |
| `--verify-ssl` | Enable SSL certificate verification | off |
| `--creds USER:PASS` | Test credentials | `wiener:peter` |
| `--ua FILE` | Custom User-Agent list (one per line) | built-in pool |
| `--output FILE` | Write JSON findings report to file | — |
| `--timeout N` | Request timeout in seconds | `15` |
| `--list` | List all available tests and exit | — |
| `--version` | Show version and exit | — |

---

## 📊 Sample Output

```
╔═══════════════════════════════════════════════════════════════╗
║        BAC Hunter  ·  Broken Access Control  v3.0.0           ║
║        OWASP A01:2021  ·  Low‑noise  ·  Bug Bounty Ready      ║
║        For authorised testing and research only               ║
╚═══════════════════════════════════════════════════════════════╝

  Target     : https://target.com
  Stealth    : ON  (UA rotation + jitter + rate‑limit backoff)
  Passive    : ON  (no destructive PoC actions)

─────────────────────────────────────────────────────────────────
  TEST 01  ·  Unprotected Admin Panel  [High]
─────────────────────────────────────────────────────────────────
  [*] Probing: https://target.com/administrator-panel
  [VULN] Admin panel accessible at: https://target.com/administrator-panel  (HTTP 200)

═════════════════════════════════════════════════════════════════
  SUMMARY OF FINDINGS
═════════════════════════════════════════════════════════════════
  [VULN]  Test 01 — Unprotected Admin Panel  [Critical]
           Accessible at /administrator-panel without authentication
  [SAFE]  Test 02 — Admin Path in Source
```

### JSON Report Format

```json
{
  "tool": "BAC Hunter v3.0.0",
  "target": "https://target.com",
  "timestamp": "2026-04-23T10:00:00Z",
  "summary": {
    "total_tests": 20,
    "vulnerabilities": 3,
    "by_severity": {
      "Critical": 1,
      "High": 2,
      "Medium": 0,
      "Low": 0
    }
  },
  "findings": [...]
}
```

---

## 🔄 Changelog

### v3.0.0 — Quality Refactor
- `Config` dataclass replaces scattered global variables
- `Finding` dataclass with typed fields replaces raw dicts
- Proper `Timeout` and `ConnectionError` handling in all requests
- Extracted reusable helpers: `extract_api_key()`, `extract_password_field()`, `_handle_rate_limit()`
- CSRF extraction now checks 4 common field names (`csrf`, `_csrf`, `csrfmiddlewaretoken`, `authenticity_token`)
- URL validated before any tests run
- New `--timeout` CLI flag
- `--version` flag now works correctly
- `frozenset` for admin page indicators (faster lookups)
- Full type annotations throughout the codebase
- Login detection checks multiple logout link patterns

### v2.0.0
- Added Tests 19 & 20 (Method Switching, Auth Param Fuzzing)
- Stealth mode with UA rotation and jitter
- Passive mode for safe production testing
- JSON report output

### v1.0.0
- Initial release with 18 BAC test categories

---

## ⚠️ Legal Disclaimer

This tool is intended **exclusively** for:
- Authorised penetration testing engagements
- Bug bounty programs where you have written scope permission
- Security research on systems you own

**The author takes no responsibility for misuse.** Running this tool against systems without explicit authorisation is illegal in most jurisdictions and violates the terms of service of most bug bounty platforms.

---

## 👤 Author

**Mursalin** — [@TheMursalin](https://github.com/TheMursalin)

If this tool helped you find a bug, a ⭐ on the repo is always appreciated!

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
