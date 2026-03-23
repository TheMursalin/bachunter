# 🔐 BAC Hunter v2.0
### Broken Access Control Bug Bounty Suite · OWASP A01:2021

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![OWASP](https://img.shields.io/badge/OWASP-A01%3A2021-red)
![Version](https://img.shields.io/badge/Version-2.0-blueviolet)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

> **For authorised penetration testing and bug bounty programs ONLY.**
> Only run against systems you own or have explicit written permission to test. Unauthorised use is illegal and unethical.

---

## 📖 Overview

**BAC Hunter** is a low-noise, bug-bounty-ready Python suite for detecting **Broken Access Control** vulnerabilities — the #1 vulnerability class in the OWASP Top 10 (A01:2021). It automates 19 targeted test cases covering everything from basic admin panel enumeration to JWT algorithm bypass, all with stealth controls designed for real-world engagements.

---

## ✨ Features

- **19 automated tests** covering the full OWASP A01:2021 attack surface
- **Stealth mode** — User-Agent rotation, jitter delays, and automatic rate-limit backoff
- **Passive mode** — zero destructive or mutating actions, safe for production environments
- **Severity-tagged findings** — Critical / High / Medium / Low classification
- **JSON report export** for clean documentation and triage
- **Burp Suite proxy integration** out of the box
- **Custom UA lists, credentials, and delay windows** for flexible engagements

---

## 🧪 Test Coverage

| # | Test Name | Severity |
|---|-----------|----------|
| 01 | Unprotected Admin Panel (Path Brute) | High |
| 02 | Admin Path Disclosed in Page Source | Medium |
| 03 | Cookie-Based Bypass (`Admin=true`) | High |
| 04 | Role ID Escalation via JSON Body | High |
| 05 | X-Original-URL / X-Rewrite-URL Header Override | High |
| 06 | HTTP Method Bypass (GET on POST-only endpoint) | Medium |
| 07 | IDOR — Horizontal Escalation (`?id=`) | High |
| 08 | IDOR — GUID Leaked in Page | Medium |
| 09 | IDOR — Sensitive Data in 302 Body | High |
| 10 | IDOR — Admin Password Extraction | Critical |
| 11 | IDOR — Insecure File Download | High |
| 12 | Missing Function-Level Access Control (POST) | High |
| 13 | Referer-Based Access Control Bypass | Medium |
| 14 | IP Spoofing / Forwarding Headers Bypass 🆕 | High |
| 15 | Path Normalisation / Encoding Bypass 🆕 | Medium |
| 16 | HTTP Verb Tampering (HEAD, OPTIONS, PATCH) 🆕 | Medium |
| 17 | Mass Assignment (Extra Privilege Fields) 🆕 | High |
| 18 | HTTP Parameter Pollution (Duplicate Params) 🆕 | Medium |
| 19 | JWT "none" Algorithm Bypass 🆕 | Critical |

---

## ⚙️ Installation

**Requirements:** Python 3.10+

```bash
# Clone the repository
git clone https://github.com/yourusername/bac-hunter.git
cd bac-hunter

# Install dependencies
pip install requests beautifulsoup4 urllib3
```

---

## 🚀 Usage

```bash
python3 bac_hunter.py <target_url> [options]
```

### Examples

```bash
# Full scan with stealth and passive mode (recommended for bug bounties)
python3 bac_hunter.py https://target.com --stealth --passive

# Run specific tests only
python3 bac_hunter.py https://target.com --test 1 5 14 15 16 --stealth

# Export findings to JSON with Burp proxy
python3 bac_hunter.py https://target.com --proxy http://127.0.0.1:8080 --output findings.json

# Custom credentials, no proxy
python3 bac_hunter.py https://target.com --creds admin:hunter2 --no-proxy

# List all available tests
python3 bac_hunter.py https://target.com --list
```

---

## 🛠️ Options

| Flag | Description | Default |
|------|-------------|---------|
| `--stealth` | Enable UA rotation, jitter delays, and rate-limit backoff | Off |
| `--passive` | Skip all destructive / mutating PoC actions | Off |
| `--delay MIN MAX` | Custom jitter window in seconds | `0.8–2.5s` (stealth) |
| `--proxy URL` | Proxy URL for traffic inspection | `http://127.0.0.1:8080` |
| `--no-proxy` | Disable proxy entirely | — |
| `--verify-ssl` | Enable SSL certificate verification | Off |
| `--creds U:P` | Override test credentials | `wiener:peter` |
| `--ua FILE` | Load custom User-Agent list (one per line) | Built-in pool |
| `--test N [N...]` | Run specific test numbers only | All tests |
| `--output FILE` | Write JSON findings report to file | — |
| `--list` | Print all available tests and exit | — |

---

## 📊 Sample Output

```
╔═══════════════════════════════════════════════════════════════╗
║        BAC Hunter  ·  Broken Access Control  v2.0             ║
║        OWASP A01:2021  ·  Low-noise  ·  Bug Bounty Ready      ║
║        For authorised testing and research only               ║
╚═══════════════════════════════════════════════════════════════╝

  Target    : https://target.com
  Stealth   : ON  (UA rotation + jitter + rate-limit backoff)
  Passive   : ON  (no destructive PoC actions)

═══════════════════════════════════════════════════════════════════
  SUMMARY OF FINDINGS
═══════════════════════════════════════════════════════════════════
  [VULN]  Test 03 — Cookie-Based Bypass              [High]
  [VULN]  Test 10 — IDOR Admin Password Extraction   [Critical]
  [VULN]  Test 19 — JWT "none" Algorithm Bypass      [Critical]
  [SAFE]  Test 01 — Unprotected Admin Panel
  ...
═══════════════════════════════════════════════════════════════════
```

### JSON Report Structure

```json
{
  "tool": "BAC Hunter v2.0",
  "target": "https://target.com",
  "timestamp": "2025-01-01T12:00:00Z",
  "summary": {
    "total_tests": 19,
    "vulnerabilities": 3,
    "by_severity": {
      "Critical": 2,
      "High": 1,
      "Medium": 0,
      "Low": 0
    }
  },
  "findings": [...]
}
```

---

## 🥷 Stealth Controls

BAC Hunter is designed to operate quietly in bug bounty programs where noise can get you blocked or disqualified.

- **User-Agent rotation** — cycles through a realistic pool of browser UAs (or your custom list)
- **Jitter delays** — randomised sleep between requests to mimic human behaviour
- **Rate-limit backoff** — automatically respects `429` responses with `Retry-After` support
- **Passive mode** — disables all write/mutate operations, making it safe for production targets

---

## 🛡️ Remediation Guidance

If BAC Hunter detects vulnerabilities, here's what to fix:

- **Enforce server-side access control** on every endpoint — never trust client-supplied roles, cookies, headers, or IPs
- **Use indirect object references** — never expose raw database IDs in URLs or request bodies
- **Validate JWTs properly** — reject the `none` algorithm and verify signatures server-side
- **Restrict HTTP methods** — only allow the methods each endpoint is designed to handle
- **Audit mass assignment** — whitelist allowed fields, never bind user input directly to privileged models

---

## 🤝 Contributing

Contributions, new test ideas, and bug reports are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/test-20-new-bypass`)
3. Commit your changes (`git commit -m 'Add test 20: new bypass technique'`)
4. Push to the branch (`git push origin feature/test-20-new-bypass`)
5. Open a Pull Request

---

## ⚠️ Disclaimer

BAC Hunter is intended **strictly for authorised security testing and educational purposes**. The authors are not responsible for any misuse or damage caused by this tool. Always obtain explicit written permission before testing any system you do not own.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">Built with ❤️ for the bug bounty community · Happy hunting 🎯</p>
