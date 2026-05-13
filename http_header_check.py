#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║                      http_header_check.py                           ║
║                   HTTP Security Header Analyzer                     ║
╚══════════════════════════════════════════════════════════════════════╝

DESCRIPTION
-----------
Fetches a URL and audits its HTTP response headers against a checklist
of security headers. Flags missing or misconfigured headers, shows the
raw values of present ones, and produces a risk-scored summary.

Useful during web app recon on HackTheBox, OSCP, and authorized bug
bounty engagements. Missing security headers are low-hanging findings
that also hint at the maturity (or lack thereof) of a target's security
posture.

REQUIREMENTS
------------
    pip install requests

USAGE
-----
    # Check a single URL
    python3 http_header_check.py -u https://target.com

    # Check multiple URLs from a file (one per line)
    python3 http_header_check.py -f urls.txt

    # Save results to file
    python3 http_header_check.py -u https://target.com -o results.txt

    # Skip TLS verification (OSCP lab hosts, self-signed certs)
    python3 http_header_check.py -u https://192.168.1.50 --no-verify

    # Show all response headers (not just security ones)
    python3 http_header_check.py -u https://target.com --dump-headers

    # Custom timeout (default: 10s)
    python3 http_header_check.py -u https://target.com -t 20

EXAMPLE OUTPUT
--------------
    [*] Checking: https://target.com
    [*] Status  : 200  |  Server: nginx/1.18.0

    [✓] Strict-Transport-Security : max-age=31536000; includeSubDomains
    [✓] X-Content-Type-Options    : nosniff
    [✗] MISSING  Content-Security-Policy   — Prevents XSS and injection attacks  [HIGH]
    [✗] MISSING  X-Frame-Options          — Prevents clickjacking               [MEDIUM]
    [✗] MISSING  Permissions-Policy       — Controls browser feature access      [LOW]
    --------------------------------------------------
    [*] Score: 2/7 headers present | Risk: HIGH

NOTES
-----
  - For authorized testing only (CTFs, HackTheBox, OSCP labs, scoped bug bounty).
  - A missing CSP or HSTS on a login page is often a valid finding worth noting.
  - Pair with Burp Suite to catch headers that only appear on authenticated responses.
  - Server/X-Powered-By leaking version info is flagged separately under info disclosure.
"""

import sys
import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings when --no-verify is used
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# ─────────────────────────────────────────────
# SECURITY HEADER DEFINITIONS
# ─────────────────────────────────────────────
# Format: 'Header-Name': (description, risk_if_missing, recommended_value_hint)
SECURITY_HEADERS = {
    'Content-Security-Policy':   (
        'Prevents XSS and data injection attacks',
        'HIGH',
        "default-src 'self'"
    ),
    'Strict-Transport-Security': (
        'Forces HTTPS, prevents protocol downgrade',
        'HIGH',
        'max-age=31536000; includeSubDomains'
    ),
    'X-Frame-Options':           (
        'Prevents clickjacking via iframe embedding',
        'MEDIUM',
        'DENY or SAMEORIGIN'
    ),
    'X-Content-Type-Options':    (
        'Prevents MIME-type sniffing',
        'MEDIUM',
        'nosniff'
    ),
    'Referrer-Policy':           (
        'Controls how much referrer info is sent',
        'LOW',
        'strict-origin-when-cross-origin'
    ),
    'Permissions-Policy':        (
        'Restricts access to browser APIs (camera, mic, etc.)',
        'LOW',
        'geolocation=(), microphone=(), camera=()'
    ),
    'X-XSS-Protection':          (
        'Legacy XSS filter for older browsers (largely deprecated)',
        'INFO',
        '1; mode=block'
    ),
}

# Headers that leak server info — flagged separately as info disclosure
INFO_DISCLOSURE_HEADERS = [
    'Server',
    'X-Powered-By',
    'X-AspNet-Version',
    'X-AspNetMvc-Version',
    'X-Generator',
]

# Risk level ordering for final score calculation
RISK_ORDER = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}


# ─────────────────────────────────────────────
# CORE CHECK FUNCTION
# ─────────────────────────────────────────────
def check_headers(url, timeout=10, verify_ssl=True, dump_all=False, output_file=None):
    """
    Fetch the URL, audit security headers, and flag info disclosure headers.
    Returns the worst risk level observed from missing headers.
    """

    def log(line):
        """Print to console and optionally write to output file."""
        print(line)
        if output_file:
            output_file.write(line + '\n')
            output_file.flush()

    try:
        headers = {
            # Mimic a browser — some servers return different headers based on UA
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        }
        response = requests.get(
            url,
            allow_redirects=True,           # Follow redirects to reach the final response
            timeout=timeout,
            verify=verify_ssl,
            headers=headers
        )

    except requests.exceptions.SSLError:
        print(f'[ERROR] SSL error on {url} — try --no-verify for self-signed certs')
        return None
    except requests.exceptions.ConnectionError:
        print(f'[ERROR] Could not connect to {url}')
        return None
    except requests.exceptions.Timeout:
        print(f'[ERROR] Request timed out after {timeout}s')
        return None
    except Exception as e:
        print(f'[ERROR] Unexpected error: {e}')
        return None

    log(f'\n[*] Checking: {url}')

    # Show status code and server banner (useful recon even before header audit)
    server_banner = response.headers.get('Server', 'not disclosed')
    log(f'[*] Status  : {response.status_code}  |  Server: {server_banner}')

    # If redirected, show where we ended up
    if response.url != url:
        log(f'[*] Redirected to: {response.url}')

    log('')

    # ── Security header audit ──────────────────
    missing_risks = []
    present_count = 0

    for header, (desc, risk, hint) in SECURITY_HEADERS.items():
        value = response.headers.get(header)
        if value:
            # Truncate long values to keep output readable
            display_val = value[:80] + '…' if len(value) > 80 else value
            log(f'  [✓] {header:<35}: {display_val}')
            present_count += 1
        else:
            log(f'  [✗] MISSING  {header:<33} — {desc}  [{risk}]')
            missing_risks.append(risk)

    # ── Info disclosure check ──────────────────
    disclosed = [(h, response.headers[h]) for h in INFO_DISCLOSURE_HEADERS if h in response.headers]
    if disclosed:
        log(f'\n  [!] Info Disclosure Headers:')
        for h, v in disclosed:
            log(f'      {h}: {v}')       # Version strings here are recon gold

    # ── Dump all headers if requested ──────────
    if dump_all:
        log(f'\n  [~] All Response Headers:')
        for h, v in response.headers.items():
            log(f'      {h}: {v}')

    # ── Per-URL summary ────────────────────────
    total   = len(SECURITY_HEADERS)
    worst   = max(missing_risks, key=lambda r: RISK_ORDER[r]) if missing_risks else None
    risk_label = worst if worst else 'NONE'

    log(f'\n  {"─" * 48}')
    log(f'  [*] Score : {present_count}/{total} headers present  |  Risk: {risk_label}')

    return worst


# ─────────────────────────────────────────────
# ARGUMENT PARSING + ENTRYPOINT
# ─────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Audit HTTP security headers for a target URL.',
        epilog='Example: python3 http_header_check.py -u https://target.com'
    )

    # Input: single URL or file of URLs
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url',  help='Single URL to check')
    group.add_argument('-f', '--file', help='File of URLs to check (one per line)')

    parser.add_argument('-o', '--output',       default=None, help='Save results to file')
    parser.add_argument('-t', '--timeout',      default=10, type=int, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--no-verify',          action='store_true', help='Skip TLS certificate verification')
    parser.add_argument('--dump-headers',       action='store_true', help='Print all response headers, not just security ones')

    args = parser.parse_args()

    # Build URL list
    if args.url:
        urls = [args.url]
    else:
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f'[ERROR] File not found: {args.file}')
            sys.exit(1)

    verify_ssl  = not args.no_verify
    output_file = open(args.output, 'w') if args.output else None

    all_risks = []
    try:
        for url in urls:
            result = check_headers(
                url,
                timeout=args.timeout,
                verify_ssl=verify_ssl,
                dump_all=args.dump_headers,
                output_file=output_file
            )
            if result:
                all_risks.append(result)
    finally:
        if output_file:
            output_file.close()

    # ── Final summary across all URLs ──────────
    if len(urls) > 1:
        overall = max(all_risks, key=lambda r: RISK_ORDER[r]) if all_risks else 'NONE'
        print(f'\n{"═" * 50}')
        print(f'[*] Scanned {len(urls)} URLs  |  Overall worst risk: {overall}')

    if args.output:
        print(f'[*] Results saved to: {args.output}')
