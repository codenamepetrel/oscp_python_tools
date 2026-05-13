#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║                        js_secret_scan.py                            ║
║              JavaScript File Secret/Credential Scanner              ║
╚══════════════════════════════════════════════════════════════════════╝

DESCRIPTION
-----------
Fetches a remote JavaScript file and scans its content for exposed
secrets, credentials, and sensitive patterns (API keys, JWTs, AWS keys,
private keys, passwords, tokens, S3 buckets, etc.).

Useful for recon during CTFs, HackTheBox, OSCP, and authorized bug bounty
engagements. JS files served by web apps frequently contain hardcoded creds
left in by devs — this automates the grep.

REQUIREMENTS
------------
    pip install requests

USAGE
-----
    # Scan a single JS file URL
    python3 js_secret_scan.py -u https://target.com/static/app.js

    # Scan multiple URLs from a file (one URL per line)
    python3 js_secret_scan.py -f urls.txt

    # Save results to an output file
    python3 js_secret_scan.py -u https://target.com/static/app.js -o results.txt

    # Increase request timeout (default: 10s)
    python3 js_secret_scan.py -u https://target.com/static/app.js -t 20

    # Skip TLS verification (useful for internal/OSCP lab hosts)
    python3 js_secret_scan.py -u https://192.168.1.50/app.js --no-verify

EXAMPLE OUTPUT
--------------
    [*] Scanning: https://target.com/static/app.js

    [!] AWS Key     → AKIAIOSFODNN7EXAMPLE
    [!] JWT Token   → eyJhbGci...
    [!] S3 Bucket   → my-company-backups
    --------------------------------------------------
    [*] 3 hit(s) found in https://target.com/static/app.js

NOTES
-----
  - For authorized testing only (CTFs, HackTheBox, OSCP labs, scoped bug bounty).
  - False positives are possible — validate hits manually before reporting.
  - Pair with Burp Suite JS discovery to build your URL list.
"""

import re
import sys
import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings when --no-verify is used
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# ─────────────────────────────────────────────
# SECRET PATTERNS
# ─────────────────────────────────────────────
# Each entry is (label, regex). Patterns are intentionally broad to catch
# variations in how devs format/name their variables.
PATTERNS = {
    'API Key':      r'(?:api[_-]?key|apikey)["\'\s:=]+(["\'][A-Za-z0-9_\-]{20,}["\'])',
    'AWS Key':      r'AKIA[0-9A-Z]{16}',                                      # AWS access key IDs always start with AKIA
    'AWS Secret':   r'(?:aws_secret|aws_secret_access_key)["\'\s:=]+(["\'][A-Za-z0-9/+=]{40}["\'])',
    'JWT Token':    r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',            # JWTs always start with eyJ (base64 of '{"')
    'Private Key':  r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',    # PEM private key headers
    'Password':     r'(?:password|passwd|pwd)["\'\s:=]+(["\'][^"\'>{]{6,}["\'])',
    'Secret':       r'(?:secret|token)["\'\s:=]+(["\'][A-Za-z0-9_\-]{16,}["\'])',
    'S3 Bucket':    r's3\.amazonaws\.com/([a-z0-9.\-]{3,63})',
    'Google API':   r'AIza[0-9A-Za-z\-_]{35}',                                # Google API keys always start with AIza
    'Slack Token':  r'xox[baprs]-[0-9A-Za-z\-]{10,}',                        # Slack token prefixes
    'Basic Auth':   r'(?:https?://)([^:]+:[^@]+)@',                           # Credentials embedded in URLs
    'Generic Token':r'(?:bearer|token)["\'\s:=]+(["\'][A-Za-z0-9_\-\.]{20,}["\'])',
}


# ─────────────────────────────────────────────
# CORE SCAN FUNCTION
# ─────────────────────────────────────────────
def scan_js(url, timeout=10, verify_ssl=True, output_file=None):
    """
    Fetch a JS URL and scan its content against all patterns.
    Returns the number of hits found.
    """
    print(f'\n[*] Scanning: {url}')

    try:
        headers = {
            # Mimic a browser fetch request — some servers reject non-browser UA
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
        }
        response = requests.get(url, timeout=timeout, verify=verify_ssl, headers=headers)
        response.raise_for_status()             # Raise on 4xx/5xx HTTP errors
        js_content = response.text

    except requests.exceptions.SSLError:
        print(f'[ERROR] SSL error — try --no-verify for self-signed certs')
        return 0
    except requests.exceptions.ConnectionError:
        print(f'[ERROR] Could not connect to {url}')
        return 0
    except requests.exceptions.Timeout:
        print(f'[ERROR] Request timed out after {timeout}s')
        return 0
    except requests.exceptions.HTTPError as e:
        print(f'[ERROR] HTTP {e.response.status_code} — {url}')
        return 0
    except Exception as e:
        print(f'[ERROR] Unexpected error: {e}')
        return 0

    hit_count = 0

    for label, pattern in PATTERNS.items():
        matches = re.findall(pattern, js_content, re.IGNORECASE)

        if not matches:
            continue                            # No hits for this pattern — move on

        # re.findall returns a list of strings or tuples depending on capture groups;
        # flatten tuples and deduplicate so output is clean
        flat = list({m if isinstance(m, str) else m[0] for m in matches if m})

        for match in flat:
            result = f'[!] {label:<15} → {match}'
            print(result)
            if output_file:
                output_file.write(f'{url} | {result}\n')
                output_file.flush()             # Flush immediately in case of crash
            hit_count += 1

    # Summary line per URL
    separator = '-' * 50
    if hit_count:
        summary = f'[*] {hit_count} hit(s) found in {url}'
    else:
        summary = f'[+] Nothing obvious found in {url}'

    print(separator)
    print(summary)

    if output_file:
        output_file.write(separator + '\n')
        output_file.write(summary + '\n\n')
        output_file.flush()

    return hit_count


# ─────────────────────────────────────────────
# ARGUMENT PARSING + ENTRYPOINT
# ─────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Scan JavaScript files for exposed secrets and credentials.',
        epilog='Example: python3 js_secret_scan.py -u https://target.com/static/app.js'
    )

    # Input: single URL or file of URLs (mutually exclusive)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url',  help='Single JS file URL to scan')
    group.add_argument('-f', '--file', help='File containing JS URLs (one per line)')

    parser.add_argument('-o', '--output',    default=None,  help='Save results to file')
    parser.add_argument('-t', '--timeout',   default=10, type=int, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--no-verify',       action='store_true',  help='Skip TLS certificate verification')

    args = parser.parse_args()

    # Build list of URLs to scan
    if args.url:
        urls = [args.url]
    else:
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]  # Drop blank lines
        except FileNotFoundError:
            print(f'[ERROR] File not found: {args.file}')
            sys.exit(1)

    verify_ssl = not args.no_verify            # Flip the flag for requests

    output_file = open(args.output, 'w') if args.output else None

    total_hits = 0
    try:
        for url in urls:
            total_hits += scan_js(url, timeout=args.timeout, verify_ssl=verify_ssl, output_file=output_file)
    finally:
        if output_file:
            output_file.close()

    # Final tally across all URLs
    print(f'\n[*] Scan complete. Total hits across all targets: {total_hits}')
    if args.output:
        print(f'[*] Results saved to: {args.output}')
