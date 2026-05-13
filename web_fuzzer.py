#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║                         web_fuzz.py                                 ║
║               Web Directory & Path Fuzzer                           ║
╚══════════════════════════════════════════════════════════════════════╝

DESCRIPTION
-----------
Multithreaded web path fuzzer. Iterates a wordlist against a base URL,
appending common extensions per word. Flags any response that isn't a
clean 404/400/410 miss — including 403s, which confirm a path EXISTS
even if you can't access it yet.

Useful for content discovery during HackTheBox, OSCP, and authorized
bug bounty recon. Frequently uncovers admin panels, backup files,
config leaks, and forgotten endpoints.

REQUIREMENTS
------------
    pip install requests

WORDLIST RECOMMENDATIONS
------------------------
    # Broad coverage (fast, good starting point)
    /usr/share/seclists/Discovery/Web-Content/common.txt

    # Deeper directory enumeration
    /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

    # Backup/config file hunting
    /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt

    Install SecLists on Kali:
        sudo apt install seclists

USAGE
-----
    # Basic fuzz
    python3 web_fuzz.py -u https://target.com -w wordlist.txt

    # Custom thread count (default: 30)
    python3 web_fuzz.py -u https://target.com -w wordlist.txt -t 50

    # Only flag specific status codes
    python3 web_fuzz.py -u https://target.com -w wordlist.txt --match 200,301,403

    # Add extra extensions beyond the defaults
    python3 web_fuzz.py -u https://target.com -w wordlist.txt -x .zip,.conf,.log

    # Save results to file
    python3 web_fuzz.py -u https://target.com -w wordlist.txt -o results.txt

    # Skip TLS verification (OSCP lab hosts, self-signed certs)
    python3 web_fuzz.py -u https://192.168.1.50 -w wordlist.txt --no-verify

    # Quiet mode — only print hits, suppress progress noise
    python3 web_fuzz.py -u https://target.com -w wordlist.txt -q

EXAMPLE OUTPUT
--------------
    [*] Target  : https://target.com
    [*] Wordlist: common.txt (4615 words)
    [*] Threads : 30  |  Extensions: 6  |  Total requests: ~27690
    ──────────────────────────────────────────────────────────────

    [200]  https://target.com/index.php              (12840 bytes)
    [301]  https://target.com/admin                  (   0 bytes)  → /admin/
    [403]  https://target.com/admin/config.php       ( 278 bytes)  ← EXISTS, access denied
    [200]  https://target.com/backup.sql.bak         (98120 bytes)
    [200]  https://target.com/config.php.old         ( 540 bytes)

STATUS CODE CHEATSHEET
----------------------
    200  Found and readable
    301  Permanent redirect (follow it)
    302  Temporary redirect (follow it)
    403  EXISTS but access denied — this is your next target
    401  Exists but requires auth — try default creds
    500  Server error — often means the path exists and broke something

NOTES
-----
  - For authorized testing only (CTFs, HackTheBox, OSCP labs, scoped bug bounty).
  - 403s are as interesting as 200s — the path exists, just locked down.
  - Pair with Burp Suite to manually investigate hits.
  - Lower thread count (-t 10) if the target rate-limits or you see false positives.
  - ffuf or gobuster will be faster for very large wordlists, but this script
    gives you more control and visibility for targeted runs.
"""

import sys
import argparse
import requests
import threading
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings when --no-verify is used
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# ─────────────────────────────────────────────
# DEFAULTS
# ─────────────────────────────────────────────
DEFAULT_EXTENSIONS  = ['', '.php', '.html', '.txt', '.bak', '.old']
DEFAULT_THREADS     = 30
DEFAULT_TIMEOUT     = 5
# Responses with these codes are treated as "not found" and suppressed
DEFAULT_IGNORE_CODES = {400, 404, 410}

# Thread-safe counter for progress tracking
_lock         = threading.Lock()
_checked      = 0
_total        = 0


# ─────────────────────────────────────────────
# CORE CHECK FUNCTION
# ─────────────────────────────────────────────
def check_path(base_url, word, extensions, ignore_codes, timeout, verify_ssl,
               quiet, output_file, session):
    """
    Try base_url/word + each extension. Print and optionally save any hit
    whose status code isn't in ignore_codes.
    """
    global _checked

    word = word.strip()
    if not word or word.startswith('#'):    # Skip blank lines and comments in wordlist
        return

    for ext in extensions:
        url = f'{base_url.rstrip("/")}/{word}{ext}'
        try:
            r = session.get(
                url,
                allow_redirects=False,      # Don't follow redirects — 301/302 are hits worth seeing
                timeout=timeout,
                verify=verify_ssl
            )

            if r.status_code in ignore_codes:
                continue                    # Clean miss — skip silently

            # Build redirect hint for 3xx responses
            location = ''
            if r.status_code in (301, 302, 307, 308):
                location = f'  → {r.headers.get("Location", "?")}'

            # Flag 403s as "exists but locked" — these are high-value targets
            access_note = '  ← EXISTS, access denied' if r.status_code == 403 else ''

            size   = len(r.content)
            result = f'[{r.status_code}]  {url:<60} ({size:>6} bytes){location}{access_note}'

            with _lock:                     # Serialize console output across threads
                print(result)
                if output_file:
                    output_file.write(result + '\n')
                    output_file.flush()     # Flush immediately — don't lose hits on crash

        except requests.exceptions.Timeout:
            pass                            # Path didn't respond in time — expected at scale
        except requests.exceptions.ConnectionError:
            pass                            # Connection refused or DNS miss — skip
        except Exception:
            pass                            # Catch-all for SSL errors, resets, etc.

    # Update progress counter (regardless of hits)
    with _lock:
        _checked += 1
        if not quiet and _total > 0 and _checked % 100 == 0:
            pct = (_checked / _total) * 100
            print(f'    [~] Progress: {_checked}/{_total} words ({pct:.0f}%)', end='\r')


# ─────────────────────────────────────────────
# MAIN FUZZER
# ─────────────────────────────────────────────
def fuzz(base_url, wordlist_path, threads, extensions, ignore_codes,
         timeout, verify_ssl, quiet, output_file):
    """
    Load wordlist, spin up thread pool, dispatch all check_path tasks.
    """
    global _total, _checked
    _checked = 0

    try:
        with open(wordlist_path, 'r', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f'[ERROR] Wordlist not found: {wordlist_path}')
        sys.exit(1)

    _total = len(words)
    total_requests = _total * len(extensions)

    print(f'[*] Target  : {base_url}')
    print(f'[*] Wordlist: {wordlist_path} ({_total} words)')
    print(f'[*] Threads : {threads}  |  Extensions: {len(extensions)}  |  Total requests: ~{total_requests}')
    print(f'[*] Ignoring: {sorted(ignore_codes)}')
    print('─' * 62)

    # Reuse a single session across all threads — saves TCP handshake overhead
    # and allows connection pooling
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(
            lambda w: check_path(
                base_url, w, extensions, ignore_codes,
                timeout, verify_ssl, quiet, output_file, session
            ),
            words
        )

    # Clear the progress line before final summary
    if not quiet:
        print(' ' * 60, end='\r')

    print(f'\n[*] Done. {_total} words checked ({total_requests} requests).')


# ─────────────────────────────────────────────
# ARGUMENT PARSING + ENTRYPOINT
# ─────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Multithreaded web directory and path fuzzer.',
        epilog='Example: python3 web_fuzz.py -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt'
    )
    parser.add_argument('-u', '--url',       required=True, help='Base URL to fuzz (e.g. https://target.com)')
    parser.add_argument('-w', '--wordlist',  required=True, help='Path to wordlist file')
    parser.add_argument('-t', '--threads',   default=DEFAULT_THREADS, type=int,
                        help=f'Thread count (default: {DEFAULT_THREADS})')
    parser.add_argument('-x', '--extensions', default=None,
                        help='Comma-separated extra extensions (e.g. .zip,.conf,.log). Appended to defaults.')
    parser.add_argument('--match',           default=None,
                        help='Only show these status codes (e.g. 200,301,403). Overrides ignore list.')
    parser.add_argument('--ignore',          default=None,
                        help=f'Comma-separated status codes to suppress (default: {sorted(DEFAULT_IGNORE_CODES)})')
    parser.add_argument('-o', '--output',    default=None,  help='Save results to file')
    parser.add_argument('--no-verify',       action='store_true', help='Skip TLS certificate verification')
    parser.add_argument('-q', '--quiet',     action='store_true', help='Suppress progress updates, only print hits')

    args = parser.parse_args()

    # Build extension list
    extensions = list(DEFAULT_EXTENSIONS)
    if args.extensions:
        extras = [e if e.startswith('.') else f'.{e}' for e in args.extensions.split(',')]
        extensions += extras                # Append extras, don't replace defaults

    # Build ignore set — --match overrides --ignore
    if args.match:
        # If --match is set, only show those codes (ignore everything else)
        match_codes  = set(int(c.strip()) for c in args.match.split(','))
        ignore_codes = set(range(100, 600)) - match_codes
    elif args.ignore:
        ignore_codes = set(int(c.strip()) for c in args.ignore.split(','))
    else:
        ignore_codes = DEFAULT_IGNORE_CODES

    verify_ssl   = not args.no_verify
    output_file  = open(args.output, 'w') if args.output else None

    try:
        fuzz(
            base_url     = args.url,
            wordlist_path= args.wordlist,
            threads      = args.threads,
            extensions   = extensions,
            ignore_codes = ignore_codes,
            timeout      = DEFAULT_TIMEOUT,
            verify_ssl   = verify_ssl,
            quiet        = args.quiet,
            output_file  = output_file
        )
    finally:
        if output_file:
            output_file.close()

    if args.output:
        print(f'[*] Results saved to: {args.output}')
