"""
subdomain_enum.py - Async subdomain enumerator
Author: 1337 Pete
Description: Brute-forces subdomains using a wordlist via async HTTP/HTTPS requests.
             Concurrency-limited to avoid flooding the OS or triggering rate limits.

             pip install aiohttp
             subdomain_enum.py
Async subdomain enumerator built in Python. Uses `aiohttp` to blast through a wordlist concurrently while staying within sane connection limits.
---
Features
Async/semaphore-gated — no OS connection floods
Tries HTTPS first, falls back to HTTP automatically
Follows redirects (catches 301/302 responses)
Skips SSL verification (catches self-signed internal hosts)
Optional output file (`-o`)
CLI flags for concurrency, protocol control, wordlist, domain
---
Requirements
```bash
pip install aiohttp
```
---
Usage
Basic
```bash
python3 subdomain_enum.py -d target.com -w wordlist.txt
```
With output file
```bash
python3 subdomain_enum.py -d target.com -w wordlist.txt -o results.txt
```
Custom concurrency (default: 100)
```bash
python3 subdomain_enum.py -d target.com -w wordlist.txt -c 200
```
HTTPS only
```bash
python3 subdomain_enum.py -d target.com -w wordlist.txt --https-only
```
HTTP only
```bash
python3 subdomain_enum.py -d target.com -w wordlist.txt --http-only
```
---
Recommended Wordlists (SecLists)
```bash
# Small/fast (good starting point)
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Medium
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# Full send
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```
Install SecLists on Kali:
```bash
sudo apt install seclists
```
---
Example Output
```
[*] Target   : target.com
[*] Wordlist : subdomains-top1million-5000.txt (5000 words)
[*] Threads  : 100 concurrent
[*] Protocols: https, http
[*] Started  : 2026-05-13 10:22:01
--------------------------------------------------
[FOUND] https://www.target.com — Status: 200
[FOUND] https://mail.target.com — Status: 200
[FOUND] http://dev.target.com — Status: 302
--------------------------------------------------
[*] Done. 5000 words checked.
```
---
Notes
This tool is for authorized testing only (CTFs, HackTheBox, OSCP labs, bug bounty with scope).
Crank `-c` down if you're hitting rate limits or seeing false negatives.
For passive/DNS-only enumeration, consider pairing with `amass` or `subfinder`.
"""

import asyncio
import aiohttp
import argparse
import sys
from datetime import datetime

# ─────────────────────────────────────────────
# CONFIGURATION DEFAULTS
# ─────────────────────────────────────────────
DEFAULT_CONCURRENCY = 100    # Max simultaneous connections
DEFAULT_TIMEOUT     = 3      # Seconds before a request is abandoned
DEFAULT_PROTOCOLS   = ['https', 'http']  # Try HTTPS first, fall back to HTTP


# ─────────────────────────────────────────────
# CORE CHECK FUNCTION
# ─────────────────────────────────────────────
async def check_subdomain(session, semaphore, subdomain, domain, protocols, output_file):
    """
    Attempt to reach subdomain.domain over each protocol.
    Semaphore limits how many of these run concurrently.
    """
    async with semaphore:                          # Acquire a slot; blocks if at concurrency cap
        for proto in protocols:
            url = f'{proto}://{subdomain}.{domain}'
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
                    allow_redirects=True,          # Follow redirects (catches 301/302 hits)
                    ssl=False                       # Skip SSL verification (self-signed certs on internal hosts)
                ) as response:
                    if response.status < 400:      # 1xx/2xx/3xx = something is alive
                        result = f'[FOUND] {url} — Status: {response.status}'
                        print(result)
                        if output_file:            # Write hit to file if -o was specified
                            output_file.write(result + '\n')
                            output_file.flush()    # Flush immediately so hits aren't lost on crash
                        break                      # No need to try HTTP if HTTPS already hit
            except asyncio.TimeoutError:
                pass                               # Host didn't respond in time — skip silently
            except aiohttp.ClientConnectorError:
                pass                               # DNS didn't resolve or connection refused — expected
            except Exception:
                pass                               # Catch-all for SSL errors, resets, etc.


# ─────────────────────────────────────────────
# MAIN RUNNER
# ─────────────────────────────────────────────
async def main(domain, wordlist_path, concurrency, protocols, output_path):
    """
    Load the wordlist, spin up the aiohttp session, and dispatch all tasks.
    """
    # Load wordlist, strip blank lines and whitespace
    try:
        with open(wordlist_path, 'r', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f'[ERROR] Wordlist not found: {wordlist_path}')
        sys.exit(1)

    total = len(words)
    print(f'[*] Target   : {domain}')
    print(f'[*] Wordlist : {wordlist_path} ({total} words)')
    print(f'[*] Threads  : {concurrency} concurrent')
    print(f'[*] Protocols: {", ".join(protocols)}')
    print(f'[*] Started  : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print('-' * 50)

    semaphore = asyncio.Semaphore(concurrency)     # Gate that limits concurrent coroutines

    # TCPConnector limits the connection pool size to match our concurrency cap
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)

    output_file = open(output_path, 'w') if output_path else None

    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            # Build all tasks upfront — semaphore controls actual execution rate
            tasks = [
                check_subdomain(session, semaphore, word, domain, protocols, output_file)
                for word in words
            ]
            await asyncio.gather(*tasks)           # Run all tasks, collecting results
    finally:
        if output_file:
            output_file.close()

    print('-' * 50)
    print(f'[*] Done. {total} words checked.')
    if output_path:
        print(f'[*] Results saved to: {output_path}')


# ─────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Async subdomain enumerator',
        epilog='Example: python3 subdomain_enum.py -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
    )
    parser.add_argument('-d', '--domain',      required=True,  help='Target domain (e.g. target.com)')
    parser.add_argument('-w', '--wordlist',    required=True,  help='Path to subdomain wordlist')
    parser.add_argument('-o', '--output',      default=None,   help='Save results to file (optional)')
    parser.add_argument('-c', '--concurrency', default=DEFAULT_CONCURRENCY, type=int,
                        help=f'Max concurrent requests (default: {DEFAULT_CONCURRENCY})')
    parser.add_argument('--http-only',         action='store_true', help='Only try HTTP (skip HTTPS)')
    parser.add_argument('--https-only',        action='store_true', help='Only try HTTPS (skip HTTP)')

    args = parser.parse_args()

    # Resolve protocol list based on flags
    if args.http_only:
        protocols = ['http']
    elif args.https_only:
        protocols = ['https']
    else:
        protocols = DEFAULT_PROTOCOLS

    asyncio.run(main(args.domain, args.wordlist, args.concurrency, protocols, args.output))
