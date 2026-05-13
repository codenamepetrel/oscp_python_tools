#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║                         port_scan.py                                ║
║                    TCP Port Scanner w/ Banner Grab                  ║
╚══════════════════════════════════════════════════════════════════════╝

DESCRIPTION
-----------
Multithreaded TCP port scanner with per-service banner grabbing.
Connects to each port, attempts a protocol-appropriate probe to pull
a service banner, and reports open ports with service identification.

Useful for initial recon on HackTheBox, OSCP, and authorized engagements.
Good for a quick sweep before handing off to Nmap for deeper enumeration.

REQUIREMENTS
------------
    Standard library only — no pip installs needed.

USAGE
-----
    # Scan default port range (1-1024)
    python3 port_scan.py -t 192.168.1.1

    # Scan a custom port range
    python3 port_scan.py -t 192.168.1.1 -p 1-65535

    # Scan specific ports (comma-separated)
    python3 port_scan.py -t 192.168.1.1 -p 22,80,443,8080,8443

    # Custom thread count (default: 100)
    python3 port_scan.py -t 192.168.1.1 -p 1-65535 --threads 200

    # Custom timeout per port (default: 1s)
    python3 port_scan.py -t 192.168.1.1 --timeout 2

    # Save results to file
    python3 port_scan.py -t 192.168.1.1 -p 1-65535 -o results.txt

    # Quiet mode — hits only, no progress noise
    python3 port_scan.py -t 192.168.1.1 -p 1-65535 -q

EXAMPLE OUTPUT
--------------
    [*] Target  : 192.168.1.1
    [*] Range   : ports 1–1024 (1024 total)
    [*] Threads : 100  |  Timeout: 1s
    ──────────────────────────────────────────────────────────────
    [OPEN]  22    ssh      SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
    [OPEN]  80    http     HTTP/1.1 200 OK
    [OPEN]  443   https    No banner
    [OPEN]  8080  http-alt HTTP/1.1 302 Found
    ──────────────────────────────────────────────────────────────
    [*] Done. 4 open port(s) found in 12.3s.

BANNER GRAB NOTES
-----------------
  - SSH, FTP, SMTP, POP3, IMAP  → passive grab (server speaks first)
  - HTTP/HTTPS                  → HEAD request probe
  - Everything else             → generic newline probe, then passive listen
  - Banners give you version info for CVE hunting without running Nmap -sV

OSCP / HTB TIPS
---------------
  - Full range scan (-p 1-65535) often reveals high ports that initial
    recon misses (e.g. 8080, 8443, 27017 MongoDB, 6379 Redis).
  - Always follow up open ports with:
      nmap -sC -sV -p <open_ports> <host>
  - 1s timeout is fine for LAN/VPN. Increase to 2-3s for flaky hosts.
"""

import socket
import argparse
import sys
import threading
import concurrent.futures
import time

# ─────────────────────────────────────────────
# WELL-KNOWN PORT → SERVICE NAME MAP
# ─────────────────────────────────────────────
# Used to label output without a reverse DNS lookup per port.
KNOWN_PORTS = {
    21:    'ftp',       22:    'ssh',       23:    'telnet',
    25:    'smtp',      53:    'dns',       80:    'http',
    110:   'pop3',      111:   'rpcbind',   135:   'msrpc',
    139:   'netbios',   143:   'imap',      443:   'https',
    445:   'smb',       993:   'imaps',     995:   'pop3s',
    1433:  'mssql',     1521:  'oracle',    2049:  'nfs',
    3306:  'mysql',     3389:  'rdp',       5432:  'postgres',
    5900:  'vnc',       6379:  'redis',     6443:  'k8s-api',
    8080:  'http-alt',  8443:  'https-alt', 8888:  'http-alt',
    9200:  'elastic',   27017: 'mongodb',
}

# Ports where the server speaks first — don't send a probe, just listen
PASSIVE_BANNER_PORTS = {21, 22, 23, 25, 110, 143, 220, 993, 995}

# Thread-safe state
_lock    = threading.Lock()
_open    = []           # Accumulate open port results
_checked = 0
_total   = 0


# ─────────────────────────────────────────────
# BANNER GRABBING
# ─────────────────────────────────────────────
def grab_banner(s, port, timeout):
    """
    Attempt to pull a service banner from an already-connected socket.
    Strategy depends on port: passive listen for servers that speak first,
    HTTP HEAD probe for web ports, generic newline probe for everything else.
    Returns a stripped banner string or 'No banner'.
    """
    try:
        s.settimeout(timeout)

        if port in PASSIVE_BANNER_PORTS:
            # Server speaks first (SSH, FTP, SMTP, etc.) — just receive
            banner = s.recv(1024).decode(errors='ignore').strip()

        elif port in (80, 8080, 8888, 8000):
            # HTTP — send a minimal HEAD request
            s.send(b'HEAD / HTTP/1.0\r\nHost: target\r\n\r\n')
            banner = s.recv(1024).decode(errors='ignore').strip().split('\n')[0]

        elif port in (443, 8443):
            # HTTPS — raw socket won't handshake; just note it
            banner = 'TLS — use openssl s_client for banner'

        else:
            # Generic probe: send a newline and see if anything comes back
            s.send(b'\r\n')
            banner = s.recv(1024).decode(errors='ignore').strip()

        return banner[:120] if banner else 'No banner'

    except Exception:
        return 'No banner'


# ─────────────────────────────────────────────
# CORE SCAN FUNCTION
# ─────────────────────────────────────────────
def scan_port(host, port, timeout, quiet, output_file):
    """
    Attempt a TCP connection to host:port.
    On success, grab a banner and record the result.
    """
    global _checked

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))     # Returns 0 on success, errno otherwise

        if result == 0:                         # Port is open
            banner  = grab_banner(s, port, timeout)
            service = KNOWN_PORTS.get(port, 'unknown')
            line    = f'[OPEN]  {port:<6} {service:<12} {banner}'

            with _lock:                         # Serialize output across threads
                print(line)
                _open.append(port)
                if output_file:
                    output_file.write(line + '\n')
                    output_file.flush()         # Flush immediately — don't lose hits on crash

        s.close()

    except socket.gaierror:
        # DNS resolution failed — bail out entirely, no point continuing
        print(f'[ERROR] Could not resolve host: {host}')
        sys.exit(1)
    except OSError:
        pass                                    # Port closed or filtered — expected
    except Exception:
        pass                                    # Catch-all for unexpected socket errors

    finally:
        with _lock:
            _checked += 1
            if not quiet and _total > 0 and _checked % 50 == 0:
                pct = (_checked / _total) * 100
                print(f'    [~] Progress: {_checked}/{_total} ports ({pct:.0f}%)', end='\r')


# ─────────────────────────────────────────────
# MAIN SCANNER
# ─────────────────────────────────────────────
def scan(host, ports, threads, timeout, quiet, output_file):
    """
    Resolve the host, print scan header, dispatch all port scan tasks.
    """
    global _total, _checked
    _checked = 0
    _total   = len(ports)

    # Resolve hostname to IP upfront so threads don't each do a DNS lookup
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f'[ERROR] Could not resolve: {host}')
        sys.exit(1)

    display_range = f'{min(ports)}–{max(ports)}' if len(ports) > 1 else str(ports[0])

    print(f'[*] Target  : {host} ({ip})')
    print(f'[*] Range   : ports {display_range} ({_total} total)')
    print(f'[*] Threads : {threads}  |  Timeout: {timeout}s')
    print('─' * 62)

    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(
            lambda p: scan_port(ip, p, timeout, quiet, output_file),
            ports
        )

    elapsed = time.time() - start_time

    if not quiet:
        print(' ' * 60, end='\r')             # Clear progress line

    print('─' * 62)
    print(f'[*] Done. {len(_open)} open port(s) found in {elapsed:.1f}s.')

    if _open:
        print(f'[*] Open   : {", ".join(str(p) for p in sorted(_open))}')


# ─────────────────────────────────────────────
# ARGUMENT PARSING + ENTRYPOINT
# ─────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='TCP port scanner with banner grabbing.',
        epilog='Example: python3 port_scan.py -t 192.168.1.1 -p 1-65535'
    )
    parser.add_argument('-t', '--target',   required=True, help='Target IP or hostname')
    parser.add_argument('-p', '--ports',    default='1-1024',
                        help='Port range (1-1024), specific ports (22,80,443), or "all" (default: 1-1024)')
    parser.add_argument('--threads',        default=100, type=int, help='Thread count (default: 100)')
    parser.add_argument('--timeout',        default=1.0, type=float, help='Per-port timeout in seconds (default: 1)')
    parser.add_argument('-o', '--output',   default=None, help='Save results to file')
    parser.add_argument('-q', '--quiet',    action='store_true', help='Only print open ports, suppress progress')

    args = parser.parse_args()

    # Parse port specification into a sorted list
    if args.ports == 'all':
        ports = list(range(1, 65536))
    elif '-' in args.ports:
        start, end = args.ports.split('-')
        ports = list(range(int(start), int(end) + 1))
    elif ',' in args.ports:
        ports = sorted(set(int(p.strip()) for p in args.ports.split(',')))
    else:
        ports = [int(args.ports)]             # Single port

    output_file = open(args.output, 'w') if args.output else None

    try:
        scan(
            host       = args.target,
            ports      = ports,
            threads    = args.threads,
            timeout    = args.timeout,
            quiet      = args.quiet,
            output_file= output_file
        )
    except KeyboardInterrupt:
        print(f'\n[!] Interrupted. {len(_open)} open port(s) found so far: {sorted(_open)}')
    finally:
        if output_file:
            output_file.close()

    if args.output:
        print(f'[*] Results saved to: {args.output}')
