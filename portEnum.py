#!/usr/bin/env python3

##############################################
## Freeworld - Allergic to aluminum baby   ##
## Port Enumeration                         ##
## Usage: python3 portEnum.py <IP> <PORT>   ##
##############################################

import subprocess
import sys
import os
import time

if len(sys.argv) < 3:
    print("Usage: python3 portEnum.py <IP> <PORT>")
    print("Example: python3 portEnum.py 192.168.1.10 8080")
    sys.exit(1)

TARGET = sys.argv[1]
PORT = sys.argv[2]
OUTPUT_DIR = f"/root/oscp/scans/{TARGET}"
REPORT = f"{OUTPUT_DIR}/port{PORT}_report.txt"
WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
VHOST_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

def ping_check(target):
    print(f"[*] Pinging {target}...")
    result = subprocess.run(
        ["ping", "-c", "3", "-W", "2", target],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    if result.returncode == 0:
        print(f"[+] Host {target} is UP")
        return True
    else:
        print(f"[-] Host {target} did not respond to ping. Aborting.")
        return False

def rustscan_check(target, port):
    print(f"[*] Running RustScan to verify port {port} is open on {target}...")
    result = subprocess.run(
        ["rustscan", "-a", target, "-p", port, "--", "-sV", "--open"],
        capture_output=True,
        text=True
    )
    output = result.stdout + result.stderr
    if "Open" in output or f"{port}/tcp" in output:
        print(f"[+] Port {port} confirmed OPEN via RustScan")
        return True
    else:
        print(f"[-] Port {port} does not appear open on {target}. Aborting.")
        return False

def get_vhost_baseline(target, port):
    print(f"[*] Getting baseline response size for vhost filtering...")
    result = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{size_download}",
         "-H", f"Host: nonexistent_baseline_fuzz.{target}",
         f"http://{target}:{port}"],
        capture_output=True,
        text=True
    )
    size = result.stdout.strip()
    if size.isdigit():
        print(f"[+] Baseline response size: {size} bytes")
        return size
    else:
        print(f"[!] Could not determine baseline size, defaulting to -fc 404,400 filtering")
        return None

def open_terminal(command):
    terminals = [
        ["gnome-terminal", "--", "bash", "-c", f"{command}; echo DONE; sleep 5"],
        ["xterm", "-e", f"bash -c '{command}; echo DONE; sleep 5'"],
        ["xfce4-terminal", "-e", f"bash -c '{command}; echo DONE; sleep 5'"],
        ["konsole", "-e", f"bash -c '{command}; echo DONE; sleep 5'"],
    ]
    for term in terminals:
        try:
            subprocess.Popen(term)
            return
        except FileNotFoundError:
            continue
    print("[-] No terminal emulator found")

def append_report(title, filepath):
    with open(REPORT, "a") as r:
        r.write(f"\n{'='*50}\n")
        r.write(f"## {title}\n")
        r.write(f"{'='*50}\n")
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                r.write(f.read())
        else:
            r.write(f"[-] Output file not found: {filepath}\n")

def main():
    # --- Pre-flight checks ---
    if not ping_check(TARGET):
        sys.exit(1)

    if not rustscan_check(TARGET, PORT):
        sys.exit(1)

    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Initialize report
    with open(REPORT, "w") as r:
        r.write(f"{'='*50}\n")
        r.write(f"Port {PORT} Scan Report\n")
        r.write(f"Target: {TARGET}\n")
        r.write(f"{'='*50}\n")

    print(f"\n[*] Starting Port {PORT} scans against {TARGET}")
    print(f"[*] Output directory: {OUTPUT_DIR}")
    print(f"[*] Report: {REPORT}\n")

    # WhatWeb fingerprinting
    whatweb_out = f"{OUTPUT_DIR}/whatweb_{PORT}.txt"
    whatweb_cmd = (
        f"whatweb -a 3 http://{TARGET}:{PORT} "
        f"--log-verbose={whatweb_out}"
    )
    print("[*] Opening WhatWeb terminal...")
    open_terminal(whatweb_cmd)
    time.sleep(2)

    # Nmap deep dive with vuln scripts
    nmap_out = f"{OUTPUT_DIR}/nmap_{PORT}.txt"
    nmap_cmd = (
        f"nmap -sC -sV -p {PORT} --script vuln {TARGET} "
        f"-oN {nmap_out}"
    )
    print("[*] Opening Nmap terminal...")
    open_terminal(nmap_cmd)
    time.sleep(2)

    # Gobuster
    gobuster_out = f"{OUTPUT_DIR}/gobuster_{PORT}.txt"
    gobuster_cmd = (
        f"gobuster dir -u http://{TARGET}:{PORT} "
        f"-w {WORDLIST} "
        f"-x php,html,txt,bak "
        f"-o {gobuster_out}"
    )
    print("[*] Opening Gobuster terminal...")
    open_terminal(gobuster_cmd)
    time.sleep(2)

    # Feroxbuster
    ferox_out = f"{OUTPUT_DIR}/feroxbuster_{PORT}.txt"
    ferox_cmd = (
        f"feroxbuster -u http://{TARGET}:{PORT} "
        f"-w {WORDLIST} "
        f"-x php,html,txt,bak "
        f"--depth 3 "
        f"-o {ferox_out}"
    )
    print("[*] Opening Feroxbuster terminal...")
    open_terminal(ferox_cmd)
    time.sleep(2)

    # Nikto
    nikto_out = f"{OUTPUT_DIR}/nikto_{PORT}.txt"
    nikto_cmd = (
        f"nikto -h http://{TARGET}:{PORT} "
        f"-o {nikto_out}"
    )
    print("[*] Opening Nikto terminal...")
    open_terminal(nikto_cmd)
    time.sleep(2)

    # WhatWeb (second run)
    whatweb_out = f"{OUTPUT_DIR}/whatweb_{PORT}.txt"
    whatweb_cmd = (
        f"whatweb -a 3 http://{TARGET}:{PORT} "
        f"--log-verbose={whatweb_out}"
    )
    print("[*] Opening WhatWeb terminal...")
    open_terminal(whatweb_cmd)
    time.sleep(2)

    # ffuf - Virtual Host / Subdomain Fuzzing
    ffuf_vhost_out = f"{OUTPUT_DIR}/ffuf_vhost_{PORT}.txt"
    baseline_size = get_vhost_baseline(TARGET, PORT)
    if baseline_size:
        size_filter = f"-fs {baseline_size}"
    else:
        size_filter = "-fc 404,400"

    ffuf_vhost_cmd = (
        f"ffuf -u http://{TARGET}:{PORT} "
        f"-H \"Host: FUZZ.{TARGET}\" "
        f"-w {VHOST_WORDLIST} "
        f"{size_filter} "
        f"-o {ffuf_vhost_out} "
        f"-of csv"
    )
    print("[*] Opening ffuf VHost fuzzing terminal...")
    open_terminal(ffuf_vhost_cmd)
    time.sleep(2)

    # ffuf - File Extension Fuzzing
    ffuf_ext_out = f"{OUTPUT_DIR}/ffuf_ext_{PORT}.txt"
    ffuf_ext_cmd = (
        f"ffuf -u http://{TARGET}:{PORT}/FUZZ "
        f"-w {WORDLIST} "
        f"-e .php,.html,.txt,.bak,.conf,.log,.xml,.json "
        f"-fc 404 "
        f"-o {ffuf_ext_out} "
        f"-of csv"
    )
    print("[*] Opening ffuf File Extension fuzzing terminal...")
    open_terminal(ffuf_ext_cmd)
    time.sleep(2)

    # Wait for scans to finish
    print("\n[*] All scans running in separate terminals...")
    print("[*] Press ENTER when all terminal scans are done")
    input()

    # Build final report
    print("\n[*] Building report...")
    append_report("WHATWEB Fingerprint", whatweb_out)
    append_report("NMAP Deep Dive + Vuln Scan", nmap_out)
    append_report("GOBUSTER Directory Scan", gobuster_out)
    append_report("FEROXBUSTER Recursive Scan", ferox_out)
    append_report("NIKTO Web Scan", nikto_out)
    append_report("FFUF VHost Fuzzing", ffuf_vhost_out)
    append_report("FFUF File Extension Fuzzing", ffuf_ext_out)

    print(f"\n[+] Report saved to: {REPORT}")
    print(f"[+] View with: cat {REPORT}")
    print(f"[+] Or: less {REPORT}")

if __name__ == "__main__":
    main()
