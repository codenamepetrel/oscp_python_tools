#!/usr/bin/env python3

##############################################
## Freeworld - Allergic to aluminum baby   ##
## Web Port Auto Scanner                   ##
## Usage: python3 scanport.py <IP> <PORT>  ##
##############################################

import subprocess
import sys
import os
import time

if len(sys.argv) < 3:
    print("Usage: python3 scanport.py <IP> <PORT>")
    print("Example: python3 scanport.py 192.168.1.10 8080")
    sys.exit(1)

TARGET = sys.argv[1]
PORT = sys.argv[2]
OUTPUT_DIR = f"/root/oscp/scans/{TARGET}"
REPORT = f"{OUTPUT_DIR}/port{PORT}_report.txt"
WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

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

    # WhatWeb
    whatweb_out = f"{OUTPUT_DIR}/whatweb_{PORT}.txt"
    whatweb_cmd = (
        f"whatweb -a 3 http://{TARGET}:{PORT} "
        f"--log-verbose={whatweb_out}"
    )
    print("[*] Opening WhatWeb terminal...")
    open_terminal(whatweb_cmd)

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

    print(f"\n[+] Report saved to: {REPORT}")
    print(f"[+] View with: cat {REPORT}")
    print(f"[+] Or: less {REPORT}")

if __name__ == "__main__":
    main()
