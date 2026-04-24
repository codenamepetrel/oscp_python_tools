#!/usr/bin/env python3

##############################################
## Freeworld - Allergic to aluminum baby   ##
## Enum Blaster Auto Scanner               ##
## Usage: python3 blasterEnum.py <IP> <PORT>##
##############################################

import subprocess
import sys
import os

if len(sys.argv) < 3:
    print("Usage: python3 blasterEnum.py <IP> <PORT>")
    print("Example: python3 blasterEnum.py 192.168.1.10 8080")
    sys.exit(1)

TARGET     = sys.argv[1]
PORT       = sys.argv[2]
OUTPUT_DIR = f"/root/oscp/scans/{TARGET}"
REPORT     = f"{OUTPUT_DIR}/port{PORT}_report.txt"
WORDLIST   = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

# ── Colors ────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def head(msg):  print(f"\n{CYAN}{BOLD}[*] {msg}{RESET}")
def info(msg):  print(f"{GREEN}[+] {msg}{RESET}")
def warn(msg):  print(f"{YELLOW}[~] {msg}{RESET}")
def err(msg):   print(f"{RED}[-] {msg}{RESET}")

def run_tool(label, cmd, outfile):
    head(f"{label}")
    print(f"    $ {cmd}\n")
    with open(outfile, "w") as f:
        result = subprocess.run(
            cmd, shell=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        f.write(result.stdout)
        print(result.stdout)
    info(f"Saved → {outfile}")

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
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(REPORT, "w") as r:
        r.write(f"{'='*50}\n")
        r.write(f"Port {PORT} Scan Report\n")
        r.write(f"Target: {TARGET}\n")
        r.write(f"{'='*50}\n")

    print(f"\n{BOLD}[*] Starting Port {PORT} scans against {TARGET}{RESET}")
    print(f"[*] Output directory: {OUTPUT_DIR}")
    print(f"[*] Report: {REPORT}\n")

    # ── WhatWeb ───────────────────────────────────────────────────
    whatweb_out = f"{OUTPUT_DIR}/whatweb_{PORT}.txt"
    run_tool("WhatWeb Fingerprint",
        f"whatweb -a 3 http://{TARGET}:{PORT} --log-verbose={whatweb_out}",
        whatweb_out)

    # ── Nmap + vuln scripts ───────────────────────────────────────
    nmap_out = f"{OUTPUT_DIR}/nmap_{PORT}.txt"
    run_tool("Nmap Deep Dive + Vuln Scan",
        f"nmap -sC -sV -p {PORT} --script vuln {TARGET} -oN {nmap_out}",
        nmap_out)

    # ── Gobuster ──────────────────────────────────────────────────
    gobuster_out = f"{OUTPUT_DIR}/gobuster_{PORT}.txt"
    run_tool("Gobuster Directory Scan",
        f"gobuster dir -u http://{TARGET}:{PORT} -w {WORDLIST} "
        f"-x php,html,txt,bak -o {gobuster_out}",
        gobuster_out)

    # ── Feroxbuster ───────────────────────────────────────────────
    ferox_out = f"{OUTPUT_DIR}/feroxbuster_{PORT}.txt"
    run_tool("Feroxbuster Recursive Scan",
        f"feroxbuster -u http://{TARGET}:{PORT} -w {WORDLIST} "
        f"-x php,html,txt,bak --depth 3 -o {ferox_out}",
        ferox_out)

    # ── Nikto ─────────────────────────────────────────────────────
    nikto_out = f"{OUTPUT_DIR}/nikto_{PORT}.txt"
    run_tool("Nikto Web Scan",
        f"nikto -h http://{TARGET}:{PORT} -o {nikto_out}",
        nikto_out)

    # ── ffuf ──────────────────────────────────────────────────────
    ffuf_out = f"{OUTPUT_DIR}/ffuf_{PORT}.txt"
    run_tool("ffuf Fuzz Scan",
        f"ffuf -u http://{TARGET}:{PORT}/FUZZ -w {WORDLIST} "
        f"-e .php,.html,.txt,.bak -o {ffuf_out} -of md",
        ffuf_out)

    # ── Build report ──────────────────────────────────────────────
    head("Building final report...")
    append_report("WHATWEB Fingerprint",        whatweb_out)
    append_report("NMAP Deep Dive + Vuln Scan", nmap_out)
    append_report("GOBUSTER Directory Scan",    gobuster_out)
    append_report("FEROXBUSTER Recursive Scan", ferox_out)
    append_report("NIKTO Web Scan",             nikto_out)
    append_report("FFUF Fuzz Scan",             ffuf_out)

    info(f"Report saved → {REPORT}")
    print(f"    View: cat {REPORT}  |  less {REPORT}\n")

if __name__ == "__main__":
    main()
