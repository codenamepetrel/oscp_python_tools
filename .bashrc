# ============================================
# Freeworld - OSCP Aliases
# ============================================

# Navigation
alias goose='cd /root/oscp'
alias mknotes='mkdir -p $(pwd)/{scans,exploits,loot} && touch $(pwd)/notes.md'

# Quick servers
alias goServ='python3 -m http.server'
alias goResp='responder -I tun0 -v'

# IP helper
refreship() {
    export MYIP=$(ip addr show tun0 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1)
    echo "[+] MYIP set to $MYIP"
}
export MYIP=$(ip addr show tun0 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1)

# Nmap scans
alias nmapq='nmap -sC -sV -oA quick'
alias nmapf='nmap -sC -sV -p- -oA full'
alias nmapu='nmap -sU --top-ports 100 -oA udp'

# Searchsploit
alias sspt='searchsploit'
alias ssgt='searchsploit -m'

# Wordlists
alias rockyou='/usr/share/wordlists/rockyou.txt'
alias dirmed='/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'

# Privilege escalation checks
alias privesc='sudo -l; id; whoami; uname -a'
alias suid='find / -perm -u=s -type f 2>/dev/null'
alias guid='find / -perm -g=s -type f 2>/dev/null'
alias world='find / -writable -type f 2>/dev/null | grep -v proc'
alias worlddir='find / -writable -type d 2>/dev/null | grep -v proc'
alias crons='cat /etc/crontab; ls -la /etc/cron*'
alias caps='getcap -r / 2>/dev/null'

# System enumeration
alias sysinfo='uname -a; cat /etc/os-release; hostname; id'
alias users='cat /etc/passwd | grep -v nologin | grep -v false'
alias network='ifconfig; ip a; netstat -tulpn 2>/dev/null'
alias procs='ps aux'
alias services='systemctl list-units --type=service 2>/dev/null'

# Credential hunting
alias passhunt='grep -ri "password" /home /var/www /opt 2>/dev/null'
alias keyhunt='find / -name "*.key" -o -name "*.pem" -o -name "id_rsa" 2>/dev/null'
alias confhunt='find / -name "*.conf" -o -name "*.config" -o -name "*.ini" 2>/dev/null | grep -v proc'
alias histcheck='cat ~/.bash_history; cat ~/.zsh_history 2>/dev/null'

# File system checks
alias loot='ls -la /home; ls -la /root 2>/dev/null; ls -la /var/www 2>/dev/null'
alias proof='find / -name "proof.txt" -o -name "local.txt" 2>/dev/null'
alias interesting='find / -name "*.txt" -o -name "*.bak" -o -name "*.old" 2>/dev/null | grep -v proc'

# Network checks
alias arpscan='arp -a; cat /etc/hosts'
alias ports='ss -tulpn 2>/dev/null || netstat -tulpn'
alias routes='route -n; ip route'
