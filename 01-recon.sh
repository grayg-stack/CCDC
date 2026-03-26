#!/bin/bash
# ============================================================
# MACCDC 2026 - Linux Initial Reconnaissance Script
# RUN FIRST - Read-only, breaks nothing, captures baseline
# Usage: sudo bash 01-recon.sh | tee /root/recon-$(hostname).txt
# ============================================================

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
NC='\033[0m'

banner() { echo -e "\n${GRN}========== $1 ==========${NC}"; }
warn()   { echo -e "${RED}[!] $1${NC}"; }
info()   { echo -e "${YEL}[*] $1${NC}"; }

echo "============================================"
echo " MACCDC Linux Recon - $(hostname)"
echo " $(date)"
echo "============================================"

# --- System Info ---
banner "SYSTEM INFO"
echo "Hostname: $(hostname)"
echo "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime)"
echo "IP Addresses:"
ip -4 addr show | grep inet | awk '{print "  " $2 " on " $NF}'

# --- Users & Auth ---
banner "USER ACCOUNTS"
info "All users with shells (non-nologin/false):"
grep -vE '(nologin|false|sync|halt|shutdown)$' /etc/passwd
echo ""

info "UID 0 accounts (should ONLY be root):"
awk -F: '$3 == 0 {print "  " $0}' /etc/passwd
UID0_COUNT=$(awk -F: '$3 == 0' /etc/passwd | wc -l)
[ "$UID0_COUNT" -gt 1 ] && warn "MULTIPLE UID 0 ACCOUNTS DETECTED!"

echo ""
info "Users with password hashes in /etc/shadow:"
awk -F: '$2 !~ /^[!*]/ && $2 != "" {print "  " $1 " (has password set)"}' /etc/shadow 2>/dev/null

echo ""
info "Users with empty passwords:"
awk -F: '$2 == "" {print "  [DANGER] " $1 " has NO password!"}' /etc/shadow 2>/dev/null

echo ""
info "Sudo/wheel group members:"
for g in sudo wheel adm root; do
    members=$(getent group "$g" 2>/dev/null | cut -d: -f4)
    [ -n "$members" ] && echo "  $g: $members"
done

echo ""
info "/etc/sudoers entries (non-comment):"
grep -v '^#\|^$\|^Defaults' /etc/sudoers 2>/dev/null
[ -d /etc/sudoers.d ] && grep -rv '^#\|^$' /etc/sudoers.d/ 2>/dev/null

# --- SSH ---
banner "SSH CONFIGURATION"
info "SSH authorized_keys across all users:"
find / -name authorized_keys -type f 2>/dev/null | while read f; do
    echo "  $f ($(wc -l < "$f") keys):"
    cat "$f" | awk '{print "    " $0}'
done

echo ""
info "Key sshd_config settings:"
for opt in PermitRootLogin PasswordAuthentication PubkeyAuthentication PermitEmptyPasswords Port; do
    val=$(grep -i "^$opt" /etc/ssh/sshd_config 2>/dev/null | tail -1)
    [ -n "$val" ] && echo "  $val" || echo "  $opt: (default/not set)"
done

# --- Network ---
banner "LISTENING SERVICES"
(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep LISTEN
echo ""
info "Established connections:"
(ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null) | grep ESTAB

# --- Scheduled Tasks ---
banner "CRON JOBS & SCHEDULED TASKS"
info "System crontabs:"
cat /etc/crontab 2>/dev/null | grep -v '^#\|^$'
echo ""
info "/etc/cron.d/ entries:"
for f in /etc/cron.d/*; do
    [ -f "$f" ] && echo "  --- $f ---" && grep -v '^#\|^$' "$f"
done
echo ""
info "User crontabs:"
for user in $(cut -f1 -d: /etc/passwd); do
    cron=$(crontab -l -u "$user" 2>/dev/null | grep -v '^#\|^$')
    [ -n "$cron" ] && echo "  [$user]: $cron"
done
echo ""
info "Systemd timers:"
systemctl list-timers --all --no-pager 2>/dev/null | head -20

# --- Persistence Checks ---
banner "PERSISTENCE MECHANISMS"
info "SUID binaries (check for unusual ones):"
find / -perm -4000 -type f 2>/dev/null | while read f; do
    rpm -qf "$f" 2>/dev/null | grep -q "not owned" && echo "  ${RED}[UNOWNED]${NC} $f" || echo "  $f"
done
echo ""
info "World-writable files in system dirs:"
find /usr /etc /var -writable -type f 2>/dev/null | head -20

echo ""
info "Files in /tmp and /dev/shm:"
ls -la /tmp/ 2>/dev/null | tail -20
ls -la /dev/shm/ 2>/dev/null

echo ""
info "Recently modified files in /etc (last 24h):"
find /etc -type f -mtime -1 2>/dev/null | head -20

# --- Running Processes ---
banner "RUNNING PROCESSES"
ps auxf --width=200 | head -60
echo ""
info "Processes running as root (non-kernel):"
ps -eo user,pid,comm | awk '$1=="root" && $3!~/^\[/ {print "  " $0}' | head -30

# --- Services ---
banner "ENABLED SERVICES"
systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | head -40

# --- Firewall ---
banner "FIREWALL STATUS"
info "iptables rules:"
iptables -L -n -v 2>/dev/null | head -30
echo ""
info "UFW status:"
ufw status verbose 2>/dev/null
echo ""
info "nftables rules:"
nft list ruleset 2>/dev/null | head -30

# --- Web Content Check ---
banner "WEB SERVER CHECK"
for dir in /var/www /srv/www /usr/share/nginx/html /var/www/html; do
    if [ -d "$dir" ]; then
        info "Web root found: $dir"
        ls -la "$dir"/ 2>/dev/null | head -15
    fi
done

# --- Mail Check ---
banner "MAIL SERVER CHECK"
for cfg in /etc/postfix/main.cf /etc/dovecot/dovecot.conf /etc/mail/sendmail.mc; do
    [ -f "$cfg" ] && info "Config found: $cfg"
done

# --- DNS Check ---
banner "DNS SERVER CHECK"
for cfg in /etc/named.conf /etc/bind/named.conf /etc/named/named.conf; do
    [ -f "$cfg" ] && info "Config found: $cfg"
done

# --- FTP/TFTP ---
banner "FTP/TFTP CHECK"
for cfg in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd/proftpd.conf /etc/xinetd.d/tftp; do
    [ -f "$cfg" ] && info "Config found: $cfg"
done

echo ""
banner "RECON COMPLETE - Review output for anomalies"
echo "Save this output: sudo bash 01-recon.sh | tee /root/recon-\$(hostname).txt"
