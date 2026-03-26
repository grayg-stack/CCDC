#!/bin/bash
# ============================================================
# MACCDC 2026 - Linux Hardening Script
# Interactive - asks before each major change
# Usage: sudo bash 02-harden.sh
# ============================================================

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
NC='\033[0m'

banner() { echo -e "\n${GRN}========== $1 ==========${NC}"; }
warn()   { echo -e "${RED}[!] $1${NC}"; }
info()   { echo -e "${YEL}[*] $1${NC}"; }
ok()     { echo -e "${GRN}[+] $1${NC}"; }

ask() {
    echo -en "${CYN}[?] $1 (y/N): ${NC}"
    read -r ans
    [[ "$ans" =~ ^[Yy] ]]
}

[ "$(id -u)" -ne 0 ] && { warn "Must run as root!"; exit 1; }

BACKUP_DIR="/root/ccdc-backups-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
ok "Backup directory: $BACKUP_DIR"

backup() {
    [ -f "$1" ] && cp -a "$1" "$BACKUP_DIR/$(echo "$1" | tr '/' '_')" && info "Backed up $1"
}

echo "============================================"
echo " MACCDC Linux Hardening - $(hostname)"
echo " $(date)"
echo " ALL changes are interactive & backed up"
echo "============================================"

# --- 1. Password Changes ---
banner "PHASE 1: PASSWORD CHANGES"
if ask "Change root password?"; then
    passwd root
fi

if ask "Change ALL user passwords (bulk)?"; then
    NEW_PASS=""
    echo -en "${CYN}Enter new password for all users: ${NC}"
    read -rs NEW_PASS
    echo ""
    grep -vE '(nologin|false|sync|halt|shutdown)$' /etc/passwd | cut -d: -f1 | while read user; do
        [ "$user" = "root" ] && continue
        echo "$user:$NEW_PASS" | chpasswd 2>/dev/null && ok "Changed: $user" || warn "Failed: $user"
    done
    info "REMEMBER: Submit scored account password changes via Support Ticket!"
fi

# --- 2. Remove Rogue Accounts ---
banner "PHASE 2: ACCOUNT AUDIT"
info "UID 0 accounts (besides root):"
awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | while read user; do
    warn "Rogue UID 0 account: $user"
    if ask "Lock account '$user'?"; then
        usermod -L "$user" && ok "Locked: $user"
        usermod -s /usr/sbin/nologin "$user" 2>/dev/null
    fi
done

info "Accounts with empty passwords:"
awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | while read user; do
    warn "Empty password: $user"
    if ask "Lock account '$user'?"; then
        passwd -l "$user" && ok "Locked: $user"
    fi
done

# --- 3. SSH Hardening ---
banner "PHASE 3: SSH HARDENING"
SSHD_CONF="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONF" ] && ask "Harden SSH configuration?"; then
    backup "$SSHD_CONF"

    # Disable root login
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONF"
    # Disable empty passwords
    sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD_CONF"
    # Set max auth tries
    sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$SSHD_CONF"
    # Disable X11 forwarding
    sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$SSHD_CONF"
    # Set login grace time
    sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 60/' "$SSHD_CONF"
    # Disable rhosts
    sed -i 's/^#*IgnoreRhosts.*/IgnoreRhosts yes/' "$SSHD_CONF"

    # Add settings if they don't exist
    grep -q "^PermitRootLogin" "$SSHD_CONF" || echo "PermitRootLogin no" >> "$SSHD_CONF"
    grep -q "^PermitEmptyPasswords" "$SSHD_CONF" || echo "PermitEmptyPasswords no" >> "$SSHD_CONF"
    grep -q "^MaxAuthTries" "$SSHD_CONF" || echo "MaxAuthTries 3" >> "$SSHD_CONF"
    grep -q "^Protocol" "$SSHD_CONF" || echo "Protocol 2" >> "$SSHD_CONF"

    ok "SSH hardened. Restarting sshd..."
    systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null
    ok "SSH restarted"
fi

# --- 4. Remove Unauthorized SSH Keys ---
banner "PHASE 4: SSH KEY AUDIT"
find / -name authorized_keys -type f 2>/dev/null | while read keyfile; do
    if [ -s "$keyfile" ]; then
        warn "Found SSH keys in: $keyfile"
        cat "$keyfile"
        if ask "Remove ALL keys from $keyfile?"; then
            backup "$keyfile"
            > "$keyfile"
            ok "Cleared: $keyfile"
        fi
    fi
done

# --- 5. Cron Job Audit ---
banner "PHASE 5: CRON JOB AUDIT"
info "Checking user crontabs for suspicious entries..."
for user in $(cut -f1 -d: /etc/passwd); do
    cron=$(crontab -l -u "$user" 2>/dev/null | grep -v '^#\|^$')
    if [ -n "$cron" ]; then
        echo -e "${YEL}[$user crontab]:${NC}"
        echo "$cron"
        if ask "Clear crontab for $user?"; then
            crontab -l -u "$user" > "$BACKUP_DIR/crontab_$user" 2>/dev/null
            crontab -r -u "$user" 2>/dev/null
            ok "Cleared crontab for $user"
        fi
    fi
done

info "Checking /etc/cron.d/ for suspicious entries..."
for f in /etc/cron.d/*; do
    [ -f "$f" ] || continue
    echo -e "${YEL}$f:${NC}"
    cat "$f" | grep -v '^#\|^$'
done

# --- 6. Suspicious Process Check ---
banner "PHASE 6: SUSPICIOUS PROCESS CHECK"
info "Looking for common Red Team tools..."
SUSPICIOUS="nc ncat nmap socat meterpreter reverse_shell bindshell python.*-c.*import.*socket perl.*-e.*socket ruby.*-e.*socket bash.*-i.*>.*dev/tcp php.*-r.*fsockopen xmrig minerd cryptominer"
for proc in $SUSPICIOUS; do
    pids=$(ps aux | grep -i "$proc" | grep -v grep | awk '{print $2}')
    if [ -n "$pids" ]; then
        warn "Suspicious process matching '$proc':"
        ps aux | grep -i "$proc" | grep -v grep
        if ask "Kill these processes?"; then
            echo "$pids" | xargs kill -9 2>/dev/null
            ok "Killed processes matching: $proc"
        fi
    fi
done

# --- 7. Kernel Hardening (sysctl) ---
banner "PHASE 7: KERNEL HARDENING"
if ask "Apply sysctl network hardening?"; then
    backup /etc/sysctl.conf
    cat >> /etc/sysctl.conf << 'SYSCTL'

# CCDC Hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
kernel.randomize_va_space = 2
SYSCTL
    sysctl -p 2>/dev/null
    ok "Sysctl hardening applied"
fi

# --- 8. Host Firewall (iptables) ---
banner "PHASE 8: HOST FIREWALL"
if ask "Set up basic iptables rules (allows scored services)?"; then
    backup /etc/iptables.rules 2>/dev/null

    # Flush existing
    iptables -F
    iptables -X

    # Default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT

    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow scored services (DO NOT REMOVE THESE)
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT    # SSH (management)
    iptables -A INPUT -p tcp --dport 25 -j ACCEPT    # SMTP
    iptables -A INPUT -p tcp --dport 53 -j ACCEPT    # DNS
    iptables -A INPUT -p udp --dport 53 -j ACCEPT    # DNS
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT    # HTTP
    iptables -A INPUT -p tcp --dport 110 -j ACCEPT   # POP3
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT   # HTTPS
    iptables -A INPUT -p tcp --dport 21 -j ACCEPT    # FTP
    iptables -A INPUT -p tcp --dport 20 -j ACCEPT    # FTP data
    iptables -A INPUT -p udp --dport 69 -j ACCEPT    # TFTP
    iptables -A INPUT -p udp --dport 123 -j ACCEPT   # NTP
    iptables -A INPUT -p tcp --dport 587 -j ACCEPT   # SMTP submission
    iptables -A INPUT -p tcp --dport 993 -j ACCEPT   # IMAPS
    iptables -A INPUT -p tcp --dport 995 -j ACCEPT   # POP3S
    iptables -A INPUT -p icmp -j ACCEPT              # ICMP (scoring may use)

    # FTP passive mode range (common)
    iptables -A INPUT -p tcp --dport 30000:31000 -j ACCEPT

    # Log drops
    iptables -A INPUT -j LOG --log-prefix "IPTABLES-DROP: " --log-level 4

    ok "Iptables rules applied. All scored service ports are open."
    info "Saving rules..."
    iptables-save > /etc/iptables.rules 2>/dev/null
    # Persist across reboot (varies by distro)
    command -v netfilter-persistent >/dev/null && netfilter-persistent save 2>/dev/null
fi

# --- 9. Quick Service Check ---
banner "PHASE 9: SERVICE VERIFICATION"
info "Checking that scored services are still listening..."
for port in 22 25 53 80 110 443 21 69 123; do
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
        ok "Port $port is LISTENING"
    elif ss -ulnp 2>/dev/null | grep -q ":$port "; then
        ok "Port $port is LISTENING (UDP)"
    else
        warn "Port $port is NOT listening - check service!"
    fi
done

# --- 10. File Permission Hardening ---
banner "PHASE 10: FILE PERMISSIONS"
if ask "Harden critical file permissions?"; then
    chmod 600 /etc/shadow 2>/dev/null
    chmod 644 /etc/passwd 2>/dev/null
    chmod 600 /etc/gshadow 2>/dev/null
    chmod 644 /etc/group 2>/dev/null
    chmod 700 /root 2>/dev/null
    chmod 600 /etc/ssh/sshd_config 2>/dev/null
    ok "File permissions hardened"
fi

banner "HARDENING COMPLETE"
echo -e "${GRN}Backups saved to: $BACKUP_DIR${NC}"
echo -e "${YEL}NEXT STEPS:${NC}"
echo "  1. Verify scored services on NISE dashboard"
echo "  2. Submit password changes via Support Ticket"
echo "  3. Run 03-monitor.sh for continuous monitoring"
