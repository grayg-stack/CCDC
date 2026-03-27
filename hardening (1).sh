#!/bin/bash

# ================================
# Parameter Handling
# ================================
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <NEW_PASSWORD> <CURRENT_PASSWORD>"
    exit 1
fi

NEW_PASS="$1"
ADMIN_USER="blueteam"       # Standard team admin account — change if needed
CUR_PASS="$2"

# ================================
# Privilege Escalation Check
# ================================
if [ "$EUID" -ne 0 ]; then
    echo "[+] Attempting sudo escalation..."
    echo "$CUR_PASS" | sudo -S -v
    if [ $? -ne 0 ]; then
        echo "[-] Sudo authentication failed"
        exit 1
    fi
    exec sudo -S bash "$0" "$NEW_PASS" "$CUR_PASS"
fi

# ================================
# Setup — logs go to /root, NOT /tmp
# ================================
LOG_DIR="/root/hardening_logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR"

echo "[+] Running as root. Starting hardening..."
echo "[+] Logs: $LOG_DIR"

# ================================
# Helper: Package Manager
# ================================
install_pkg() {
    if command -v apt-get &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
    elif command -v dnf &>/dev/null; then
        dnf install -y "$@"
    elif command -v yum &>/dev/null; then
        yum install -y "$@"
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm "$@"
    else
        echo "[-] No supported package manager found. Install $* manually."
        return 1
    fi
}

# ================================
# 1. Create Admin User
# ================================
echo ""
echo "[+] Creating admin user '$ADMIN_USER'..."

useradd -m -s /bin/bash "$ADMIN_USER"
if [ $? -ne 0 ]; then
    echo "[!] useradd failed for $ADMIN_USER — user may already exist, forcing password reset"
fi

echo "$ADMIN_USER:$NEW_PASS" | chpasswd
echo "[*] Password set for $ADMIN_USER"

usermod -aG sudo "$ADMIN_USER" 2>/dev/null || usermod -aG wheel "$ADMIN_USER"
echo "[*] $ADMIN_USER added to sudo/wheel group"

# ================================
# 2. Root Password Change + Lock Root Account
# ================================
echo ""
echo "[+] Updating root password..."
echo "root:$NEW_PASS" | chpasswd
echo "[*] Root password updated"

# Lock the root account so it cannot be used to log in directly
echo "[+] Locking root account..."
passwd -l root
echo "[*] Root account locked (sudo still works via $ADMIN_USER)"

# Expire root account as an extra layer
usermod -e 1 root 2>/dev/null
echo "[*] Root account expiry set"

# ================================
# 3. Change Passwords for ALL Non-System Users
# ================================
echo ""
echo "[+] Finding and updating passwords for all non-system users..."

CHANGED_USERS=()
SKIPPED_USERS=()

while IFS=: read -r username _ uid _ _ _ shell; do
    if [[ "$uid" -ge 1000 && "$uid" -ne 65534 ]]; then
        if [[ "$shell" == *"nologin"* || "$shell" == *"false"* ]]; then
            SKIPPED_USERS+=("$username (no login shell)")
            continue
        fi
        if [[ "$username" == "$ADMIN_USER" ]]; then
            continue
        fi
        echo "$username:$NEW_PASS" | chpasswd
        if [ $? -eq 0 ]; then
            CHANGED_USERS+=("$username")
            echo "[*] Password changed for: $username"
        else
            echo "[!] Failed to change password for: $username"
        fi
    fi
done < /etc/passwd

# Save full user list
awk -F: '$3 >= 1000 && $3 != 65534 {print $1, "UID="$3, "Shell="$7}' /etc/passwd \
    | tee "$LOG_DIR/users_$TIMESTAMP.txt"

echo ""
echo "[+] Password changes summary:"
echo "    Changed : ${CHANGED_USERS[*]:-none}"
echo "    Skipped : ${SKIPPED_USERS[*]:-none}"

# ================================
# 4. SSH Hardening
# ================================
echo ""
echo "[+] Hardening SSH..."

SSHD_CONFIG="/etc/ssh/sshd_config"
cp "$SSHD_CONFIG" "$LOG_DIR/sshd_config_backup_$TIMESTAMP"

# Disable root login
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
grep -q "^PermitRootLogin" "$SSHD_CONFIG" || echo "PermitRootLogin no" >> "$SSHD_CONFIG"

# Limit auth attempts
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$SSHD_CONFIG"
grep -q "^MaxAuthTries" "$SSHD_CONFIG" || echo "MaxAuthTries 3" >> "$SSHD_CONFIG"

# Keep password auth on (no keys distributed yet)
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD_CONFIG"
grep -q "^PasswordAuthentication" "$SSHD_CONFIG" || echo "PasswordAuthentication yes" >> "$SSHD_CONFIG"

# Whitelist only admin user
if grep -q "^AllowUsers" "$SSHD_CONFIG"; then
    sed -i "s/^AllowUsers.*/AllowUsers $ADMIN_USER/" "$SSHD_CONFIG"
else
    echo "AllowUsers $ADMIN_USER" >> "$SSHD_CONFIG"
fi

systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null
echo "[*] SSH hardened — root login disabled, only $ADMIN_USER allowed"

# ================================
# 5. Clear All SSH Authorized Keys (Red Team Pre-Plant)
# ================================
echo ""
echo "[+] Auditing and clearing SSH authorized_keys..."

find / -name authorized_keys 2>/dev/null > "$LOG_DIR/ssh_keys_files_$TIMESTAMP.txt"

while read -r keyfile; do
    # Back up before wiping
    SAFE_NAME=$(echo "$keyfile" | tr '/' '_')
    cp "$keyfile" "$LOG_DIR/ssh_key_backup_${SAFE_NAME}_$TIMESTAMP" 2>/dev/null
    echo "---- $keyfile (BEFORE WIPE) ----" >> "$LOG_DIR/ssh_keys_content_$TIMESTAMP.txt"
    cat "$keyfile"                          >> "$LOG_DIR/ssh_keys_content_$TIMESTAMP.txt"
    # Wipe
    echo "" > "$keyfile"
    chmod 600 "$keyfile"
    echo "[*] Cleared authorized_keys: $keyfile"
done < "$LOG_DIR/ssh_keys_files_$TIMESTAMP.txt"

echo "[*] All authorized_keys cleared (backups in $LOG_DIR)"

# ================================
# 6. Remove Immutable Flags (Red Team Persistence Trick)
# ================================
echo ""
echo "[+] Checking and removing immutable file flags..."

find /etc/ -exec lsattr {} 2>/dev/null \; | grep '^....i' | awk '{print $2}' \
    > "$LOG_DIR/immutable_$TIMESTAMP.txt"

if [ -s "$LOG_DIR/immutable_$TIMESTAMP.txt" ]; then
    while read -r immfile; do
        chattr -i "$immfile" && echo "[*] Removed immutable flag: $immfile"
    done < "$LOG_DIR/immutable_$TIMESTAMP.txt"
else
    echo "[*] No immutable files found"
fi

# ================================
# 7. Cron Jobs Audit
# ================================
echo ""
echo "[+] Checking cron jobs..."

crontab -l > "$LOG_DIR/cron_$TIMESTAMP.txt" 2>/dev/null

for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null >> "$LOG_DIR/cron_$TIMESTAMP.txt"
done

ls -la /etc/cron* /var/spool/cron/ >> "$LOG_DIR/cron_$TIMESTAMP.txt" 2>/dev/null
echo "[*] Cron jobs saved to $LOG_DIR/cron_$TIMESTAMP.txt — review manually"

# ================================
# 8. Baseline System State
# ================================
echo ""
echo "[+] Creating system baseline..."

ps aux        > "$LOG_DIR/baseline_ps_$TIMESTAMP.txt"
ss -tulpn     > "$LOG_DIR/baseline_ports_$TIMESTAMP.txt"
netstat -antp > "$LOG_DIR/connections_$TIMESTAMP.txt" 2>/dev/null

# Collect bash history for all users
echo "[+] Collecting bash history..."
cat /root/.bash_history > "$LOG_DIR/bash_history_root_$TIMESTAMP.txt" 2>/dev/null
for homedir in /home/*/; do
    user=$(basename "$homedir")
    cat "$homedir/.bash_history" > "$LOG_DIR/bash_history_${user}_$TIMESTAMP.txt" 2>/dev/null
done

# Check /tmp for planted binaries
ls -la /tmp/                              > "$LOG_DIR/tmp_listing_$TIMESTAMP.txt"
find /tmp -executable -type f 2>/dev/null > "$LOG_DIR/tmp_exec_$TIMESTAMP.txt"

# SUID binaries
find / -perm -4000 -type f 2>/dev/null | sort > "$LOG_DIR/suid_$TIMESTAMP.txt"

# Recently modified files in key dirs
find /etc /bin /sbin /usr -type f -mtime -1 2>/dev/null > "$LOG_DIR/recent_files_$TIMESTAMP.txt"

# Check hidden dirs in home folders
ls -la ~/ /root/ /home/*/ >> "$LOG_DIR/hidden_dirs_$TIMESTAMP.txt" 2>/dev/null

echo "[*] Baseline saved"

# ================================
# 9. Firewall — Auto-detect, Install & Harden
#    OUTPUT defaults to DROP (egress filtering = #1 red team stopper)
# ================================
echo ""
echo "[+] Configuring firewall..."

# Install iptables if missing
if ! command -v iptables &>/dev/null; then
    echo "[*] iptables not found, installing..."
    install_pkg iptables
fi

# Install persistence helper
if command -v apt-get &>/dev/null; then
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    install_pkg iptables-persistent
elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then
    install_pkg iptables-services
    systemctl enable iptables
fi

# Install Fail2Ban
echo "[+] Installing Fail2Ban..."
if ! command -v fail2ban-client &>/dev/null; then
    install_pkg fail2ban
fi

# Configure Fail2Ban SSH jail
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
backend  = %(syslog_backend)s
maxretry = 3
EOF

systemctl enable fail2ban 2>/dev/null
systemctl restart fail2ban 2>/dev/null
echo "[*] Fail2Ban configured (SSH: 3 attempts, 1hr ban)"

# Backup existing rules
iptables-save > "$LOG_DIR/iptables_backup_$TIMESTAMP.rules"

# Flush everything
iptables -F
iptables -X

# --- Default policies ---
# INPUT:   DROP everything not explicitly allowed
# FORWARD: DROP (not a router)
# OUTPUT:  DROP — egress filtering is #1 red team stopper
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# --- INPUT rules ---
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 22  -j ACCEPT    # SSH management
iptables -A INPUT -p tcp --dport 80  -j ACCEPT    # HTTP
iptables -A INPUT -p tcp --dport 443 -j ACCEPT    # HTTPS
iptables -A INPUT -p tcp --dport 25  -j ACCEPT    # SMTP
iptables -A INPUT -p tcp --dport 110 -j ACCEPT    # POP3
iptables -A INPUT -p tcp --dport 53  -j ACCEPT    # DNS TCP
iptables -A INPUT -p udp --dport 53  -j ACCEPT    # DNS UDP
iptables -A INPUT -p tcp --dport 21  -j ACCEPT    # FTP
iptables -A INPUT -p udp --dport 69  -j ACCEPT    # TFTP
iptables -A INPUT -p udp --dport 123 -j ACCEPT    # NTP
iptables -A INPUT -p tcp --dport 9997 -j ACCEPT   # Splunk forwarder receiving
iptables -A INPUT -p tcp --dport 514  -j ACCEPT   # Syslog TCP
iptables -A INPUT -p udp --dport 514  -j ACCEPT   # Syslog UDP

# --- OUTPUT rules (egress whitelist — drops red team callbacks) ---
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -p udp --dport 53  -j ACCEPT   # DNS
iptables -A OUTPUT -p tcp --dport 53  -j ACCEPT   # DNS TCP
iptables -A OUTPUT -p tcp --dport 80  -j ACCEPT   # HTTP updates
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT   # HTTPS updates
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT   # NTP
iptables -A OUTPUT -p tcp --dport 25  -j ACCEPT   # SMTP outbound (mail server)
iptables -A OUTPUT -p tcp --dport 9997 -j ACCEPT  # Splunk Universal Forwarder outbound
iptables -A OUTPUT -p tcp --dport 514  -j ACCEPT  # Syslog TCP outbound
iptables -A OUTPUT -p udp --dport 514  -j ACCEPT  # Syslog UDP outbound
# Everything else outbound: DROP — catches red team callbacks

# --- Save rules persistently ---
echo "[+] Saving firewall rules..."
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
elif command -v service &>/dev/null && service iptables status &>/dev/null 2>&1; then
    service iptables save
else
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    echo "[!] Rules saved to /etc/iptables/rules.v4 — verify auto-load on reboot"
fi

echo "[*] Firewall configured:"
echo "    INPUT  → DROP by default, all scored service ports + SSH open"
echo "    OUTPUT → DROP by default, DNS/HTTP/HTTPS/NTP/SMTP whitelisted only"
echo "    Any unexpected outbound = red team callback — investigate immediately"

# ================================
# 10. Summary
# ================================
echo ""
echo "================================================"
echo "[+] Hardening complete."
echo "[+] Admin user  : $ADMIN_USER (sudo enabled)"
echo "[+] Root login  : DISABLED via SSH"
echo "[+] Passwords   : root + admin + ${#CHANGED_USERS[@]} other user(s) updated"
echo "[+] SSH keys    : ALL authorized_keys wiped (backups in $LOG_DIR)"
echo "[+] Immutable   : flags removed from any flagged files"
echo "[+] Fail2Ban    : enabled (SSH jail, 3 attempts = 1hr ban)"
echo "[+] Firewall    : egress + ingress filtered, all scored ports open"
echo "[+] Logs saved  : $LOG_DIR"
echo ""
echo "[!] NEXT STEPS:"
echo "    1. Verify SSH as $ADMIN_USER BEFORE closing this session"
echo "    2. Remove ports not on THIS box: edit iptables INPUT rules above"
echo "    3. Review cron jobs   : $LOG_DIR/cron_$TIMESTAMP.txt"
echo "    4. Review SUID bins   : $LOG_DIR/suid_$TIMESTAMP.txt"
echo "    5. Review recent mods : $LOG_DIR/recent_files_$TIMESTAMP.txt"
echo "    6. Watch auth logs    : tail -f /var/log/auth.log"
echo "    7. Watch connections  : watch -n5 'ss -tulpn'"
echo "================================================"
