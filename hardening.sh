#!/bin/bash

# ================================
# Parameter Handling
# ================================
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <NEW_PASSWORD> <USERNAME> <CURRENT_PASSWORD>"
    exit 1
fi

NEW_PASS="$1"
ADMIN_USER="$2"
CUR_PASS="$3"

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

    exec sudo -S bash "$0" "$NEW_PASS" "$ADMIN_USER" "$CUR_PASS"
fi

# ================================
# Setup
# ================================
LOG_DIR="/tmp/hardening_logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p $LOG_DIR

echo "[+] Running as root. Starting hardening..."

# ================================
# 1. Ensure Admin User Exists
# ================================
echo "[+] Ensuring admin user exists..."

if id "$ADMIN_USER" &>/dev/null; then
    echo "[*] User $ADMIN_USER exists"
else
    echo "[*] Creating user $ADMIN_USER"
    useradd -m -s /bin/bash "$ADMIN_USER"
fi

# Set password
echo "$ADMIN_USER:$NEW_PASS" | chpasswd

# Add to sudo group
usermod -aG sudo "$ADMIN_USER" 2>/dev/null || usermod -aG wheel "$ADMIN_USER"

# ================================
# 2. Root Password Change
# ================================
echo "[+] Updating root password..."
echo "root:$NEW_PASS" | chpasswd

# ================================
# 3. Accounts Audit
# ================================
echo "[+] Auditing accounts..."

grep -vE "nologin|false|sync" /etc/passwd \
    | tee $LOG_DIR/users_$TIMESTAMP.txt

# ================================
# 4. SSH Key Audit
# ================================
echo "[+] Auditing SSH authorized_keys..."

find / -name authorized_keys 2>/dev/null > $LOG_DIR/ssh_keys_files_$TIMESTAMP.txt

while read file; do
    echo "---- $file ----" >> $LOG_DIR/ssh_keys_content_$TIMESTAMP.txt
    cat "$file" >> $LOG_DIR/ssh_keys_content_$TIMESTAMP.txt
done < $LOG_DIR/ssh_keys_files_$TIMESTAMP.txt

# ================================
# 5. Cron Jobs Audit
# ================================
echo "[+] Checking cron jobs..."

crontab -l > $LOG_DIR/cron_$TIMESTAMP.txt 2>/dev/null

for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u $user -l 2>/dev/null >> $LOG_DIR/cron_$TIMESTAMP.txt
done

ls -la /etc/cron* /var/spool/cron/ >> $LOG_DIR/cron_$TIMESTAMP.txt 2>/dev/null

# ================================
# 6. Baseline System State
# ================================
echo "[+] Creating system baseline..."

ps aux > $LOG_DIR/baseline_ps_$TIMESTAMP.txt
ss -tulpn > $LOG_DIR/baseline_ports_$TIMESTAMP.txt
netstat -antp > $LOG_DIR/connections_$TIMESTAMP.txt 2>/dev/null

# ================================
# 7. Firewall (FIXED STRATEGY)
# ================================
echo "[+] Configuring firewall..."

iptables-save > $LOG_DIR/iptables_backup_$TIMESTAMP.rules

iptables -F
iptables -X

# Safer defaults
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT   # ← FIXED

# Established
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Loopback
iptables -A INPUT -i lo -j ACCEPT

# SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Common services
for port in 80 443; do
    iptables -A INPUT -p tcp --dport $port -j ACCEPT
done

# Splunk forwarder input
iptables -A INPUT -p tcp --dport 9997 -j ACCEPT
# Syslog input
iptables -A INPUT -p tcp --dport 514 -j ACCEPT
iptables -A INPUT -p udp --dport 514 -j ACCEPT

iptables-save > /etc/iptables/rules.v4

# ================================
# 8. SSH Hardening (Dynamic User)
# ================================
echo "[+] Hardening SSH..."

SSHD_CONFIG="/etc/ssh/sshd_config"
cp $SSHD_CONFIG $LOG_DIR/sshd_config_backup_$TIMESTAMP

sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' $SSHD_CONFIG
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' $SSHD_CONFIG
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' $SSHD_CONFIG

# Replace AllowUsers dynamically
if grep -q "^AllowUsers" $SSHD_CONFIG; then
    sed -i "s/^AllowUsers.*/AllowUsers $ADMIN_USER/" $SSHD_CONFIG
else
    echo "AllowUsers $ADMIN_USER" >> $SSHD_CONFIG
fi

systemctl restart sshd 2>/dev/null

# ================================
# 9. Persistence Checks
# ================================
echo "[+] Checking persistence..."

find /etc/ -exec lsattr {} 2>/dev/null \; | grep '^....i' > $LOG_DIR/immutable_$TIMESTAMP.txt

ls -la /tmp/ > $LOG_DIR/tmp_listing_$TIMESTAMP.txt
find /tmp -executable -type f 2>/dev/null > $LOG_DIR/tmp_exec_$TIMESTAMP.txt

find / -perm -4000 -type f 2>/dev/null | sort > $LOG_DIR/suid_$TIMESTAMP.txt

find /etc /bin /sbin /usr -type f -mtime -1 2>/dev/null > $LOG_DIR/recent_files_$TIMESTAMP.txt

# ================================
# 10. Summary
# ================================
echo "[+] Hardening complete."
echo "[+] Admin user: $ADMIN_USER"
echo "[+] Logs: $LOG_DIR"
echo "[!] Review SSH keys, cron jobs, and firewall rules."