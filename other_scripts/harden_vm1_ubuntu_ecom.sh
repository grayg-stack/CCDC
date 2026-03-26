#!/bin/bash
###############################################################################
# harden_vm1_ubuntu_ecom.sh
# MACCDC 2026 - VM1: Ubuntu Ecom (Ubuntu Server 24.04.3)
# IP: 172.20.242.30 | Scored: HTTP(80), HTTPS(443)
# Default creds: sysadmin:changeme
#
# Usage: sudo ./harden_vm1_ubuntu_ecom.sh <NEW_PASSWORD>
#
# This script hardens the Ubuntu E-commerce web server. It changes default
# passwords, locks down SSH, configures iptables, audits persistence, and
# hardens PHP. Safe to run multiple times (idempotent).
###############################################################################

set -euo pipefail

# --- Auto-escalate to root ---
if [[ $EUID -ne 0 ]]; then
    echo "[!] Not running as root. Re-executing with sudo..."
    exec sudo "$0" "$@"
fi

# --- Validate arguments ---
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <NEW_PASSWORD>"
    echo "  NEW_PASSWORD will be set for root, sysadmin, and the new blueteam user."
    exit 1
fi

NEW_PASSWORD="$1"
LOGDIR="/root/hardening_logs"
LOGFILE="${LOGDIR}/harden_vm1_$(date +%Y%m%d_%H%M%S).log"
HOSTNAME_TAG="VM1-UbuntuEcom"
SUMMARY=()

# --- Setup logging ---
mkdir -p "$LOGDIR"
chmod 700 "$LOGDIR"

# Tee all output to logfile and console
exec > >(tee -a "$LOGFILE") 2>&1

echo "============================================================"
echo " ${HOSTNAME_TAG} Hardening Script"
echo " Started: $(date)"
echo " Log: ${LOGFILE}"
echo "============================================================"

###############################################################################
# 1. PASSWORD CHANGES
###############################################################################
echo ""
echo "[+] Changing root password..."
echo "root:${NEW_PASSWORD}" | chpasswd && SUMMARY+=("root password changed") || SUMMARY+=("FAILED: root password change")

echo "[+] Changing sysadmin password..."
echo "sysadmin:${NEW_PASSWORD}" | chpasswd && SUMMARY+=("sysadmin password changed") || SUMMARY+=("FAILED: sysadmin password change")

###############################################################################
# 2. CREATE BLUETEAM ADMIN USER
###############################################################################
echo ""
if id "blueteam" &>/dev/null; then
    echo "[*] User 'blueteam' already exists, ensuring sudo membership..."
else
    echo "[+] Creating blueteam admin user..."
    useradd -m -s /bin/bash blueteam
    SUMMARY+=("blueteam user created")
fi
echo "blueteam:${NEW_PASSWORD}" | chpasswd
usermod -aG sudo blueteam 2>/dev/null || usermod -aG wheel blueteam 2>/dev/null || true
SUMMARY+=("blueteam password set and added to sudo")

###############################################################################
# 3. SSH HARDENING
###############################################################################
echo ""
echo "[+] Hardening SSH configuration..."
SSHD_CONFIG="/etc/ssh/sshd_config"
cp -f "$SSHD_CONFIG" "${LOGDIR}/sshd_config.bak.$(date +%Y%m%d_%H%M%S)"

# Function to set or add an SSH config directive
set_sshd_option() {
    local key="$1"
    local value="$2"
    if grep -qE "^\s*#?\s*${key}\b" "$SSHD_CONFIG"; then
        sed -i "s|^\s*#\?\s*${key}\b.*|${key} ${value}|" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
}

set_sshd_option "PermitRootLogin" "no"
set_sshd_option "MaxAuthTries" "3"
set_sshd_option "PasswordAuthentication" "yes"
set_sshd_option "PubkeyAuthentication" "yes"
set_sshd_option "PermitEmptyPasswords" "no"
set_sshd_option "X11Forwarding" "no"
set_sshd_option "UsePAM" "yes"

# AllowUsers - must be handled carefully (remove old line, add new one)
sed -i '/^\s*AllowUsers/d' "$SSHD_CONFIG"
echo "AllowUsers blueteam sysadmin" >> "$SSHD_CONFIG"

echo "[+] Restarting SSH service..."
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
SUMMARY+=("SSH hardened: root login disabled, MaxAuthTries=3, AllowUsers=blueteam,sysadmin")

###############################################################################
# 4. CLEAR AUTHORIZED_KEYS (backup first)
###############################################################################
echo ""
echo "[+] Backing up and clearing all authorized_keys files..."
AUTHKEYS_BACKUP="${LOGDIR}/authorized_keys_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$AUTHKEYS_BACKUP"

find / -name "authorized_keys" -type f 2>/dev/null | while read -r keyfile; do
    echo "[*] Found: ${keyfile}"
    # Preserve directory structure in backup
    backup_path="${AUTHKEYS_BACKUP}${keyfile}"
    mkdir -p "$(dirname "$backup_path")"
    cp -f "$keyfile" "$backup_path"
    > "$keyfile"
    echo "[+] Cleared: ${keyfile}"
done
SUMMARY+=("All authorized_keys backed up to ${AUTHKEYS_BACKUP} and cleared")

###############################################################################
# 5. CHECK FOR IMMUTABLE FILES
###############################################################################
echo ""
echo "[+] Checking for immutable files (chattr +i)..."
IMMUTABLE_FILES=$(lsattr -R / 2>/dev/null | grep -E "^....i" || true)
if [[ -n "$IMMUTABLE_FILES" ]]; then
    echo "[!] Found immutable files:"
    echo "$IMMUTABLE_FILES" | tee "${LOGDIR}/immutable_files.log"
    echo "[+] Removing immutable flags..."
    echo "$IMMUTABLE_FILES" | awk '{print $2}' | while read -r ifile; do
        chattr -i "$ifile" 2>/dev/null && echo "[+] Removed immutable flag: ${ifile}" || true
    done
    SUMMARY+=("Immutable files found and flags removed - check ${LOGDIR}/immutable_files.log")
else
    echo "[*] No immutable files found."
fi

###############################################################################
# 6. IPTABLES FIREWALL
###############################################################################
echo ""
echo "[+] Configuring iptables firewall..."

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# --- INPUT RULES ---
# Allow established/related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
# Allow HTTP (scored)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
# Allow HTTPS (scored)
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
# Allow SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
# Allow ICMP (ping - useful for scoring checks)
iptables -A INPUT -p icmp -j ACCEPT

# --- OUTPUT RULES ---
# Allow established/related connections
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allow loopback
iptables -A OUTPUT -o lo -j ACCEPT
# Allow DNS
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
# Allow HTTP
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
# Allow HTTPS
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
# Allow NTP
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

# Log dropped packets (rate-limited)
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPT-INPUT-DROP: "
iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "IPT-OUTPUT-DROP: "

# Save rules
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save 2>/dev/null || true
elif command -v iptables-save &>/dev/null; then
    iptables-save > /etc/iptables.rules 2>/dev/null || true
fi

SUMMARY+=("iptables configured: INPUT DROP (allow 80,443,22), OUTPUT DROP (allow EST/REL,53,80,443,123)")

###############################################################################
# 7. AUDIT CRON JOBS
###############################################################################
echo ""
echo "[+] Auditing cron jobs..."
{
    echo "=== System crontabs ==="
    for crondir in /etc/crontab /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/; do
        if [[ -e "$crondir" ]]; then
            echo "--- ${crondir} ---"
            if [[ -d "$crondir" ]]; then
                ls -la "$crondir" 2>/dev/null
                for f in "$crondir"/*; do
                    [[ -f "$f" ]] && echo ">> $f:" && cat "$f" 2>/dev/null
                done
            else
                cat "$crondir" 2>/dev/null
            fi
        fi
    done
    echo ""
    echo "=== User crontabs ==="
    for user in $(cut -d: -f1 /etc/passwd); do
        crontab_content=$(crontab -l -u "$user" 2>/dev/null) || continue
        if [[ -n "$crontab_content" ]]; then
            echo "--- ${user} ---"
            echo "$crontab_content"
        fi
    done
    echo ""
    echo "=== Systemd timers ==="
    systemctl list-timers --all 2>/dev/null || true
} | tee "${LOGDIR}/cron_audit.log"
SUMMARY+=("Cron jobs audited - see ${LOGDIR}/cron_audit.log")

###############################################################################
# 8. BASELINE PROCESSES, PORTS, CONNECTIONS
###############################################################################
echo ""
echo "[+] Baselining processes, ports, and connections..."
{
    echo "=== Running Processes ==="
    ps auxf 2>/dev/null || ps aux
    echo ""
    echo "=== Listening Ports ==="
    ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
    echo ""
    echo "=== All Network Connections ==="
    ss -tanp 2>/dev/null || netstat -tanp 2>/dev/null
    echo ""
    echo "=== UDP Listeners ==="
    ss -ulnp 2>/dev/null || netstat -ulnp 2>/dev/null
} | tee "${LOGDIR}/baseline.log"
SUMMARY+=("Process/port/connection baseline saved to ${LOGDIR}/baseline.log")

###############################################################################
# 9. CHECK /tmp FOR EXECUTABLES
###############################################################################
echo ""
echo "[+] Checking /tmp for executable files..."
TMP_EXECS=$(find /tmp -type f -executable 2>/dev/null || true)
if [[ -n "$TMP_EXECS" ]]; then
    echo "[!] Executable files found in /tmp:"
    echo "$TMP_EXECS" | tee "${LOGDIR}/tmp_executables.log"
    SUMMARY+=("WARNING: Executables found in /tmp - review ${LOGDIR}/tmp_executables.log")
else
    echo "[*] No executable files found in /tmp."
fi

###############################################################################
# 10. PHP HARDENING
###############################################################################
echo ""
echo "[+] Hardening PHP configuration..."
PHP_HARDENED=false
for php_ini in $(find /etc/php* /etc/php /usr/local/etc/php -name "php.ini" -type f 2>/dev/null); do
    echo "[*] Hardening: ${php_ini}"
    cp -f "$php_ini" "${LOGDIR}/$(basename "$php_ini").bak.$(date +%Y%m%d_%H%M%S)"

    # Disable dangerous functions
    if grep -qE "^\s*disable_functions\s*=" "$php_ini"; then
        sed -i 's|^\s*disable_functions\s*=.*|disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source|' "$php_ini"
    else
        echo 'disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source' >> "$php_ini"
    fi

    # expose_php Off
    if grep -qE "^\s*expose_php\s*=" "$php_ini"; then
        sed -i 's|^\s*expose_php\s*=.*|expose_php = Off|' "$php_ini"
    else
        echo 'expose_php = Off' >> "$php_ini"
    fi

    # display_errors Off
    if grep -qE "^\s*display_errors\s*=" "$php_ini"; then
        sed -i 's|^\s*display_errors\s*=.*|display_errors = Off|' "$php_ini"
    else
        echo 'display_errors = Off' >> "$php_ini"
    fi

    # allow_url_include Off
    if grep -qE "^\s*allow_url_include\s*=" "$php_ini"; then
        sed -i 's|^\s*allow_url_include\s*=.*|allow_url_include = Off|' "$php_ini"
    else
        echo 'allow_url_include = Off' >> "$php_ini"
    fi

    # allow_url_fopen Off
    if grep -qE "^\s*allow_url_fopen\s*=" "$php_ini"; then
        sed -i 's|^\s*allow_url_fopen\s*=.*|allow_url_fopen = Off|' "$php_ini"
    else
        echo 'allow_url_fopen = Off' >> "$php_ini"
    fi

    PHP_HARDENED=true
done

if $PHP_HARDENED; then
    SUMMARY+=("PHP hardened: dangerous functions disabled, expose_php/display_errors/allow_url_include/allow_url_fopen Off")
else
    echo "[!] No php.ini files found - check PHP installation manually."
    SUMMARY+=("WARNING: No php.ini found - PHP hardening skipped")
fi

###############################################################################
# 11. RESTART WEB SERVER
###############################################################################
echo ""
echo "[+] Restarting web server..."
if systemctl is-active apache2 &>/dev/null; then
    systemctl restart apache2 && echo "[+] Apache2 restarted." && SUMMARY+=("Apache2 restarted")
elif systemctl is-active httpd &>/dev/null; then
    systemctl restart httpd && echo "[+] httpd restarted." && SUMMARY+=("httpd restarted")
elif systemctl is-active nginx &>/dev/null; then
    systemctl restart nginx && echo "[+] Nginx restarted." && SUMMARY+=("Nginx restarted")
else
    echo "[!] No recognized web server running. Check manually!"
    SUMMARY+=("WARNING: No web server detected to restart")
fi

###############################################################################
# 12. ADDITIONAL QUICK CHECKS
###############################################################################
echo ""
echo "[+] Checking for suspicious SUID/SGID binaries..."
find / -perm -4000 -type f 2>/dev/null | tee "${LOGDIR}/suid_binaries.log"
echo "[+] SUID binaries logged to ${LOGDIR}/suid_binaries.log"

echo ""
echo "[+] Checking /etc/passwd for UID 0 accounts..."
awk -F: '$3 == 0 {print "[!] UID 0 account: " $1}' /etc/passwd | tee -a "${LOGDIR}/uid0_accounts.log"

echo ""
echo "[+] Checking for world-writable files in web directories..."
for webdir in /var/www /srv/www /usr/share/nginx; do
    if [[ -d "$webdir" ]]; then
        find "$webdir" -perm -o+w -type f 2>/dev/null | tee -a "${LOGDIR}/world_writable_web.log"
    fi
done

###############################################################################
# SUMMARY
###############################################################################
echo ""
echo "============================================================"
echo " ${HOSTNAME_TAG} HARDENING COMPLETE"
echo " Finished: $(date)"
echo "============================================================"
echo ""
echo "Actions taken:"
for item in "${SUMMARY[@]}"; do
    echo "  [+] ${item}"
done
echo ""
echo "Log directory: ${LOGDIR}"
echo "Full log: ${LOGFILE}"
echo ""
echo "REMINDERS:"
echo "  - Test HTTP (port 80) and HTTPS (port 443) scoring immediately!"
echo "  - Password change on scored service accounts requires a ticket at auth.ccdc.events"
echo "  - Verify web application is functioning after PHP changes"
echo "  - Run audit script next: ./audit_vm1_ubuntu_ecom.sh"
echo "============================================================"
