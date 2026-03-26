#!/bin/bash
###############################################################################
# harden_vm2_fedora_webmail.sh
# MACCDC 2026 - VM2: Fedora Webmail (Fedora 42)
# IP: 172.20.242.40 | Scored: SMTP(25), POP3(110)
# Also likely HTTP(80)/HTTPS(443) for webmail UI
# Default creds: sysadmin:changeme
#
# Usage: sudo ./harden_vm2_fedora_webmail.sh <NEW_PASSWORD>
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
LOGFILE="${LOGDIR}/harden_vm2_$(date +%Y%m%d_%H%M%S).log"
HOSTNAME_TAG="VM2-FedoraWebmail"
SUMMARY=()

# --- Setup logging ---
mkdir -p "$LOGDIR"
chmod 700 "$LOGDIR"

exec > >(tee -a "$LOGFILE") 2>&1

echo "============================================================"
echo " ${HOSTNAME_TAG} Hardening Script"
echo " Started: $(date)"
echo " Log: ${LOGFILE}"
echo "============================================================"

###############################################################################
# 1. BACKUP MAIL CONFIGS FIRST (before any changes)
###############################################################################
echo ""
echo "[+] Backing up mail service configurations..."
MAIL_BACKUP="${LOGDIR}/mail_config_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$MAIL_BACKUP"

if [[ -d /etc/postfix ]]; then
    cp -a /etc/postfix "$MAIL_BACKUP/postfix"
    echo "[+] Postfix config backed up to ${MAIL_BACKUP}/postfix"
fi
if [[ -d /etc/dovecot ]]; then
    cp -a /etc/dovecot "$MAIL_BACKUP/dovecot"
    echo "[+] Dovecot config backed up to ${MAIL_BACKUP}/dovecot"
fi
if [[ -f /etc/aliases ]]; then
    cp -a /etc/aliases "$MAIL_BACKUP/aliases"
    echo "[+] /etc/aliases backed up"
fi
SUMMARY+=("Mail configs backed up to ${MAIL_BACKUP}")

###############################################################################
# 2. VERIFY MAIL SERVICES STATUS (pre-hardening)
###############################################################################
echo ""
echo "[+] Checking mail service status (pre-hardening)..."
echo "[*] Postfix status:"
systemctl status postfix --no-pager 2>/dev/null || echo "[!] Postfix not found or not running"
echo ""
echo "[*] Dovecot status:"
systemctl status dovecot --no-pager 2>/dev/null || echo "[!] Dovecot not found or not running"
echo ""

# Record whether services were running before we start
POSTFIX_WAS_RUNNING=false
DOVECOT_WAS_RUNNING=false
systemctl is-active postfix &>/dev/null && POSTFIX_WAS_RUNNING=true
systemctl is-active dovecot &>/dev/null && DOVECOT_WAS_RUNNING=true

echo "[*] Postfix running pre-hardening: ${POSTFIX_WAS_RUNNING}"
echo "[*] Dovecot running pre-hardening: ${DOVECOT_WAS_RUNNING}"

###############################################################################
# 3. PASSWORD CHANGES
###############################################################################
echo ""
echo "[+] Changing root password..."
echo "root:${NEW_PASSWORD}" | chpasswd && SUMMARY+=("root password changed") || SUMMARY+=("FAILED: root password change")

echo "[+] Changing sysadmin password..."
echo "sysadmin:${NEW_PASSWORD}" | chpasswd && SUMMARY+=("sysadmin password changed") || SUMMARY+=("FAILED: sysadmin password change")

###############################################################################
# 4. CREATE BLUETEAM ADMIN USER
###############################################################################
echo ""
if id "blueteam" &>/dev/null; then
    echo "[*] User 'blueteam' already exists, ensuring wheel membership..."
else
    echo "[+] Creating blueteam admin user..."
    useradd -m -s /bin/bash blueteam
    SUMMARY+=("blueteam user created")
fi
echo "blueteam:${NEW_PASSWORD}" | chpasswd
usermod -aG wheel blueteam
SUMMARY+=("blueteam password set and added to wheel group")

###############################################################################
# 5. SSH HARDENING
###############################################################################
echo ""
echo "[+] Hardening SSH configuration..."
SSHD_CONFIG="/etc/ssh/sshd_config"
cp -f "$SSHD_CONFIG" "${LOGDIR}/sshd_config.bak.$(date +%Y%m%d_%H%M%S)"

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

sed -i '/^\s*AllowUsers/d' "$SSHD_CONFIG"
echo "AllowUsers blueteam sysadmin" >> "$SSHD_CONFIG"

echo "[+] Restarting SSH service..."
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
SUMMARY+=("SSH hardened: root login disabled, MaxAuthTries=3, AllowUsers=blueteam,sysadmin")

###############################################################################
# 6. CLEAR AUTHORIZED_KEYS (backup first)
###############################################################################
echo ""
echo "[+] Backing up and clearing all authorized_keys files..."
AUTHKEYS_BACKUP="${LOGDIR}/authorized_keys_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$AUTHKEYS_BACKUP"

find / -name "authorized_keys" -type f 2>/dev/null | while read -r keyfile; do
    echo "[*] Found: ${keyfile}"
    backup_path="${AUTHKEYS_BACKUP}${keyfile}"
    mkdir -p "$(dirname "$backup_path")"
    cp -f "$keyfile" "$backup_path"
    > "$keyfile"
    echo "[+] Cleared: ${keyfile}"
done
SUMMARY+=("All authorized_keys backed up and cleared")

###############################################################################
# 7. CHECK FOR IMMUTABLE FILES
###############################################################################
echo ""
echo "[+] Checking for immutable files..."
IMMUTABLE_FILES=$(lsattr -R / 2>/dev/null | grep -E "^....i" || true)
if [[ -n "$IMMUTABLE_FILES" ]]; then
    echo "[!] Found immutable files:"
    echo "$IMMUTABLE_FILES" | tee "${LOGDIR}/immutable_files.log"
    echo "[+] Removing immutable flags..."
    echo "$IMMUTABLE_FILES" | awk '{print $2}' | while read -r ifile; do
        chattr -i "$ifile" 2>/dev/null && echo "[+] Removed immutable flag: ${ifile}" || true
    done
    SUMMARY+=("Immutable files found and flags removed")
else
    echo "[*] No immutable files found."
fi

###############################################################################
# 8. IPTABLES FIREWALL
###############################################################################
echo ""
echo "[+] Configuring iptables firewall..."

# Disable firewalld if present (Fedora uses firewalld by default, switch to iptables)
if systemctl is-active firewalld &>/dev/null; then
    echo "[+] Stopping firewalld to use iptables directly..."
    systemctl stop firewalld
    systemctl disable firewalld 2>/dev/null || true
    SUMMARY+=("firewalld stopped and disabled in favor of iptables")
fi

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
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
# SMTP (scored)
iptables -A INPUT -p tcp --dport 25 -j ACCEPT
# POP3 (scored)
iptables -A INPUT -p tcp --dport 110 -j ACCEPT
# HTTP (webmail UI)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
# HTTPS (webmail UI)
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
# SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
# ICMP
iptables -A INPUT -p icmp -j ACCEPT

# --- OUTPUT RULES ---
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
# DNS
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
# HTTP
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
# HTTPS
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
# NTP
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
# SMTP outbound (mail delivery)
iptables -A OUTPUT -p tcp --dport 25 -j ACCEPT

# Log dropped
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPT-INPUT-DROP: "
iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "IPT-OUTPUT-DROP: "

# Save rules
if command -v iptables-save &>/dev/null; then
    iptables-save > /etc/sysconfig/iptables 2>/dev/null || iptables-save > /etc/iptables.rules 2>/dev/null || true
fi

SUMMARY+=("iptables configured: INPUT DROP (allow 25,110,80,443,22), OUTPUT DROP (allow EST/REL,53,80,443,123,25)")

###############################################################################
# 9. AUDIT CRON JOBS
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
SUMMARY+=("Cron jobs audited")

###############################################################################
# 10. BASELINE PROCESSES, PORTS, CONNECTIONS
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
} | tee "${LOGDIR}/baseline.log"
SUMMARY+=("Process/port baseline saved")

###############################################################################
# 11. CHECK /tmp FOR EXECUTABLES
###############################################################################
echo ""
echo "[+] Checking /tmp for executable files..."
TMP_EXECS=$(find /tmp -type f -executable 2>/dev/null || true)
if [[ -n "$TMP_EXECS" ]]; then
    echo "[!] Executable files found in /tmp:"
    echo "$TMP_EXECS" | tee "${LOGDIR}/tmp_executables.log"
    SUMMARY+=("WARNING: Executables found in /tmp")
else
    echo "[*] No executable files found in /tmp."
fi

###############################################################################
# 12. CHECK POSTFIX RELAY CONFIG
###############################################################################
echo ""
echo "[+] Checking Postfix relay configuration..."
if [[ -f /etc/postfix/main.cf ]]; then
    echo "[*] Key Postfix settings:"
    grep -E "^(myhostname|mydomain|myorigin|mydestination|relayhost|inet_interfaces|smtpd_relay_restrictions|mynetworks)" /etc/postfix/main.cf 2>/dev/null | sed 's/^/  /'
    echo ""
    echo "[*] Open relay check - looking for 'permit' without restrictions..."
    if grep -qE "^\s*smtpd_relay_restrictions\s*=.*permit$" /etc/postfix/main.cf 2>/dev/null; then
        echo "[!] WARNING: Postfix may be configured as an open relay!"
        SUMMARY+=("WARNING: Possible open relay in Postfix config")
    else
        echo "[*] Postfix relay restrictions appear to be in place."
    fi
else
    echo "[!] /etc/postfix/main.cf not found!"
fi

###############################################################################
# 13. VERIFY MAIL SERVICES (post-hardening)
###############################################################################
echo ""
echo "[+] Verifying mail services after hardening..."
echo "[*] Postfix status:"
systemctl status postfix --no-pager 2>/dev/null || echo "[!] Postfix not running!"
echo ""
echo "[*] Dovecot status:"
systemctl status dovecot --no-pager 2>/dev/null || echo "[!] Dovecot not running!"

# Restart mail services if they were running before but are not now
if $POSTFIX_WAS_RUNNING && ! systemctl is-active postfix &>/dev/null; then
    echo "[!] Postfix was running but is now stopped! Restarting..."
    systemctl start postfix
    SUMMARY+=("Postfix restarted (was stopped after hardening)")
fi
if $DOVECOT_WAS_RUNNING && ! systemctl is-active dovecot &>/dev/null; then
    echo "[!] Dovecot was running but is now stopped! Restarting..."
    systemctl start dovecot
    SUMMARY+=("Dovecot restarted (was stopped after hardening)")
fi

###############################################################################
# 14. ADDITIONAL CHECKS
###############################################################################
echo ""
echo "[+] Checking for suspicious SUID/SGID binaries..."
find / -perm -4000 -type f 2>/dev/null | tee "${LOGDIR}/suid_binaries.log"

echo ""
echo "[+] Checking /etc/passwd for UID 0 accounts..."
awk -F: '$3 == 0 {print "[!] UID 0 account: " $1}' /etc/passwd

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
echo "  - Test SMTP (port 25) and POP3 (port 110) scoring IMMEDIATELY!"
echo "  - Test webmail UI (HTTP/HTTPS) if applicable"
echo "  - Password change on scored service accounts requires a ticket at auth.ccdc.events"
echo "  - DO NOT disable mail service accounts (postfix, dovecot, mail)"
echo "  - Mail config backup: ${MAIL_BACKUP}"
echo "  - Run audit script next: ./audit_vm2_fedora_webmail.sh"
echo "============================================================"
