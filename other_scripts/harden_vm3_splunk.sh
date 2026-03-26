#!/bin/bash
###############################################################################
# harden_vm3_splunk.sh
# MACCDC 2026 - VM3: Splunk (Oracle Linux 9.2)
# IP: 172.20.242.20 | NOT scored but critical for monitoring
# Default creds: root:changemenow, sysadmin:changemenow, admin:changeme (Splunk web)
#
# Usage: sudo ./harden_vm3_splunk.sh <NEW_PASSWORD>
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
    echo "  NEW_PASSWORD will be set for root, sysadmin, blueteam, and Splunk admin."
    exit 1
fi

NEW_PASSWORD="$1"
LOGDIR="/root/hardening_logs"
LOGFILE="${LOGDIR}/harden_vm3_$(date +%Y%m%d_%H%M%S).log"
HOSTNAME_TAG="VM3-Splunk"
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
# 1. PASSWORD CHANGES
###############################################################################
echo ""
echo "[+] Changing root password (default was: changemenow)..."
echo "root:${NEW_PASSWORD}" | chpasswd && SUMMARY+=("root password changed") || SUMMARY+=("FAILED: root password change")

echo "[+] Changing sysadmin password (default was: changemenow)..."
echo "sysadmin:${NEW_PASSWORD}" | chpasswd && SUMMARY+=("sysadmin password changed") || SUMMARY+=("FAILED: sysadmin password change")

###############################################################################
# 2. CREATE BLUETEAM ADMIN USER
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
# 3. SPLUNK ADMIN PASSWORD CHANGE
###############################################################################
echo ""
echo "[+] Attempting to change Splunk admin password..."
SPLUNK_BIN="/opt/splunk/bin/splunk"
if [[ -x "$SPLUNK_BIN" ]]; then
    echo "[*] Found Splunk at ${SPLUNK_BIN}"
    echo "[+] Running: ${SPLUNK_BIN} edit user admin -password <NEW_PASS> -auth admin:changeme"
    if $SPLUNK_BIN edit user admin -password "$NEW_PASSWORD" -auth admin:changeme 2>&1; then
        echo "[+] Splunk admin password changed successfully!"
        SUMMARY+=("Splunk admin password changed via CLI")
    else
        echo "[!] Splunk CLI password change failed. Try manually:"
        echo "    ${SPLUNK_BIN} edit user admin -password NEW_PASS -auth admin:CURRENT_PASS"
        echo "    Or change via Splunk Web at https://172.20.242.20:8000"
        SUMMARY+=("WARNING: Splunk admin password change failed - change manually!")
    fi
else
    # Try alternate locations
    for alt_path in /opt/splunkforwarder/bin/splunk /usr/local/splunk/bin/splunk; do
        if [[ -x "$alt_path" ]]; then
            SPLUNK_BIN="$alt_path"
            echo "[*] Found Splunk at ${SPLUNK_BIN}"
            break
        fi
    done
    if [[ ! -x "$SPLUNK_BIN" ]]; then
        echo "[!] Splunk binary not found at expected locations!"
        echo "[!] Search for it manually: find / -name splunk -type f 2>/dev/null"
        SUMMARY+=("WARNING: Splunk binary not found")
    fi
fi

echo ""
echo "[*] REMINDER: If CLI password change failed, change Splunk admin password manually:"
echo "    1. Open https://172.20.242.20:8000 in browser"
echo "    2. Login with admin:changeme"
echo "    3. Settings > Access Controls > Users > admin > Change password"

###############################################################################
# 4. SSH HARDENING
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
# 5. CLEAR AUTHORIZED_KEYS (backup first)
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
# 6. CHECK FOR IMMUTABLE FILES
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
# 7. IPTABLES FIREWALL
###############################################################################
echo ""
echo "[+] Configuring iptables firewall..."

# Disable firewalld if present (Oracle Linux may use it)
if systemctl is-active firewalld &>/dev/null; then
    echo "[+] Stopping firewalld to use iptables directly..."
    systemctl stop firewalld
    systemctl disable firewalld 2>/dev/null || true
    SUMMARY+=("firewalld stopped and disabled")
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
# Splunk Web
iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
# Splunk Management
iptables -A INPUT -p tcp --dport 8089 -j ACCEPT
# Syslog (receive logs from other hosts)
iptables -A INPUT -p tcp --dport 514 -j ACCEPT
iptables -A INPUT -p udp --dport 514 -j ACCEPT
# Splunk forwarder receiving
iptables -A INPUT -p tcp --dport 9997 -j ACCEPT
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

# Log dropped
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPT-INPUT-DROP: "
iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "IPT-OUTPUT-DROP: "

# Save rules
if command -v iptables-save &>/dev/null; then
    iptables-save > /etc/sysconfig/iptables 2>/dev/null || iptables-save > /etc/iptables.rules 2>/dev/null || true
fi

SUMMARY+=("iptables configured: INPUT DROP (allow 8000,8089,514,9997,22), OUTPUT DROP (allow EST/REL,53,80,443,123)")

###############################################################################
# 8. AUDIT CRON JOBS
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
# 9. BASELINE PROCESSES, PORTS, CONNECTIONS
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
# 10. CHECK /tmp FOR EXECUTABLES
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
# 11. CHECK SPLUNK STATUS (do NOT restart unless necessary)
###############################################################################
echo ""
echo "[+] Checking Splunk service status..."
if [[ -x "${SPLUNK_BIN:-/opt/splunk/bin/splunk}" ]]; then
    SPLUNK_BIN="${SPLUNK_BIN:-/opt/splunk/bin/splunk}"
    echo "[*] Splunk status:"
    $SPLUNK_BIN status 2>/dev/null || echo "[!] Could not get Splunk status"
    echo ""
    echo "[*] Splunk listening ports:"
    ss -tlnp 2>/dev/null | grep -E ":(8000|8089|9997|514)\b" | sed 's/^/  /' || echo "  None detected"
else
    echo "[!] Splunk binary not found. Check if Splunk is running:"
    echo "    ps aux | grep splunk"
fi
echo ""
echo "[*] NOTE: Splunk was NOT restarted. Only restart if absolutely necessary."
echo "[*] To restart Splunk: /opt/splunk/bin/splunk restart"

###############################################################################
# 12. ADDITIONAL CHECKS
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
echo "  - This box is NOT scored but is CRITICAL for monitoring"
echo "  - Verify Splunk Web is accessible at https://172.20.242.20:8000"
echo "  - If Splunk admin password CLI change failed, change it manually via web UI"
echo "  - Ensure other VMs are forwarding logs to this Splunk instance"
echo "  - Run audit script next: ./audit_vm3_splunk.sh"
echo "============================================================"
