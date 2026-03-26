#!/bin/bash
###############################################################################
# harden_vm4_ubuntu_wks.sh
# MACCDC 2026 - VM4: Ubuntu Workstation (Ubuntu Desktop 24.04.3)
# IP: DHCP | NOT scored, cannot be retasked
# Default creds: sysadmin:changeme
#
# Minimal hardening for the workstation. This machine is used for injects
# and general team operations. Do NOT install services or change its role.
#
# Usage: sudo ./harden_vm4_ubuntu_wks.sh <NEW_PASSWORD>
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
LOGFILE="${LOGDIR}/harden_vm4_$(date +%Y%m%d_%H%M%S).log"
HOSTNAME_TAG="VM4-UbuntuWorkstation"
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
echo ""
echo "[*] NOTE: This is a WORKSTATION. Minimal hardening only."
echo "[*] Do NOT install services or change the role of this machine."

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

if [[ -f "$SSHD_CONFIG" ]]; then
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
else
    echo "[*] SSH config not found - SSH may not be installed on this workstation."
    echo "[*] If SSH is needed, install with: apt install openssh-server"
    SUMMARY+=("SSH config not found - skipped SSH hardening")
fi

###############################################################################
# 4. CLEAR AUTHORIZED_KEYS (backup first)
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
# 5. CHECK FOR IMMUTABLE FILES
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
# 6. IPTABLES FIREWALL (minimal - workstation needs internet for injects)
###############################################################################
echo ""
echo "[+] Configuring iptables firewall (minimal workstation rules)..."

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies - OUTPUT is ACCEPT for workstation (needs general internet)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# --- INPUT RULES ---
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
# SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
# ICMP
iptables -A INPUT -p icmp -j ACCEPT

# Log dropped input
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPT-INPUT-DROP: "

# Save rules
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save 2>/dev/null || true
elif command -v iptables-save &>/dev/null; then
    iptables-save > /etc/iptables.rules 2>/dev/null || true
fi

SUMMARY+=("iptables configured: INPUT DROP (allow SSH,ICMP), OUTPUT ACCEPT (workstation)")

###############################################################################
# 7. CHECK PERSISTENCE MECHANISMS
###############################################################################
echo ""
echo "[+] Checking persistence mechanisms..."

# Cron jobs
echo "[*] Cron jobs:"
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
} | tee "${LOGDIR}/cron_audit.log"

# Systemd user services
echo ""
echo "[*] Checking for user systemd services..."
find /etc/systemd/system/ /home/*/.config/systemd/ /root/.config/systemd/ -name "*.service" -type f 2>/dev/null | while read -r svc; do
    echo "[!] Custom service found: ${svc}"
    cat "$svc" 2>/dev/null | sed 's/^/    /'
done | tee "${LOGDIR}/custom_services.log"

# Startup applications (.desktop autostart)
echo ""
echo "[*] Checking autostart entries..."
find /etc/xdg/autostart/ /home/*/.config/autostart/ /root/.config/autostart/ -name "*.desktop" -type f 2>/dev/null | while read -r desktop; do
    echo "[*] Autostart entry: ${desktop}"
    grep -E "^(Name|Exec|Hidden)" "$desktop" 2>/dev/null | sed 's/^/    /'
done | tee "${LOGDIR}/autostart_entries.log"

# .bashrc / .profile persistence
echo ""
echo "[*] Checking shell RC files for suspicious entries..."
for user_home in /root /home/*; do
    for rcfile in .bashrc .bash_profile .profile .zshrc; do
        rcpath="${user_home}/${rcfile}"
        if [[ -f "$rcpath" ]]; then
            # Look for suspicious patterns
            suspicious=$(grep -nE "(curl|wget|nc |ncat|python.*-c|base64|eval|/dev/tcp|reverse|backdoor)" "$rcpath" 2>/dev/null || true)
            if [[ -n "$suspicious" ]]; then
                echo "[!] Suspicious entry in ${rcpath}:"
                echo "$suspicious" | sed 's/^/    /'
            fi
        fi
    done
done | tee "${LOGDIR}/shell_rc_audit.log"

# Systemd timers
echo ""
echo "[*] Systemd timers:"
systemctl list-timers --all 2>/dev/null | tee -a "${LOGDIR}/cron_audit.log"

SUMMARY+=("Persistence mechanisms audited")

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
} | tee "${LOGDIR}/baseline.log"
SUMMARY+=("Process/port baseline saved")

###############################################################################
# 9. CHECK /tmp FOR EXECUTABLES
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
# 10. ADDITIONAL CHECKS
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
echo "  - This workstation is NOT scored and CANNOT be retasked"
echo "  - Do NOT install services or change its role"
echo "  - OUTPUT is ACCEPT so the workstation can access internet for injects"
echo "  - Run audit script next: ./audit_vm4_ubuntu_wks.sh"
echo "============================================================"
