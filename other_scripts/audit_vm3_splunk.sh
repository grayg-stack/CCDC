#!/bin/bash
###############################################################################
# audit_vm3_splunk.sh
# MACCDC 2026 - VM3: Splunk (Oracle Linux 9.2)
# IP: 172.20.242.20 | NOT scored but critical for monitoring
#
# Interactive user audit for Splunk/Oracle Linux. Uses wheel group.
# Shows Splunk-specific users and service status.
#
# Usage: sudo ./audit_vm3_splunk.sh
###############################################################################

set -uo pipefail

# --- Auto-escalate to root ---
if [[ $EUID -ne 0 ]]; then
    echo "[!] Not running as root. Re-executing with sudo..."
    exec sudo "$0" "$@"
fi

# --- ANSI Color Codes ---
RED='\033[1;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
MAGENTA='\033[1;35m'
BOLD='\033[1m'
NC='\033[0m'

LOGDIR="/root/hardening_logs"
LOGFILE="${LOGDIR}/audit_vm3_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$LOGDIR"
chmod 700 "$LOGDIR"

exec > >(tee -a "$LOGFILE") 2>&1

ACTIONS_TAKEN=()

# Splunk service accounts that should NOT be deleted
SPLUNK_SERVICE_ACCOUNTS=("splunk" "splunkfwd" "splunkd")

echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD} VM3 Splunk (Oracle Linux) - Interactive User Audit${NC}"
echo -e "${BOLD} $(date)${NC}"
echo -e "${BOLD}============================================================${NC}"

###############################################################################
# SECTION 0: Splunk service status
###############################################################################
echo ""
echo -e "${BOLD}=== SPLUNK SERVICE STATUS ===${NC}"
echo ""

SPLUNK_BIN="/opt/splunk/bin/splunk"
for alt_path in /opt/splunk/bin/splunk /opt/splunkforwarder/bin/splunk /usr/local/splunk/bin/splunk; do
    if [[ -x "$alt_path" ]]; then
        SPLUNK_BIN="$alt_path"
        break
    fi
done

if [[ -x "$SPLUNK_BIN" ]]; then
    echo -e "${CYAN}Splunk binary: ${SPLUNK_BIN}${NC}"
    echo -e "${CYAN}Splunk status:${NC}"
    $SPLUNK_BIN status 2>/dev/null | sed 's/^/  /' || echo "  Could not get status"
else
    echo -e "${YELLOW}[!] Splunk binary not found at standard locations${NC}"
    echo "[*] Checking for Splunk processes..."
    ps aux | grep -i splunk | grep -v grep | sed 's/^/  /' || echo "  No Splunk processes found"
fi

echo ""
echo -e "${CYAN}Splunk-related listening ports:${NC}"
ss -tlnp 2>/dev/null | grep -E ":(8000|8089|8191|9997|514)\b" | sed 's/^/  /' || echo "  None detected"
echo ""

# Also check for Splunk web users via REST API if accessible
echo -e "${CYAN}Splunk web users (if accessible):${NC}"
if [[ -x "$SPLUNK_BIN" ]]; then
    $SPLUNK_BIN list user -auth admin:changeme 2>/dev/null | sed 's/^/  /' || \
    echo "  Could not list Splunk users (auth may have changed)"
fi
echo ""

###############################################################################
# SECTION 1: Display all users
###############################################################################
echo -e "${BOLD}=== ALL USERS WITH UID >= 1000 OR LOGIN SHELLS ===${NC}"
echo ""

AUDIT_USERS=()
while IFS=: read -r username _ uid gid _ homedir shell; do
    if [[ $uid -ge 1000 ]] || { [[ "$shell" != */nologin ]] && [[ "$shell" != */false ]] && [[ "$shell" != "/bin/sync" ]] && [[ $uid -ne 0 ]]; }; then
        AUDIT_USERS+=("$username")
    fi
done < /etc/passwd

# Display root
echo -e "${RED}--- root account ---${NC}"
echo -e "  Username: root"
echo -e "  UID: 0 | GID: 0"
echo -e "  Shell: $(grep '^root:' /etc/passwd | cut -d: -f7)"
echo -e "  Home: /root"
echo -e "  Groups: $(groups root 2>/dev/null | cut -d: -f2)"
echo -e "  Last login: $(lastlog -u root 2>/dev/null | tail -1 || echo 'unknown')"
echo -e "  Password status: $(passwd -S root 2>/dev/null || echo 'unknown')"
echo ""

for username in "${AUDIT_USERS[@]}"; do
    user_info=$(getent passwd "$username" 2>/dev/null) || continue
    uid=$(echo "$user_info" | cut -d: -f3)
    gid=$(echo "$user_info" | cut -d: -f4)
    homedir=$(echo "$user_info" | cut -d: -f6)
    shell=$(echo "$user_info" | cut -d: -f7)
    user_groups=$(groups "$username" 2>/dev/null | cut -d: -f2 || echo "none")
    last_login=$(lastlog -u "$username" 2>/dev/null | tail -1 || echo "unknown")
    pass_status=$(passwd -S "$username" 2>/dev/null || echo "unknown")

    # Check if Splunk service account
    is_splunk_svc=false
    for svc in "${SPLUNK_SERVICE_ACCOUNTS[@]}"; do
        if [[ "$username" == "$svc" ]]; then
            is_splunk_svc=true
            break
        fi
    done

    is_wheel=false
    if echo "$user_groups" | grep -qw "wheel"; then
        is_wheel=true
    fi

    color=$GREEN
    tag=""
    if $is_splunk_svc; then
        color=$MAGENTA
        tag=" [SPLUNK SERVICE - DO NOT DELETE]"
    elif $is_wheel; then
        color=$RED
        tag=" [WHEEL/SUDO]"
    elif [[ "$shell" != "/bin/bash" ]] && [[ "$shell" != "/bin/sh" ]] && [[ "$shell" != "/usr/bin/bash" ]]; then
        color=$YELLOW
        tag=" [UNUSUAL SHELL]"
    fi

    echo -e "${color}--- ${username}${tag} ---${NC}"
    echo -e "  Username: ${username}"
    echo -e "  UID: ${uid} | GID: ${gid}"
    echo -e "  Shell: ${shell}"
    echo -e "  Home: ${homedir}"
    echo -e "  Groups: ${user_groups}"
    echo -e "  Last login: ${last_login}"
    echo -e "  Password status: ${pass_status}"

    crontab_content=$(crontab -l -u "$username" 2>/dev/null) || crontab_content=""
    if [[ -n "$crontab_content" ]]; then
        echo -e "  ${YELLOW}Crontab entries:${NC}"
        echo "$crontab_content" | sed 's/^/    /'
    fi
    echo ""
done

###############################################################################
# SECTION 2: SSH authorized_keys
###############################################################################
echo -e "${BOLD}=== SSH AUTHORIZED_KEYS ===${NC}"
echo ""
found_keys=false
while IFS=: read -r username _ _ _ _ homedir _; do
    keyfile="${homedir}/.ssh/authorized_keys"
    if [[ -f "$keyfile" ]] && [[ -s "$keyfile" ]]; then
        echo -e "${YELLOW}[!] ${username}: ${keyfile}${NC}"
        cat "$keyfile" | sed 's/^/    /'
        echo ""
        found_keys=true
    fi
done < /etc/passwd
if ! $found_keys; then
    echo -e "${GREEN}[*] No authorized_keys files with content found.${NC}"
fi
echo ""

###############################################################################
# SECTION 3: Docker group check
###############################################################################
echo -e "${BOLD}=== DOCKER GROUP MEMBERS ===${NC}"
echo ""
docker_users=$(getent group docker 2>/dev/null | cut -d: -f4)
if [[ -n "$docker_users" ]]; then
    echo -e "${RED}[!] Users in docker group: ${docker_users}${NC}"
else
    echo -e "${GREEN}[*] No users in docker group.${NC}"
fi
echo ""

###############################################################################
# SECTION 4: Sudoers audit
###############################################################################
echo -e "${BOLD}=== SUDOERS AUDIT ===${NC}"
echo ""
echo -e "${CYAN}--- /etc/sudoers ---${NC}"
if [[ -f /etc/sudoers ]]; then
    grep -v '^#' /etc/sudoers | grep -v '^$' | sed 's/^/  /'
fi
echo ""
echo -e "${CYAN}--- /etc/sudoers.d/ ---${NC}"
if [[ -d /etc/sudoers.d ]]; then
    for sf in /etc/sudoers.d/*; do
        if [[ -f "$sf" ]]; then
            echo -e "  ${YELLOW}File: ${sf}${NC}"
            grep -v '^#' "$sf" | grep -v '^$' | sed 's/^/    /'
        fi
    done
fi
echo ""

###############################################################################
# SECTION 5: Interactive user actions
###############################################################################
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD} INTERACTIVE USER MANAGEMENT${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""
echo -e "For each user, choose an action:"
echo -e "  ${BOLD}[p]${NC} - Change password"
echo -e "  ${BOLD}[d]${NC} - Delete user (with home directory)"
echo -e "  ${BOLD}[l]${NC} - Lock account (disable login)"
echo -e "  ${BOLD}[s]${NC} - Skip (white/black team account)"
echo -e "  ${BOLD}[Enter]${NC} - Leave as-is"
echo ""

for username in "${AUDIT_USERS[@]}"; do
    user_info=$(getent passwd "$username" 2>/dev/null) || continue
    uid=$(echo "$user_info" | cut -d: -f3)
    shell=$(echo "$user_info" | cut -d: -f7)
    user_groups=$(groups "$username" 2>/dev/null | cut -d: -f2 || echo "")

    # Check if Splunk service account
    is_splunk_svc=false
    for svc in "${SPLUNK_SERVICE_ACCOUNTS[@]}"; do
        if [[ "$username" == "$svc" ]]; then
            is_splunk_svc=true
            break
        fi
    done

    if $is_splunk_svc; then
        echo -e "${MAGENTA}[SPLUNK SERVICE] ${username}${NC} (UID:${uid} Shell:${shell}) - AUTO-SKIP"
        ACTIONS_TAKEN+=("AUTO-SKIPPED (Splunk service): ${username}")
        continue
    fi

    is_wheel=false
    if echo "$user_groups" | grep -qw "wheel"; then
        is_wheel=true
    fi

    if $is_wheel; then
        echo -ne "${RED}[WHEEL] ${username}${NC} (UID:${uid} Shell:${shell}): "
    else
        echo -ne "${GREEN}${username}${NC} (UID:${uid} Shell:${shell}): "
    fi

    read -r action </dev/tty

    case "$action" in
        p|P)
            echo -n "  Enter new password for ${username}: "
            read -rs new_pass </dev/tty
            echo ""
            echo "${username}:${new_pass}" | chpasswd
            echo -e "  ${GREEN}[+] Password changed for ${username}${NC}"
            ACTIONS_TAKEN+=("PASSWORD CHANGED: ${username}")
            ;;
        d|D)
            echo -n "  Are you SURE you want to delete ${username}? (yes/no): "
            read -r confirm </dev/tty
            if [[ "$confirm" == "yes" ]]; then
                pkill -u "$username" 2>/dev/null || true
                sleep 1
                userdel -r "$username" 2>/dev/null || userdel "$username" 2>/dev/null
                echo -e "  ${RED}[+] Deleted user ${username}${NC}"
                ACTIONS_TAKEN+=("DELETED: ${username}")
            else
                echo "  [*] Skipped deletion of ${username}"
            fi
            ;;
        l|L)
            usermod -L "$username"
            usermod -s /sbin/nologin "$username" 2>/dev/null || usermod -s /usr/sbin/nologin "$username" 2>/dev/null
            echo -e "  ${YELLOW}[+] Locked account ${username} and set shell to nologin${NC}"
            ACTIONS_TAKEN+=("LOCKED: ${username}")
            ;;
        s|S)
            echo -e "  ${CYAN}[*] Skipped (team account): ${username}${NC}"
            ACTIONS_TAKEN+=("SKIPPED (team): ${username}")
            ;;
        "")
            echo "  [*] Left as-is: ${username}"
            ;;
        *)
            echo "  [*] Unknown action, leaving as-is: ${username}"
            ;;
    esac
done

###############################################################################
# SUMMARY
###############################################################################
echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD} AUDIT SUMMARY${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""
if [[ ${#ACTIONS_TAKEN[@]} -gt 0 ]]; then
    echo "Actions taken:"
    for action in "${ACTIONS_TAKEN[@]}"; do
        echo "  [+] ${action}"
    done
else
    echo "  No actions taken."
fi
echo ""
echo "Full log saved to: ${LOGFILE}"
echo ""
echo "REMINDERS:"
echo "  - Splunk is NOT scored but is CRITICAL for monitoring"
echo "  - Verify Splunk Web is still accessible at https://172.20.242.20:8000"
echo "  - Do NOT delete the splunk service account"
echo "  - Ensure log forwarding from other VMs is still working"
echo -e "${BOLD}============================================================${NC}"
