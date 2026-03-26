#!/bin/bash
###############################################################################
# audit_vm4_ubuntu_wks.sh
# MACCDC 2026 - VM4: Ubuntu Workstation (Ubuntu Desktop 24.04.3)
# IP: DHCP | NOT scored, cannot be retasked
#
# Interactive user audit for Ubuntu Workstation. Uses sudo group (Ubuntu).
#
# Usage: sudo ./audit_vm4_ubuntu_wks.sh
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
BOLD='\033[1m'
NC='\033[0m'

LOGDIR="/root/hardening_logs"
LOGFILE="${LOGDIR}/audit_vm4_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$LOGDIR"
chmod 700 "$LOGDIR"

exec > >(tee -a "$LOGFILE") 2>&1

ACTIONS_TAKEN=()

echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD} VM4 Ubuntu Workstation - Interactive User Audit${NC}"
echo -e "${BOLD} $(date)${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""
echo -e "${CYAN}[*] This is a WORKSTATION. NOT scored, cannot be retasked.${NC}"

###############################################################################
# SECTION 1: Display all users
###############################################################################
echo ""
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

    is_sudo=false
    if echo "$user_groups" | grep -qwE "sudo|wheel"; then
        is_sudo=true
    fi

    color=$GREEN
    tag=""
    if $is_sudo; then
        color=$RED
        tag=" [SUDO]"
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
echo -e "${BOLD}=== DOCKER GROUP MEMBERS (container escape risk) ===${NC}"
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
# SECTION 5: Desktop-specific checks
###############################################################################
echo -e "${BOLD}=== DESKTOP-SPECIFIC CHECKS ===${NC}"
echo ""

# Autostart entries (desktop persistence)
echo -e "${CYAN}--- Autostart entries ---${NC}"
for autostart_dir in /etc/xdg/autostart /home/*/.config/autostart /root/.config/autostart; do
    if [[ -d "$autostart_dir" ]]; then
        for desktop_file in "$autostart_dir"/*.desktop; do
            if [[ -f "$desktop_file" ]]; then
                echo -e "  ${YELLOW}${desktop_file}${NC}"
                grep -E "^(Name|Exec|Hidden)" "$desktop_file" 2>/dev/null | sed 's/^/    /'
            fi
        done
    fi
done
echo ""

# Snap packages (potential attack surface)
echo -e "${CYAN}--- Installed snap packages ---${NC}"
if command -v snap &>/dev/null; then
    snap list 2>/dev/null | sed 's/^/  /' || echo "  No snaps"
else
    echo "  snap not installed"
fi
echo ""

# Flatpak packages
echo -e "${CYAN}--- Installed flatpak packages ---${NC}"
if command -v flatpak &>/dev/null; then
    flatpak list 2>/dev/null | sed 's/^/  /' || echo "  No flatpaks"
else
    echo "  flatpak not installed"
fi
echo ""

# Browser extensions (common persistence)
echo -e "${CYAN}--- Browser profile directories ---${NC}"
find /home -maxdepth 4 -type d \( -name ".mozilla" -o -name ".config/google-chrome" -o -name ".config/chromium" \) 2>/dev/null | sed 's/^/  /'
echo ""

###############################################################################
# SECTION 6: Interactive user actions
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

    is_sudo=false
    if echo "$user_groups" | grep -qwE "sudo|wheel"; then
        is_sudo=true
    fi

    if $is_sudo; then
        echo -ne "${RED}[SUDO] ${username}${NC} (UID:${uid} Shell:${shell}): "
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
echo "  - This workstation is NOT scored and CANNOT be retasked"
echo "  - Keep it available for injects and team operations"
echo "  - Do NOT install services or change its role"
echo -e "${BOLD}============================================================${NC}"
