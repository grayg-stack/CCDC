#!/bin/bash
# ============================================================
# MACCDC 2026 - Linux Continuous Monitor
# Run in a tmux/screen session for persistent monitoring
# Usage: sudo bash 03-monitor.sh
# ============================================================

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
NC='\033[0m'

INTERVAL=30  # seconds between checks
LOGFILE="/root/monitor-$(hostname).log"

alert() {
    local msg="[$(date '+%H:%M:%S')] [ALERT] $1"
    echo -e "${RED}$msg${NC}"
    echo "$msg" >> "$LOGFILE"
}

info() {
    local msg="[$(date '+%H:%M:%S')] [INFO] $1"
    echo -e "${YEL}$msg${NC}"
    echo "$msg" >> "$LOGFILE"
}

ok() {
    echo -e "${GRN}[$(date '+%H:%M:%S')] [OK] $1${NC}"
}

# Capture initial state
info "Starting continuous monitor on $(hostname)..."
info "Logging to $LOGFILE"
info "Interval: ${INTERVAL}s"

# Baseline snapshots
BASELINE_USERS=$(cut -d: -f1 /etc/passwd | sort)
BASELINE_SHADOW=$(awk -F: '{print $1":"length($2)}' /etc/shadow 2>/dev/null | sort)
BASELINE_SUID=$(find / -perm -4000 -type f 2>/dev/null | sort)
BASELINE_CRON=$(for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u "$u" 2>/dev/null; done | sort)
BASELINE_PORTS=$(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | sort)
BASELINE_SSHD=$(md5sum /etc/ssh/sshd_config 2>/dev/null | awk '{print $1}')

check_cycle=0

while true; do
    check_cycle=$((check_cycle + 1))

    # --- Check for new/removed users ---
    CURRENT_USERS=$(cut -d: -f1 /etc/passwd | sort)
    NEW_USERS=$(comm -13 <(echo "$BASELINE_USERS") <(echo "$CURRENT_USERS"))
    DEL_USERS=$(comm -23 <(echo "$BASELINE_USERS") <(echo "$CURRENT_USERS"))
    [ -n "$NEW_USERS" ] && alert "NEW USER ACCOUNTS: $NEW_USERS"
    [ -n "$DEL_USERS" ] && alert "DELETED USER ACCOUNTS: $DEL_USERS"

    # --- Check for password changes (hash length changes) ---
    CURRENT_SHADOW=$(awk -F: '{print $1":"length($2)}' /etc/shadow 2>/dev/null | sort)
    SHADOW_DIFF=$(diff <(echo "$BASELINE_SHADOW") <(echo "$CURRENT_SHADOW"))
    [ -n "$SHADOW_DIFF" ] && alert "PASSWORD HASH CHANGES DETECTED:\n$SHADOW_DIFF"

    # --- Check for new SUID binaries ---
    CURRENT_SUID=$(find / -perm -4000 -type f 2>/dev/null | sort)
    NEW_SUID=$(comm -13 <(echo "$BASELINE_SUID") <(echo "$CURRENT_SUID"))
    [ -n "$NEW_SUID" ] && alert "NEW SUID BINARIES: $NEW_SUID"

    # --- Check for cron changes ---
    CURRENT_CRON=$(for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u "$u" 2>/dev/null; done | sort)
    [ "$CURRENT_CRON" != "$BASELINE_CRON" ] && alert "CRON JOBS CHANGED!"

    # --- Check for new listening ports ---
    CURRENT_PORTS=$(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | sort)
    NEW_PORTS=$(comm -13 <(echo "$BASELINE_PORTS") <(echo "$CURRENT_PORTS"))
    GONE_PORTS=$(comm -23 <(echo "$BASELINE_PORTS") <(echo "$CURRENT_PORTS"))
    [ -n "$NEW_PORTS" ] && alert "NEW LISTENING PORTS: $NEW_PORTS"
    [ -n "$GONE_PORTS" ] && alert "PORTS NO LONGER LISTENING: $GONE_PORTS (scored service may be down!)"

    # --- Check sshd_config changes ---
    CURRENT_SSHD=$(md5sum /etc/ssh/sshd_config 2>/dev/null | awk '{print $1}')
    [ "$CURRENT_SSHD" != "$BASELINE_SSHD" ] && alert "sshd_config HAS BEEN MODIFIED!"

    # --- Check for suspicious processes ---
    for pattern in "nc -l" "ncat -l" "/dev/tcp" "python.*socket" "bash -i" "perl -e" "socat" "meterpreter" "xmrig" "minerd"; do
        found=$(ps aux 2>/dev/null | grep -i "$pattern" | grep -v grep | grep -v monitor)
        [ -n "$found" ] && alert "SUSPICIOUS PROCESS [$pattern]: $found"
    done

    # --- Check for files in /tmp and /dev/shm ---
    SKETCHY_TMP=$(find /tmp /dev/shm -newer /root/monitor-*.log -type f 2>/dev/null | head -10)
    [ -n "$SKETCHY_TMP" ] && alert "NEW FILES in /tmp or /dev/shm:\n$SKETCHY_TMP"

    # --- Check for failed SSH logins (last 30 seconds) ---
    FAILED_SSH=$(journalctl -u sshd --since "${INTERVAL} seconds ago" --no-pager 2>/dev/null | grep -i "failed\|invalid" | tail -5)
    [ -z "$FAILED_SSH" ] && FAILED_SSH=$(grep -i "failed\|invalid" /var/log/auth.log 2>/dev/null | tail -5)
    [ -n "$FAILED_SSH" ] && alert "FAILED SSH ATTEMPTS:\n$FAILED_SSH"

    # --- Check scored service ports ---
    for port in 25 53 80 110 443 21 69 123; do
        if ! ss -tlnp 2>/dev/null | grep -q ":$port " && ! ss -ulnp 2>/dev/null | grep -q ":$port "; then
            alert "SCORED SERVICE PORT $port IS DOWN!"
        fi
    done

    # Status heartbeat every 10 cycles
    [ $((check_cycle % 10)) -eq 0 ] && ok "Monitor cycle $check_cycle - all checks passed at $(date '+%H:%M:%S')"

    # Update baselines for next cycle
    BASELINE_USERS="$CURRENT_USERS"
    BASELINE_SHADOW="$CURRENT_SHADOW"
    BASELINE_SUID="$CURRENT_SUID"
    BASELINE_CRON="$CURRENT_CRON"
    BASELINE_PORTS="$CURRENT_PORTS"
    BASELINE_SSHD="$CURRENT_SSHD"

    sleep "$INTERVAL"
done
