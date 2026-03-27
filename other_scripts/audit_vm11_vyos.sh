#!/bin/vbash
# =============================================================================
# VM11 - VyOS Router AUDIT Script
# MACCDC 2026 - Run directly on VyOS: bash audit_vm11_vyos.sh
# =============================================================================
#
# USAGE:
#   bash audit_vm11_vyos.sh              # print to terminal
#   bash audit_vm11_vyos.sh | tee audit_$(date +%H%M).txt  # save timestamped copy
#
# NETWORK TOPOLOGY:
#   eth0 (external/scoring): 172.31.21.2/29
#   eth1 (Net1 to FW1):      172.16.101.1/24
#   eth2 (Net2 to FW2):      172.16.102.1/24
#
# EXPECTED USERS: vyos, blueteam (anything else = flag it)
# =============================================================================

source /opt/vyatta/etc/functions/script-template

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Helper: print a clearly visible section banner
section() {
    echo ""
    echo "################################################################"
    echo "# $1"
    echo "################################################################"
}

# Helper: run a show command and label it
run() {
    echo ""
    echo ">>> $*"
    "$@" 2>&1 || echo "    [command returned error or not available]"
}

echo "============================================================"
echo " VM11 VyOS AUDIT — MACCDC 2026"
echo " Run at: $TIMESTAMP"
echo "============================================================"

# =============================================================================
# SECTION 1: SYSTEM STATUS
# =============================================================================
section "1 — SYSTEM STATUS"

run show version
run show system uptime

# =============================================================================
# SECTION 2: USER ACCOUNT AUDIT
# FLAG: anything besides vyos and blueteam
# =============================================================================
section "2 — USER ACCOUNT AUDIT"
echo "  EXPECTED: vyos, blueteam only. Flag anything else."

run show system login

# Pull user lines directly from config — more reliable than show system login
echo ""
echo ">>> show configuration commands | grep 'login user'"
cli-shell-api showConfig | grep 'login user' 2>/dev/null || \
    /bin/cli-shell-api showCfg 2>/dev/null | grep 'login user' || \
    echo "    [could not retrieve config — try manually: show configuration commands | grep user]"

# =============================================================================
# SECTION 3: INTERFACE AUDIT
# FLAG: wrong IPs, extra interfaces, any interface DOWN
# =============================================================================
section "3 — INTERFACE AUDIT"
echo "  EXPECTED:"
echo "    eth0: 172.31.21.2/29  (external/scoring)"
echo "    eth1: 172.16.101.1/24 (Net1 to FW1)"
echo "    eth2: 172.16.102.1/24 (Net2 to FW2)"

run show interfaces
run show interfaces ethernet detail

# =============================================================================
# SECTION 4: ROUTING TABLE AUDIT
# FLAG: unexpected routes (could be route injection)
# =============================================================================
section "4 — ROUTING TABLE AUDIT"
echo "  EXPECTED ROUTES:"
echo "    0.0.0.0/0        - default (via scoring gateway)"
echo "    172.31.21.0/29   - directly connected, eth0"
echo "    172.16.101.0/24  - directly connected, eth1"
echo "    172.16.102.0/24  - directly connected, eth2"
echo "    172.20.242.0/24  - via 172.16.101.254 (FW1 inside)"
echo "    172.20.240.0/24  - via 172.16.102.254 (FW2 inside)"

run show ip route
run show ip route summary

# =============================================================================
# SECTION 5: FIREWALL AUDIT
# FLAG: missing rules, unexpected allow-all, modified defaults
# =============================================================================
section "5 — FIREWALL AUDIT"

run show firewall
run show firewall summary
run show firewall statistics
run show firewall ipv4 input filter
run show firewall ipv4 forward filter
run show firewall ipv4 output filter

# =============================================================================
# SECTION 6: NAT RULES AUDIT
# FLAG: missing or modified rules — will break scored services
# =============================================================================
section "6 — NAT RULES AUDIT (CRITICAL — missing rules = service failure)"

run show nat source rules
run show nat destination rules

# =============================================================================
# SECTION 7: SSH SERVICE AUDIT
# FLAG: unexpected listen addresses, auth changes
# =============================================================================
section "7 — SSH SERVICE AUDIT"

run show service ssh

# =============================================================================
# SECTION 8: ACTIVE CONNECTIONS (conntrack)
# FLAG: unexpected source IPs, high session counts, unusual ports
# =============================================================================
section "8 — ACTIVE CONNECTIONS"
echo "  FLAG: unknown source IPs, large session counts, C2 ports (4444, 1234, 8080, 9001)"

run show conntrack table ipv4

# =============================================================================
# SECTION 9: RECENT LOGS
# FLAG: login attempts, config commits you didn't make, errors
# =============================================================================
section "9 — RECENT LOGS (last 100 lines)"

run show log

echo ""
echo ">>> show log | grep -i login"
show log 2>/dev/null | grep -i "login" || echo "    [none]"

echo ""
echo ">>> show log | grep -i commit"
show log 2>/dev/null | grep -i "commit" || echo "    [none]"

echo ""
echo ">>> show log | grep -i 'authentication failure\|failed\|invalid user'"
show log 2>/dev/null | grep -iE "authentication failure|failed|invalid user" || echo "    [none]"

# =============================================================================
# SECTION 10: SERVICE AUDIT
# FLAG: telnet, dhcp-server, tftp-server, or any service you didn't enable
# =============================================================================
section "10 — SERVICE AUDIT"
echo "  FLAG: telnet, dhcp-server, tftp-server, or unexpected services"

run show configuration commands

# =============================================================================
# SECTION 11: CONFIG DIFF (unauthorized changes since last save)
# =============================================================================
section "11 — CONFIG DIFF (running vs saved)"
echo "  If output is empty = no uncommitted changes."
echo "  Any diff here = something changed without being saved (or attacker modified)"

# compare saved must be run from within configure context
configure
echo ""
echo ">>> compare saved"
compare saved 2>&1 || echo "    [no diff or compare not available]"
exit  # back to op mode

run show system commit

# =============================================================================
# SECTION 12: CONNECTIVITY TESTS
# FLAG: any ping that should succeed returning 0% success
# =============================================================================
section "12 — CONNECTIVITY TESTS TO SCORED SERVICES"
echo "  NOTE: FW/server pings may fail if PAN policy blocks ICMP — that's OK."
echo "  Router-to-firewall outside interface pings SHOULD succeed."

# FW outside interfaces (should always respond)
run ping 172.16.101.254 count 3
run ping 172.16.102.254 count 3

# FW inside interfaces (depends on PAN policy)
run ping 172.20.242.254 count 2
run ping 172.20.240.254 count 2

# Linux zone servers (VM1, VM2, VM3)
run ping 172.20.242.30  count 2
run ping 172.20.242.40  count 2
run ping 172.20.242.20  count 2

# Windows zone servers (VM5, VM6, VM7)
run ping 172.20.240.102 count 2
run ping 172.20.240.101 count 2
run ping 172.20.240.104 count 2

# =============================================================================
# SECTION 13: FULL CONFIG DUMP (save this output for comparison later)
# =============================================================================
section "13 — FULL CONFIG DUMP (save this for later diff)"

run show configuration

# =============================================================================
# SUMMARY / WHAT TO FLAG
# =============================================================================
echo ""
echo "============================================================"
echo " AUDIT COMPLETE — $TIMESTAMP"
echo "============================================================"
echo ""
echo " WHAT TO FLAG AS SUSPICIOUS:"
echo "   1. Unknown users (expected: vyos, blueteam only)"
echo "   2. Changed interface IPs"
echo "   3. Missing or unexpected static routes"
echo "   4. Missing/modified NAT rules (scored services will break!)"
echo "   5. New or modified firewall rules"
echo "   6. Unexpected services (telnet, dhcp, tftp)"
echo "   7. Suspicious conntrack entries (unknown IPs, C2 ports)"
echo "   8. SSH config changes"
echo "   9. Config diff output — any diff = unauthorized change"
echo "  10. Routes to unexpected networks (pivot/tunnel indicator)"
echo ""
echo " IF YOU FIND SOMETHING — fix it:"
echo "   Rogue user:   configure; delete system login user <name>; commit; save"
echo "   Bad route:    configure; delete protocols static route <prefix>; commit; save"
echo "   Bad FW rule:  configure; delete firewall ipv4 input filter rule <N>; commit; save"
echo ""
echo " BLOCK A RED TEAM IP:"
echo "   configure"
echo "   set firewall ipv4 input filter rule 5 action drop"
echo "   set firewall ipv4 input filter rule 5 source address X.X.X.X/32"
echo "   set firewall ipv4 forward filter rule 5 action drop"
echo "   set firewall ipv4 forward filter rule 5 source address X.X.X.X/32"
echo "   commit && save"
echo "============================================================"