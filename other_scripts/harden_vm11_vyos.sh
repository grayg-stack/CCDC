#!/bin/vbash
# =============================================================================
# VM11 - VyOS Router Hardening Script
# MACCDC 2026 - Run directly on VyOS: bash harden_vm11_vyos.sh
# =============================================================================
#
# USAGE:
#   scp harden_vm11_vyos.sh vyos@172.31.21.2:~/
#   ssh vyos@172.31.21.2
#   bash harden_vm11_vyos.sh
#
# NETWORK TOPOLOGY:
#   eth0 (external/scoring): 172.31.21.2/29
#   eth1 (Net1 to FW1):      172.16.101.1/24
#   eth2 (Net2 to FW2):      172.16.102.1/24
# =============================================================================

source /opt/vyatta/etc/functions/script-template

# Bail on any unhandled error
set -e

# =============================================================================
# SECTION 0: PASSWORD PROMPT
# Get new passwords interactively before touching anything.
# =============================================================================
echo ""
echo "============================================================"
echo " VM11 VyOS Hardening — MACCDC 2026"
echo "============================================================"
echo ""
echo "[*] Enter new password for the 'vyos' account:"
read -s VYOS_PASS
echo "[*] Confirm password:"
read -s VYOS_PASS2
if [ "$VYOS_PASS" != "$VYOS_PASS2" ]; then
    echo "[!] Passwords do not match. Aborting."
    exit 1
fi
if [ -z "$VYOS_PASS" ]; then
    echo "[!] Password cannot be empty. Aborting."
    exit 1
fi

echo ""
echo "[*] Enter password for backup 'blueteam' admin account:"
read -s BT_PASS
echo "[*] Confirm password:"
read -s BT_PASS2
if [ "$BT_PASS" != "$BT_PASS2" ]; then
    echo "[!] Passwords do not match. Aborting."
    exit 1
fi
if [ -z "$BT_PASS" ]; then
    echo "[!] Password cannot be empty. Aborting."
    exit 1
fi

echo ""
echo "[*] Passwords accepted. Starting hardening..."
echo ""

# =============================================================================
# All configuration happens inside a single configure session.
# =============================================================================
configure

# =============================================================================
# SECTION 1: CREDENTIALS (DO THIS FIRST)
# =============================================================================
echo "[1/7] Rotating credentials..."

set system login user vyos authentication plaintext-password "$VYOS_PASS"

set system login user blueteam authentication plaintext-password "$BT_PASS"
set system login user blueteam level admin

commit
echo "    [+] Passwords updated."

# =============================================================================
# SECTION 2: SYSTEM HARDENING
# =============================================================================
echo "[2/7] System hardening..."

set system host-name VM11-VyOS-Router

set system login banner pre-login "AUTHORIZED USE ONLY. All activity is monitored and recorded."

set system time-zone America/New_York

set service ntp server 0.pool.ntp.org
set service ntp server 1.pool.ntp.org

set system syslog global facility all level info
set system syslog global facility protocols level debug

# Delete unused services — errors here are fine if they weren't set
delete service telnet    2>/dev/null || true
delete service dhcp-server  2>/dev/null || true
delete service tftp-server  2>/dev/null || true

commit
echo "    [+] System hardened."

# =============================================================================
# SECTION 3: SSH HARDENING
# =============================================================================
echo "[3/7] SSH hardening..."

set service ssh port 22
set service ssh listen-address 0.0.0.0
delete service ssh disable-password-authentication 2>/dev/null || true
set service ssh client-keepalive-interval 120

commit
echo "    [+] SSH hardened."

# =============================================================================
# SECTION 4: FIREWALL — INPUT FILTER (protect the router itself)
# =============================================================================
echo "[4/7] Applying input filter (protect management plane)..."

set firewall ipv4 input filter default-action drop
set firewall ipv4 input filter default-log

# Allow established/related
set firewall ipv4 input filter rule 10 action accept
set firewall ipv4 input filter rule 10 state established
set firewall ipv4 input filter rule 10 state related
set firewall ipv4 input filter rule 10 description "Allow established and related"

# Allow ICMP
set firewall ipv4 input filter rule 15 action accept
set firewall ipv4 input filter rule 15 protocol icmp
set firewall ipv4 input filter rule 15 description "Allow ICMP"

# SSH from Net1 transit segment (172.16.101.0/24)
set firewall ipv4 input filter rule 20 action accept
set firewall ipv4 input filter rule 20 protocol tcp
set firewall ipv4 input filter rule 20 destination port 22
set firewall ipv4 input filter rule 20 source address 172.16.101.0/24
set firewall ipv4 input filter rule 20 description "SSH from Net1"

# SSH from Net2 transit segment (172.16.102.0/24)
set firewall ipv4 input filter rule 25 action accept
set firewall ipv4 input filter rule 25 protocol tcp
set firewall ipv4 input filter rule 25 destination port 22
set firewall ipv4 input filter rule 25 source address 172.16.102.0/24
set firewall ipv4 input filter rule 25 description "SSH from Net2"

# SSH from Linux server LAN (behind FW1)
set firewall ipv4 input filter rule 30 action accept
set firewall ipv4 input filter rule 30 protocol tcp
set firewall ipv4 input filter rule 30 destination port 22
set firewall ipv4 input filter rule 30 source address 172.20.242.0/24
set firewall ipv4 input filter rule 30 description "SSH from Linux LAN"

# SSH from Windows server LAN (behind FW2)
set firewall ipv4 input filter rule 35 action accept
set firewall ipv4 input filter rule 35 protocol tcp
set firewall ipv4 input filter rule 35 destination port 22
set firewall ipv4 input filter rule 35 source address 172.20.240.0/24
set firewall ipv4 input filter rule 35 description "SSH from Windows LAN"

# SSH from scoring/external subnet
set firewall ipv4 input filter rule 40 action accept
set firewall ipv4 input filter rule 40 protocol tcp
set firewall ipv4 input filter rule 40 destination port 22
set firewall ipv4 input filter rule 40 source address 172.31.21.0/29
set firewall ipv4 input filter rule 40 description "SSH from scoring subnet"

# NTP responses
set firewall ipv4 input filter rule 50 action accept
set firewall ipv4 input filter rule 50 protocol udp
set firewall ipv4 input filter rule 50 source port 123
set firewall ipv4 input filter rule 50 description "NTP responses"

# DNS responses
set firewall ipv4 input filter rule 60 action accept
set firewall ipv4 input filter rule 60 protocol udp
set firewall ipv4 input filter rule 60 source port 53
set firewall ipv4 input filter rule 60 description "DNS responses"

# Explicit drop + log everything else
set firewall ipv4 input filter rule 999 action drop
set firewall ipv4 input filter rule 999 log
set firewall ipv4 input filter rule 999 description "Drop all other input"

commit
echo "    [+] Input filter applied."

# =============================================================================
# SECTION 5: FIREWALL — FORWARD FILTER (transit traffic through router)
# Keep open — Palo Altos handle zone filtering. Dropping here breaks scoring.
# =============================================================================
echo "[5/7] Applying forward filter (transit — keep open for scoring)..."

set firewall ipv4 forward filter default-action accept
set firewall ipv4 forward filter default-log

set firewall ipv4 forward filter rule 10 action accept
set firewall ipv4 forward filter rule 10 state established
set firewall ipv4 forward filter rule 10 state related
set firewall ipv4 forward filter rule 10 description "Allow established/related forward"

set firewall ipv4 forward filter rule 999 action accept
set firewall ipv4 forward filter rule 999 log
set firewall ipv4 forward filter rule 999 description "Accept and log all forwarded traffic"

commit
echo "    [+] Forward filter applied."

# =============================================================================
# SECTION 6: FIREWALL — OUTPUT FILTER (traffic originating FROM router)
# =============================================================================
echo "[6/7] Applying output filter..."

set firewall ipv4 output filter default-action accept

set firewall ipv4 output filter rule 10 action accept
set firewall ipv4 output filter rule 10 state established
set firewall ipv4 output filter rule 10 state related
set firewall ipv4 output filter rule 10 description "Allow established/related outbound"

commit
echo "    [+] Output filter applied."

# =============================================================================
# SECTION 7: SAVE
# =============================================================================
echo "[7/7] Saving configuration..."
save
echo "    [+] Configuration saved."

exit  # exit configure mode

# =============================================================================
# POST-HARDENING VERIFICATION (op-mode)
# =============================================================================
echo ""
echo "============================================================"
echo " Hardening complete. Running verification checks..."
echo "============================================================"
echo ""

echo "--- INTERFACES ---"
show interfaces

echo ""
echo "--- ROUTING TABLE ---"
show ip route

echo ""
echo "--- FIREWALL INPUT FILTER ---"
show firewall ipv4 input filter

echo ""
echo "--- FIREWALL FORWARD FILTER ---"
show firewall ipv4 forward filter

echo ""
echo "--- SSH SERVICE ---"
show service ssh

echo ""
echo "--- SYSTEM LOGIN USERS ---"
show system login

echo ""
echo "--- NAT SOURCE RULES ---"
show nat source rules

echo ""
echo "--- NAT DESTINATION RULES ---"
show nat destination rules

echo ""
echo "============================================================"
echo " All done. Verify the above output looks correct."
echo ""
echo " EMERGENCY — if input filter locks you out:"
echo "   Use NETLAB console access, then:"
echo "   configure"
echo "   delete firewall ipv4 input filter"
echo "   commit && save"
echo ""
echo " BLOCK A RED TEAM IP (run manually):"
echo "   configure"
echo "   set firewall ipv4 input filter rule 5 action drop"
echo "   set firewall ipv4 input filter rule 5 source address X.X.X.X/32"
echo "   set firewall ipv4 forward filter rule 5 action drop"
echo "   set firewall ipv4 forward filter rule 5 source address X.X.X.X/32"
echo "   commit && save"
echo "============================================================"