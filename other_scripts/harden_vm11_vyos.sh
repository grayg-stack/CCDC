#!/bin/bash
# =============================================================================
# VM11 - VyOS Router Hardening Script
# MACCDC 2026 - PASTE INTO VyOS CONFIGURE MODE TERMINAL
# =============================================================================
#
# THESE ARE VyOS CLI COMMANDS, NOT BASH COMMANDS.
# Despite the .sh extension, this file is a reference of commands to paste
# into the VyOS configure-mode shell.
#
# HOW TO USE:
#   1. SSH into VyOS: ssh vyos@172.31.21.2 (or from internal nets)
#   2. Enter configure mode: configure
#   3. Paste sections one at a time
#   4. After each section: commit
#   5. When done: save
#
# NETWORK TOPOLOGY:
#   eth0 (external/scoring): 172.31.21.2/29
#   eth1 (Net1 to FW1):      172.16.101.1/24
#   eth2 (Net2 to FW2):      172.16.102.1/24
#
# DEFAULT CREDS: vyos:changeme
# =============================================================================


# =============================================================================
# SECTION 1: ENTER CONFIGURE MODE
# =============================================================================
# >>> PASTE THIS <<<

configure

# =============================================================================
# SECTION 2: CREDENTIAL CHANGES (DO THIS FIRST!)
# =============================================================================
# >>> PASTE THIS - CHANGE PASSWORDS BEFORE PASTING <<<

# Change the default vyos password IMMEDIATELY
set system login user vyos authentication plaintext-password NEW_PASSWORD_HERE

# Create backup admin account
set system login user blueteam authentication plaintext-password NEW_PASSWORD_HERE
set system login user blueteam level admin

commit

# =============================================================================
# SECTION 3: SYSTEM HARDENING
# =============================================================================
# >>> PASTE THIS <<<

# Set hostname (verify current hostname first with: show host name)
set system host-name VM11-VyOS-Router

# Set login banner
set system login banner pre-login "AUTHORIZED USE ONLY. All activity is monitored and recorded."

# Set timezone
set system time-zone America/New_York

# Configure NTP
set service ntp server 0.pool.ntp.org
set service ntp server 1.pool.ntp.org

# Configure syslog - log to local and optionally remote
set system syslog global facility all level info
set system syslog global facility protocols level debug

# Disable unused services (if they exist - errors are OK if not set)
delete service telnet
delete service dhcp-server
delete service tftp-server

commit

# =============================================================================
# SECTION 4: SSH HARDENING
# =============================================================================
# >>> PASTE THIS <<<

# SSH configuration - keep password auth (we need it for team access)
set service ssh port 22
set service ssh listen-address 0.0.0.0
delete service ssh disable-password-authentication

# SSH login restrictions - VyOS 1.4.x syntax
# Limit login attempts and timeouts
set service ssh client-keepalive-interval 120

commit

# =============================================================================
# SECTION 5: FIREWALL - PROTECT THE ROUTER (INPUT FILTER)
# =============================================================================
# This section protects the VyOS management plane (LOCAL zone).
# VyOS 1.4.x uses the newer firewall model.
# The Palo Altos handle zone-level filtering for LAN traffic.
# VyOS just needs to:
#   - Route traffic between Net1, Net2, and External
#   - Protect itself from unauthorized management access
#
# >>> PASTE THIS - VyOS 1.4.x (ROLLING/SAGITTA) SYNTAX <<<

# ---- INPUT FILTER: Traffic destined TO the router itself ----
set firewall ipv4 input filter default-action drop
set firewall ipv4 input filter default-log

# Rule 10: Accept established/related
set firewall ipv4 input filter rule 10 action accept
set firewall ipv4 input filter rule 10 state established
set firewall ipv4 input filter rule 10 state related
set firewall ipv4 input filter rule 10 description "Allow established and related"

# Rule 15: Accept ICMP (ping) - useful for diagnostics and scoring checks
set firewall ipv4 input filter rule 15 action accept
set firewall ipv4 input filter rule 15 protocol icmp
set firewall ipv4 input filter rule 15 description "Allow ICMP"

# Rule 20: Allow SSH from Net1 (Linux LAN transit)
set firewall ipv4 input filter rule 20 action accept
set firewall ipv4 input filter rule 20 protocol tcp
set firewall ipv4 input filter rule 20 destination port 22
set firewall ipv4 input filter rule 20 source address 172.16.101.0/24
set firewall ipv4 input filter rule 20 description "SSH from Net1"

# Rule 25: Allow SSH from Net2 (Windows LAN transit)
set firewall ipv4 input filter rule 25 action accept
set firewall ipv4 input filter rule 25 protocol tcp
set firewall ipv4 input filter rule 25 destination port 22
set firewall ipv4 input filter rule 25 source address 172.16.102.0/24
set firewall ipv4 input filter rule 25 description "SSH from Net2"

# Rule 30: Allow SSH from Linux LAN (through FW1)
set firewall ipv4 input filter rule 30 action accept
set firewall ipv4 input filter rule 30 protocol tcp
set firewall ipv4 input filter rule 30 destination port 22
set firewall ipv4 input filter rule 30 source address 172.20.242.0/24
set firewall ipv4 input filter rule 30 description "SSH from Linux LAN"

# Rule 35: Allow SSH from Windows LAN (through FW2)
set firewall ipv4 input filter rule 35 action accept
set firewall ipv4 input filter rule 35 protocol tcp
set firewall ipv4 input filter rule 35 destination port 22
set firewall ipv4 input filter rule 35 source address 172.20.240.0/24
set firewall ipv4 input filter rule 35 description "SSH from Windows LAN"

# Rule 40: Allow SSH from external/scoring (needed during competition)
set firewall ipv4 input filter rule 40 action accept
set firewall ipv4 input filter rule 40 protocol tcp
set firewall ipv4 input filter rule 40 destination port 22
set firewall ipv4 input filter rule 40 source address 172.31.21.0/29
set firewall ipv4 input filter rule 40 description "SSH from scoring subnet"

# Rule 50: Allow NTP responses to router
set firewall ipv4 input filter rule 50 action accept
set firewall ipv4 input filter rule 50 protocol udp
set firewall ipv4 input filter rule 50 source port 123
set firewall ipv4 input filter rule 50 description "NTP responses"

# Rule 60: Allow DNS responses to router
set firewall ipv4 input filter rule 60 action accept
set firewall ipv4 input filter rule 60 protocol udp
set firewall ipv4 input filter rule 60 source port 53
set firewall ipv4 input filter rule 60 description "DNS responses"

# Rule 999: Drop and log everything else (explicit - default already drops)
set firewall ipv4 input filter rule 999 action drop
set firewall ipv4 input filter rule 999 log
set firewall ipv4 input filter rule 999 description "Drop all other input"

commit

# ---- FORWARD FILTER: Traffic transiting THROUGH the router ----
# We must allow traffic through for scored services!
# The Palo Altos do the real filtering. VyOS just routes.

set firewall ipv4 forward filter default-action accept
set firewall ipv4 forward filter default-log
set firewall ipv4 forward filter rule 10 action accept
set firewall ipv4 forward filter rule 10 state established
set firewall ipv4 forward filter rule 10 state related
set firewall ipv4 forward filter rule 10 description "Allow established/related forward"

# Rule 999: Log everything else that gets forwarded (but still accept)
# We keep forward open because Palo Altos handle filtering
# If we drop here, scored services will break
set firewall ipv4 forward filter rule 999 action accept
set firewall ipv4 forward filter rule 999 log
set firewall ipv4 forward filter rule 999 description "Accept and log all forwarded traffic"

commit

# ---- OUTPUT FILTER: Traffic FROM the router ----
set firewall ipv4 output filter default-action accept
set firewall ipv4 output filter rule 10 action accept
set firewall ipv4 output filter rule 10 state established
set firewall ipv4 output filter rule 10 state related
set firewall ipv4 output filter rule 10 description "Allow established/related outbound"

commit

# =============================================================================
# SECTION 5-ALT: FIREWALL - VyOS 1.3.x (EQUULEUS) LEGACY SYNTAX
# =============================================================================
# >>> DO NOT PASTE - REFERENCE ONLY <<<
# If the 1.4.x syntax above fails, the router may be running 1.3.x.
# Use these commands instead:
#
# set firewall name WAN-LOCAL default-action drop
# set firewall name WAN-LOCAL rule 10 action accept
# set firewall name WAN-LOCAL rule 10 state established enable
# set firewall name WAN-LOCAL rule 10 state related enable
# set firewall name WAN-LOCAL rule 20 action accept
# set firewall name WAN-LOCAL rule 20 protocol tcp
# set firewall name WAN-LOCAL rule 20 destination port 22
# set firewall name WAN-LOCAL rule 20 source address 172.16.101.0/24
# set firewall name WAN-LOCAL rule 25 action accept
# set firewall name WAN-LOCAL rule 25 protocol tcp
# set firewall name WAN-LOCAL rule 25 destination port 22
# set firewall name WAN-LOCAL rule 25 source address 172.16.102.0/24
# set firewall name WAN-LOCAL rule 30 action accept
# set firewall name WAN-LOCAL rule 30 protocol icmp
# set firewall name WAN-LOCAL rule 40 action accept
# set firewall name WAN-LOCAL rule 40 protocol tcp
# set firewall name WAN-LOCAL rule 40 destination port 22
# set firewall name WAN-LOCAL rule 40 source address 172.31.21.0/29
#
# Apply to external interface (check interface name - might be eth0):
# set firewall interface eth0 local name WAN-LOCAL
#
# For transit traffic (keep open - Palo Altos filter):
# set firewall name TRANSIT default-action accept
# set firewall interface eth0 in name TRANSIT
#
# commit
# save

# =============================================================================
# SECTION 6: NAT VERIFICATION
# =============================================================================
# >>> DO NOT PASTE - REFERENCE ONLY <<<
# NAT rules should already exist to route external traffic to internal servers.
# VERIFY these exist before changing anything! Run in operational mode:
#
#   show nat destination rules
#   show nat source rules
#
# Expected DNAT rules (external IPs -> internal servers through firewalls):
# The scoring engine hits external IPs which must DNAT to internal servers.
# DO NOT DELETE ANY NAT RULES without understanding what they do!
#
# If NAT rules are missing, scored services will fail.
# Example DNAT syntax (DO NOT paste unless confirmed missing):
#
# set nat destination rule 10 inbound-interface name eth0
# set nat destination rule 10 destination address <EXTERNAL_VIP>
# set nat destination rule 10 protocol tcp
# set nat destination rule 10 destination port 80,443
# set nat destination rule 10 translation address 172.16.101.254
# ... (traffic goes to FW1 which then forwards to actual server)

# =============================================================================
# SECTION 7: ROUTING VERIFICATION
# =============================================================================
# >>> DO NOT PASTE - REFERENCE ONLY <<<
# Run these in operational mode to verify routing:
#
#   show ip route
#
# Expected routes:
#   172.31.21.0/29   - directly connected (eth0/external)
#   172.16.101.0/24  - directly connected (eth1/Net1)
#   172.16.102.0/24  - directly connected (eth2/Net2)
#   172.20.242.0/24  - via 172.16.101.254 (FW1 inside network)
#   172.20.240.0/24  - via 172.16.102.254 (FW2 inside network)
#   0.0.0.0/0        - default route (via scoring/internet gateway)
#
# If routes to 172.20.x.x subnets are missing, add them:
#   set protocols static route 172.20.242.0/24 next-hop 172.16.101.254
#   set protocols static route 172.20.240.0/24 next-hop 172.16.102.254

# =============================================================================
# SECTION 8: SAVE CONFIGURATION
# =============================================================================
# >>> PASTE THIS <<<

commit
save

# =============================================================================
# SECTION 9: VERIFICATION COMMANDS (RUN IN OPERATIONAL MODE)
# =============================================================================
# >>> EXIT CONFIGURE MODE FIRST: exit <<<

exit

show firewall
show firewall ipv4 input filter
show firewall ipv4 forward filter
show firewall ipv4 output filter
show interfaces
show ip route
show service ssh
show system login
show configuration commands | grep user
show nat destination rules
show nat source rules
show version
show system uptime

# =============================================================================
# EMERGENCY: IF FIREWALL LOCKS YOU OUT
# =============================================================================
# >>> DO NOT PASTE - REFERENCE ONLY <<<
# If the input filter locks you out, you need console access via NETLAB.
# From console:
#   configure
#   delete firewall ipv4 input filter
#   commit
#   save
# Then re-apply firewall rules carefully.
#
# =============================================================================
# INCIDENT RESPONSE: BLOCK A SPECIFIC MALICIOUS IP
# =============================================================================
# >>> MODIFY AND PASTE AS NEEDED <<<
# To block a confirmed malicious /32 IP (ONLY /32 per competition rules):
#
#   configure
#   set firewall ipv4 input filter rule 5 action drop
#   set firewall ipv4 input filter rule 5 source address X.X.X.X/32
#   set firewall ipv4 input filter rule 5 description "Block malicious IP"
#   set firewall ipv4 forward filter rule 5 action drop
#   set firewall ipv4 forward filter rule 5 source address X.X.X.X/32
#   set firewall ipv4 forward filter rule 5 description "Block malicious IP forward"
#   commit
#   save
# =============================================================================
