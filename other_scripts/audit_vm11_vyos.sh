#!/bin/bash
# =============================================================================
# VM11 - VyOS Router AUDIT Script
# MACCDC 2026 - PASTE INTO VyOS OPERATIONAL MODE TERMINAL
# =============================================================================
#
# THESE ARE VyOS OPERATIONAL MODE COMMANDS, NOT BASH COMMANDS.
# Paste these into the VyOS CLI (NOT configure mode).
# Run these periodically to check for unauthorized changes.
#
# HOW TO USE:
#   1. SSH into VyOS: ssh vyos@172.31.21.2
#   2. You should be in operational mode ($ prompt, not # prompt)
#   3. Paste sections one at a time and review output
#
# NETWORK TOPOLOGY:
#   eth0 (external/scoring): 172.31.21.2/29
#   eth1 (Net1 to FW1):      172.16.101.1/24
#   eth2 (Net2 to FW2):      172.16.102.1/24
# =============================================================================


# =============================================================================
# SECTION 1: SYSTEM STATUS
# =============================================================================
# >>> PASTE THIS <<<

show version
show system uptime
show system memory
show system cpu

# =============================================================================
# SECTION 2: USER ACCOUNT AUDIT (CHECK FOR UNAUTHORIZED USERS)
# =============================================================================
# >>> PASTE THIS <<<
# EXPECTED USERS: vyos, blueteam (and any team-created accounts)
# FLAG anything else as suspicious!

show system login
show configuration commands | grep user
show configuration commands | grep authentication

# =============================================================================
# SECTION 3: INTERFACE AUDIT
# =============================================================================
# >>> PASTE THIS <<<
# VERIFY:
#   eth0: 172.31.21.2/29  (external/scoring)
#   eth1: 172.16.101.1/24 (Net1 to FW1)
#   eth2: 172.16.102.1/24 (Net2 to FW2)
# FLAG any extra interfaces, changed IPs, or interfaces in DOWN state

show interfaces
show interfaces ethernet detail

# =============================================================================
# SECTION 4: ROUTING TABLE AUDIT
# =============================================================================
# >>> PASTE THIS <<<
# EXPECTED ROUTES:
#   172.31.21.0/29   - directly connected (eth0)
#   172.16.101.0/24  - directly connected (eth1)
#   172.16.102.0/24  - directly connected (eth2)
#   172.20.242.0/24  - via 172.16.101.254 (static to FW1 inside)
#   172.20.240.0/24  - via 172.16.102.254 (static to FW2 inside)
#   0.0.0.0/0        - default route
# FLAG any unexpected routes (could indicate route injection attack)

show ip route
show ip route summary
show configuration commands | grep route

# =============================================================================
# SECTION 5: FIREWALL AUDIT
# =============================================================================
# >>> PASTE THIS <<<

show firewall
show firewall summary
show firewall statistics

# VyOS 1.4.x specific
show firewall ipv4 input filter
show firewall ipv4 forward filter
show firewall ipv4 output filter

# VyOS 1.3.x fallback
show firewall name WAN-LOCAL
show firewall name TRANSIT

# Check full firewall config
show configuration commands | grep firewall

# =============================================================================
# SECTION 6: NAT RULES AUDIT (CRITICAL FOR SCORED SERVICES)
# =============================================================================
# >>> PASTE THIS <<<
# NAT rules route external traffic to internal servers.
# If these are deleted or changed, scored services WILL FAIL.

show nat destination rules
show nat source rules
show configuration commands | grep nat

# =============================================================================
# SECTION 7: SSH SERVICE AUDIT
# =============================================================================
# >>> PASTE THIS <<<

show service ssh
show configuration commands | grep ssh

# =============================================================================
# SECTION 8: ACTIVE CONNECTIONS & TRAFFIC
# =============================================================================
# >>> PASTE THIS <<<
# Look for suspicious connections - unexpected source IPs, weird ports

show conntrack table ipv4
show conntrack table ipv4 | head 50

# =============================================================================
# SECTION 9: RECENT LOGS
# =============================================================================
# >>> PASTE THIS <<<
# Look for login attempts, config changes, errors

show log | tail 100
show log | grep -i "login"
show log | grep -i "commit"
show log | grep -i "error"
show log | grep -i "fail"

# =============================================================================
# SECTION 10: SERVICE AUDIT
# =============================================================================
# >>> PASTE THIS <<<
# Check for unauthorized services running

show configuration commands | grep service
show configuration commands | grep server

# =============================================================================
# SECTION 11: CONFIGURATION DIFF (CHECK FOR UNAUTHORIZED CHANGES)
# =============================================================================
# >>> PASTE THIS <<<
# Compare running config against saved config

compare saved

# Show recent config commits
show system commit

# =============================================================================
# SECTION 12: CONNECTIVITY TESTS TO SCORED SERVICES
# =============================================================================
# >>> PASTE THIS <<<
# Quick connectivity check to make sure routing works
# These pings go through the firewalls to the internal servers

# Ping FW1 outside interface
ping 172.16.101.254 count 2

# Ping FW2 outside interface
ping 172.16.102.254 count 2

# Ping FW1 inside interface (may or may not respond depending on PAN policy)
ping 172.20.242.254 count 2

# Ping FW2 inside interface
ping 172.20.240.254 count 2

# Ping scored services through FW1 (Linux zone)
ping 172.20.242.20 count 2
ping 172.20.242.30 count 2
ping 172.20.242.40 count 2

# Ping scored services through FW2 (Windows zone)
ping 172.20.240.101 count 2
ping 172.20.240.102 count 2
ping 172.20.240.104 count 2

# =============================================================================
# SECTION 13: FULL CONFIG DUMP (FOR BACKUP/COMPARISON)
# =============================================================================
# >>> PASTE THIS (SAVE OUTPUT FOR LATER COMPARISON) <<<

show configuration
show configuration commands

# =============================================================================
# QUICK REFERENCE: WHAT TO FLAG AS SUSPICIOUS
# =============================================================================
# >>> DO NOT PASTE - REFERENCE ONLY <<<
#
# 1. Unknown user accounts (anything besides vyos, blueteam, team accounts)
# 2. Changed IP addresses on any interface
# 3. Missing or modified static routes
# 4. Missing or modified NAT rules (will break scored services!)
# 5. New or modified firewall rules you didn't create
# 6. Unauthorized services enabled (DHCP, TFTP, DNS forwarding)
# 7. Connections from unexpected source IPs in conntrack table
# 8. SSH config changes (new keys, changed listen address)
# 9. Any config diff between running and saved
# 10. Routes to unexpected networks (potential pivot/tunnel)
#
# IF YOU FIND SOMETHING SUSPICIOUS:
#   1. Screenshot/document it
#   2. Report to team lead
#   3. If it's a rouge user: delete system login user <name>
#   4. If it's a bad route: delete protocols static route <route>
#   5. If it's a bad firewall rule: delete firewall ... rule <N>
#   6. commit && save after any fix
# =============================================================================
