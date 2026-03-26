#!/usr/bin/env bash
# =============================================================================
# MACCDC 2026 — Palo Alto Device Hardening Script (Team 5)
# Run on BOTH firewalls after their respective config scripts
# =============================================================================
# Linux FW  (VM9):   ssh admin@172.20.242.150  → maccdc2026_panos_linux.sh
# Windows FW (VM10): ssh admin@172.20.240.200  → maccdc2026_panos_windows.sh
# Default creds: admin:Changeme123 — CHANGE IMMEDIATELY
# =============================================================================
# SAFE FOR BOTH FIREWALLS:
#   This script only modifies deviceconfig and mgt-config (management plane).
#   It NEVER touches rulebase security rules, service objects, or open ports.
#   The only two lines that differ per firewall are permitted-ip and hostname
#   — both are clearly marked below with the correct value for each FW.
# =============================================================================
# Covers:
#   1. Audit existing accounts and sessions (do this FIRST)
#   2. Management plane lockdown
#   3. Password and lockout policy
#   4. SSH hardening
#   5. Threat prevention profiles (if licensed)
#   6. Signature updates (operational mode)
#   7. Logging hardening
#   8. Verification commands
#
# Sections marked [CONFIGURE MODE] run inside: configure
# Sections marked [OPERATIONAL MODE] run at the base prompt (not configure)
# =============================================================================

# =============================================================================
# STEP 0 — AUDIT FIRST (OPERATIONAL MODE)
# =============================================================================
# Before touching anything, see what's already there.
# Run these at the base prompt BEFORE entering configure mode.
#
# Who is currently logged into the device?
#   show admins
#
# What admin accounts exist?
#   show config running | match "users"
#   show config running | match "admin"
#
# Any active sessions to/from unexpected IPs?
#   show session all
#
# Check software version:
#   show system info
#
# Check whether threat prevention is licensed:
#   show system info | match threat
#   show license
#
# Check current management access services:
#   show system services

# =============================================================================
# STEP 1 — MANAGEMENT PLANE LOCKDOWN (CONFIGURE MODE)
# =============================================================================
# Enter configure mode first:  configure

# Disable insecure/unused management protocols
set deviceconfig system service disable-http yes
set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-snmp yes

# Keep HTTPS and SSH enabled (needed for access)
set deviceconfig system service disable-https no
set deviceconfig system service disable-ssh no

# Disable unused features that add attack surface
set deviceconfig setting config rematch yes

# Permit management from the inside network — PASTE THE CORRECT LINE:
#   Linux FW  (172.20.242.150):
set deviceconfig system permitted-ip 172.20.242.0/24
#   Windows FW (172.20.240.200):
# set deviceconfig system permitted-ip 172.20.240.0/24

# Set device hostname — PASTE THE CORRECT LINE:
#   Linux FW  (172.20.242.150):
set deviceconfig system hostname PA-FW-LINUX-T05
#   Windows FW (172.20.240.200):
# set deviceconfig system hostname PA-FW-WIN-T05

# Set DNS (needed for updates and logging)
set deviceconfig system dns-setting servers primary 8.8.8.8
set deviceconfig system dns-setting servers secondary 8.8.4.4

# Set NTP servers (time integrity matters for log correlation)
set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 0.pool.ntp.org
set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address 1.pool.ntp.org

# Login banner — signals unauthorized access clearly for incident report purposes
set deviceconfig system login-banner "AUTHORIZED USE ONLY. All activity is monitored and logged."

# Idle session timeout in minutes (kick idle CLI sessions)
set deviceconfig setting management idle-timeout 10

# Disable IPv6 on the management interface
set deviceconfig system ipv6-enable no

# =============================================================================
# STEP 1b — DENY ALL IPv6 ON DATA PLANE (CONFIGURE MODE)
# =============================================================================
# Block IPv6 traffic across all zones via a top-of-rulebase deny rule.
# PAN-OS will still process the packet but drop it before any zone rules fire.

set rulebase security rules RULE-00_DENY-IPv6 from any
set rulebase security rules RULE-00_DENY-IPv6 to any
set rulebase security rules RULE-00_DENY-IPv6 source any
set rulebase security rules RULE-00_DENY-IPv6 destination any
set rulebase security rules RULE-00_DENY-IPv6 application ipv6
set rulebase security rules RULE-00_DENY-IPv6 service any
set rulebase security rules RULE-00_DENY-IPv6 action deny
set rulebase security rules RULE-00_DENY-IPv6 log-end yes
move rulebase security rules RULE-00_DENY-IPv6 top

# =============================================================================
# STEP 2 — ADMIN ACCOUNT HARDENING (CONFIGURE MODE)
# =============================================================================

# Create a password profile with lockout and complexity requirements
set mgt-config password-profile HARDENED-PROFILE failed-attempts 5
set mgt-config password-profile HARDENED-PROFILE lockout-time 10
set mgt-config password-profile HARDENED-PROFILE minimum-length 14
set mgt-config password-profile HARDENED-PROFILE minimum-uppercase-letters 1
set mgt-config password-profile HARDENED-PROFILE minimum-lowercase-letters 1
set mgt-config password-profile HARDENED-PROFILE minimum-numeric-letters 1
set mgt-config password-profile HARDENED-PROFILE minimum-special-characters 1

# Apply the profile to admin and set a per-user idle timeout
set mgt-config users admin password-profile HARDENED-PROFILE
set mgt-config users admin timeout 10

# Change the admin password (you will be prompted):
#   set mgt-config users admin password
#
# *** ALSO SUBMIT A SUPPORT TICKET IF ADMIN IS A SCORED SERVICE ACCOUNT ***

# Remove any accounts you don't recognize (check output of: show admins first)
# delete mgt-config users <UNKNOWN-ACCOUNT>

# If you need a second team admin account (recommended — in case admin is locked out):
# set mgt-config users team-admin permissions role-based superuser yes
# set mgt-config users team-admin password
# set mgt-config users team-admin password-profile HARDENED-PROFILE

# =============================================================================
# STEP 3 — SSH HARDENING (CONFIGURE MODE)
# =============================================================================
# Restrict to strong ciphers, MACs, and key exchange algorithms.
# Drops legacy weak crypto that red team tools love.

# Strong ciphers only (AES-GCM)
set deviceconfig setting ssh ciphersuites ciphers aes256-gcm@openssh.com
set deviceconfig setting ssh ciphersuites ciphers aes128-gcm@openssh.com

# Strong MACs only (SHA-2)
set deviceconfig setting ssh ciphersuites macs hmac-sha2-256
set deviceconfig setting ssh ciphersuites macs hmac-sha2-512

# Strong key exchange only (ECDH / DH group 14+)
set deviceconfig setting ssh ciphersuites kex-algos ecdh-sha2-nistp256
set deviceconfig setting ssh ciphersuites kex-algos ecdh-sha2-nistp384
set deviceconfig setting ssh ciphersuites kex-algos ecdh-sha2-nistp521
set deviceconfig setting ssh ciphersuites kex-algos diffie-hellman-group14-sha256

# SSH regenerate host keys (in case they were pre-provisioned/shared):
# In operational mode:
#   request ssh regenerate-hostkeys

# =============================================================================
# STEP 4 — THREAT PREVENTION PROFILES (CONFIGURE MODE, if licensed)
# =============================================================================
# Check license first (operational mode):  show license | match threat
#
# If licensed, create strict profiles and attach to all inbound rules.

# --- Anti-Spyware: block C2 beaconing at the DNS layer ---
# set profiles spyware STRICT-SPYWARE botnet-domains sinkhole yes
# set profiles spyware STRICT-SPYWARE botnet-domains dns-security-categories pan-dns-sec-cc action sinkhole
# set profiles spyware STRICT-SPYWARE botnet-domains dns-security-categories pan-dns-sec-malware action sinkhole
# set profiles spyware STRICT-SPYWARE rules simple-critical action block-ip track-by attacker duration 300
# set profiles spyware STRICT-SPYWARE rules simple-high action block-ip track-by attacker duration 300
# set profiles spyware STRICT-SPYWARE rules simple-medium action alert
# set profiles spyware STRICT-SPYWARE rules simple-low action alert

# --- Vulnerability Protection: block exploits ---
# set profiles vulnerability STRICT-VP rules brute-force action block-ip track-by attacker-and-victim duration 300
# set profiles vulnerability STRICT-VP rules simple-client-critical action reset-both
# set profiles vulnerability STRICT-VP rules simple-client-high action reset-both
# set profiles vulnerability STRICT-VP rules simple-server-critical action reset-both
# set profiles vulnerability STRICT-VP rules simple-server-high action reset-both

# --- Anti-Virus ---
# set profiles virus STRICT-AV decoder ftp action reset-both
# set profiles virus STRICT-AV decoder http action reset-both
# set profiles virus STRICT-AV decoder smtp action reset-both
# set profiles virus STRICT-AV decoder pop3 action reset-both

# --- Create a profile group bundling all three ---
# set profile-group STRICT-SEC virus STRICT-AV spyware STRICT-SPYWARE vulnerability STRICT-VP

# --- Attach to all inbound rules (Linux FW rule names) ---
# set rulebase security rules RULE-03_IN_HTTP         profile-setting group STRICT-SEC
# set rulebase security rules RULE-04_IN_HTTPS        profile-setting group STRICT-SEC
# set rulebase security rules RULE-05_IN_HTTP-WEBMAIL profile-setting group STRICT-SEC
# set rulebase security rules RULE-06_IN_HTTPS-WEBMAIL profile-setting group STRICT-SEC
# set rulebase security rules RULE-07_IN_SMTP         profile-setting group STRICT-SEC
# set rulebase security rules RULE-08_IN_POP3         profile-setting group STRICT-SEC
#
# --- Attach to all inbound rules (Windows FW rule names) ---
# set rulebase security rules RULE-03_IN_HTTP  profile-setting group STRICT-SEC
# set rulebase security rules RULE-04_IN_HTTPS profile-setting group STRICT-SEC
# set rulebase security rules RULE-05_IN_DNS   profile-setting group STRICT-SEC
# set rulebase security rules RULE-06_IN_FTP   profile-setting group STRICT-SEC
# set rulebase security rules RULE-07_IN_TFTP  profile-setting group STRICT-SEC
# set rulebase security rules RULE-08_IN_NTP   profile-setting group STRICT-SEC

# =============================================================================
# STEP 5 — LOG FORWARDING PROFILE (CONFIGURE MODE)
# =============================================================================
# Splunk instance at 172.20.242.20 — forwarding on TCP/9997
set log-settings syslog SPLUNK-FORWARD server SPLUNK transport TCP
set log-settings syslog SPLUNK-FORWARD server SPLUNK port 9997
set log-settings syslog SPLUNK-FORWARD server SPLUNK server 172.20.242.20
set log-settings syslog SPLUNK-FORWARD server SPLUNK format BSD
set log-settings syslog SPLUNK-FORWARD server SPLUNK facility LOG_USER

# Log forwarding profile — traffic and threat logs to Splunk
set log-settings profiles FORWARD-ALL match-list TRAFFIC-FWD send-syslog SPLUNK-FORWARD
set log-settings profiles FORWARD-ALL match-list TRAFFIC-FWD log-type traffic
set log-settings profiles FORWARD-ALL match-list THREAT-FWD send-syslog SPLUNK-FORWARD
set log-settings profiles FORWARD-ALL match-list THREAT-FWD log-type threat

# =============================================================================
# STEP 6 — COMMIT
# =============================================================================
# commit
#
# If commit fails:
#   show jobs all

# =============================================================================
# STEP 7 — SIGNATURE UPDATES (OPERATIONAL MODE)
# =============================================================================
# Run these AFTER committing the hardening config.
# These are operational mode commands (NOT in configure mode).

# Check current content/threat versions:
#   show system info | match content
#   show content-preview info

# Download and install latest threat content (signatures, AV, etc.):
#   request content upgrade download latest
#   request content upgrade install version latest
#
#   request anti-virus upgrade download latest
#   request anti-virus upgrade install version latest
#
#   request wildfire upgrade download latest
#   request wildfire upgrade install version latest

# Check job status after each (wait for completion before next):
#   show jobs all

# =============================================================================
# STEP 8 — POST-HARDENING VERIFICATION (OPERATIONAL MODE)
# =============================================================================

# Management services — confirm HTTP and Telnet show as disabled:
#   show system services

# Confirm only expected admin accounts exist:
#   show admins
#   show config running | match "mgt-config"

# Confirm management permitted-ip is set:
#   show system info | match permitted

# Check that sessions look clean (no unexpected established connections):
#   show session all
#   show session all filter state ACTIVE

# Confirm NTP is syncing:
#   show ntp

# Confirm DNS resolution works:
#   ping host 8.8.8.8

# Confirm threat content version:
#   show system info | match content-version
#   show system info | match av-version

# Confirm zone protection is active on OUTSIDE zone:
#   show zone-protection zone OUTSIDE

# Confirm SSH crypto settings took effect:
#   show deviceconfig setting ssh

# Confirm IPv6 is disabled on management interface:
#   show system info | match ipv6
# Confirm IPv6 deny rule is at the top of the rulebase:
#   show rulebase security rules RULE-00_DENY-IPv6

# =============================================================================
# QUICK INCIDENT RESPONSE — LOCK DOWN FAST
# =============================================================================
# If you're being actively attacked and need to slam the door fast:
#
# Block a specific attacker IP (add to TOP of rulebase):
#   configure
#   set address RT-IP-1  ip-netmask <ATTACKER>/32  description "RT block HH:MM"
#   set rulebase security rules RULE-00_BLOCK_RT-1 from OUTSIDE
#   set rulebase security rules RULE-00_BLOCK_RT-1 to   INSIDE
#   set rulebase security rules RULE-00_BLOCK_RT-1 source RT-IP-1
#   set rulebase security rules RULE-00_BLOCK_RT-1 destination any
#   set rulebase security rules RULE-00_BLOCK_RT-1 application any
#   set rulebase security rules RULE-00_BLOCK_RT-1 service any
#   set rulebase security rules RULE-00_BLOCK_RT-1 action deny
#   set rulebase security rules RULE-00_BLOCK_RT-1 log-end yes
#   move rulebase security rules RULE-00_BLOCK_RT-1 top
#   commit
#
# Kill an active session (get session ID from: show session all):
#   clear session id <ID>
#
# Kill ALL active sessions (nuclear — will briefly drop scored services):
#   clear session all
#
# Force disconnect all active admin CLI sessions:
#   clear session all filter destination <PA-MGMT-IP>

# =============================================================================
# KNOWN COMPETITION NOTES
# =============================================================================
# - Orange Team sends traffic from random IPs — do NOT block unknown IPs
#   without confirming they are red team. Orange = simulated users.
# - Scoring engine IP: ask White Team at drop flag → uncomment RULE-01 in
#   the respective linux/windows config script and commit immediately.
# - Any firewall rule that blocks the scoring engine = your uptime score drops.
# - Only block /32 IPs. Blocking subnets = competition rules violation.
# - Password changes on scored service accounts MUST be reported via Support Ticket.
