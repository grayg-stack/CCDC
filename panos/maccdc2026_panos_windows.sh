#!/usr/bin/env bash
# =============================================================================
# MACCDC 2026 — Firewall 2 Config (Team 5)
# VM10 — PAN-OS 11.0.2
# =============================================================================
# SSH target:  ssh admin@172.20.240.200   (management IP)
# Default creds: admin:Changeme123  — CHANGE IMMEDIATELY
#
# This firewall guards the WINDOWS network (172.20.240.0/24):
#   Server 2019 AD/DNS  172.20.240.102  DNS (scored)
#   Server 2019 Web     172.20.240.101  HTTP/HTTPS (scored)
#   Server 2022 FTP     172.20.240.104  FTP/TFTP/NTP (scored)
#   Windows 11 Wks      172.20.240.100  workstation (not scored)
#
# Network:
#   OUTSIDE interface: ethernet1/1  172.16.102.254/24  (to VyOS net2)
#   INSIDE  interface: ethernet1/2  172.20.240.254/24  (Windows LAN)
#
# Run maccdc2026_panos_harden.sh on this firewall too after this config.
# =============================================================================

# =============================================================================
# SECTION 1 — ZONES & ZONE PROTECTION
# =============================================================================
set zone OUTSIDE network layer3 ethernet1/1
set zone INSIDE  network layer3 ethernet1/2

set zone-protection-profile ZP-OUTSIDE flood tcp-syn enable yes
set zone-protection-profile ZP-OUTSIDE flood tcp-syn activate 5000
set zone-protection-profile ZP-OUTSIDE flood tcp-syn red 10000
set zone-protection-profile ZP-OUTSIDE flood tcp-syn maximal 40000
set zone-protection-profile ZP-OUTSIDE flood udp enable yes
set zone-protection-profile ZP-OUTSIDE flood udp activate 5000
set zone-protection-profile ZP-OUTSIDE flood udp red 10000
set zone-protection-profile ZP-OUTSIDE flood udp maximal 40000
set zone-protection-profile ZP-OUTSIDE flood icmp enable yes
set zone-protection-profile ZP-OUTSIDE flood icmp activate 500
set zone-protection-profile ZP-OUTSIDE flood icmp red 1000
set zone-protection-profile ZP-OUTSIDE flood other enable yes
set zone-protection-profile ZP-OUTSIDE scan threat port-scan enable yes
set zone-protection-profile ZP-OUTSIDE scan threat host-sweep enable yes
set zone-protection-profile ZP-OUTSIDE scan block-ip track-by attacker
set zone-protection-profile ZP-OUTSIDE scan block-ip duration 300
set zone OUTSIDE network layer3 zone-protection-profile ZP-OUTSIDE

# =============================================================================
# SECTION 2 — ADDRESS OBJECTS
# =============================================================================
set address DNS-SERVER    ip-netmask 172.20.240.102/32   description "Server 2019 AD/DNS — DNS scored"
set address WEB-SERVER    ip-netmask 172.20.240.101/32   description "Server 2019 Web — HTTP/HTTPS scored"
set address FTP-SERVER    ip-netmask 172.20.240.104/32   description "Server 2022 FTP — FTP/TFTP/NTP scored"
set address WIN-WKS       ip-netmask 172.20.240.100/32   description "Windows 11 workstation"
set address INTERNAL-NET  ip-netmask 172.20.240.0/24     description "Windows FW inside network"
set address SPLUNK        ip-netmask 172.20.242.20/32    description "Splunk — Linux network logging"

# Scoring engine — get from White Team at drop flag:
# set address SCORING-ENGINE  ip-netmask <IP>/32  description "Scoring engine — DO NOT BLOCK"

# =============================================================================
# SECTION 3 — SERVICE OBJECTS
# =============================================================================
set service svc-http         protocol tcp port 80
set service svc-https        protocol tcp port 443
set service svc-dns-tcp      protocol tcp port 53
set service svc-dns-udp      protocol udp port 53
set service svc-ftp-ctrl     protocol tcp port 21
set service svc-ftp-data     protocol tcp port 20
set service svc-ftp-passive  protocol tcp port 1024-65535
# ^ Tighten to a narrow range (e.g. 60000-65535) if you can configure the
#   FTP server's passive port range to match.
set service svc-tftp         protocol udp port 69
set service svc-ntp          protocol udp port 123
set service svc-smtp         protocol tcp port 25
set service svc-splunk       protocol tcp port 9997

# =============================================================================
# SECTION 4 — SECURITY POLICIES
# =============================================================================

# ------------------------------------------------------------------
# RULE 00 — LIVE RED TEAM BLOCK TEMPLATE
# ------------------------------------------------------------------
# configure
# set address RT-IP-1  ip-netmask <ATTACKER>/32  description "RT block HH:MM"
# set rulebase security rules RULE-00_BLOCK_RT-1 from OUTSIDE
# set rulebase security rules RULE-00_BLOCK_RT-1 to   INSIDE
# set rulebase security rules RULE-00_BLOCK_RT-1 source RT-IP-1
# set rulebase security rules RULE-00_BLOCK_RT-1 destination any
# set rulebase security rules RULE-00_BLOCK_RT-1 application any
# set rulebase security rules RULE-00_BLOCK_RT-1 service any
# set rulebase security rules RULE-00_BLOCK_RT-1 action deny
# set rulebase security rules RULE-00_BLOCK_RT-1 log-end yes
# move rulebase security rules RULE-00_BLOCK_RT-1 top
# commit
# /32 ONLY — subnet blocks are a rules violation.

# ------------------------------------------------------------------
# RULE 01 — Scoring engine allow (uncomment once IP is known)
# ------------------------------------------------------------------
# set rulebase security rules RULE-01_IN_SCORING from OUTSIDE
# set rulebase security rules RULE-01_IN_SCORING to   INSIDE
# set rulebase security rules RULE-01_IN_SCORING source SCORING-ENGINE
# set rulebase security rules RULE-01_IN_SCORING destination any
# set rulebase security rules RULE-01_IN_SCORING application any
# set rulebase security rules RULE-01_IN_SCORING service any
# set rulebase security rules RULE-01_IN_SCORING action allow
# set rulebase security rules RULE-01_IN_SCORING log-end yes
# set rulebase security rules RULE-01_IN_SCORING description "Scoring engine — DO NOT BLOCK"

# ------------------------------------------------------------------
# RULE 02 — SSH management inbound
# ------------------------------------------------------------------
set rulebase security rules RULE-02_IN_SSH from OUTSIDE
set rulebase security rules RULE-02_IN_SSH to   INSIDE
set rulebase security rules RULE-02_IN_SSH source any
set rulebase security rules RULE-02_IN_SSH destination INTERNAL-NET
set rulebase security rules RULE-02_IN_SSH application ssh
set rulebase security rules RULE-02_IN_SSH service application-default
set rulebase security rules RULE-02_IN_SSH action allow
set rulebase security rules RULE-02_IN_SSH log-end yes
set rulebase security rules RULE-02_IN_SSH description "SSH mgmt — RESTRICT SOURCE ASAP"

# ------------------------------------------------------------------
# RULE 03 — Inbound HTTP (SCORED) — Server 2019 Web
# ------------------------------------------------------------------
set rulebase security rules RULE-03_IN_HTTP from OUTSIDE
set rulebase security rules RULE-03_IN_HTTP to   INSIDE
set rulebase security rules RULE-03_IN_HTTP source any
set rulebase security rules RULE-03_IN_HTTP destination WEB-SERVER
set rulebase security rules RULE-03_IN_HTTP application web-browsing
set rulebase security rules RULE-03_IN_HTTP service svc-http
set rulebase security rules RULE-03_IN_HTTP action allow
set rulebase security rules RULE-03_IN_HTTP log-end yes
set rulebase security rules RULE-03_IN_HTTP description "SCORED: HTTP → Server 2019 Web"

# ------------------------------------------------------------------
# RULE 04 — Inbound HTTPS (SCORED) — Server 2019 Web
# ------------------------------------------------------------------
set rulebase security rules RULE-04_IN_HTTPS from OUTSIDE
set rulebase security rules RULE-04_IN_HTTPS to   INSIDE
set rulebase security rules RULE-04_IN_HTTPS source any
set rulebase security rules RULE-04_IN_HTTPS destination WEB-SERVER
set rulebase security rules RULE-04_IN_HTTPS application ssl
set rulebase security rules RULE-04_IN_HTTPS service svc-https
set rulebase security rules RULE-04_IN_HTTPS action allow
set rulebase security rules RULE-04_IN_HTTPS log-end yes
set rulebase security rules RULE-04_IN_HTTPS description "SCORED: HTTPS → Server 2019 Web"

# ------------------------------------------------------------------
# RULE 05 — Inbound DNS (SCORED) — Server 2019 AD/DNS
# ------------------------------------------------------------------
set rulebase security rules RULE-05_IN_DNS from OUTSIDE
set rulebase security rules RULE-05_IN_DNS to   INSIDE
set rulebase security rules RULE-05_IN_DNS source any
set rulebase security rules RULE-05_IN_DNS destination DNS-SERVER
set rulebase security rules RULE-05_IN_DNS application dns
set rulebase security rules RULE-05_IN_DNS service [ svc-dns-tcp svc-dns-udp ]
set rulebase security rules RULE-05_IN_DNS action allow
set rulebase security rules RULE-05_IN_DNS log-end yes
set rulebase security rules RULE-05_IN_DNS description "SCORED: DNS (TCP+UDP) → Server 2019 AD/DNS"

# ------------------------------------------------------------------
# RULE 06 — Inbound FTP (SCORED) — Server 2022 FTP
# ------------------------------------------------------------------
set rulebase security rules RULE-06_IN_FTP from OUTSIDE
set rulebase security rules RULE-06_IN_FTP to   INSIDE
set rulebase security rules RULE-06_IN_FTP source any
set rulebase security rules RULE-06_IN_FTP destination FTP-SERVER
set rulebase security rules RULE-06_IN_FTP application ftp
set rulebase security rules RULE-06_IN_FTP service [ svc-ftp-ctrl svc-ftp-data svc-ftp-passive ]
set rulebase security rules RULE-06_IN_FTP action allow
set rulebase security rules RULE-06_IN_FTP log-end yes
set rulebase security rules RULE-06_IN_FTP description "SCORED: FTP → Server 2022 FTP"

# ------------------------------------------------------------------
# RULE 07 — Inbound TFTP (SCORED) — Server 2022 FTP
# ------------------------------------------------------------------
set rulebase security rules RULE-07_IN_TFTP from OUTSIDE
set rulebase security rules RULE-07_IN_TFTP to   INSIDE
set rulebase security rules RULE-07_IN_TFTP source any
set rulebase security rules RULE-07_IN_TFTP destination FTP-SERVER
set rulebase security rules RULE-07_IN_TFTP application tftp
set rulebase security rules RULE-07_IN_TFTP service svc-tftp
set rulebase security rules RULE-07_IN_TFTP action allow
set rulebase security rules RULE-07_IN_TFTP log-end yes
set rulebase security rules RULE-07_IN_TFTP description "SCORED: TFTP → Server 2022 FTP"

# ------------------------------------------------------------------
# RULE 08 — Inbound NTP (SCORED) — Server 2022 FTP
# ------------------------------------------------------------------
set rulebase security rules RULE-08_IN_NTP from OUTSIDE
set rulebase security rules RULE-08_IN_NTP to   INSIDE
set rulebase security rules RULE-08_IN_NTP source any
set rulebase security rules RULE-08_IN_NTP destination FTP-SERVER
set rulebase security rules RULE-08_IN_NTP application ntp
set rulebase security rules RULE-08_IN_NTP service svc-ntp
set rulebase security rules RULE-08_IN_NTP action allow
set rulebase security rules RULE-08_IN_NTP log-end yes
set rulebase security rules RULE-08_IN_NTP description "SCORED: NTP → Server 2022 FTP"

# ------------------------------------------------------------------
# RULE 09 — DENY all other inbound
# ------------------------------------------------------------------
set rulebase security rules RULE-09_IN_DENY-ALL from OUTSIDE
set rulebase security rules RULE-09_IN_DENY-ALL to   INSIDE
set rulebase security rules RULE-09_IN_DENY-ALL source any
set rulebase security rules RULE-09_IN_DENY-ALL destination any
set rulebase security rules RULE-09_IN_DENY-ALL application any
set rulebase security rules RULE-09_IN_DENY-ALL service any
set rulebase security rules RULE-09_IN_DENY-ALL action deny
set rulebase security rules RULE-09_IN_DENY-ALL log-end yes
set rulebase security rules RULE-09_IN_DENY-ALL description "DENY ALL other inbound"

# ------------------------------------------------------------------
# RULE 10 — Outbound DNS
# ------------------------------------------------------------------
set rulebase security rules RULE-10_OUT_DNS from INSIDE
set rulebase security rules RULE-10_OUT_DNS to   OUTSIDE
set rulebase security rules RULE-10_OUT_DNS source INTERNAL-NET
set rulebase security rules RULE-10_OUT_DNS destination any
set rulebase security rules RULE-10_OUT_DNS application dns
set rulebase security rules RULE-10_OUT_DNS service [ svc-dns-tcp svc-dns-udp ]
set rulebase security rules RULE-10_OUT_DNS action allow
set rulebase security rules RULE-10_OUT_DNS log-end no
set rulebase security rules RULE-10_OUT_DNS description "Outbound DNS"

# ------------------------------------------------------------------
# RULE 11 — Outbound NTP
# ------------------------------------------------------------------
set rulebase security rules RULE-11_OUT_NTP from INSIDE
set rulebase security rules RULE-11_OUT_NTP to   OUTSIDE
set rulebase security rules RULE-11_OUT_NTP source INTERNAL-NET
set rulebase security rules RULE-11_OUT_NTP destination any
set rulebase security rules RULE-11_OUT_NTP application ntp
set rulebase security rules RULE-11_OUT_NTP service application-default
set rulebase security rules RULE-11_OUT_NTP action allow
set rulebase security rules RULE-11_OUT_NTP log-end no
set rulebase security rules RULE-11_OUT_NTP description "Outbound NTP"

# ------------------------------------------------------------------
# RULE 12 — Outbound HTTP/HTTPS (Windows Update, patches)
# ------------------------------------------------------------------
set rulebase security rules RULE-12_OUT_WEB from INSIDE
set rulebase security rules RULE-12_OUT_WEB to   OUTSIDE
set rulebase security rules RULE-12_OUT_WEB source INTERNAL-NET
set rulebase security rules RULE-12_OUT_WEB destination any
set rulebase security rules RULE-12_OUT_WEB application [ web-browsing ssl ]
set rulebase security rules RULE-12_OUT_WEB service [ svc-http svc-https ]
set rulebase security rules RULE-12_OUT_WEB action allow
set rulebase security rules RULE-12_OUT_WEB log-end yes
set rulebase security rules RULE-12_OUT_WEB description "Outbound HTTP/HTTPS — monitor for C2"

# ------------------------------------------------------------------
# RULE 12b — Outbound Splunk forwarder (Windows hosts → Splunk:9997)
# ------------------------------------------------------------------
set rulebase security rules RULE-12b_OUT_SPLUNK from INSIDE
set rulebase security rules RULE-12b_OUT_SPLUNK to   OUTSIDE
set rulebase security rules RULE-12b_OUT_SPLUNK source INTERNAL-NET
set rulebase security rules RULE-12b_OUT_SPLUNK destination SPLUNK
set rulebase security rules RULE-12b_OUT_SPLUNK application any
set rulebase security rules RULE-12b_OUT_SPLUNK service svc-splunk
set rulebase security rules RULE-12b_OUT_SPLUNK action allow
set rulebase security rules RULE-12b_OUT_SPLUNK log-end yes
set rulebase security rules RULE-12b_OUT_SPLUNK description "Splunk forwarder — Windows hosts → Splunk:9997"

# ------------------------------------------------------------------
# RULE 13 — DENY ALL other egress — RED TEAM CALLBACK BLOCKER
# ------------------------------------------------------------------
set rulebase security rules RULE-13_OUT_DENY-ALL from INSIDE
set rulebase security rules RULE-13_OUT_DENY-ALL to   OUTSIDE
set rulebase security rules RULE-13_OUT_DENY-ALL source any
set rulebase security rules RULE-13_OUT_DENY-ALL destination any
set rulebase security rules RULE-13_OUT_DENY-ALL application any
set rulebase security rules RULE-13_OUT_DENY-ALL service any
set rulebase security rules RULE-13_OUT_DENY-ALL action deny
set rulebase security rules RULE-13_OUT_DENY-ALL log-end yes
set rulebase security rules RULE-13_OUT_DENY-ALL description "DENY ALL egress — CALLBACK BLOCKER"

# =============================================================================
# SECTION 5 — DEFAULT RULES & COMMIT
# =============================================================================
set rulebase default-security-rules rules intrazone-default log-end yes
set rulebase default-security-rules rules interzone-default log-end yes
set rulebase default-security-rules rules interzone-default action deny

# commit

# =============================================================================
# VERIFICATION (operational mode)
# =============================================================================
# show security policy
# test security-policy-match from OUTSIDE to INSIDE source 1.1.1.1 destination 172.20.240.101 protocol 6 port 80
# test security-policy-match from OUTSIDE to INSIDE source 1.1.1.1 destination 172.20.240.101 protocol 6 port 443
# test security-policy-match from OUTSIDE to INSIDE source 1.1.1.1 destination 172.20.240.102 protocol 17 port 53
# test security-policy-match from OUTSIDE to INSIDE source 1.1.1.1 destination 172.20.240.104 protocol 6 port 21
# test security-policy-match from OUTSIDE to INSIDE source 1.1.1.1 destination 172.20.240.104 protocol 17 port 69
# test security-policy-match from OUTSIDE to INSIDE source 1.1.1.1 destination 172.20.240.104 protocol 17 port 123
# tail follow yes lines 20 traffic
