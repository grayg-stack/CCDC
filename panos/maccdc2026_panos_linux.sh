#!/usr/bin/env bash
# =============================================================================
# MACCDC 2026 — Firewall 1 Config (Team 5)
# VM9 — PAN-OS 11.0.2
# =============================================================================
# SSH target:  ssh admin@172.20.242.150   (management IP)
# Default creds: admin:Changeme123  — CHANGE IMMEDIATELY
#
# This firewall guards the LINUX network (172.20.242.0/24):
#   Ubuntu Ecom    172.20.242.30   HTTP/HTTPS (scored)
#   Fedora Webmail 172.20.242.40   SMTP/POP3  (scored)
#   Splunk         172.20.242.20   internal only
#
# Network:
#   OUTSIDE interface: ethernet1/1  172.16.101.254/24  (to VyOS net1)
#   INSIDE  interface: ethernet1/2  172.20.242.254/24  (Linux LAN)
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
set address ECOM-SERVER   ip-netmask 172.20.242.30/32   description "Ubuntu Ecom — HTTP/HTTPS scored"
set address WEBMAIL       ip-netmask 172.20.242.40/32   description "Fedora Webmail — SMTP/POP3 scored"
set address SPLUNK        ip-netmask 172.20.242.20/32   description "Splunk — internal logging only"
set address INTERNAL-NET  ip-netmask 172.20.242.0/24    description "Linux FW inside network"

# Scoring engine — get from White Team at drop flag:
# set address SCORING-ENGINE  ip-netmask <IP>/32  description "Scoring engine — DO NOT BLOCK"

# =============================================================================
# SECTION 3 — SERVICE OBJECTS
# =============================================================================
set service svc-http      protocol tcp port 80
set service svc-https     protocol tcp port 443
set service svc-smtp      protocol tcp port 25
set service svc-pop3      protocol tcp port 110
set service svc-dns-tcp   protocol tcp port 53
set service svc-dns-udp   protocol udp port 53
set service svc-splunk       protocol tcp port 9997
set service svc-syslog-tcp   protocol tcp port 514
set service svc-syslog-udp   protocol udp port 514

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
# RULE 03 — Inbound HTTP (SCORED) — Ubuntu Ecom
# ------------------------------------------------------------------
set rulebase security rules RULE-03_IN_HTTP from OUTSIDE
set rulebase security rules RULE-03_IN_HTTP to   INSIDE
set rulebase security rules RULE-03_IN_HTTP source any
set rulebase security rules RULE-03_IN_HTTP destination ECOM-SERVER
set rulebase security rules RULE-03_IN_HTTP application web-browsing
set rulebase security rules RULE-03_IN_HTTP service svc-http
set rulebase security rules RULE-03_IN_HTTP action allow
set rulebase security rules RULE-03_IN_HTTP log-end yes
set rulebase security rules RULE-03_IN_HTTP description "SCORED: HTTP → Ubuntu Ecom"

# ------------------------------------------------------------------
# RULE 04 — Inbound HTTPS (SCORED) — Ubuntu Ecom
# ------------------------------------------------------------------
set rulebase security rules RULE-04_IN_HTTPS from OUTSIDE
set rulebase security rules RULE-04_IN_HTTPS to   INSIDE
set rulebase security rules RULE-04_IN_HTTPS source any
set rulebase security rules RULE-04_IN_HTTPS destination ECOM-SERVER
set rulebase security rules RULE-04_IN_HTTPS application ssl
set rulebase security rules RULE-04_IN_HTTPS service svc-https
set rulebase security rules RULE-04_IN_HTTPS action allow
set rulebase security rules RULE-04_IN_HTTPS log-end yes
set rulebase security rules RULE-04_IN_HTTPS description "SCORED: HTTPS → Ubuntu Ecom"

# ------------------------------------------------------------------
# RULE 05 — Inbound HTTP to Webmail (SCORED)
# ------------------------------------------------------------------
# Fedora Webmail likely serves HTTP for the webmail UI in addition to SMTP/POP3.
set rulebase security rules RULE-05_IN_HTTP-WEBMAIL from OUTSIDE
set rulebase security rules RULE-05_IN_HTTP-WEBMAIL to   INSIDE
set rulebase security rules RULE-05_IN_HTTP-WEBMAIL source any
set rulebase security rules RULE-05_IN_HTTP-WEBMAIL destination WEBMAIL
set rulebase security rules RULE-05_IN_HTTP-WEBMAIL application web-browsing
set rulebase security rules RULE-05_IN_HTTP-WEBMAIL service svc-http
set rulebase security rules RULE-05_IN_HTTP-WEBMAIL action allow
set rulebase security rules RULE-05_IN_HTTP-WEBMAIL log-end yes
set rulebase security rules RULE-05_IN_HTTP-WEBMAIL description "SCORED: HTTP → Fedora Webmail UI"

# ------------------------------------------------------------------
# RULE 06 — Inbound HTTPS to Webmail (SCORED)
# ------------------------------------------------------------------
set rulebase security rules RULE-06_IN_HTTPS-WEBMAIL from OUTSIDE
set rulebase security rules RULE-06_IN_HTTPS-WEBMAIL to   INSIDE
set rulebase security rules RULE-06_IN_HTTPS-WEBMAIL source any
set rulebase security rules RULE-06_IN_HTTPS-WEBMAIL destination WEBMAIL
set rulebase security rules RULE-06_IN_HTTPS-WEBMAIL application ssl
set rulebase security rules RULE-06_IN_HTTPS-WEBMAIL service svc-https
set rulebase security rules RULE-06_IN_HTTPS-WEBMAIL action allow
set rulebase security rules RULE-06_IN_HTTPS-WEBMAIL log-end yes
set rulebase security rules RULE-06_IN_HTTPS-WEBMAIL description "SCORED: HTTPS → Fedora Webmail UI"

# ------------------------------------------------------------------
# RULE 07 — Inbound SMTP (SCORED) — Fedora Webmail
# ------------------------------------------------------------------
set rulebase security rules RULE-07_IN_SMTP from OUTSIDE
set rulebase security rules RULE-07_IN_SMTP to   INSIDE
set rulebase security rules RULE-07_IN_SMTP source any
set rulebase security rules RULE-07_IN_SMTP destination WEBMAIL
set rulebase security rules RULE-07_IN_SMTP application smtp
set rulebase security rules RULE-07_IN_SMTP service svc-smtp
set rulebase security rules RULE-07_IN_SMTP action allow
set rulebase security rules RULE-07_IN_SMTP log-end yes
set rulebase security rules RULE-07_IN_SMTP description "SCORED: SMTP → Fedora Webmail"

# ------------------------------------------------------------------
# RULE 08 — Inbound POP3 (SCORED) — Fedora Webmail
# ------------------------------------------------------------------
set rulebase security rules RULE-08_IN_POP3 from OUTSIDE
set rulebase security rules RULE-08_IN_POP3 to   INSIDE
set rulebase security rules RULE-08_IN_POP3 source any
set rulebase security rules RULE-08_IN_POP3 destination WEBMAIL
set rulebase security rules RULE-08_IN_POP3 application pop3
set rulebase security rules RULE-08_IN_POP3 service svc-pop3
set rulebase security rules RULE-08_IN_POP3 action allow
set rulebase security rules RULE-08_IN_POP3 log-end yes
set rulebase security rules RULE-08_IN_POP3 description "SCORED: POP3 → Fedora Webmail"

# ------------------------------------------------------------------
# RULE 08b — Inbound Splunk forwarder from Windows network (OUTSIDE → SPLUNK:9997)
# ------------------------------------------------------------------
set rulebase security rules RULE-08b_IN_SPLUNK from OUTSIDE
set rulebase security rules RULE-08b_IN_SPLUNK to   INSIDE
set rulebase security rules RULE-08b_IN_SPLUNK source any
set rulebase security rules RULE-08b_IN_SPLUNK destination SPLUNK
set rulebase security rules RULE-08b_IN_SPLUNK application any
set rulebase security rules RULE-08b_IN_SPLUNK service svc-splunk
set rulebase security rules RULE-08b_IN_SPLUNK action allow
set rulebase security rules RULE-08b_IN_SPLUNK log-end yes
set rulebase security rules RULE-08b_IN_SPLUNK description "Splunk forwarder inbound — Windows hosts → Splunk:9997"

# ------------------------------------------------------------------
# RULE 08c — Inbound Syslog from Windows network (OUTSIDE → SPLUNK:514 TCP+UDP)
# ------------------------------------------------------------------
set rulebase security rules RULE-08c_IN_SYSLOG from OUTSIDE
set rulebase security rules RULE-08c_IN_SYSLOG to   INSIDE
set rulebase security rules RULE-08c_IN_SYSLOG source any
set rulebase security rules RULE-08c_IN_SYSLOG destination SPLUNK
set rulebase security rules RULE-08c_IN_SYSLOG application any
set rulebase security rules RULE-08c_IN_SYSLOG service [ svc-syslog-tcp svc-syslog-udp ]
set rulebase security rules RULE-08c_IN_SYSLOG action allow
set rulebase security rules RULE-08c_IN_SYSLOG log-end yes
set rulebase security rules RULE-08c_IN_SYSLOG description "Syslog inbound — Windows hosts → Splunk:514 TCP+UDP"

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
# RULE 12 — Outbound HTTP/HTTPS (patches, Splunk updates)
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
# RULE 13 — Outbound SMTP (Webmail sending only)
# ------------------------------------------------------------------
set rulebase security rules RULE-13_OUT_SMTP from INSIDE
set rulebase security rules RULE-13_OUT_SMTP to   OUTSIDE
set rulebase security rules RULE-13_OUT_SMTP source WEBMAIL
set rulebase security rules RULE-13_OUT_SMTP destination any
set rulebase security rules RULE-13_OUT_SMTP application smtp
set rulebase security rules RULE-13_OUT_SMTP service svc-smtp
set rulebase security rules RULE-13_OUT_SMTP action allow
set rulebase security rules RULE-13_OUT_SMTP log-end yes
set rulebase security rules RULE-13_OUT_SMTP description "Outbound SMTP from Webmail only"

# ------------------------------------------------------------------
# RULE 14 — DENY ALL other egress — RED TEAM CALLBACK BLOCKER
# ------------------------------------------------------------------
set rulebase security rules RULE-14_OUT_DENY-ALL from INSIDE
set rulebase security rules RULE-14_OUT_DENY-ALL to   OUTSIDE
set rulebase security rules RULE-14_OUT_DENY-ALL source any
set rulebase security rules RULE-14_OUT_DENY-ALL destination any
set rulebase security rules RULE-14_OUT_DENY-ALL application any
set rulebase security rules RULE-14_OUT_DENY-ALL service any
set rulebase security rules RULE-14_OUT_DENY-ALL action deny
set rulebase security rules RULE-14_OUT_DENY-ALL log-end yes
set rulebase security rules RULE-14_OUT_DENY-ALL description "DENY ALL egress — CALLBACK BLOCKER"

# ------------------------------------------------------------------
# RULE 15 — Splunk forwarder intra-zone (INSIDE → SPLUNK:9997)
# ------------------------------------------------------------------
set rulebase security rules RULE-15_INT_SPLUNK from INSIDE
set rulebase security rules RULE-15_INT_SPLUNK to   INSIDE
set rulebase security rules RULE-15_INT_SPLUNK source INTERNAL-NET
set rulebase security rules RULE-15_INT_SPLUNK destination SPLUNK
set rulebase security rules RULE-15_INT_SPLUNK application any
set rulebase security rules RULE-15_INT_SPLUNK service svc-splunk
set rulebase security rules RULE-15_INT_SPLUNK action allow
set rulebase security rules RULE-15_INT_SPLUNK log-end yes
set rulebase security rules RULE-15_INT_SPLUNK description "Splunk forwarder — INSIDE hosts → Splunk:9997"

# ------------------------------------------------------------------
# RULE 15b — Syslog intra-zone (INSIDE → SPLUNK:514 TCP+UDP)
# ------------------------------------------------------------------
set rulebase security rules RULE-15b_INT_SYSLOG from INSIDE
set rulebase security rules RULE-15b_INT_SYSLOG to   INSIDE
set rulebase security rules RULE-15b_INT_SYSLOG source INTERNAL-NET
set rulebase security rules RULE-15b_INT_SYSLOG destination SPLUNK
set rulebase security rules RULE-15b_INT_SYSLOG application any
set rulebase security rules RULE-15b_INT_SYSLOG service [ svc-syslog-tcp svc-syslog-udp ]
set rulebase security rules RULE-15b_INT_SYSLOG action allow
set rulebase security rules RULE-15b_INT_SYSLOG log-end yes
set rulebase security rules RULE-15b_INT_SYSLOG description "Syslog — INSIDE hosts → Splunk:514 TCP+UDP"

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
# test security-policy-match from OUTSIDE to INSIDE source 1.1.1.1 destination 172.20.242.30 protocol 6 port 80
# test security-policy-match from OUTSIDE to INSIDE source 1.1.1.1 destination 172.20.242.30 protocol 6 port 443
# test security-policy-match from OUTSIDE to INSIDE source 1.1.1.1 destination 172.20.242.40 protocol 6 port 25
# test security-policy-match from OUTSIDE to INSIDE source 1.1.1.1 destination 172.20.242.40 protocol 6 port 110
# tail follow yes lines 20 traffic
