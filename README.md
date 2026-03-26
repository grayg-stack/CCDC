# MACCDC 2026 - Scripts & Tools Arsenal

## How to Use

**Competition Rule Reminder:** All tools must be freely available and open source. No private staging areas. Your team's GitHub repo will be copied to Nextcloud and visible to all teams. Download what you need BEFORE competition or pull from Nextcloud during.

---

## PART 1: CURATED GITHUB REPOS

### Tier 1 — CCDC-Specific (Use These First)

| Repo | What It Does | Priority |
|------|-------------|----------|
| [WGU-CCDC/Blue-Team-Tools](https://github.com/WGU-CCDC/Blue-Team-Tools) | Full toolkit: Linux/Windows hardening scripts, SSH hardening, Apache hardening, password changers, organized by OS. Battle-tested at WRCCDC. | **#1 PICK** |
| [ucrcyber/CCDC](https://github.com/ucrcyber/CCDC) | UCR's blue team automation scripts from WRCCDC/NCCDC. Includes per-OS hardening, service configs, and IR templates. 38 stars, actively maintained. | **#2 PICK** |
| [megatop1/WindowsCCDC](https://github.com/megatop1/WindowsCCDC) | Windows-specific: system enum batch script, WindowsEnum.ps1, DeepBlueCLI copy, PoSh-R2 for remote response, STIG compliance scripts for Win7/10/Server 2008/2016. Curated by John Hammond. | **ESSENTIAL for Windows** |
| [C0nd4/CCDC-Blueteam-Manual](https://github.com/C0nd4/CCDC-Blueteam-Manual) | Comprehensive blue team manual covering initial access procedures, hardening workflows, and common mistakes. Great for team briefing. | **READ BEFORE COMP** |
| [jordanpotti/ccdc](https://github.com/jordanpotti/ccdc) | Cross-school CCDC collaboration repo with battle plans, report templates, and shared scripts. | Reference |
| [crag-h4k/linux-hardening](https://github.com/crag-h4k/linux-hardening) | CCDC-focused Linux hardening: sshd_config, iptables rules, hardening scripts, and a quick-start guide. | Linux reference |
| [lchack/CCDC](https://github.com/lchack/CCDC) | Detailed Linux hardening text guide with step-by-step commands for user audit, log review, SSH hardening, and cron analysis. | Linux checklist |

### Tier 2 — Detection & Monitoring Tools

| Repo | What It Does | Use Case |
|------|-------------|----------|
| [sans-blue-team/DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) | PowerShell threat hunting via Windows Event Logs. Detects brute force, new users, service tampering, suspicious commands, Meterpreter, pass-the-hash, and more. 2.4k stars. | **RUN ON ALL WINDOWS BOXES** every 15-30 min: `.\DeepBlue.ps1 -log security` |
| [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) | Production-ready Sysmon config XML. Logs process creation, network connections, file changes with minimal noise. 4.6k+ stars. | Install Sysmon + this config on Windows servers immediately |
| [Yamato-Security/RustyBlue](https://github.com/Yamato-Security/RustyBlue) | Rust port of DeepBlueCLI — much faster on large log files. Standalone binary, no PS dependency. | Alternative to DeepBlueCLI if PS is compromised |

### Tier 3 — Linux Hardening (General Purpose)

| Repo | What It Does | Caution Level |
|------|-------------|---------------|
| [konstruktoid/hardening](https://github.com/konstruktoid/hardening) | Ubuntu hardening script following CIS benchmarks and DISA STIGs. UFW, kernel hardening, sysctl, audit logging. Well-maintained. | **Review before running** — may be aggressive |
| [Jsitech/JShielder](https://github.com/Jsitech/JShielder) | Automated Linux server hardening: SSH, iptables, kernel, auditing, sysstat, arpwatch. CIS benchmark option. | Medium — review settings |
| [emirozer/nixarmor](https://github.com/emirozer/nixarmor) | Multi-distro Linux hardening (Ubuntu/Debian/Fedora/CentOS). Installs chkrootkit, hardens SSH, configures firewall. | Medium — test first |
| [simeononsecurity/Blue-Team-Tools](https://github.com/simeononsecurity/Blue-Team-Tools) | Broad collection: scripts, configs for multiple OSes. Windows hardening script that's specifically designed to resist compromise. | Reference/pick what you need |

### Tier 4 — Useful Utilities

| Tool | Repo/Source | What It Does |
|------|------------|-------------|
| **chkrootkit** | Pre-installed or `apt install chkrootkit` | Scans for known rootkits on Linux |
| **rkhunter** | `apt install rkhunter` | Rootkit hunter — checks binaries, permissions, hidden files |
| **ClamAV** | `apt install clamav` | Open source antivirus for Linux |
| **Lynis** | [CISOfy/lynis](https://github.com/CISOfy/lynis) | Security auditing tool for Linux — generates hardening score and recommendations |
| **YARA** | [VirusTotal/yara](https://github.com/VirusTotal/yara) | Pattern matching for malware detection |

---

## PART 2: CUSTOM SCRIPTS (in this repo)

These scripts are custom-built for the 2026 MACCDC environment (11 VMs, Palo Alto, VyOS, scored services).

### Linux Scripts (`linux/`)

| Script | Purpose | When to Run |
|--------|---------|-------------|
| `01-recon.sh` | Full system reconnaissance — users, ports, cron, SSH keys, SUID, processes. Read-only, safe to run immediately. | **T+0 minutes** (first thing) |
| `02-harden.sh` | Interactive hardening — passwords, SSH, cron cleanup, iptables, sysctl, process kill. Asks before each change. Backs up everything. | **T+5 minutes** (after recon) |
| `03-monitor.sh` | Continuous background monitor — alerts on new users, password changes, new ports, cron changes, suspicious processes, dropped scored services. Run in tmux. | **T+15 minutes** (leave running) |

**Usage:**
```bash
# On each Linux VM:
sudo bash 01-recon.sh | tee /root/recon-$(hostname).txt
sudo bash 02-harden.sh
# In a tmux session:
sudo bash 03-monitor.sh
```

### Windows Scripts (`windows/`)

| Script | Purpose | When to Run |
|--------|---------|-------------|
| `01-recon.ps1` | Full enumeration — local/domain users, admins, services, tasks, shares, firewall, ports, recent security events. | **T+0 minutes** |
| `02-harden.ps1` | Interactive hardening — firewall + scored service rules, disable LLMNR/NBT-NS/SMBv1, audit policies, PowerShell logging, scheduled task cleanup, RDP hardening. | **T+5 minutes** |
| `03-passwords.ps1` | Bulk password changer for local and domain users with safety guards. | **T+2 minutes** (after recon) |

**Usage:**
```powershell
# On each Windows VM (run as Administrator):
powershell -ExecutionPolicy Bypass -File 01-recon.ps1 | Tee-Object C:\recon.txt
powershell -ExecutionPolicy Bypass -File 03-passwords.ps1
powershell -ExecutionPolicy Bypass -File 02-harden.ps1
```

---

## PART 3: DEPLOYMENT ORDER

### First 15 Minutes Sequence

```
ALL VMs SIMULTANEOUSLY:

Linux VMs (Linux Lead + Support):
  1. sudo bash 01-recon.sh | tee /root/recon.txt     [2 min]
  2. Change root password manually                     [30 sec]
  3. sudo bash 02-harden.sh (selective — passwords    [10 min]
     first, SSH, then cron/firewall)
  4. tmux new -s monitor && sudo bash 03-monitor.sh   [background]

Windows VMs (Windows Lead + Support):
  1. Run 01-recon.ps1                                  [2 min]
  2. Run 03-passwords.ps1 (change all passwords)       [3 min]
  3. Run 02-harden.ps1 (firewall, protocols, audit)    [8 min]
  4. Download & run DeepBlueCLI: .\DeepBlue.ps1        [2 min]

Network (Firewall Lead):
  1. Browser to PA management IP
  2. Change admin/Changeme123 on BOTH Palo Altos       [1 min]
  3. Review existing security policies                  [5 min]
  4. Begin building scored-service allow rules          [10 min]
```

---

## PART 4: KEY REMINDERS

- **TEST AFTER EVERY CHANGE** — check NISE service dashboard
- **NEVER block all traffic** trying to stop Red Team — you'll block scoring
- **Back up configs** before modifying (scripts do this automatically)
- **Submit password changes** for scored accounts via Support Ticket at auth.ccdc.events
- **All tools must be FOSS** — no trial software, no private repos
- **Your GitHub repo is PUBLIC** to all teams via Nextcloud — don't put secrets in it
- **Print this document** — printed materials are allowed at competition

---

## PART 5: TOOL DOWNLOAD COMMANDS

Run these on competition day if you have internet access through the proxy:

```bash
# Linux — install security tools
sudo apt update && sudo apt install -y chkrootkit rkhunter clamav lynis tmux

# OR for RHEL/CentOS:
sudo yum install -y rkhunter clamav tmux
```

```powershell
# Windows — download DeepBlueCLI (if GitHub is accessible through proxy)
Invoke-WebRequest -Uri "https://github.com/sans-blue-team/DeepBlueCLI/archive/refs/heads/master.zip" -OutFile "C:\DeepBlueCLI.zip"
Expand-Archive -Path "C:\DeepBlueCLI.zip" -DestinationPath "C:\"

# Run it:
Set-ExecutionPolicy Bypass -Scope CurrentUser
cd C:\DeepBlueCLI-master
.\DeepBlue.ps1 -log security
.\DeepBlue.ps1 -log system
```
