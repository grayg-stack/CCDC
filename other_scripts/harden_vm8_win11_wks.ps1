#Requires -Version 5.1
<#
.SYNOPSIS
    MACCDC 2026 - Harden VM8: Windows 11 Workstation
    IP: 172.20.240.100 | NOT scored, cannot retask
.DESCRIPTION
    Box-specific hardening for the Windows 11 workstation.
    - Changes Administrator and UserOne passwords, creates blueteam admin
    - Minimal firewall (RDP for management)
    - Basic security policy
    - Checks persistence mechanisms (tasks, services, run keys)
    - Does NOT change role or install server services
.PARAMETER NewPassword
    The new password to set for Administrator, UserOne, and blueteam accounts.
.NOTES
    Run on VM8 (172.20.240.100). Safe to run multiple times (idempotent).
    This machine is NOT scored. Focus is on preventing red team from using
    it as a pivot point into the rest of the network.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$NewPassword
)

# --- Elevate to Administrator if not already ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Not running as Administrator. Relaunching elevated..." -ForegroundColor Yellow
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -NewPassword `"$NewPassword`""
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

# --- Setup logging ---
$logDir = "C:\hardening_logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $logDir "harden_vm8_wks_$timestamp.log"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] $Message"
    Write-Host $entry -ForegroundColor $Color
    Add-Content -Path $logFile -Value $entry
}

Write-Log "=============================================" "Cyan"
Write-Log "  VM8 Windows 11 Workstation Hardening" "Cyan"
Write-Log "  MACCDC 2026 - 172.20.240.100" "Cyan"
Write-Log "  NOT scored - cannot retask" "Cyan"
Write-Log "=============================================" "Cyan"
Write-Log ""

# ============================================================
# 1. CHANGE ADMINISTRATOR PASSWORD
# ============================================================
Write-Log "[+] Changing Administrator password..." "Green"
try {
    $secPass = ConvertTo-SecureString $NewPassword -AsPlainText -Force
    Set-LocalUser -Name "Administrator" -Password $secPass -ErrorAction Stop
    Write-Log "[+] Administrator password changed." "Green"
} catch {
    try {
        net user Administrator $NewPassword 2>&1 | Out-Null
        Write-Log "[+] Administrator password changed (net user)." "Green"
    } catch {
        Write-Log "[-] Failed to change Administrator password: $_" "Red"
    }
}

# ============================================================
# 2. CHANGE USERONE PASSWORD
# ============================================================
Write-Log "[+] Changing UserOne password..." "Green"
try {
    $secPass = ConvertTo-SecureString $NewPassword -AsPlainText -Force
    Set-LocalUser -Name "UserOne" -Password $secPass -ErrorAction Stop
    Write-Log "[+] UserOne password changed." "Green"
} catch {
    try {
        net user UserOne $NewPassword 2>&1 | Out-Null
        Write-Log "[+] UserOne password changed (net user)." "Green"
    } catch {
        Write-Log "[-] Failed to change UserOne password (user may not exist): $_" "Yellow"
    }
}

# ============================================================
# 3. CREATE BLUETEAM ADMIN ACCOUNT
# ============================================================
Write-Log "[+] Creating blueteam admin account..." "Green"
try {
    $existingUser = Get-LocalUser -Name "blueteam" -ErrorAction SilentlyContinue
    if ($existingUser) {
        Write-Log "[*] blueteam already exists. Resetting password." "Yellow"
        Set-LocalUser -Name "blueteam" -Password $secPass
        Enable-LocalUser -Name "blueteam"
    } else {
        New-LocalUser -Name "blueteam" -Password $secPass -FullName "Blue Team Admin" -Description "CCDC 2026 Blue Team" -PasswordNeverExpires -ErrorAction Stop | Out-Null
        Write-Log "[+] blueteam account created." "Green"
    }
    Add-LocalGroupMember -Group "Administrators" -Member "blueteam" -ErrorAction SilentlyContinue
    Write-Log "[+] blueteam added to Administrators." "Green"
} catch {
    Write-Log "[-] Failed to create blueteam: $_" "Red"
}

# ============================================================
# 4. ENABLE WINDOWS FIREWALL
# ============================================================
Write-Log "[+] Enabling Windows Firewall for all profiles..." "Green"
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
    Write-Log "[+] Windows Firewall enabled." "Green"
} catch {
    Write-Log "[-] Failed to enable firewall: $_" "Red"
}

# ============================================================
# 5. CONFIGURE FIREWALL RULES
# ============================================================
Write-Log "[+] Configuring firewall rules (minimal - workstation)..." "Green"

Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow

# Remove old CCDC rules if re-running
Get-NetFirewallRule -DisplayName "CCDC*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

# RDP for management
New-NetFirewallRule -DisplayName "CCDC-RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# ICMP for diagnostics
New-NetFirewallRule -DisplayName "CCDC-ICMPv4" -Direction Inbound -Protocol ICMPv4 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

Write-Log "[+] Firewall rules: RDP(3389), ICMPv4 allowed. All else blocked inbound." "Green"

# ============================================================
# 6. APPLY BASIC SECURITY POLICY
# ============================================================
Write-Log "[+] Exporting current security policy..." "Green"
$seceditExport = Join-Path $logDir "secedit_export_vm8_$timestamp.inf"
secedit /export /cfg $seceditExport /quiet 2>&1 | Out-Null

Write-Log "[+] Applying basic security policy..." "Green"
$secTemplate = Join-Path $logDir "harden_template_vm8_$timestamp.inf"
$secDB = Join-Path $logDir "harden_vm8_$timestamp.sdb"

$secContent = @"
[Unicode]
Unicode=yes

[System Access]
MinimumPasswordLength = 12
PasswordComplexity = 1
MaximumPasswordAge = 90
MinimumPasswordAge = 1
PasswordHistorySize = 5
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30

[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 1
AuditPrivilegeUse = 1
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 1
AuditAccountLogon = 3

[Version]
signature="`$CHICAGO`$"
Revision=1
"@

Set-Content -Path $secTemplate -Value $secContent -Encoding Unicode
secedit /configure /db $secDB /cfg $secTemplate /quiet 2>&1 | Out-Null
Write-Log "[+] Security policy applied." "Green"

# ============================================================
# 7. HARDEN NTLM / ANONYMOUS / LM
# ============================================================
Write-Log "[+] Hardening authentication settings..." "Green"
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
try {
    Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force
    Set-ItemProperty -Path $lsaPath -Name "NoLMHash" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
    Write-Log "[+] NTLMv2 enforced, LM hash disabled, anonymous restricted." "Green"
} catch {
    Write-Log "[-] Auth hardening partially failed: $_" "Red"
}

# ============================================================
# 8. DISABLE TEREDO
# ============================================================
Write-Log "[+] Disabling Teredo tunneling..." "Green"
try {
    netsh interface teredo set state disabled 2>&1 | Out-Null
    Write-Log "[+] Teredo disabled." "Green"
} catch {
    Write-Log "[-] Failed to disable Teredo: $_" "Red"
}

# ============================================================
# 9. DISABLE REMOTE ASSISTANCE (workstation hardening)
# ============================================================
Write-Log "[+] Disabling Remote Assistance..." "Green"
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Log "[+] Remote Assistance disabled." "Green"
} catch {
    Write-Log "[*] Could not disable Remote Assistance." "Yellow"
}

# ============================================================
# 10. DISABLE POWERSHELL V2 (reduces attack surface)
# ============================================================
Write-Log "[+] Disabling PowerShell v2 engine..." "Green"
try {
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Write-Log "[+] PowerShell v2 disabled." "Green"
} catch {
    Write-Log "[*] Could not disable PowerShell v2 (may already be disabled)." "Yellow"
}

# ============================================================
# 11. ENABLE POWERSHELL SCRIPT BLOCK LOGGING
# ============================================================
Write-Log "[+] Enabling PowerShell script block logging..." "Green"
try {
    $psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $psLogPath)) {
        New-Item -Path $psLogPath -Force | Out-Null
    }
    Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
    Write-Log "[+] Script block logging enabled." "Green"
} catch {
    Write-Log "[-] Failed to enable script block logging: $_" "Red"
}

# ============================================================
# 12. AUDIT - LOCAL ADMINISTRATORS
# ============================================================
Write-Log "" "White"
Write-Log "========== AUDIT: LOCAL ADMINISTRATORS ==========" "Cyan"
try {
    $localAdmins = net localgroup Administrators 2>&1
    $localAdmins | ForEach-Object { Write-Log "  $_" "White" }
} catch {
    Write-Log "[-] Could not enumerate local admins: $_" "Red"
}

# ============================================================
# 13. AUDIT - ACTIVE SESSIONS
# ============================================================
Write-Log "" "White"
Write-Log "========== AUDIT: ACTIVE SESSIONS ==========" "Cyan"
try {
    $sessions = qwinsta 2>&1
    $sessions | ForEach-Object { Write-Log "  $_" "White" }
} catch {
    Write-Log "[-] Could not enumerate sessions: $_" "Red"
}

# ============================================================
# 14. AUDIT - SCHEDULED TASKS (persistence check)
# ============================================================
Write-Log "" "White"
Write-Log "========== AUDIT: SCHEDULED TASKS (non-Microsoft) ==========" "Cyan"
try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled"
    }
    if ($tasks) {
        foreach ($task in $tasks) {
            $actions = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
            Write-Log "  [TASK] $($task.TaskPath)$($task.TaskName) - $actions" "Yellow"
        }
    } else {
        Write-Log "  No non-Microsoft scheduled tasks found." "Green"
    }
} catch {
    Write-Log "[-] Could not enumerate scheduled tasks: $_" "Red"
}

# ============================================================
# 15. AUDIT - SUSPICIOUS SERVICES
# ============================================================
Write-Log "" "White"
Write-Log "========== AUDIT: SUSPICIOUS AUTO-START SERVICES ==========" "Cyan"
try {
    $suspSvc = Get-WmiObject Win32_Service | Where-Object {
        $_.StartMode -eq "Auto" -and
        $_.PathName -and
        $_.PathName -notmatch "\\Windows\\system32\\" -and
        $_.PathName -notmatch "\\Windows\\SysWOW64\\" -and
        $_.PathName -notmatch "svchost\.exe" -and
        $_.PathName -notmatch "\\Microsoft\\" -and
        $_.PathName -notmatch "\\Program Files\\" -and
        $_.PathName -notmatch "\\Program Files \(x86\)\\"
    }
    if ($suspSvc) {
        foreach ($svc in $suspSvc) {
            Write-Log "  [SVC] $($svc.Name) - $($svc.DisplayName)" "Yellow"
            Write-Log "    Path: $($svc.PathName) | RunAs: $($svc.StartName)" "Yellow"
        }
    } else {
        Write-Log "  No suspicious services found." "Green"
    }
} catch {
    Write-Log "[-] Could not enumerate services: $_" "Red"
}

# ============================================================
# 16. AUDIT - REGISTRY RUN KEYS
# ============================================================
Write-Log "" "White"
Write-Log "========== AUDIT: REGISTRY RUN KEYS ==========" "Cyan"
$runKeyPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($keyPath in $runKeyPaths) {
    if (Test-Path $keyPath) {
        $entries = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
        $props = $entries.PSObject.Properties | Where-Object {
            $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")
        }
        if ($props) {
            Write-Log "  [$keyPath]" "Yellow"
            foreach ($p in $props) {
                Write-Log "    $($p.Name) = $($p.Value)" "Yellow"
            }
        }
    }
}

# ============================================================
# 17. AUDIT - NETWORK CONNECTIONS
# ============================================================
Write-Log "" "White"
Write-Log "========== AUDIT: ESTABLISHED NETWORK CONNECTIONS ==========" "Cyan"
try {
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
        $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        Write-Log "  $($c.LocalAddress):$($c.LocalPort) -> $($c.RemoteAddress):$($c.RemotePort) | PID: $($c.OwningProcess) ($($proc.ProcessName))" "White"
    }
} catch {
    Write-Log "[-] Could not enumerate connections: $_" "Red"
}

# ============================================================
# 18. SUMMARY
# ============================================================
Write-Log "" "White"
Write-Log "=============================================" "Cyan"
Write-Log "  HARDENING COMPLETE - VM8 Workstation (172.20.240.100)" "Cyan"
Write-Log "=============================================" "Cyan"
Write-Log "  [+] Administrator password changed" "Green"
Write-Log "  [+] UserOne password changed" "Green"
Write-Log "  [+] blueteam admin account created/updated" "Green"
Write-Log "  [+] Windows Firewall enabled (RDP + ICMP only inbound)" "Green"
Write-Log "  [+] Basic security policy applied" "Green"
Write-Log "  [+] NTLMv2 enforced, LM hash disabled" "Green"
Write-Log "  [+] Teredo disabled" "Green"
Write-Log "  [+] Remote Assistance disabled" "Green"
Write-Log "  [+] PowerShell v2 disabled, script block logging enabled" "Green"
Write-Log "  [+] Persistence mechanisms audited" "Green"
Write-Log "  [+] Full log: $logFile" "Green"
Write-Log "" "White"
Write-Log "  NOTE: This is NOT a scored machine. Focus on preventing" "Yellow"
Write-Log "  red team from using it as a pivot point." "Yellow"
Write-Log "" "White"
Write-Log "  NEXT STEP: Run audit_vm8_win11_wks.ps1 for interactive user review" "Yellow"
Write-Log "" "White"
