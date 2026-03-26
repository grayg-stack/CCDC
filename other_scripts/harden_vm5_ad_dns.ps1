#Requires -Version 5.1
<#
.SYNOPSIS
    MACCDC 2026 - Harden VM5: Server 2019 AD/DNS Domain Controller
    IP: 172.20.240.102 | Scored: DNS
.DESCRIPTION
    Box-specific hardening for the Active Directory Domain Controller and DNS server.
    - Changes Administrator password, creates blueteam admin
    - Configures Windows Firewall (DNS, LDAP, Kerberos, RDP, SMB allowed)
    - Applies hardened security policy (NTLMv2, password complexity, auditing)
    - Audits local/domain admins, services, tasks, sessions, run keys
    - Verifies DNS and AD services are running
    CRITICAL: Does NOT delete any AD user accounts (needed for POP3 scoring).
.PARAMETER NewPassword
    The new password to set for Administrator and blueteam accounts.
.NOTES
    Run on VM5 (172.20.240.102). Safe to run multiple times (idempotent).
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
$logFile = Join-Path $logDir "harden_vm5_ad_dns_$timestamp.log"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] $Message"
    Write-Host $entry -ForegroundColor $Color
    Add-Content -Path $logFile -Value $entry
}

Write-Log "=============================================" "Cyan"
Write-Log "  VM5 AD/DNS Hardening - MACCDC 2026" "Cyan"
Write-Log "  Target: 172.20.240.102 (Server 2019 AD/DNS)" "Cyan"
Write-Log "=============================================" "Cyan"
Write-Log ""

# ============================================================
# 1. CHANGE ADMINISTRATOR PASSWORD
# ============================================================
Write-Log "[+] Changing local Administrator password..." "Green"
try {
    $secPass = ConvertTo-SecureString $NewPassword -AsPlainText -Force
    # On a DC, local accounts are domain accounts
    Set-ADAccountPassword -Identity "Administrator" -NewPassword $secPass -Reset -ErrorAction Stop
    Write-Log "[+] Administrator password changed successfully." "Green"
} catch {
    Write-Log "[!] AD password change failed, trying net user fallback..." "Yellow"
    try {
        net user Administrator $NewPassword /domain 2>&1 | Out-Null
        Write-Log "[+] Administrator password changed via net user." "Green"
    } catch {
        Write-Log "[-] Failed to change Administrator password: $_" "Red"
    }
}

# ============================================================
# 2. CREATE BLUETEAM ADMIN ACCOUNT
# ============================================================
Write-Log "[+] Creating blueteam admin account..." "Green"
try {
    $existingUser = Get-ADUser -Filter {SamAccountName -eq "blueteam"} -ErrorAction SilentlyContinue
    if ($existingUser) {
        Write-Log "[*] blueteam account already exists. Resetting password." "Yellow"
        Set-ADAccountPassword -Identity "blueteam" -NewPassword $secPass -Reset
        Enable-ADAccount -Identity "blueteam"
    } else {
        New-ADUser -Name "blueteam" `
            -SamAccountName "blueteam" `
            -AccountPassword $secPass `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -Description "Blue Team Admin - CCDC 2026" `
            -ErrorAction Stop
        Write-Log "[+] blueteam account created." "Green"
    }
    # Add to Domain Admins
    try {
        Add-ADGroupMember -Identity "Domain Admins" -Members "blueteam" -ErrorAction SilentlyContinue
        Write-Log "[+] blueteam added to Domain Admins." "Green"
    } catch {
        Write-Log "[*] blueteam may already be in Domain Admins." "Yellow"
    }
} catch {
    Write-Log "[-] Failed to create blueteam account: $_" "Red"
}

# ============================================================
# 3. ENABLE WINDOWS FIREWALL
# ============================================================
Write-Log "[+] Enabling Windows Firewall for all profiles..." "Green"
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
    Write-Log "[+] Windows Firewall enabled on all profiles." "Green"
} catch {
    Write-Log "[-] Failed to enable firewall: $_" "Red"
}

# ============================================================
# 4. CONFIGURE FIREWALL RULES
# ============================================================
Write-Log "[+] Configuring firewall rules..." "Green"

# Set default inbound to Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow

# Remove old CCDC rules if re-running
Get-NetFirewallRule -DisplayName "CCDC*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

# DNS TCP
New-NetFirewallRule -DisplayName "CCDC-DNS-TCP" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# DNS UDP
New-NetFirewallRule -DisplayName "CCDC-DNS-UDP" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# LDAP
New-NetFirewallRule -DisplayName "CCDC-LDAP" -Direction Inbound -Protocol TCP -LocalPort 389 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# LDAP UDP
New-NetFirewallRule -DisplayName "CCDC-LDAP-UDP" -Direction Inbound -Protocol UDP -LocalPort 389 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# LDAPS
New-NetFirewallRule -DisplayName "CCDC-LDAPS" -Direction Inbound -Protocol TCP -LocalPort 636 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# Kerberos TCP
New-NetFirewallRule -DisplayName "CCDC-Kerberos-TCP" -Direction Inbound -Protocol TCP -LocalPort 88 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# Kerberos UDP
New-NetFirewallRule -DisplayName "CCDC-Kerberos-UDP" -Direction Inbound -Protocol UDP -LocalPort 88 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# RDP
New-NetFirewallRule -DisplayName "CCDC-RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# SMB (required for domain operations)
New-NetFirewallRule -DisplayName "CCDC-SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# Global Catalog
New-NetFirewallRule -DisplayName "CCDC-GC" -Direction Inbound -Protocol TCP -LocalPort 3268 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "CCDC-GC-SSL" -Direction Inbound -Protocol TCP -LocalPort 3269 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# AD replication / RPC
New-NetFirewallRule -DisplayName "CCDC-RPC-Endpoint" -Direction Inbound -Protocol TCP -LocalPort 135 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# AD Web Services
New-NetFirewallRule -DisplayName "CCDC-ADWS" -Direction Inbound -Protocol TCP -LocalPort 9389 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

Write-Log "[+] Firewall rules configured (DNS, LDAP, Kerberos, RDP, SMB, GC, RPC, ADWS)." "Green"

# ============================================================
# 5. EXPORT CURRENT SECURITY POLICY
# ============================================================
Write-Log "[+] Exporting current security policy..." "Green"
$seceditExport = Join-Path $logDir "secedit_export_vm5_$timestamp.inf"
secedit /export /cfg $seceditExport /quiet 2>&1 | Out-Null
Write-Log "[+] Security policy exported to $seceditExport" "Green"

# ============================================================
# 6. APPLY HARDENED SECURITY SETTINGS
# ============================================================
Write-Log "[+] Applying hardened security settings..." "Green"
$secTemplate = Join-Path $logDir "harden_template_vm5_$timestamp.inf"
$secDB = Join-Path $logDir "harden_vm5_$timestamp.sdb"

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
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 1
AuditDSAccess = 3
AuditAccountLogon = 3

[Version]
signature="`$CHICAGO`$"
Revision=1
"@

Set-Content -Path $secTemplate -Value $secContent -Encoding Unicode
secedit /configure /db $secDB /cfg $secTemplate /quiet 2>&1 | Out-Null
Write-Log "[+] Hardened security policy applied." "Green"

# ============================================================
# 7. SET LAN MANAGER AUTH TO NTLMv2 ONLY
# ============================================================
Write-Log "[+] Setting LAN Manager authentication to NTLMv2 only..." "Green"
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
try {
    Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force
    Write-Log "[+] NTLMv2 only authentication enforced (LmCompatibilityLevel=5)." "Green"
} catch {
    Write-Log "[-] Failed to set NTLMv2: $_" "Red"
}

# ============================================================
# 8. DISABLE LM HASH STORAGE
# ============================================================
Write-Log "[+] Disabling LM hash storage..." "Green"
try {
    Set-ItemProperty -Path $lsaPath -Name "NoLMHash" -Value 1 -Type DWord -Force
    Write-Log "[+] LM hash storage disabled." "Green"
} catch {
    Write-Log "[-] Failed to disable LM hash: $_" "Red"
}

# ============================================================
# 9. RESTRICT ANONYMOUS ACCESS
# ============================================================
Write-Log "[+] Restricting anonymous access..." "Green"
try {
    Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1 -Type DWord -Force
    Write-Log "[+] Anonymous access restricted." "Green"
} catch {
    Write-Log "[-] Failed to restrict anonymous access: $_" "Red"
}

# ============================================================
# 10. DISABLE TEREDO
# ============================================================
Write-Log "[+] Disabling Teredo tunneling..." "Green"
try {
    netsh interface teredo set state disabled 2>&1 | Out-Null
    Write-Log "[+] Teredo disabled." "Green"
} catch {
    Write-Log "[-] Failed to disable Teredo: $_" "Red"
}

# ============================================================
# 11. AUDIT - LOCAL ADMINISTRATORS
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
# 12. AUDIT - DOMAIN ADMINS
# ============================================================
Write-Log "" "White"
Write-Log "========== AUDIT: DOMAIN ADMINS ==========" "Cyan"
try {
    $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction Stop
    foreach ($da in $domainAdmins) {
        Write-Log "  $($da.SamAccountName) ($($da.objectClass))" "Yellow"
    }
} catch {
    Write-Log "[-] Could not enumerate Domain Admins: $_" "Red"
}

# ============================================================
# 13. AUDIT - RUNNING SERVICES
# ============================================================
Write-Log "" "White"
Write-Log "========== AUDIT: RUNNING SERVICES ==========" "Cyan"
$services = Get-Service | Where-Object { $_.Status -eq "Running" }
foreach ($svc in $services) {
    Write-Log "  [Running] $($svc.Name) - $($svc.DisplayName)" "White"
}

# ============================================================
# 14. AUDIT - SCHEDULED TASKS
# ============================================================
Write-Log "" "White"
Write-Log "========== AUDIT: SCHEDULED TASKS (non-Microsoft) ==========" "Cyan"
try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled"
    }
    if ($tasks) {
        foreach ($task in $tasks) {
            Write-Log "  [TASK] $($task.TaskPath)$($task.TaskName) - State: $($task.State)" "Yellow"
            $taskInfo = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            if ($taskInfo) {
                Write-Log "         Last Run: $($taskInfo.LastRunTime)" "White"
            }
        }
    } else {
        Write-Log "  No non-Microsoft scheduled tasks found." "Green"
    }
} catch {
    Write-Log "[-] Could not enumerate scheduled tasks: $_" "Red"
}

# ============================================================
# 15. AUDIT - ACTIVE SESSIONS
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
# 17. VERIFY DNS SERVICE
# ============================================================
Write-Log "" "White"
Write-Log "========== SERVICE CHECK: DNS ==========" "Cyan"
try {
    $dnsSvc = Get-Service -Name DNS -ErrorAction Stop
    if ($dnsSvc.Status -eq "Running") {
        Write-Log "[+] DNS Service is RUNNING." "Green"
    } else {
        Write-Log "[-] DNS Service is NOT running! Status: $($dnsSvc.Status)" "Red"
        Write-Log "[!] Attempting to start DNS service..." "Yellow"
        Start-Service -Name DNS -ErrorAction Stop
        Write-Log "[+] DNS Service started." "Green"
    }
} catch {
    Write-Log "[-] DNS Service check failed: $_" "Red"
}

# ============================================================
# 18. VERIFY ACTIVE DIRECTORY SERVICES
# ============================================================
Write-Log "" "White"
Write-Log "========== SERVICE CHECK: ACTIVE DIRECTORY ==========" "Cyan"
$adServices = @("NTDS", "kdc", "Netlogon", "DFSR", "W32Time", "ADWS")
foreach ($svcName in $adServices) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction Stop
        if ($svc.Status -eq "Running") {
            Write-Log "[+] $svcName ($($svc.DisplayName)) is RUNNING." "Green"
        } else {
            Write-Log "[-] $svcName is NOT running! Status: $($svc.Status)" "Red"
            Write-Log "[!] Attempting to start $svcName..." "Yellow"
            Start-Service -Name $svcName -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Log "[*] $svcName not found on this system (may be expected)." "Yellow"
    }
}

# ============================================================
# 19. REMINDER: DO NOT DELETE AD USERS
# ============================================================
Write-Log "" "White"
Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "Red"
Write-Log "!! CRITICAL: DO NOT DELETE AD USER ACCOUNTS        !!" "Red"
Write-Log "!! POP3 scoring depends on AD usernames existing.  !!" "Red"
Write-Log "!! Use audit_vm5_ad_dns.ps1 for interactive review !!" "Red"
Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "Red"

# ============================================================
# 20. SUMMARY
# ============================================================
Write-Log "" "White"
Write-Log "=============================================" "Cyan"
Write-Log "  HARDENING COMPLETE - VM5 AD/DNS (172.20.240.102)" "Cyan"
Write-Log "=============================================" "Cyan"
Write-Log "  [+] Administrator password changed" "Green"
Write-Log "  [+] blueteam admin account created/updated" "Green"
Write-Log "  [+] Windows Firewall enabled (all profiles)" "Green"
Write-Log "  [+] Firewall rules: DNS, LDAP, Kerberos, RDP, SMB, GC, RPC, ADWS" "Green"
Write-Log "  [+] Security policy exported and hardened" "Green"
Write-Log "  [+] NTLMv2 enforced, LM hash disabled" "Green"
Write-Log "  [+] Anonymous access restricted" "Green"
Write-Log "  [+] Teredo disabled" "Green"
Write-Log "  [+] DNS and AD services verified" "Green"
Write-Log "  [+] Full audit logged to $logFile" "Green"
Write-Log "" "White"
Write-Log "  NEXT STEP: Run audit_vm5_ad_dns.ps1 for interactive user review" "Yellow"
Write-Log "" "White"
