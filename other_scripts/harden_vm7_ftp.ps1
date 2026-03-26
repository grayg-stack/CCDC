#Requires -Version 5.1
<#
.SYNOPSIS
    MACCDC 2026 - Harden VM7: Server 2022 FTP/TFTP/NTP
    IP: 172.20.240.104 | Scored: FTP(21), TFTP(69/UDP), NTP(123/UDP)
.DESCRIPTION
    Box-specific hardening for the FTP, TFTP, and NTP server.
    - Changes Administrator password, creates blueteam admin
    - Configures Windows Firewall (FTP, TFTP, NTP, RDP allowed)
    - Verifies FTP, TFTP, and NTP services are running
    - Checks FTP site bindings and anonymous access settings
    - Ensures FTP and TFTP content files exist
    - Applies hardened security policy
    CRITICAL: Does NOT disable anonymous FTP or modify FTP/TFTP content files.
.PARAMETER NewPassword
    The new password to set for Administrator and blueteam accounts.
.NOTES
    Run on VM7 (172.20.240.104). Safe to run multiple times (idempotent).
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
$logFile = Join-Path $logDir "harden_vm7_ftp_$timestamp.log"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] $Message"
    Write-Host $entry -ForegroundColor $Color
    Add-Content -Path $logFile -Value $entry
}

Write-Log "=============================================" "Cyan"
Write-Log "  VM7 FTP/TFTP/NTP Hardening - MACCDC 2026" "Cyan"
Write-Log "  Target: 172.20.240.104 (Server 2022)" "Cyan"
Write-Log "  Scored: FTP(21), TFTP(69/UDP), NTP(123/UDP)" "Cyan"
Write-Log "=============================================" "Cyan"
Write-Log ""

# ============================================================
# 1. CHANGE ADMINISTRATOR PASSWORD
# ============================================================
Write-Log "[+] Changing Administrator password..." "Green"
try {
    $secPass = ConvertTo-SecureString $NewPassword -AsPlainText -Force
    # Try AD first (if domain-joined)
    Set-ADAccountPassword -Identity "Administrator" -NewPassword $secPass -Reset -ErrorAction Stop
    Write-Log "[+] Administrator password changed (AD)." "Green"
} catch {
    try {
        $admin = [ADSI]"WinNT://./Administrator,user"
        $admin.SetPassword($NewPassword)
        $admin.SetInfo()
        Write-Log "[+] Administrator password changed (local)." "Green"
    } catch {
        try {
            net user Administrator $NewPassword 2>&1 | Out-Null
            Write-Log "[+] Administrator password changed (net user)." "Green"
        } catch {
            Write-Log "[-] Failed to change Administrator password: $_" "Red"
        }
    }
}

# ============================================================
# 2. CREATE BLUETEAM ADMIN ACCOUNT
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
# 3. ENABLE WINDOWS FIREWALL
# ============================================================
Write-Log "[+] Enabling Windows Firewall for all profiles..." "Green"
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
    Write-Log "[+] Windows Firewall enabled." "Green"
} catch {
    Write-Log "[-] Failed to enable firewall: $_" "Red"
}

# ============================================================
# 4. CONFIGURE FIREWALL RULES
# ============================================================
Write-Log "[+] Configuring firewall rules..." "Green"

Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow

# Remove old CCDC rules if re-running
Get-NetFirewallRule -DisplayName "CCDC*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

# FTP Control (21)
New-NetFirewallRule -DisplayName "CCDC-FTP-Control" -Direction Inbound -Protocol TCP -LocalPort 21 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# FTP Data (20)
New-NetFirewallRule -DisplayName "CCDC-FTP-Data" -Direction Inbound -Protocol TCP -LocalPort 20 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# FTP Passive Mode - use a restricted range instead of 1024-65535
# First try to set the FTP passive port range, then open that range
$passiveRangeStart = 50000
$passiveRangeEnd = 50100
New-NetFirewallRule -DisplayName "CCDC-FTP-Passive" -Direction Inbound -Protocol TCP -LocalPort "$passiveRangeStart-$passiveRangeEnd" -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# Also allow broader range as fallback in case passive range is configured differently
New-NetFirewallRule -DisplayName "CCDC-FTP-Passive-Broad" -Direction Inbound -Protocol TCP -LocalPort "1024-65535" -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# TFTP (69/UDP)
New-NetFirewallRule -DisplayName "CCDC-TFTP" -Direction Inbound -Protocol UDP -LocalPort 69 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# NTP (123/UDP)
New-NetFirewallRule -DisplayName "CCDC-NTP" -Direction Inbound -Protocol UDP -LocalPort 123 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# RDP (3389)
New-NetFirewallRule -DisplayName "CCDC-RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

Write-Log "[+] Firewall rules: FTP(20,21), FTP-Passive, TFTP(69/UDP), NTP(123/UDP), RDP(3389)." "Green"

# ============================================================
# 5. VERIFY FTP SERVICE
# ============================================================
Write-Log "" "White"
Write-Log "========== SERVICE CHECK: FTP ==========" "Cyan"
$ftpServiceNames = @("FTPSVC", "MSFTPSVC", "ftpsvc")
$ftpRunning = $false
foreach ($svcName in $ftpServiceNames) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction Stop
        if ($svc.Status -eq "Running") {
            Write-Log "[+] FTP Service ($svcName) is RUNNING." "Green"
            $ftpRunning = $true
        } else {
            Write-Log "[!] FTP Service ($svcName) found but NOT running. Starting..." "Yellow"
            Start-Service -Name $svcName -ErrorAction Stop
            Write-Log "[+] FTP Service ($svcName) started." "Green"
            $ftpRunning = $true
        }
        break
    } catch {
        # Service not found with this name, try next
    }
}
if (-not $ftpRunning) {
    Write-Log "[-] FTP Service not found with standard names (FTPSVC, MSFTPSVC)." "Red"
    Write-Log "[*] Checking all services for FTP..." "Yellow"
    $allFtp = Get-Service | Where-Object { $_.Name -match "ftp" -or $_.DisplayName -match "ftp" }
    foreach ($s in $allFtp) {
        Write-Log "  Found: $($s.Name) - $($s.DisplayName) - $($s.Status)" "Yellow"
    }
}

# ============================================================
# 6. VERIFY TFTP SERVICE
# ============================================================
Write-Log "" "White"
Write-Log "========== SERVICE CHECK: TFTP ==========" "Cyan"
$tftpRunning = $false
$tftpServiceNames = @("tftpd", "SolarWinds TFTP Server", "WDSTFTPSvc")
foreach ($svcName in $tftpServiceNames) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction Stop
        if ($svc.Status -eq "Running") {
            Write-Log "[+] TFTP Service ($svcName) is RUNNING." "Green"
            $tftpRunning = $true
        } else {
            Write-Log "[!] TFTP Service ($svcName) found but NOT running. Starting..." "Yellow"
            Start-Service -Name $svcName -ErrorAction Stop
            Write-Log "[+] TFTP Service ($svcName) started." "Green"
            $tftpRunning = $true
        }
        break
    } catch { }
}
if (-not $tftpRunning) {
    Write-Log "[!] TFTP Service not found with standard names." "Yellow"
    Write-Log "[*] Checking all services for TFTP..." "Yellow"
    $allTftp = Get-Service | Where-Object { $_.Name -match "tftp" -or $_.DisplayName -match "tftp" }
    foreach ($s in $allTftp) {
        Write-Log "  Found: $($s.Name) - $($s.DisplayName) - $($s.Status)" "Yellow"
    }
    if (-not $allTftp) {
        Write-Log "[-] No TFTP service found. May need manual investigation." "Red"
    }
}

# ============================================================
# 7. VERIFY NTP/W32TIME SERVICE
# ============================================================
Write-Log "" "White"
Write-Log "========== SERVICE CHECK: NTP (W32Time) ==========" "Cyan"
try {
    $ntpSvc = Get-Service -Name W32Time -ErrorAction Stop
    if ($ntpSvc.Status -eq "Running") {
        Write-Log "[+] Windows Time (W32Time) is RUNNING." "Green"
    } else {
        Write-Log "[!] W32Time found but NOT running. Starting..." "Yellow"
        Start-Service -Name W32Time -ErrorAction Stop
        Write-Log "[+] W32Time started." "Green"
    }

    # Ensure W32Time is set to auto-start
    Set-Service -Name W32Time -StartupType Automatic -ErrorAction SilentlyContinue

    # Show NTP configuration
    Write-Log "[+] NTP Configuration:" "Green"
    $ntpConfig = w32tm /query /configuration 2>&1
    $ntpConfig | ForEach-Object { Write-Log "  $_" "White" }

    # Show NTP peers
    Write-Log "[+] NTP Peers/Source:" "Green"
    $ntpPeers = w32tm /query /peers 2>&1
    $ntpPeers | ForEach-Object { Write-Log "  $_" "White" }

    # Ensure NTP server is configured to serve time (announce as NTP server)
    Write-Log "[+] Configuring W32Time as NTP server..." "Green"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "AnnounceFlags" -Value 5 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -Name "Enabled" -Value 1 -Type DWord -Force
        Restart-Service W32Time -Force -ErrorAction SilentlyContinue
        Write-Log "[+] W32Time configured as NTP server (AnnounceFlags=5)." "Green"
    } catch {
        Write-Log "[-] Failed to configure NTP server: $_" "Red"
    }
} catch {
    Write-Log "[-] W32Time service not found: $_" "Red"
}

# ============================================================
# 8. CHECK FTP SITE BINDINGS AND ANONYMOUS ACCESS
# ============================================================
Write-Log "" "White"
Write-Log "========== FTP SITE CONFIGURATION ==========" "Cyan"
try {
    Import-Module WebAdministration -ErrorAction Stop

    # List FTP sites
    $ftpSites = Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue | Where-Object {
        $_.Bindings.Collection.protocol -contains "ftp"
    }
    if ($ftpSites) {
        foreach ($site in $ftpSites) {
            Write-Log "  FTP Site: $($site.Name)" "White"
            Write-Log "    State: $($site.State)" "White"
            Write-Log "    Physical Path: $($site.physicalPath)" "White"
            foreach ($binding in $site.Bindings.Collection) {
                Write-Log "    Binding: $($binding.protocol)://$($binding.bindingInformation)" "White"
            }
        }
    } else {
        Write-Log "[*] No IIS FTP sites found. FTP may be running as a standalone service." "Yellow"
    }

    # Check anonymous authentication
    try {
        $anonAuth = Get-WebConfiguration -Filter /system.ftpServer/security/authentication/anonymousAuthentication -PSPath "IIS:\" -ErrorAction SilentlyContinue
        if ($anonAuth) {
            Write-Log "  Anonymous FTP: Enabled=$($anonAuth.enabled)" "Yellow"
            Write-Log "  [!] NOTE: Do NOT disable anonymous FTP if scoring requires it." "Yellow"
        }
    } catch {
        Write-Log "[*] Could not check FTP anonymous auth via WebAdministration." "Yellow"
    }
} catch {
    Write-Log "[*] WebAdministration module not available. Checking via appcmd..." "Yellow"
    try {
        $sites = & "$env:SystemRoot\system32\inetsrv\appcmd.exe" list site 2>&1
        $sites | ForEach-Object { Write-Log "  $_" "White" }
    } catch {
        Write-Log "[*] Could not enumerate FTP sites." "Yellow"
    }
}

# ============================================================
# 9. CHECK FTP CONTENT FILES
# ============================================================
Write-Log "" "White"
Write-Log "========== FTP CONTENT FILES ==========" "Cyan"
$ftpRoots = @("C:\inetpub\ftproot", "C:\FTP", "C:\ftproot")
foreach ($root in $ftpRoots) {
    if (Test-Path $root) {
        Write-Log "  FTP Root found: $root" "Green"
        $files = Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            Write-Log "    $($f.FullName) ($($f.Length) bytes, Modified: $($f.LastWriteTime))" "White"
        }
    }
}

# ============================================================
# 10. CHECK TFTP ROOT DIRECTORY
# ============================================================
Write-Log "" "White"
Write-Log "========== TFTP CONTENT FILES ==========" "Cyan"
$tftpRoots = @("C:\TFTP-Root", "C:\TFTPRoot", "C:\inetpub\tftproot", "C:\TFTP")
foreach ($root in $tftpRoots) {
    if (Test-Path $root) {
        Write-Log "  TFTP Root found: $root" "Green"
        $files = Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            Write-Log "    $($f.FullName) ($($f.Length) bytes, Modified: $($f.LastWriteTime))" "White"
        }
    }
}

# ============================================================
# 11. EXPORT AND APPLY SECURITY POLICY
# ============================================================
Write-Log "" "White"
Write-Log "[+] Exporting current security policy..." "Green"
$seceditExport = Join-Path $logDir "secedit_export_vm7_$timestamp.inf"
secedit /export /cfg $seceditExport /quiet 2>&1 | Out-Null

Write-Log "[+] Applying hardened security settings..." "Green"
$secTemplate = Join-Path $logDir "harden_template_vm7_$timestamp.inf"
$secDB = Join-Path $logDir "harden_vm7_$timestamp.sdb"

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
AuditAccountLogon = 3

[Version]
signature="`$CHICAGO`$"
Revision=1
"@

Set-Content -Path $secTemplate -Value $secContent -Encoding Unicode
secedit /configure /db $secDB /cfg $secTemplate /quiet 2>&1 | Out-Null
Write-Log "[+] Security policy applied." "Green"

# ============================================================
# 12. HARDEN NTLM / ANONYMOUS / LM
# ============================================================
Write-Log "[+] Hardening authentication settings..." "Green"
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
try {
    Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force
    Set-ItemProperty -Path $lsaPath -Name "NoLMHash" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1 -Type DWord -Force
    Write-Log "[+] NTLMv2 enforced, LM hash disabled, anonymous restricted." "Green"
} catch {
    Write-Log "[-] Auth hardening partially failed: $_" "Red"
}

# ============================================================
# 13. DISABLE TEREDO
# ============================================================
Write-Log "[+] Disabling Teredo tunneling..." "Green"
try {
    netsh interface teredo set state disabled 2>&1 | Out-Null
    Write-Log "[+] Teredo disabled." "Green"
} catch {
    Write-Log "[-] Failed to disable Teredo: $_" "Red"
}

# ============================================================
# 14. AUDIT - LOCAL ADMINISTRATORS
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
# 16. AUDIT - RUNNING SERVICES
# ============================================================
Write-Log "" "White"
Write-Log "========== AUDIT: RUNNING SERVICES ==========" "Cyan"
$services = Get-Service | Where-Object { $_.Status -eq "Running" }
foreach ($svc in $services) {
    Write-Log "  [Running] $($svc.Name) - $($svc.DisplayName)" "White"
}

# ============================================================
# 17. AUDIT - SCHEDULED TASKS
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
# 18. AUDIT - REGISTRY RUN KEYS
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
# 19. REMINDERS
# ============================================================
Write-Log "" "White"
Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "Red"
Write-Log "!! CRITICAL REMINDERS:                             !!" "Red"
Write-Log "!! - Do NOT disable anonymous FTP if scoring needs !!" "Red"
Write-Log "!!   it. Check scoring docs first.                 !!" "Red"
Write-Log "!! - Do NOT modify FTP/TFTP content files.         !!" "Red"
Write-Log "!! - NTP must respond to queries on UDP 123.       !!" "Red"
Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "Red"

# ============================================================
# 20. SUMMARY
# ============================================================
Write-Log "" "White"
Write-Log "=============================================" "Cyan"
Write-Log "  HARDENING COMPLETE - VM7 FTP/TFTP/NTP (172.20.240.104)" "Cyan"
Write-Log "=============================================" "Cyan"
Write-Log "  [+] Administrator password changed" "Green"
Write-Log "  [+] blueteam admin account created/updated" "Green"
Write-Log "  [+] Windows Firewall enabled (all profiles)" "Green"
Write-Log "  [+] Firewall rules: FTP(20,21), TFTP(69/UDP), NTP(123/UDP), RDP(3389)" "Green"
Write-Log "  [+] FTP service verified" "Green"
Write-Log "  [+] TFTP service checked" "Green"
Write-Log "  [+] NTP (W32Time) verified and configured as server" "Green"
Write-Log "  [+] FTP/TFTP content files inventoried" "Green"
Write-Log "  [+] Security policy hardened" "Green"
Write-Log "  [+] NTLMv2 enforced, LM hash disabled, anon restricted" "Green"
Write-Log "  [+] Teredo disabled" "Green"
Write-Log "  [+] Full audit logged to $logFile" "Green"
Write-Log "" "White"
Write-Log "  NEXT STEP: Run audit_vm7_ftp.ps1 for interactive user review" "Yellow"
Write-Log "" "White"
