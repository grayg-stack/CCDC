#Requires -Version 5.1
<#
.SYNOPSIS
    MACCDC 2026 - Harden VM6: Server 2019 Web Server
    IP: 172.20.240.101 | Scored: HTTP, HTTPS
.DESCRIPTION
    Box-specific hardening for the Windows Web Server (IIS).
    - Changes Administrator password, creates blueteam admin
    - Configures Windows Firewall (HTTP 80, HTTPS 443, RDP 3389 allowed)
    - Verifies IIS is running and serving content
    - Exports IIS config, disables directory browsing, checks for web shells
    - Applies hardened security policy
    - Audits admins, sessions, services, tasks, run keys
    CRITICAL: Does NOT change web content (scoring engine checks specific content).
.PARAMETER NewPassword
    The new password to set for Administrator and blueteam accounts.
.NOTES
    Run on VM6 (172.20.240.101). Safe to run multiple times (idempotent).
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
$logFile = Join-Path $logDir "harden_vm6_web_$timestamp.log"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] $Message"
    Write-Host $entry -ForegroundColor $Color
    Add-Content -Path $logFile -Value $entry
}

Write-Log "=============================================" "Cyan"
Write-Log "  VM6 Web Server Hardening - MACCDC 2026" "Cyan"
Write-Log "  Target: 172.20.240.101 (Server 2019 Web)" "Cyan"
Write-Log "=============================================" "Cyan"
Write-Log ""

# ============================================================
# 1. CHANGE ADMINISTRATOR PASSWORD
# ============================================================
Write-Log "[+] Changing Administrator password..." "Green"
try {
    $secPass = ConvertTo-SecureString $NewPassword -AsPlainText -Force
    # Try AD method first (if domain-joined)
    Set-ADAccountPassword -Identity "Administrator" -NewPassword $secPass -Reset -ErrorAction Stop
    Write-Log "[+] Administrator password changed (AD)." "Green"
} catch {
    try {
        # Fall back to local user method
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
        Write-Log "[*] blueteam account already exists. Resetting password." "Yellow"
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

# HTTP
New-NetFirewallRule -DisplayName "CCDC-HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# HTTPS
New-NetFirewallRule -DisplayName "CCDC-HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
# RDP
New-NetFirewallRule -DisplayName "CCDC-RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

Write-Log "[+] Firewall rules: HTTP(80), HTTPS(443), RDP(3389) allowed. All else blocked." "Green"

# ============================================================
# 5. VERIFY IIS IS RUNNING
# ============================================================
Write-Log "[+] Verifying IIS (W3SVC) service..." "Green"
try {
    $iisSvc = Get-Service -Name W3SVC -ErrorAction Stop
    if ($iisSvc.Status -eq "Running") {
        Write-Log "[+] IIS (W3SVC) is RUNNING." "Green"
    } else {
        Write-Log "[-] IIS is NOT running! Attempting to start..." "Red"
        Start-Service -Name W3SVC -ErrorAction Stop
        Write-Log "[+] IIS started." "Green"
    }
} catch {
    Write-Log "[-] IIS service check failed: $_" "Red"
}

# ============================================================
# 6. CHECK IIS BINDINGS
# ============================================================
Write-Log "[+] Checking IIS bindings..." "Green"
try {
    Import-Module WebAdministration -ErrorAction Stop
    $bindings = Get-WebBinding -ErrorAction Stop
    foreach ($b in $bindings) {
        Write-Log "  Binding: $($b.protocol)://$($b.bindingInformation)" "White"
    }
} catch {
    Write-Log "[*] WebAdministration module not available, using appcmd..." "Yellow"
    try {
        $appcmd = & "$env:SystemRoot\system32\inetsrv\appcmd.exe" list site 2>&1
        $appcmd | ForEach-Object { Write-Log "  $_" "White" }
    } catch {
        Write-Log "[-] Could not enumerate IIS bindings: $_" "Red"
    }
}

# ============================================================
# 7. EXPORT IIS CONFIGURATION
# ============================================================
Write-Log "[+] Exporting IIS configuration..." "Green"
$iisExportDir = Join-Path $logDir "iis_config_$timestamp"
try {
    if (-not (Test-Path $iisExportDir)) { New-Item -ItemType Directory -Path $iisExportDir -Force | Out-Null }
    # Export applicationHost.config
    $appHostPath = "$env:SystemRoot\system32\inetsrv\config\applicationHost.config"
    if (Test-Path $appHostPath) {
        Copy-Item $appHostPath -Destination (Join-Path $iisExportDir "applicationHost.config.bak") -Force
        Write-Log "[+] applicationHost.config backed up." "Green"
    }
    # Export web.config from default site if it exists
    $defaultWebRoot = "C:\inetpub\wwwroot"
    if (Test-Path "$defaultWebRoot\web.config") {
        Copy-Item "$defaultWebRoot\web.config" -Destination (Join-Path $iisExportDir "wwwroot_web.config.bak") -Force
        Write-Log "[+] wwwroot web.config backed up." "Green"
    }
} catch {
    Write-Log "[-] IIS config export failed: $_" "Red"
}

# ============================================================
# 8. DISABLE IIS DIRECTORY BROWSING
# ============================================================
Write-Log "[+] Disabling IIS directory browsing..." "Green"
try {
    & "$env:SystemRoot\system32\inetsrv\appcmd.exe" set config -section:directoryBrowse -enabled:false 2>&1 | Out-Null
    Write-Log "[+] Directory browsing disabled." "Green"
} catch {
    Write-Log "[-] Failed to disable directory browsing: $_" "Red"
}

# ============================================================
# 9. DISABLE WEBDAV
# ============================================================
Write-Log "[+] Disabling WebDAV if present..." "Green"
try {
    # Remove WebDAV module from IIS
    & "$env:SystemRoot\system32\inetsrv\appcmd.exe" set config -section:handlers -"[name='WebDAV']" 2>&1 | Out-Null
    & "$env:SystemRoot\system32\inetsrv\appcmd.exe" set config -section:modules -"[name='WebDAVModule']" 2>&1 | Out-Null
    Write-Log "[+] WebDAV handlers/modules removed (if they existed)." "Green"
} catch {
    Write-Log "[*] WebDAV removal attempt completed (may not have been present)." "Yellow"
}

# ============================================================
# 10. CHECK FOR WEB SHELLS
# ============================================================
Write-Log "[+] Scanning for potential web shells in IIS content directories..." "Green"
$webRoots = @("C:\inetpub\wwwroot")
# Also check other sites
try {
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $sites = Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue
    foreach ($site in $sites) {
        $physPath = $site.physicalPath -replace '%SystemDrive%', $env:SystemDrive
        if ($physPath -and (Test-Path $physPath) -and $physPath -notin $webRoots) {
            $webRoots += $physPath
        }
    }
} catch { }

$shellPatterns = @("*.aspx", "*.asp", "*.ashx", "*.asmx", "*.php", "*.jsp", "*.war", "*.cmd", "*.bat", "*.ps1", "*.exe")
$shellKeywords = @("eval", "exec", "cmd.exe", "powershell", "WScript.Shell", "System.Diagnostics.Process", "WebShell", "reverse", "bind")

foreach ($root in $webRoots) {
    Write-Log "  Scanning: $root" "White"
    if (Test-Path $root) {
        foreach ($pattern in $shellPatterns) {
            $files = Get-ChildItem -Path $root -Filter $pattern -Recurse -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                # Check file contents for suspicious keywords (only text files)
                $suspicious = $false
                if ($file.Extension -in @(".aspx", ".asp", ".ashx", ".asmx", ".php", ".jsp")) {
                    try {
                        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                        foreach ($kw in $shellKeywords) {
                            if ($content -match $kw) {
                                $suspicious = $true
                                break
                            }
                        }
                    } catch { }
                } elseif ($file.Extension -in @(".exe", ".cmd", ".bat", ".ps1")) {
                    $suspicious = $true
                }

                if ($suspicious) {
                    Write-Log "  [!!!] POTENTIAL WEB SHELL: $($file.FullName)" "Red"
                    Write-Log "        Size: $($file.Length) bytes | Modified: $($file.LastWriteTime)" "Red"
                } else {
                    Write-Log "  [OK]  $($file.FullName) ($($file.Length) bytes)" "White"
                }
            }
        }
    }
}

# ============================================================
# 11. EXPORT AND APPLY SECURITY POLICY
# ============================================================
Write-Log "[+] Exporting current security policy..." "Green"
$seceditExport = Join-Path $logDir "secedit_export_vm6_$timestamp.inf"
secedit /export /cfg $seceditExport /quiet 2>&1 | Out-Null

Write-Log "[+] Applying hardened security settings..." "Green"
$secTemplate = Join-Path $logDir "harden_template_vm6_$timestamp.inf"
$secDB = Join-Path $logDir "harden_vm6_$timestamp.sdb"

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
# 14. AUDIT - ADMINISTRATORS
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
# 19. REMINDER - DO NOT CHANGE WEB CONTENT
# ============================================================
Write-Log "" "White"
Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "Red"
Write-Log "!! CRITICAL: DO NOT MODIFY WEB CONTENT            !!" "Red"
Write-Log "!! Scoring engine checks specific HTTP/HTTPS pages !!" "Red"
Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "Red"

# ============================================================
# 20. SUMMARY
# ============================================================
Write-Log "" "White"
Write-Log "=============================================" "Cyan"
Write-Log "  HARDENING COMPLETE - VM6 Web Server (172.20.240.101)" "Cyan"
Write-Log "=============================================" "Cyan"
Write-Log "  [+] Administrator password changed" "Green"
Write-Log "  [+] blueteam admin account created/updated" "Green"
Write-Log "  [+] Windows Firewall enabled (all profiles)" "Green"
Write-Log "  [+] Firewall rules: HTTP(80), HTTPS(443), RDP(3389)" "Green"
Write-Log "  [+] IIS verified running" "Green"
Write-Log "  [+] IIS config backed up, directory browsing disabled" "Green"
Write-Log "  [+] WebDAV disabled" "Green"
Write-Log "  [+] Web shell scan completed" "Green"
Write-Log "  [+] Security policy hardened" "Green"
Write-Log "  [+] NTLMv2 enforced, LM hash disabled, anon restricted" "Green"
Write-Log "  [+] Teredo disabled" "Green"
Write-Log "  [+] Full audit logged to $logFile" "Green"
Write-Log "" "White"
Write-Log "  NEXT STEP: Run audit_vm6_win_web.ps1 for interactive user review" "Yellow"
Write-Log "" "White"
