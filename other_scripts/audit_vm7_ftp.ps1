#Requires -Version 5.1
<#
.SYNOPSIS
    MACCDC 2026 - Interactive User Audit for VM7: FTP/TFTP/NTP Server
    IP: 172.20.240.104
.DESCRIPTION
    Interactive audit of all local user accounts on the FTP server.
    - Lists local users with details and color coding
    - Shows FTP site configuration (authorization, anonymous access)
    - Flags FTP service accounts
    - Shows NTFS permissions on FTP root
    - Shows NTP configuration
    - Prompts for action on each user
.NOTES
    Run on VM7 (172.20.240.104). Interactive - requires operator input.
#>

# --- Elevate to Administrator if not already ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Not running as Administrator. Relaunching elevated..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# --- Setup logging ---
$logDir = "C:\hardening_logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $logDir "audit_vm7_ftp_$timestamp.log"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] $Message"
    Write-Host $entry -ForegroundColor $Color
    Add-Content -Path $logFile -Value $entry
}

Write-Log "=============================================" "Cyan"
Write-Log "  VM7 FTP/TFTP/NTP Interactive User Audit" "Cyan"
Write-Log "  MACCDC 2026 - 172.20.240.104" "Cyan"
Write-Log "=============================================" "Cyan"
Write-Log ""

# ============================================================
# FTP SITE CONFIGURATION
# ============================================================
Write-Log "========== FTP SITE CONFIGURATION ==========" "Cyan"
$ftpServiceAccounts = @()

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

            # Check authorization rules
            try {
                $authRules = Get-WebConfiguration -Filter "/system.ftpServer/security/authorization" -PSPath "IIS:\Sites\$($site.Name)" -ErrorAction SilentlyContinue
                if ($authRules -and $authRules.Collection) {
                    foreach ($rule in $authRules.Collection) {
                        Write-Log "    Auth Rule: Access=$($rule.accessType), Users=$($rule.users), Roles=$($rule.roles), Permissions=$($rule.permissions)" "White"
                    }
                }
            } catch {
                Write-Log "    [*] Could not enumerate FTP authorization rules." "Yellow"
            }

            # Check anonymous authentication
            try {
                $anonAuth = Get-WebConfiguration -Filter "/system.ftpServer/security/authentication/anonymousAuthentication" -PSPath "IIS:\Sites\$($site.Name)" -ErrorAction SilentlyContinue
                if ($anonAuth) {
                    $status = if ($anonAuth.enabled) { "ENABLED" } else { "DISABLED" }
                    $color = if ($anonAuth.enabled) { "Yellow" } else { "Green" }
                    Write-Log "    Anonymous Authentication: $status (username: $($anonAuth.userName))" $color
                    if ($anonAuth.userName) {
                        $shortName = $anonAuth.userName -replace "^.*\\", ""
                        $ftpServiceAccounts += $shortName
                    }
                }
            } catch {
                Write-Log "    [*] Could not check FTP anonymous auth." "Yellow"
            }

            # Check basic authentication
            try {
                $basicAuth = Get-WebConfiguration -Filter "/system.ftpServer/security/authentication/basicAuthentication" -PSPath "IIS:\Sites\$($site.Name)" -ErrorAction SilentlyContinue
                if ($basicAuth) {
                    $status = if ($basicAuth.enabled) { "ENABLED" } else { "DISABLED" }
                    Write-Log "    Basic Authentication: $status" "White"
                }
            } catch { }
        }
    } else {
        Write-Log "  No IIS-based FTP sites found. FTP may be standalone." "Yellow"
    }

    # Check IIS app pool identities used by FTP
    $appPools = Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue
    foreach ($pool in $appPools) {
        $identity = $pool.processModel.userName
        if ($identity) {
            $shortName = $identity -replace "^.*\\", ""
            $ftpServiceAccounts += $shortName
        }
    }
} catch {
    Write-Log "[*] WebAdministration module not available." "Yellow"
    try {
        $appcmd = & "$env:SystemRoot\system32\inetsrv\appcmd.exe" list site 2>&1
        $appcmd | ForEach-Object { Write-Log "  $_" "White" }
    } catch {
        Write-Log "[*] Could not enumerate FTP config." "Yellow"
    }
}
Write-Log "" "White"

# ============================================================
# NTFS PERMISSIONS ON FTP ROOT
# ============================================================
Write-Log "========== NTFS PERMISSIONS ON FTP ROOT ==========" "Cyan"
$ftpRoots = @("C:\inetpub\ftproot", "C:\FTP", "C:\ftproot")
foreach ($root in $ftpRoots) {
    if (Test-Path $root) {
        Write-Log "  FTP Root: $root" "Green"
        try {
            $acl = Get-Acl $root -ErrorAction Stop
            foreach ($ace in $acl.Access) {
                $color = "White"
                if ($ace.FileSystemRights -match "FullControl|Modify|Write") { $color = "Yellow" }
                Write-Log "    $($ace.IdentityReference) - $($ace.FileSystemRights) ($($ace.AccessControlType))" $color
            }
        } catch {
            Write-Log "  [-] Could not get ACL: $_" "Red"
        }
    }
}
Write-Log "" "White"

# ============================================================
# NTP CONFIGURATION
# ============================================================
Write-Log "========== NTP CONFIGURATION ==========" "Cyan"
try {
    Write-Log "  W32Time Configuration:" "White"
    $ntpConfig = w32tm /query /configuration 2>&1
    $ntpConfig | ForEach-Object { Write-Log "    $_" "White" }

    Write-Log "" "White"
    Write-Log "  W32Time Status:" "White"
    $ntpStatus = w32tm /query /status 2>&1
    $ntpStatus | ForEach-Object { Write-Log "    $_" "White" }
} catch {
    Write-Log "[-] Could not query NTP config: $_" "Red"
}
Write-Log "" "White"

# ============================================================
# LOCAL USERS
# ============================================================
Write-Log "========== LOCAL USERS ==========" "Cyan"
try {
    $localUsers = Get-LocalUser -ErrorAction Stop
    foreach ($user in $localUsers) {
        # Get group memberships
        $groups = @()
        Get-LocalGroup | ForEach-Object {
            $grpName = $_.Name
            try {
                $members = Get-LocalGroupMember -Group $grpName -ErrorAction SilentlyContinue
                if ($members.Name -match "\\$([regex]::Escape($user.Name))$") { $groups += $grpName }
            } catch { }
        }
        $groupStr = $groups -join ", "

        # Color coding
        $color = "Green"
        if ($groups -contains "Administrators") { $color = "Red" }
        if (-not $user.Enabled) { $color = "Yellow" }

        # Check if FTP service account
        $isServiceAccount = $user.Name -in $ftpServiceAccounts

        Write-Log "  -----------------------------------------------" "White"
        Write-Log "  User: $($user.Name)" $color
        if ($isServiceAccount) {
            Write-Log "    ** FTP SERVICE ACCOUNT - DO NOT DELETE **" "Red"
        }
        Write-Log "    Enabled: $($user.Enabled)" $color
        Write-Log "    Last Logon: $($user.LastLogon)" $color
        Write-Log "    Description: $($user.Description)" $color
        Write-Log "    Groups: $groupStr" $color
        Write-Log "    Password Last Set: $($user.PasswordLastSet)" $color

        # Skip known accounts
        $skipAccounts = @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount", "blueteam")
        if ($user.Name -in $skipAccounts) {
            Write-Log "    [Built-in/known account - auto-skipping]" "Yellow"
            continue
        }
        if ($isServiceAccount) {
            Write-Log "    [FTP service account - auto-skipping for safety]" "Yellow"
            continue
        }

        # Interactive prompt
        Write-Host ""
        Write-Host "  Action for $($user.Name):" -ForegroundColor Cyan
        Write-Host "    [p] Change password" -ForegroundColor White
        Write-Host "    [d] Disable account" -ForegroundColor White
        Write-Host "    [r] Remove from Administrators group" -ForegroundColor White
        Write-Host "    [s] Skip (no changes)" -ForegroundColor White
        Write-Host "    [Enter] Leave as-is" -ForegroundColor White
        $action = Read-Host "  Choice"

        switch ($action.ToLower()) {
            "p" {
                $newPw = Read-Host "  Enter new password for $($user.Name)" -AsSecureString
                try {
                    Set-LocalUser -Name $user.Name -Password $newPw -ErrorAction Stop
                    Write-Log "    [+] Password changed for $($user.Name)." "Green"
                } catch {
                    Write-Log "    [-] Failed to change password: $_" "Red"
                }
            }
            "d" {
                try {
                    Disable-LocalUser -Name $user.Name -ErrorAction Stop
                    Write-Log "    [+] Account $($user.Name) DISABLED." "Yellow"
                } catch {
                    Write-Log "    [-] Failed to disable: $_" "Red"
                }
            }
            "r" {
                try {
                    Remove-LocalGroupMember -Group "Administrators" -Member $user.Name -ErrorAction Stop
                    Write-Log "    [+] Removed $($user.Name) from Administrators." "Green"
                } catch {
                    Write-Log "    [-] Failed to remove from Administrators: $_" "Red"
                }
            }
            "s" {
                Write-Log "    [*] Skipped $($user.Name)." "White"
            }
            default {
                Write-Log "    [*] Left $($user.Name) as-is." "White"
            }
        }
    }
} catch {
    Write-Log "[-] Could not enumerate local users: $_" "Red"
}

# ============================================================
# LOCAL ADMINISTRATORS GROUP
# ============================================================
Write-Log "" "White"
Write-Log "========== LOCAL ADMINISTRATORS GROUP ==========" "Cyan"
try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    foreach ($m in $admins) {
        Write-Log "  $($m.Name) ($($m.ObjectClass))" "Red"
    }
} catch {
    Write-Log "[-] Could not enumerate Administrators: $_" "Red"
}

# ============================================================
# SCHEDULED TASKS
# ============================================================
Write-Log "" "White"
Write-Log "========== SCHEDULED TASKS (non-Microsoft) ==========" "Cyan"
try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled"
    }
    if ($tasks) {
        foreach ($task in $tasks) {
            $actions = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
            Write-Log "  [TASK] $($task.TaskPath)$($task.TaskName)" "Yellow"
            Write-Log "    Actions: $actions" "Yellow"

            $choice = Read-Host "    Disable this task? (y/N)"
            if ($choice -eq "y") {
                try {
                    $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null
                    Write-Log "    [+] Task disabled." "Green"
                } catch {
                    Write-Log "    [-] Failed to disable: $_" "Red"
                }
            }
        }
    } else {
        Write-Log "  No suspicious scheduled tasks found." "Green"
    }
} catch {
    Write-Log "[-] Could not enumerate tasks: $_" "Red"
}

# ============================================================
# SUSPICIOUS SERVICES
# ============================================================
Write-Log "" "White"
Write-Log "========== SUSPICIOUS AUTO-START SERVICES ==========" "Cyan"
try {
    $suspSvc = Get-WmiObject Win32_Service | Where-Object {
        $_.StartMode -eq "Auto" -and
        $_.PathName -and
        $_.PathName -notmatch "\\Windows\\system32\\" -and
        $_.PathName -notmatch "\\Windows\\SysWOW64\\" -and
        $_.PathName -notmatch "svchost\.exe" -and
        $_.PathName -notmatch "\\Microsoft\\"
    }
    if ($suspSvc) {
        foreach ($svc in $suspSvc) {
            Write-Log "  [SVC] $($svc.Name) - $($svc.DisplayName)" "Yellow"
            Write-Log "    Path: $($svc.PathName) | RunAs: $($svc.StartName)" "Yellow"

            $choice = Read-Host "    Disable this service? (y/N)"
            if ($choice -eq "y") {
                try {
                    Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                    Write-Log "    [+] Service disabled." "Green"
                } catch {
                    Write-Log "    [-] Failed: $_" "Red"
                }
            }
        }
    } else {
        Write-Log "  No suspicious services found." "Green"
    }
} catch {
    Write-Log "[-] Could not enumerate services: $_" "Red"
}

# ============================================================
# REGISTRY RUN KEYS
# ============================================================
Write-Log "" "White"
Write-Log "========== REGISTRY RUN KEYS ==========" "Cyan"
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
                $choice = Read-Host "    Remove this entry? (y/N)"
                if ($choice -eq "y") {
                    try {
                        Remove-ItemProperty -Path $keyPath -Name $p.Name -Force -ErrorAction Stop
                        Write-Log "    [+] Removed." "Green"
                    } catch {
                        Write-Log "    [-] Failed: $_" "Red"
                    }
                }
            }
        }
    }
}

# ============================================================
# DONE
# ============================================================
Write-Log "" "White"
Write-Log "=============================================" "Cyan"
Write-Log "  Audit complete. Log saved to: $logFile" "Cyan"
Write-Log "=============================================" "Cyan"
Write-Host ""
Read-Host "Press Enter to exit"
