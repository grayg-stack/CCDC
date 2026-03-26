#Requires -Version 5.1
<#
.SYNOPSIS
    MACCDC 2026 - Interactive User Audit for VM6: Windows Web Server
    IP: 172.20.240.101
.DESCRIPTION
    Interactive audit of all local (and domain if joined) user accounts on the web server.
    - Lists local users with details and color coding
    - Shows IIS application pool identities and flags service accounts
    - Shows NTFS permissions on web root
    - If domain-joined, also shows domain users
    - Prompts for action on each user
.NOTES
    Run on VM6 (172.20.240.101). Interactive - requires operator input.
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
$logFile = Join-Path $logDir "audit_vm6_web_$timestamp.log"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] $Message"
    Write-Host $entry -ForegroundColor $Color
    Add-Content -Path $logFile -Value $entry
}

Write-Log "=============================================" "Cyan"
Write-Log "  VM6 Web Server Interactive User Audit" "Cyan"
Write-Log "  MACCDC 2026 - 172.20.240.101" "Cyan"
Write-Log "=============================================" "Cyan"
Write-Log ""

# ============================================================
# IDENTIFY IIS APP POOL IDENTITIES (need before user audit)
# ============================================================
Write-Log "========== IIS APPLICATION POOL IDENTITIES ==========" "Cyan"
$appPoolIdentities = @()
try {
    Import-Module WebAdministration -ErrorAction Stop
    $appPools = Get-ChildItem IIS:\AppPools -ErrorAction Stop
    foreach ($pool in $appPools) {
        $identity = $pool.processModel.userName
        $identityType = $pool.processModel.identityType
        Write-Log "  App Pool: $($pool.Name)" "White"
        Write-Log "    Identity Type: $identityType" "White"
        if ($identity) {
            Write-Log "    Username: $identity" "Yellow"
            # Extract just the username part (remove domain prefix)
            $shortName = $identity -replace "^.*\\", ""
            $appPoolIdentities += $shortName
        } else {
            Write-Log "    Username: (built-in identity: $identityType)" "White"
        }
        Write-Log "    State: $($pool.State)" "White"
    }
} catch {
    Write-Log "[*] Could not enumerate IIS app pools via WebAdministration module." "Yellow"
    try {
        $appcmd = & "$env:SystemRoot\system32\inetsrv\appcmd.exe" list apppool /text:* 2>&1
        $appcmd | ForEach-Object { Write-Log "  $_" "White" }
    } catch {
        Write-Log "[-] Could not enumerate app pools: $_" "Red"
    }
}
Write-Log "" "White"

# ============================================================
# NTFS PERMISSIONS ON WEB ROOT
# ============================================================
Write-Log "========== NTFS PERMISSIONS ON WEB ROOT ==========" "Cyan"
$webRoots = @("C:\inetpub\wwwroot")
# Find other site roots
try {
    $sites = Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue
    foreach ($site in $sites) {
        $physPath = $site.physicalPath -replace '%SystemDrive%', $env:SystemDrive
        if ($physPath -and (Test-Path $physPath) -and $physPath -notin $webRoots) {
            $webRoots += $physPath
        }
    }
} catch { }

foreach ($root in $webRoots) {
    Write-Log "  Permissions on: $root" "White"
    if (Test-Path $root) {
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
    } else {
        Write-Log "  [!] Path does not exist: $root" "Yellow"
    }
}
Write-Log "" "White"

# ============================================================
# CHECK IF DOMAIN-JOINED
# ============================================================
$isDomainJoined = $false
$domainName = ""
try {
    $compSys = Get-WmiObject Win32_ComputerSystem
    if ($compSys.PartOfDomain) {
        $isDomainJoined = $true
        $domainName = $compSys.Domain
        Write-Log "[*] This machine IS domain-joined: $domainName" "Yellow"
    } else {
        Write-Log "[*] This machine is NOT domain-joined (standalone/workgroup)." "White"
    }
} catch {
    Write-Log "[*] Could not determine domain membership." "Yellow"
}

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

        # Check if this is an IIS service account
        $isServiceAccount = $user.Name -in $appPoolIdentities

        Write-Log "  -----------------------------------------------" "White"
        Write-Log "  User: $($user.Name)" $color
        if ($isServiceAccount) {
            Write-Log "    ** IIS SERVICE ACCOUNT - DO NOT DELETE **" "Red"
        }
        Write-Log "    Enabled: $($user.Enabled)" $color
        Write-Log "    Last Logon: $($user.LastLogon)" $color
        Write-Log "    Description: $($user.Description)" $color
        Write-Log "    Groups: $groupStr" $color
        Write-Log "    Password Last Set: $($user.PasswordLastSet)" $color
        Write-Log "    Password Expires: $($user.PasswordExpires)" $color

        # Skip known accounts
        $skipAccounts = @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount", "blueteam")
        if ($user.Name -in $skipAccounts) {
            Write-Log "    [Built-in/known account - auto-skipping]" "Yellow"
            continue
        }

        if ($isServiceAccount) {
            Write-Log "    [IIS service account - auto-skipping for safety]" "Yellow"
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
# DOMAIN USERS (if domain-joined)
# ============================================================
if ($isDomainJoined) {
    Write-Log "" "White"
    Write-Log "========== DOMAIN USERS (domain: $domainName) ==========" "Cyan"
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adUsers = Get-ADUser -Filter * -Properties Name, Enabled, LastLogonDate, MemberOf, Description, PasswordLastSet -ErrorAction Stop
        Write-Log "  Total AD Users: $($adUsers.Count)" "Cyan"

        foreach ($adUser in $adUsers | Sort-Object Name) {
            $adminGroups = @()
            foreach ($grpDN in $adUser.MemberOf) {
                try {
                    $grp = Get-ADGroup $grpDN -ErrorAction SilentlyContinue
                    if ($grp.Name -in @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")) {
                        $adminGroups += $grp.Name
                    }
                } catch { }
            }

            $color = "Green"
            if ($adminGroups.Count -gt 0) { $color = "Red" }
            if (-not $adUser.Enabled) { $color = "Yellow" }

            Write-Log "  $($adUser.SamAccountName) | Enabled: $($adUser.Enabled) | Admin: $($adminGroups -join ', ')" $color
        }
    } catch {
        Write-Log "[*] AD module not available or query failed. Skipping domain users." "Yellow"
    }
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
# SUSPICIOUS SCHEDULED TASKS
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
