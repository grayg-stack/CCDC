#Requires -Version 5.1
<#
.SYNOPSIS
    MACCDC 2026 - Interactive User Audit for VM8: Windows 11 Workstation
    IP: 172.20.240.100
.DESCRIPTION
    Interactive audit of all local user accounts on the Windows 11 workstation.
    - Lists local users with details, group memberships, and color coding
    - Notes if this machine is domain-joined
    - Standard audit prompts for each user
    - Checks persistence: scheduled tasks, services, run keys
    NOTE: This is NOT a scored machine but can be used by red team as a pivot.
.NOTES
    Run on VM8 (172.20.240.100). Interactive - requires operator input.
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
$logFile = Join-Path $logDir "audit_vm8_wks_$timestamp.log"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] $Message"
    Write-Host $entry -ForegroundColor $Color
    Add-Content -Path $logFile -Value $entry
}

Write-Log "=============================================" "Cyan"
Write-Log "  VM8 Windows 11 Workstation User Audit" "Cyan"
Write-Log "  MACCDC 2026 - 172.20.240.100" "Cyan"
Write-Log "  NOT scored - prevent red team pivoting" "Cyan"
Write-Log "=============================================" "Cyan"
Write-Log ""

# ============================================================
# CHECK DOMAIN MEMBERSHIP
# ============================================================
$isDomainJoined = $false
$domainName = ""
try {
    $compSys = Get-WmiObject Win32_ComputerSystem
    if ($compSys.PartOfDomain) {
        $isDomainJoined = $true
        $domainName = $compSys.Domain
        Write-Log "[*] This workstation IS domain-joined: $domainName" "Yellow"
        Write-Log "[*] Domain users may have access to this machine via domain groups." "Yellow"
    } else {
        Write-Log "[*] This workstation is NOT domain-joined (standalone/workgroup)." "White"
    }
} catch {
    Write-Log "[*] Could not determine domain membership." "Yellow"
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

        Write-Log "  -----------------------------------------------" "White"
        Write-Log "  User: $($user.Name)" $color
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

        # Interactive prompt
        Write-Host ""
        Write-Host "  Action for $($user.Name):" -ForegroundColor Cyan
        Write-Host "    [p] Change password" -ForegroundColor White
        Write-Host "    [d] Disable account" -ForegroundColor White
        Write-Host "    [r] Remove from Administrators group" -ForegroundColor White
        Write-Host "    [x] Delete account" -ForegroundColor White
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
                if ($groups -contains "Administrators") {
                    try {
                        Remove-LocalGroupMember -Group "Administrators" -Member $user.Name -ErrorAction Stop
                        Write-Log "    [+] Removed $($user.Name) from Administrators." "Green"
                    } catch {
                        Write-Log "    [-] Failed to remove: $_" "Red"
                    }
                } else {
                    Write-Log "    [*] $($user.Name) is not in Administrators." "White"
                }
            }
            "x" {
                $confirm = Read-Host "  Are you sure you want to DELETE $($user.Name)? (y/N)"
                if ($confirm -eq "y") {
                    try {
                        Remove-LocalUser -Name $user.Name -ErrorAction Stop
                        Write-Log "    [+] Account $($user.Name) DELETED." "Red"
                    } catch {
                        Write-Log "    [-] Failed to delete: $_" "Red"
                    }
                } else {
                    Write-Log "    [*] Deletion cancelled." "White"
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
# DOMAIN USERS WITH LOCAL ACCESS (if domain-joined)
# ============================================================
if ($isDomainJoined) {
    Write-Log "" "White"
    Write-Log "========== DOMAIN USERS/GROUPS WITH LOCAL ACCESS ==========" "Cyan"
    Write-Log "[*] Checking local groups for domain members..." "Yellow"
    try {
        $localGroups = Get-LocalGroup -ErrorAction Stop
        foreach ($grp in $localGroups) {
            try {
                $members = Get-LocalGroupMember -Group $grp.Name -ErrorAction SilentlyContinue
                $domainMembers = $members | Where-Object { $_.PrincipalSource -eq "ActiveDirectory" }
                if ($domainMembers) {
                    Write-Log "  Group: $($grp.Name)" "Yellow"
                    foreach ($m in $domainMembers) {
                        Write-Log "    [Domain] $($m.Name) ($($m.ObjectClass))" "Yellow"
                    }
                }
            } catch { }
        }
    } catch {
        Write-Log "[-] Could not enumerate domain members in local groups: $_" "Red"
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
        Write-Log "  $($m.Name) ($($m.ObjectClass)) - Source: $($m.PrincipalSource)" "Red"
    }
} catch {
    Write-Log "[-] Could not enumerate Administrators: $_" "Red"
}

# ============================================================
# SCHEDULED TASKS (persistence)
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
            Write-Log "    State: $($task.State) | Actions: $actions" "Yellow"

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
        $_.PathName -notmatch "\\Microsoft\\" -and
        $_.PathName -notmatch "\\Program Files\\" -and
        $_.PathName -notmatch "\\Program Files \(x86\)\\"
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
# NETWORK CONNECTIONS
# ============================================================
Write-Log "" "White"
Write-Log "========== ESTABLISHED NETWORK CONNECTIONS ==========" "Cyan"
try {
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    if ($conns) {
        foreach ($c in $conns) {
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
            Write-Log "  $($c.LocalAddress):$($c.LocalPort) -> $($c.RemoteAddress):$($c.RemotePort) | PID: $($c.OwningProcess) ($($proc.ProcessName))" "White"
        }
    } else {
        Write-Log "  No established connections." "Green"
    }
} catch {
    Write-Log "[-] Could not enumerate connections: $_" "Red"
}

# ============================================================
# LISTENING PORTS
# ============================================================
Write-Log "" "White"
Write-Log "========== LISTENING PORTS ==========" "Cyan"
try {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    if ($listeners) {
        foreach ($l in $listeners) {
            $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
            $color = "White"
            # Flag unexpected listening ports
            if ($l.LocalPort -notin @(135, 445, 3389, 5985, 5986, 49664, 49665, 49666, 49667, 49668, 49669, 49670)) {
                $color = "Yellow"
            }
            Write-Log "  $($l.LocalAddress):$($l.LocalPort) | PID: $($l.OwningProcess) ($($proc.ProcessName))" $color
        }
    }
} catch {
    Write-Log "[-] Could not enumerate listeners: $_" "Red"
}

# ============================================================
# DONE
# ============================================================
Write-Log "" "White"
Write-Log "=============================================" "Cyan"
Write-Log "  Audit complete. Log saved to: $logFile" "Cyan"
Write-Log "  Remember: VM8 is NOT scored but must not" "Yellow"
Write-Log "  be used as a pivot by red team." "Yellow"
Write-Log "=============================================" "Cyan"
Write-Host ""
Read-Host "Press Enter to exit"
