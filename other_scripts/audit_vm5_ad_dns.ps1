#Requires -Version 5.1
<#
.SYNOPSIS
    MACCDC 2026 - Interactive User Audit for VM5: AD/DNS Domain Controller
    IP: 172.20.240.102
.DESCRIPTION
    Interactive audit of all local and Active Directory user accounts.
    - Lists all local users with details
    - Lists all AD users with group memberships and color coding
    - Warns about POP3 scoring dependency on AD accounts
    - Prompts for action on each user: password change, disable, remove from admin, skip
    - Audits Domain Admins, local Admins, password policies, tasks, services, run keys
    CRITICAL: POP3 scoring uses AD usernames. Do NOT delete users needed for mail scoring.
.NOTES
    Run on VM5 (172.20.240.102). Interactive - requires operator input.
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
$logFile = Join-Path $logDir "audit_vm5_ad_dns_$timestamp.log"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] $Message"
    Write-Host $entry -ForegroundColor $Color
    Add-Content -Path $logFile -Value $entry
}

# Helper: get group names for an AD user
function Get-ADUserAdminGroups {
    param([string]$SamAccountName)
    $adminGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
    $memberOf = @()
    foreach ($grp in $adminGroups) {
        try {
            $members = Get-ADGroupMember -Identity $grp -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
            if ($members -contains $SamAccountName) {
                $memberOf += $grp
            }
        } catch { }
    }
    return $memberOf
}

Write-Log "=============================================" "Cyan"
Write-Log "  VM5 AD/DNS Interactive User Audit" "Cyan"
Write-Log "  MACCDC 2026 - 172.20.240.102" "Cyan"
Write-Log "=============================================" "Cyan"
Write-Log ""

# ============================================================
# CRITICAL WARNING
# ============================================================
Write-Host ""
Write-Host "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
Write-Host "  !! CRITICAL WARNING:                                         !!" -ForegroundColor Red
Write-Host "  !! POP3 scoring uses AD usernames. Do NOT delete users that  !!" -ForegroundColor Red
Write-Host "  !! may be needed for mail scoring. When in doubt, SKIP.      !!" -ForegroundColor Red
Write-Host "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
Write-Host ""
Read-Host "Press Enter to continue..."

# ============================================================
# 1. LOCAL USERS
# ============================================================
Write-Log "========== LOCAL USERS ==========" "Cyan"
try {
    $localUsers = Get-LocalUser -ErrorAction Stop
    foreach ($user in $localUsers) {
        $groups = (Get-LocalGroup | ForEach-Object {
            $grpName = $_.Name
            try {
                $members = Get-LocalGroupMember -Group $grpName -ErrorAction SilentlyContinue
                if ($members.Name -match "\\$($user.Name)$") { $grpName }
            } catch { }
        }) -join ", "

        $color = "Green"
        if ($groups -match "Administrators") { $color = "Red" }
        if (-not $user.Enabled) { $color = "Yellow" }

        Write-Log "  User: $($user.Name)" $color
        Write-Log "    Enabled: $($user.Enabled)" $color
        Write-Log "    Last Logon: $($user.LastLogon)" $color
        Write-Log "    Description: $($user.Description)" $color
        Write-Log "    Groups: $groups" $color
        Write-Log "" "White"
    }
} catch {
    Write-Log "[-] Could not enumerate local users: $_" "Red"
}

# ============================================================
# 2. ACTIVE DIRECTORY USERS
# ============================================================
Write-Log "========== ACTIVE DIRECTORY USERS ==========" "Cyan"
$adAvailable = $false
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $adAvailable = $true
} catch {
    Write-Log "[!] Active Directory module not available. Skipping AD user audit." "Yellow"
}

if ($adAvailable) {
    try {
        $adUsers = Get-ADUser -Filter * -Properties Name, Enabled, LastLogonDate, MemberOf, Description, PasswordLastSet, PasswordNeverExpires -ErrorAction Stop

        Write-Log "  Total AD Users: $($adUsers.Count)" "Cyan"
        Write-Log "" "White"

        foreach ($adUser in $adUsers | Sort-Object Name) {
            # Determine admin group membership
            $adminMemberships = Get-ADUserAdminGroups -SamAccountName $adUser.SamAccountName

            # Determine color
            $color = "Green"
            if ($adminMemberships.Count -gt 0) { $color = "Red" }
            if (-not $adUser.Enabled) { $color = "Yellow" }

            # Get all group names
            $allGroups = @()
            foreach ($dn in $adUser.MemberOf) {
                try {
                    $grpObj = Get-ADGroup $dn -ErrorAction SilentlyContinue
                    $allGroups += $grpObj.Name
                } catch {
                    $allGroups += $dn
                }
            }
            $groupStr = $allGroups -join ", "

            Write-Log "  -----------------------------------------------" "White"
            Write-Log "  User: $($adUser.SamAccountName) ($($adUser.Name))" $color
            Write-Log "    Enabled: $($adUser.Enabled)" $color
            Write-Log "    Last Logon: $($adUser.LastLogonDate)" $color
            Write-Log "    Password Last Set: $($adUser.PasswordLastSet)" $color
            Write-Log "    Password Never Expires: $($adUser.PasswordNeverExpires)" $color
            Write-Log "    Description: $($adUser.Description)" $color
            Write-Log "    Groups: $groupStr" $color

            if ($adminMemberships.Count -gt 0) {
                Write-Log "    ** ADMIN GROUP MEMBERSHIPS: $($adminMemberships -join ', ') **" "Red"
            }

            # Skip built-in accounts from prompting
            $skipAccounts = @("Administrator", "Guest", "krbtgt", "blueteam", "DefaultAccount")
            if ($adUser.SamAccountName -in $skipAccounts) {
                Write-Log "    [Built-in/known account - auto-skipping]" "Yellow"
                continue
            }

            # Interactive prompt
            Write-Host ""
            Write-Host "  Action for $($adUser.SamAccountName):" -ForegroundColor Cyan
            Write-Host "    [p] Change password" -ForegroundColor White
            Write-Host "    [d] Disable account" -ForegroundColor White
            Write-Host "    [r] Remove from admin groups" -ForegroundColor White
            Write-Host "    [s] Skip (no changes)" -ForegroundColor White
            Write-Host "    [Enter] Leave as-is" -ForegroundColor White
            $action = Read-Host "  Choice"

            switch ($action.ToLower()) {
                "p" {
                    $newPw = Read-Host "  Enter new password for $($adUser.SamAccountName)" -AsSecureString
                    try {
                        Set-ADAccountPassword -Identity $adUser.SamAccountName -NewPassword $newPw -Reset -ErrorAction Stop
                        Write-Log "    [+] Password changed for $($adUser.SamAccountName)." "Green"
                    } catch {
                        Write-Log "    [-] Failed to change password: $_" "Red"
                    }
                }
                "d" {
                    Write-Host "  WARNING: Disabling this user may break POP3 scoring!" -ForegroundColor Red
                    $confirm = Read-Host "  Are you sure? (y/N)"
                    if ($confirm -eq "y") {
                        try {
                            Disable-ADAccount -Identity $adUser.SamAccountName -ErrorAction Stop
                            Write-Log "    [+] Account $($adUser.SamAccountName) DISABLED." "Yellow"
                        } catch {
                            Write-Log "    [-] Failed to disable: $_" "Red"
                        }
                    } else {
                        Write-Log "    [*] Skipped disabling $($adUser.SamAccountName)." "White"
                    }
                }
                "r" {
                    if ($adminMemberships.Count -eq 0) {
                        Write-Log "    [*] $($adUser.SamAccountName) is not in any admin groups." "White"
                    } else {
                        foreach ($grp in $adminMemberships) {
                            try {
                                Remove-ADGroupMember -Identity $grp -Members $adUser.SamAccountName -Confirm:$false -ErrorAction Stop
                                Write-Log "    [+] Removed $($adUser.SamAccountName) from $grp." "Green"
                            } catch {
                                Write-Log "    [-] Failed to remove from $grp : $_" "Red"
                            }
                        }
                    }
                }
                "s" {
                    Write-Log "    [*] Skipped $($adUser.SamAccountName)." "White"
                }
                default {
                    Write-Log "    [*] Left $($adUser.SamAccountName) as-is." "White"
                }
            }
        }
    } catch {
        Write-Log "[-] Failed to enumerate AD users: $_" "Red"
    }
}

# ============================================================
# 3. DOMAIN ADMINS GROUP MEMBERS
# ============================================================
Write-Log "" "White"
Write-Log "========== DOMAIN ADMINS GROUP MEMBERS ==========" "Cyan"
if ($adAvailable) {
    try {
        $daMembers = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction Stop
        foreach ($m in $daMembers) {
            Write-Log "  $($m.SamAccountName) ($($m.objectClass))" "Red"
        }
    } catch {
        Write-Log "[-] Could not enumerate Domain Admins: $_" "Red"
    }
}

# ============================================================
# 4. LOCAL ADMINISTRATORS GROUP MEMBERS
# ============================================================
Write-Log "" "White"
Write-Log "========== LOCAL ADMINISTRATORS GROUP MEMBERS ==========" "Cyan"
try {
    $laMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    foreach ($m in $laMembers) {
        Write-Log "  $($m.Name) ($($m.ObjectClass)) - Source: $($m.PrincipalSource)" "Red"
    }
} catch {
    Write-Log "[-] Could not enumerate local Administrators: $_" "Red"
}

# ============================================================
# 5. ACCOUNTS WITH PASSWORD NEVER EXPIRES
# ============================================================
Write-Log "" "White"
Write-Log "========== ACCOUNTS WITH PASSWORD NEVER EXPIRES ==========" "Cyan"
if ($adAvailable) {
    try {
        $neverExpire = Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires -ErrorAction Stop
        if ($neverExpire) {
            foreach ($u in $neverExpire) {
                Write-Log "  [!] $($u.SamAccountName) - PasswordNeverExpires = True" "Yellow"
            }
        } else {
            Write-Log "  No accounts with PasswordNeverExpires." "Green"
        }
    } catch {
        Write-Log "[-] Could not check PasswordNeverExpires: $_" "Red"
    }
}

# ============================================================
# 6. SUSPICIOUS SCHEDULED TASKS
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
                    Write-Log "    [-] Failed to disable task: $_" "Red"
                }
            }
        }
    } else {
        Write-Log "  No suspicious non-Microsoft scheduled tasks found." "Green"
    }
} catch {
    Write-Log "[-] Could not enumerate scheduled tasks: $_" "Red"
}

# ============================================================
# 7. SUSPICIOUS SERVICES
# ============================================================
Write-Log "" "White"
Write-Log "========== SUSPICIOUS AUTO-START SERVICES ==========" "Cyan"
try {
    # List services with auto-start that are not standard Windows services
    $suspiciousServices = Get-WmiObject Win32_Service | Where-Object {
        $_.StartMode -eq "Auto" -and
        $_.PathName -and
        $_.PathName -notmatch "\\Windows\\system32\\" -and
        $_.PathName -notmatch "\\Windows\\SysWOW64\\" -and
        $_.PathName -notmatch "svchost\.exe" -and
        $_.PathName -notmatch "\\Microsoft\\"
    }
    if ($suspiciousServices) {
        foreach ($svc in $suspiciousServices) {
            Write-Log "  [SVC] $($svc.Name) - $($svc.DisplayName)" "Yellow"
            Write-Log "    Path: $($svc.PathName)" "Yellow"
            Write-Log "    Run As: $($svc.StartName)" "Yellow"

            $choice = Read-Host "    Disable this service? (y/N)"
            if ($choice -eq "y") {
                try {
                    Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                    Write-Log "    [+] Service $($svc.Name) stopped and disabled." "Green"
                } catch {
                    Write-Log "    [-] Failed to disable service: $_" "Red"
                }
            }
        }
    } else {
        Write-Log "  No suspicious auto-start services found." "Green"
    }
} catch {
    Write-Log "[-] Could not enumerate services: $_" "Red"
}

# ============================================================
# 8. REGISTRY RUN KEYS
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
                        Write-Log "    [+] Removed $($p.Name) from $keyPath." "Green"
                    } catch {
                        Write-Log "    [-] Failed to remove: $_" "Red"
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
