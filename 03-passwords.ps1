# ============================================================
# MACCDC 2026 - Windows Bulk Password Change
# Changes passwords for all local AND domain users
# Usage: powershell -ExecutionPolicy Bypass -File 03-passwords.ps1
# ============================================================

Write-Host "============================================" -ForegroundColor Green
Write-Host " MACCDC Windows Password Changer" -ForegroundColor Green
Write-Host " $env:COMPUTERNAME - $(Get-Date)" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green

function Ok($text)   { Write-Host "[+] $text" -ForegroundColor Green }
function Warn($text) { Write-Host "[!] $text" -ForegroundColor Red }
function Info($text) { Write-Host "[*] $text" -ForegroundColor Yellow }

# --- Local Users ---
Write-Host "`n========== LOCAL USERS ==========" -ForegroundColor Green
$newLocalPass = Read-Host "Enter new password for LOCAL users (or SKIP)" -AsSecureString

if ($newLocalPass.Length -gt 0) {
    Get-LocalUser | Where-Object { $_.Enabled -eq $true } | ForEach-Object {
        try {
            Set-LocalUser -Name $_.Name -Password $newLocalPass -ErrorAction Stop
            Ok "Changed local: $($_.Name)"
        }
        catch {
            Warn "Failed local: $($_.Name) - $($_.Exception.Message)"
        }
    }
}

# --- Domain Users ---
Write-Host "`n========== DOMAIN USERS ==========" -ForegroundColor Green
Info "Checking if this is a Domain Controller..."

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $isDC = $true
    Info "AD module loaded - this appears to be a DC"
}
catch {
    $isDC = $false
    Info "Not a DC or AD module not available. Skipping domain user changes."
}

if ($isDC) {
    $newDomainPass = Read-Host "Enter new password for DOMAIN users (or SKIP)" -AsSecureString

    if ($newDomainPass.Length -gt 0) {
        # Don't change krbtgt or built-in service accounts
        $excludeUsers = @("krbtgt", "Guest", "DefaultAccount")

        Get-ADUser -Filter { Enabled -eq $true } | Where-Object {
            $_.SamAccountName -notin $excludeUsers
        } | ForEach-Object {
            try {
                Set-ADAccountPassword -Identity $_ -Reset -NewPassword $newDomainPass -ErrorAction Stop
                Ok "Changed domain: $($_.SamAccountName)"
            }
            catch {
                Warn "Failed domain: $($_.SamAccountName) - $($_.Exception.Message)"
            }
        }

        Warn ""
        Warn "IMPORTANT: Submit scored account password changes via Support Ticket!"
        Warn "Go to auth.ccdc.events > Support Tickets > Password Change Request"
        Warn ""
    }
}

# --- Output Summary ---
Write-Host "`n========== PASSWORD LOG ==========" -ForegroundColor Green
Info "Record the new password and submit via Support Ticket for scored accounts."
Info "Scored accounts typically include email users and service accounts."
Info "Admin/root passwords do NOT need to be reported."
