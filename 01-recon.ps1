# ============================================================
# MACCDC 2026 - Windows Initial Reconnaissance Script
# RUN FIRST - Read-only, breaks nothing, captures baseline
# Usage: powershell -ExecutionPolicy Bypass -File 01-recon.ps1 | Tee-Object -FilePath C:\recon.txt
# ============================================================

Write-Host "============================================" -ForegroundColor Green
Write-Host " MACCDC Windows Recon - $env:COMPUTERNAME" -ForegroundColor Green
Write-Host " $(Get-Date)" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green

function Banner($text) { Write-Host "`n========== $text ==========" -ForegroundColor Green }
function Warn($text)   { Write-Host "[!] $text" -ForegroundColor Red }
function Info($text)   { Write-Host "[*] $text" -ForegroundColor Yellow }

# --- System Info ---
Banner "SYSTEM INFO"
Write-Host "Hostname: $env:COMPUTERNAME"
Write-Host "Domain: $env:USERDOMAIN"
Write-Host "OS: $((Get-WmiObject Win32_OperatingSystem).Caption)"
Write-Host "IP Addresses:"
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | ForEach-Object {
    Write-Host "  $($_.IPAddress) on $($_.InterfaceAlias)"
}

# --- Local Users ---
Banner "LOCAL USER ACCOUNTS"
Info "All local users:"
Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordRequired -AutoSize

Info "Local Administrators group:"
try { Get-LocalGroupMember -Group "Administrators" | Format-Table Name, ObjectClass, PrincipalSource -AutoSize }
catch { net localgroup administrators }

Info "All local groups and members:"
Get-LocalGroup | ForEach-Object {
    $members = try { (Get-LocalGroupMember -Group $_.Name -ErrorAction Stop).Name -join ", " } catch { "Error reading" }
    if ($members) { Write-Host "  $($_.Name): $members" }
}

# --- Domain Info (if domain-joined) ---
Banner "DOMAIN INFO"
try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    Info "Domain: $($domain.Name)"
    Info "Domain Controllers:"
    $domain.DomainControllers | ForEach-Object { Write-Host "  $($_.Name) - $($_.IPAddress)" }

    Info "Domain Admins:"
    net group "Domain Admins" /domain 2>$null

    Info "Enterprise Admins:"
    net group "Enterprise Admins" /domain 2>$null

    Info "All Domain Users:"
    net user /domain 2>$null | Select-Object -First 30
}
catch {
    Info "Not domain-joined or cannot reach DC"
}

# --- Network ---
Banner "LISTENING PORTS"
Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize | Out-String | Write-Host

Info "Active connections (ESTABLISHED):"
Get-NetTCPConnection -State Established | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess -AutoSize | Out-String | Write-Host

# --- Firewall ---
Banner "FIREWALL STATUS"
Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize

# --- Scheduled Tasks ---
Banner "SCHEDULED TASKS (non-Microsoft)"
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } | ForEach-Object {
    $actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
    Write-Host "  $($_.TaskName) [$($_.State)]: $actions"
}
Write-Host ""
Info "All scheduled tasks with actions:"
schtasks /query /fo LIST /v 2>$null | Select-String "TaskName|Task To Run|Author|Run As" | Out-String -Width 200 | Write-Host

# --- Services ---
Banner "RUNNING SERVICES (non-standard)"
Get-Service | Where-Object { $_.Status -eq 'Running' } | Sort-Object DisplayName | Format-Table Name, DisplayName, StartType -AutoSize | Out-String | Write-Host

# --- Startup Items ---
Banner "STARTUP / AUTORUNS"
Info "Registry Run keys (HKLM):"
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
    Get-Member -MemberType NoteProperty | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
        $val = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run").$($_.Name)
        Write-Host "  $($_.Name): $val"
    }

Info "Registry Run keys (HKCU):"
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
    Get-Member -MemberType NoteProperty | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
        $val = (Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run").$($_.Name)
        Write-Host "  $($_.Name): $val"
    }

# --- Shares ---
Banner "NETWORK SHARES"
Get-SmbShare | Format-Table Name, Path, Description -AutoSize

# --- Installed Software ---
Banner "INSTALLED SOFTWARE (non-Microsoft)"
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Where-Object { $_.Publisher -notlike "*Microsoft*" -and $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize | Out-String | Write-Host

# --- DNS ---
Banner "DNS CONFIGURATION"
Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, ServerAddresses -AutoSize
if (Get-Service DNS -ErrorAction SilentlyContinue) {
    Info "DNS Server service is installed"
    Get-DnsServerZone -ErrorAction SilentlyContinue | Format-Table ZoneName, ZoneType -AutoSize
}

# --- Recent Security Events ---
Banner "RECENT SECURITY EVENTS (last 50)"
try {
    Get-EventLog -LogName Security -Newest 50 -ErrorAction Stop |
        Where-Object { $_.EventID -in @(4624, 4625, 4720, 4722, 4732, 4728, 4756, 4672) } |
        Format-Table TimeGenerated, EventID, Message -AutoSize -Wrap | Out-String -Width 200 | Write-Host
}
catch { Info "Cannot read Security event log" }

Banner "RECON COMPLETE - Review output for anomalies"
Write-Host "Save: powershell -ExecutionPolicy Bypass -File 01-recon.ps1 | Tee-Object -FilePath C:\recon.txt" -ForegroundColor Cyan
