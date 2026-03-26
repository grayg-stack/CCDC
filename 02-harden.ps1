# ============================================================
# MACCDC 2026 - Windows Hardening Script
# Run as Administrator
# Usage: powershell -ExecutionPolicy Bypass -File 02-harden.ps1
# ============================================================

Write-Host "============================================" -ForegroundColor Green
Write-Host " MACCDC Windows Hardening - $env:COMPUTERNAME" -ForegroundColor Green
Write-Host " $(Get-Date)" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green

function Banner($text) { Write-Host "`n========== $text ==========" -ForegroundColor Green }
function Warn($text)   { Write-Host "[!] $text" -ForegroundColor Red }
function Info($text)   { Write-Host "[*] $text" -ForegroundColor Yellow }
function Ok($text)     { Write-Host "[+] $text" -ForegroundColor Green }

function Ask($prompt) {
    $ans = Read-Host "[?] $prompt (y/N)"
    return $ans -match '^[Yy]'
}

# Check admin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Warn "Must run as Administrator!"; exit 1
}

# --- 1. Enable Windows Firewall ---
Banner "PHASE 1: WINDOWS FIREWALL"
if (Ask "Enable Windows Firewall on all profiles?") {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Ok "Firewall enabled on all profiles"

    Info "Adding rules for scored services..."
    $scoredPorts = @(
        @{Name="HTTP";      Port=80;   Protocol="TCP"},
        @{Name="HTTPS";     Port=443;  Protocol="TCP"},
        @{Name="SMTP";      Port=25;   Protocol="TCP"},
        @{Name="DNS-TCP";   Port=53;   Protocol="TCP"},
        @{Name="DNS-UDP";   Port=53;   Protocol="UDP"},
        @{Name="POP3";      Port=110;  Protocol="TCP"},
        @{Name="FTP";       Port=21;   Protocol="TCP"},
        @{Name="FTP-Data";  Port=20;   Protocol="TCP"},
        @{Name="TFTP";      Port=69;   Protocol="UDP"},
        @{Name="NTP";       Port=123;  Protocol="UDP"},
        @{Name="RDP";       Port=3389; Protocol="TCP"},
        @{Name="SMTP-Sub";  Port=587;  Protocol="TCP"},
        @{Name="POP3S";     Port=995;  Protocol="TCP"}
    )

    foreach ($svc in $scoredPorts) {
        $ruleName = "CCDC-Allow-$($svc.Name)"
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -LocalPort $svc.Port `
            -Protocol $svc.Protocol -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
        Ok "Allowed inbound: $($svc.Name) ($($svc.Protocol)/$($svc.Port))"
    }
}

# --- 2. Disable Risky Protocols ---
Banner "PHASE 2: DISABLE RISKY PROTOCOLS"
if (Ask "Disable LLMNR?") {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $regPath -Name "EnableMulticast" -Value 0 -Type DWord
    Ok "LLMNR disabled"
}

if (Ask "Disable NetBIOS over TCP/IP on all adapters?") {
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
    foreach ($adapter in $adapters) {
        $adapter.SetTcpipNetbios(2) | Out-Null  # 2 = Disable
    }
    Ok "NetBIOS disabled on all adapters"
}

if (Ask "Disable SMBv1?") {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Ok "SMBv1 disabled"
}

if (Ask "Disable WinRM (if not needed)?") {
    Stop-Service WinRM -Force -ErrorAction SilentlyContinue
    Set-Service WinRM -StartupType Disabled -ErrorAction SilentlyContinue
    Ok "WinRM disabled"
}

# --- 3. Audit Policy ---
Banner "PHASE 3: AUDIT POLICY"
if (Ask "Enable comprehensive audit policies?") {
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
    auditpol /set /category:"Account Logon" /success:enable /failure:enable
    auditpol /set /category:"Account Management" /success:enable /failure:enable
    auditpol /set /category:"Policy Change" /success:enable /failure:enable
    auditpol /set /category:"System" /success:enable /failure:enable
    auditpol /set /category:"Object Access" /failure:enable
    auditpol /set /category:"Privilege Use" /success:enable /failure:enable

    # Enable command-line auditing in process creation events
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

    Ok "Audit policies enabled"
}

# --- 4. PowerShell Logging ---
Banner "PHASE 4: POWERSHELL LOGGING"
if (Ask "Enable PowerShell script block and module logging?") {
    # Script Block Logging
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1
    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockInvocationLogging" -Value 1

    # Module Logging
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $regPath -Name "EnableModuleLogging" -Value 1
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
    New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $regPath -Name "*" -Value "*"

    Ok "PowerShell logging enabled"
}

# --- 5. Suspicious Scheduled Tasks ---
Banner "PHASE 5: SCHEDULED TASK CLEANUP"
Info "Non-Microsoft scheduled tasks:"
$suspTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled" }
foreach ($task in $suspTasks) {
    $actions = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
    Warn "Task: $($task.TaskName) | Actions: $actions"
    if (Ask "Disable task '$($task.TaskName)'?") {
        Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue | Out-Null
        Ok "Disabled: $($task.TaskName)"
    }
}

# --- 6. Service Hardening ---
Banner "PHASE 6: SERVICE AUDIT"
$riskyServices = @("RemoteRegistry", "TelnetServer", "SNMPTRAP", "SSDPSRV", "upnphost",
                    "WMPNetworkSvc", "RemoteAccess", "TapiSrv")
foreach ($svc in $riskyServices) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Warn "Risky service running: $($service.DisplayName) ($svc)"
        if (Ask "Stop and disable $svc?") {
            Stop-Service $svc -Force -ErrorAction SilentlyContinue
            Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Ok "Stopped and disabled: $svc"
        }
    }
}

# --- 7. Account Lockout Policy ---
Banner "PHASE 7: ACCOUNT LOCKOUT POLICY"
if (Ask "Set account lockout policy (5 attempts, 30 min lockout)?") {
    net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
    net accounts /minpwlen:8
    Ok "Account lockout policy configured"
}

# --- 8. RDP Hardening ---
Banner "PHASE 8: RDP HARDENING"
if (Ask "Harden RDP settings?") {
    # NLA required
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "UserAuthentication" -Value 1
    # Set encryption level to high
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "SecurityLayer" -Value 2
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "MinEncryptionLevel" -Value 3
    Ok "RDP hardened (NLA required, high encryption)"
}

# --- 9. Quick Service Check ---
Banner "PHASE 9: SERVICE VERIFICATION"
Info "Checking key services..."
$checkServices = @("DNS", "W3SVC", "IIS", "SMTP", "POP3", "IISADMIN", "Spooler")
foreach ($svc in $checkServices) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            Ok "$($service.DisplayName) is RUNNING"
        } else {
            Warn "$($service.DisplayName) is $($service.Status)"
        }
    }
}

Info "Checking listening ports..."
foreach ($port in @(25, 53, 80, 110, 443)) {
    $listening = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($listening) { Ok "Port $port is LISTENING" }
    else { Warn "Port $port is NOT listening!" }
}

Banner "HARDENING COMPLETE"
Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Verify scored services on NISE dashboard" -ForegroundColor Cyan
Write-Host "  2. Submit password changes via Support Ticket" -ForegroundColor Cyan
Write-Host "  3. Install Sysmon if available for enhanced logging" -ForegroundColor Cyan
Write-Host "  4. Run DeepBlueCLI periodically: .\DeepBlue.ps1 -log security" -ForegroundColor Cyan
