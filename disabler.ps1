# Self-elevate to admin if needed
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process wt -ArgumentList "powershell -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# If not running inside Windows Terminal, relaunch inside it
if (-not $env:WT_SESSION) {
    Start-Process wt -ArgumentList "powershell -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$host.UI.RawUI.WindowTitle = "SamSam - Driver Blocklist & Memory Integrity Manager"

# Read a registry DWORD - returns the raw value or $null
function Get-RegRaw([string]$path, [string]$name) {
    try {
        return (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name
    } catch { return $null }
}

# Convert 0/1 reg value to ENABLED/DISABLED
function RegToStatus($val) {
    if ($null -eq $val) { return "NOT SET" }
    if ($val -eq 0) { return "DISABLED" }
    if ($val -eq 1) { return "ENABLED" }
    return "UNKNOWN"
}

# Convert a Disable* boolean (true = feature OFF)
function DisableFlagToStatus($val) {
    if ($null -eq $val) { return "NOT SET" }
    if ($val -eq $true -or $val -eq 1) { return "DISABLED" }
    return "ENABLED"
}

# Convert a positive-flag boolean (true = feature ON)
function EnableFlagToStatus($val) {
    if ($null -eq $val) { return "NOT SET" }
    if ($val -eq $true -or $val -eq 1) { return "ENABLED" }
    return "DISABLED"
}

function Print-Status([string]$label, [string]$val) {
    $c = if ($val -eq "ENABLED") { "Green" } elseif ($val -eq "DISABLED") { "Red" } else { "Yellow" }
    Write-Host ("  |  " + $label.PadRight(36)) -NoNewline -ForegroundColor Cyan
    Write-Host $val.PadRight(9) -ForegroundColor $c -NoNewline
    Write-Host " |" -ForegroundColor Cyan
}

function Show-Menu {
    Clear-Host
    Write-Host ""
    Write-Host "  +=============================================================+" -ForegroundColor DarkGreen
    Write-Host "  |                                                             |" -ForegroundColor DarkGreen
    Write-Host "  |   " -ForegroundColor DarkGreen -NoNewline
    Write-Host " ____    _    __  __  ____    _    __  __ " -ForegroundColor Green -NoNewline
    Write-Host "  |" -ForegroundColor DarkGreen
    Write-Host "  |   " -ForegroundColor DarkGreen -NoNewline
    Write-Host "/ ___|  / \  |  \/  |/ ___|  / \  |  \/  |" -ForegroundColor Green -NoNewline
    Write-Host " |" -ForegroundColor DarkGreen
    Write-Host "  |   " -ForegroundColor DarkGreen -NoNewline
    Write-Host "\___ \ / _ \ | |\/| |\___ \ / _ \ | |\/| |" -ForegroundColor Green -NoNewline
    Write-Host " |" -ForegroundColor DarkGreen
    Write-Host "  |   " -ForegroundColor DarkGreen -NoNewline
    Write-Host " ___) / ___ \| |  | | ___) / ___ \| |  | |" -ForegroundColor Green -NoNewline
    Write-Host " |" -ForegroundColor DarkGreen
    Write-Host "  |   " -ForegroundColor DarkGreen -NoNewline
    Write-Host "|____/_/   \_\_|  |_||____/_/   \_\_|  |_|" -ForegroundColor Green -NoNewline
    Write-Host " |" -ForegroundColor DarkGreen
    Write-Host "  |                                                             |" -ForegroundColor DarkGreen
    Write-Host "  |   Web: samsam.lol              GitHub: itzzz_ryze          |" -ForegroundColor DarkGreen
    Write-Host "  |                                                             |" -ForegroundColor DarkGreen
    Write-Host "  +=============================================================+" -ForegroundColor DarkGreen
    Write-Host ""

    # ── Core Isolation ───────────────────────────────────────────
    $mi  = RegToStatus (Get-RegRaw "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled")
    $db  = RegToStatus (Get-RegRaw "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" "VulnerableDriverBlocklistEnable")
    $vbs = RegToStatus (Get-RegRaw "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity")
    $cgRaw = Get-RegRaw "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "LsaCfgFlags"
    $cg  = if ($null -eq $cgRaw) { "NOT SET" } elseif ($cgRaw -ge 1) { "ENABLED" } else { "DISABLED" }

    # ── Tamper Protection ────────────────────────────────────────
    $tpRaw = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" "TamperProtection"
    $tp = if ($null -eq $tpRaw) { "NOT SET" } elseif ($tpRaw -eq 5) { "ENABLED" } elseif ($tpRaw -eq 0 -or $tpRaw -eq 4) { "DISABLED" } else { "UNKNOWN" }

    # ── Defender AV via registry (works even when Defender service is off) ──
    $rtpRaw  = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring"
    $rtp     = DisableFlagToStatus $rtpRaw

    $bmRaw   = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" "DisableBehaviorMonitoring"
    $bm      = DisableFlagToStatus $bmRaw

    $ioavRaw = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" "DisableIOAVProtection"
    $ioav    = DisableFlagToStatus $ioavRaw

    $ssRaw   = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" "DisableScriptScanning"
    $ss      = DisableFlagToStatus $ssRaw

    $bafsRaw = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "DisableBlockAtFirstSeen"
    $bafs    = DisableFlagToStatus $bafsRaw

    $cloudRaw = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SpynetReporting"
    $cloud    = if ($null -eq $cloudRaw) { "NOT SET" } elseif ($cloudRaw -ge 1) { "ENABLED" } else { "DISABLED" }

    $puaRaw  = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender" "PUAProtection"
    $pua     = if ($null -eq $puaRaw) { "NOT SET" } elseif ($puaRaw -ge 1) { "ENABLED" } else { "DISABLED" }

    $sampRaw = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent"
    $samp    = if ($null -eq $sampRaw) { "NOT SET" } elseif ($sampRaw -eq 0) { "DISABLED" } elseif ($sampRaw -ge 1) { "ENABLED" } else { "DISABLED" }

    # ── Network Protection ───────────────────────────────────────
    $netRaw  = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection"
    $net     = if ($null -eq $netRaw) { "NOT SET" } elseif ($netRaw -eq 1) { "ENABLED" } elseif ($netRaw -eq 2) { "AUDIT" } else { "DISABLED" }

    # ── SmartScreen ──────────────────────────────────────────────
    $ssAppRaw = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled"
    $ssApp    = if ($null -eq $ssAppRaw) { "NOT SET" } elseif ($ssAppRaw -eq "Off" -or $ssAppRaw -eq 0) { "DISABLED" } else { "ENABLED" }

    $ssEdgeRaw = Get-RegRaw "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" "EnabledV9"
    $ssEdge    = if ($null -eq $ssEdgeRaw) { "NOT SET" } elseif ($ssEdgeRaw -eq 1) { "ENABLED" } else { "DISABLED" }

    # ── Firewall ─────────────────────────────────────────────────
    $fwDomain = "NOT SET"; $fwPrivate = "NOT SET"; $fwPublic = "NOT SET"
    try {
        $fw = Get-NetFirewallProfile -ErrorAction Stop
        $fwDomain  = if (($fw | Where-Object { $_.Name -eq "Domain"  }).Enabled) { "ENABLED" } else { "DISABLED" }
        $fwPrivate = if (($fw | Where-Object { $_.Name -eq "Private" }).Enabled) { "ENABLED" } else { "DISABLED" }
        $fwPublic  = if (($fw | Where-Object { $_.Name -eq "Public"  }).Enabled) { "ENABLED" } else { "DISABLED" }
    } catch {}

    # ── Print ────────────────────────────────────────────────────
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |  CORE ISOLATION                                              |" -ForegroundColor DarkCyan
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Print-Status "Memory Integrity (HVCI):"           $mi
    Print-Status "Vulnerable Driver Blocklist:"       $db
    Print-Status "Virtualization-Based Security:"     $vbs
    Print-Status "Credential Guard:"                  $cg
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |  WINDOWS DEFENDER - ANTIVIRUS                                |" -ForegroundColor DarkCyan
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Print-Status "Tamper Protection:"                 $tp
    Print-Status "Real-Time Protection:"              $rtp
    Print-Status "Behavior Monitoring:"               $bm
    Print-Status "Cloud-Delivered Protection:"        $cloud
    Print-Status "Block at First Seen:"               $bafs
    Print-Status "IOAV Protection (Downloads):"       $ioav
    Print-Status "Script Scanning:"                   $ss
    Print-Status "PUA Protection:"                    $pua
    Print-Status "Automatic Sample Submission:"       $samp
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |  NETWORK & BROWSER PROTECTION                                |" -ForegroundColor DarkCyan
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Print-Status "Network Protection:"                $net
    Print-Status "SmartScreen (Apps & Files):"        $ssApp
    Print-Status "SmartScreen (Edge):"                $ssEdge
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |  WINDOWS FIREWALL                                            |" -ForegroundColor DarkCyan
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Print-Status "Firewall - Domain Profile:"         $fwDomain
    Print-Status "Firewall - Private Profile:"        $fwPrivate
    Print-Status "Firewall - Public Profile:"         $fwPublic
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  Press  " -ForegroundColor DarkGray -NoNewline
    Write-Host "0" -ForegroundColor Red -NoNewline
    Write-Host "  -->  DISABLE Driver Blocklist + Memory Integrity  |" -ForegroundColor DarkGray
    Write-Host "  |  Press  " -ForegroundColor DarkGray -NoNewline
    Write-Host "1" -ForegroundColor Green -NoNewline
    Write-Host "  -->  ENABLE  Driver Blocklist + Memory Integrity  |" -ForegroundColor DarkGray
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""
}

function Do-Disable {
    Clear-Host
    Write-Host ""
    Write-Host "  +=============================================================+" -ForegroundColor DarkRed
    Write-Host "  |                                                             |" -ForegroundColor DarkRed
    Write-Host "  |    ____  ___ ____    _    ____  _     ___ _   _  ____      |" -ForegroundColor Red
    Write-Host "  |   |  _ \|_ _/ ___|  / \  | __ )| |   |_ _| \ | |/ ___|    |" -ForegroundColor Red
    Write-Host "  |   | | | || |\___ \ / _ \ |  _ \| |    | ||  \| | |  _     |" -ForegroundColor Red
    Write-Host "  |   | |_| || | ___) / ___ \| |_) | |___ | || |\  | |_| |    |" -ForegroundColor Red
    Write-Host "  |   |____/|___\____/_/   \_\____/|_____|___|_| \_|\____|     |" -ForegroundColor Red
    Write-Host "  |                                                             |" -ForegroundColor DarkRed
    Write-Host "  +=============================================================+" -ForegroundColor DarkRed
    Write-Host ""
    Write-Host "  [*] Applying both registry changes before a single restart." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [~] Step 1/2  -  Disabling Memory Integrity..." -ForegroundColor Yellow
    try {
        $p = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        if (!(Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "Enabled" -Value 0 -Type DWord -Force
        Write-Host "  [+] Memory Integrity      -->  " -NoNewline -ForegroundColor Gray
        Write-Host "DISABLED" -ForegroundColor Red
        Write-Host "      Successfully written to registry." -ForegroundColor DarkGray
    } catch { Write-Host "  [!] Failed: $($_.Exception.Message)" -ForegroundColor Red }

    Write-Host ""
    Write-Host "  [~] Step 2/2  -  Disabling Driver Blocklist..." -ForegroundColor Yellow
    try {
        $p2 = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
        if (!(Test-Path $p2)) { New-Item -Path $p2 -Force | Out-Null }
        Set-ItemProperty -Path $p2 -Name "VulnerableDriverBlocklistEnable" -Value 0 -Type DWord -Force
        Write-Host "  [+] Driver Blocklist      -->  " -NoNewline -ForegroundColor Gray
        Write-Host "DISABLED" -ForegroundColor Red
        Write-Host "      Successfully written to registry." -ForegroundColor DarkGray
    } catch { Write-Host "  [!] Failed: $($_.Exception.Message)" -ForegroundColor Red }

    Write-Host ""
    Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  [+] Both changes applied! Normally 2 restarts needed -" -ForegroundColor Green
    Write-Host "      this script handles it in ONE restart." -ForegroundColor Green
    Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""
}

function Do-Enable {
    Clear-Host
    Write-Host ""
    Write-Host "  +=============================================================+" -ForegroundColor DarkGreen
    Write-Host "  |                                                             |" -ForegroundColor DarkGreen
    Write-Host "  |    ___ _   _    _    ____  _     ___ _   _  ____           |" -ForegroundColor Green
    Write-Host "  |   | __|| \ | |  / \  | __ )| |   |_ _| \ | |/ ___|        |" -ForegroundColor Green
    Write-Host "  |   |  _| |  \| | / _ \ |  _ \| |    | ||  \| | |  _        |" -ForegroundColor Green
    Write-Host "  |   | |___| |\  |/ ___ \| |_) | |___ | || |\  | |_| |       |" -ForegroundColor Green
    Write-Host "  |   |_____|_| \_/_/   \_\____/|_____|___|_| \_|\____|        |" -ForegroundColor Green
    Write-Host "  |                                                             |" -ForegroundColor DarkGreen
    Write-Host "  +=============================================================+" -ForegroundColor DarkGreen
    Write-Host ""
    Write-Host "  [*] Applying both registry changes before a single restart." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [~] Step 1/2  -  Enabling Memory Integrity..." -ForegroundColor Yellow
    try {
        $p = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        if (!(Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "Enabled" -Value 1 -Type DWord -Force
        Write-Host "  [+] Memory Integrity      -->  " -NoNewline -ForegroundColor Gray
        Write-Host "ENABLED" -ForegroundColor Green
        Write-Host "      Successfully written to registry." -ForegroundColor DarkGray
    } catch { Write-Host "  [!] Failed: $($_.Exception.Message)" -ForegroundColor Red }

    Write-Host ""
    Write-Host "  [~] Step 2/2  -  Enabling Driver Blocklist..." -ForegroundColor Yellow
    try {
        $p2 = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
        if (!(Test-Path $p2)) { New-Item -Path $p2 -Force | Out-Null }
        Set-ItemProperty -Path $p2 -Name "VulnerableDriverBlocklistEnable" -Value 1 -Type DWord -Force
        Write-Host "  [+] Driver Blocklist      -->  " -NoNewline -ForegroundColor Gray
        Write-Host "ENABLED" -ForegroundColor Green
        Write-Host "      Successfully written to registry." -ForegroundColor DarkGray
    } catch { Write-Host "  [!] Failed: $($_.Exception.Message)" -ForegroundColor Red }

    Write-Host ""
    Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  [+] Both changes applied!" -ForegroundColor Green
    Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""
}

function Do-Countdown {
    for ($i = 3; $i -gt 0; $i--) {
        Write-Host "  [!] Restarting in $i seconds...  (Close window to cancel)" -ForegroundColor Yellow
        Start-Sleep 1
    }
    shutdown /r /t 0 /f
}

while ($true) {
    Show-Menu
    $key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
    if ($key -eq '0') { Do-Disable; Do-Countdown; break }
    elseif ($key -eq '1') { Do-Enable; Do-Countdown; break }
}
