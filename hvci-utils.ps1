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

$host.UI.RawUI.WindowTitle = "HVCI Utils"

# ── Registry helpers ─────────────────────────────────────────────────────────

function Get-RegRaw([string]$path, [string]$name) {
    try { return (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name }
    catch { return $null }
}

function RegToStatus($val) {
    if ($null -eq $val) { return "NOT SET" }
    if ($val -eq 0)     { return "DISABLED" }
    if ($val -eq 1)     { return "ENABLED" }
    return "UNKNOWN"
}

function DisableFlagToStatus($val) {
    if ($null -eq $val)                { return "NOT SET" }
    if ($val -eq $true -or $val -eq 1) { return "DISABLED" }
    return "ENABLED"
}

# ── Print helpers ────────────────────────────────────────────────────────────

function Print-Status([string]$label, [string]$val) {
    $c = if ($val -eq "ENABLED") { "Green" } elseif ($val -eq "DISABLED") { "Red" } else { "Yellow" }
    Write-Host "  |  " -NoNewline -ForegroundColor Cyan
    Write-Host $label.PadRight(36) -NoNewline -ForegroundColor Cyan
    Write-Host $val.PadRight(9)    -NoNewline -ForegroundColor $c
    Write-Host " |"                            -ForegroundColor Cyan
}

function Print-LogoLine([string]$text) {
    $inner = 61
    $left  = [math]::Floor(($inner - $text.Length) / 2)
    $right = $inner - $text.Length - $left
    Write-Host ("  |" + (" " * $left))  -NoNewline -ForegroundColor DarkGreen
    Write-Host $text                     -NoNewline -ForegroundColor Green
    Write-Host ((" " * $right) + "|")              -ForegroundColor DarkGreen
}

# ── Collect all status values ────────────────────────────────────────────────

function Get-AllStatus {
    $s = @{}

    # Core Isolation
    $s.mi    = RegToStatus (Get-RegRaw "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled")
    $s.db    = RegToStatus (Get-RegRaw "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" "VulnerableDriverBlocklistEnable")
    $s.vbs   = RegToStatus (Get-RegRaw "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity")
    $cgRaw   = Get-RegRaw   "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "LsaCfgFlags"
    $s.cg    = if ($null -eq $cgRaw) { "NOT SET" } elseif ($cgRaw -ge 1) { "ENABLED" } else { "DISABLED" }
    $ksRaw   = Get-RegRaw "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks" "Enabled"
    $s.ks    = RegToStatus $ksRaw
    $sacRaw  = Get-RegRaw "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" "VerifiedAndReputablePolicyState"
    $s.sac   = if ($null -eq $sacRaw) { "NOT SET" } elseif ($sacRaw -eq 1) { "ENABLED" } elseif ($sacRaw -eq 2) { "EVALUATING" } else { "DISABLED" }

    # Hyper-V
    $s.hyperv = "ENABLED"
    try {
        $bcd = bcdedit /enum 2>$null
        foreach ($line in $bcd) {
            if ($line -match "hypervisorlaunchtype\s+Off") { $s.hyperv = "DISABLED" }
        }
    } catch {}

    # Driver & Boot
    $s.dse   = "ENABLED"
    $s.tsm   = "DISABLED"
    try {
        $bcd = bcdedit /enum 2>$null
        foreach ($line in $bcd) {
            if ($line -match "nointegritychecks\s+Yes") { $s.dse = "DISABLED" }
            if ($line -match "testsigning\s+Yes")       { $s.tsm = "ENABLED"  }
        }
    } catch {}
    $sbRaw   = Get-RegRaw "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" "UEFISecureBootEnabled"
    $s.sb    = RegToStatus $sbRaw
    $dmaRaw  = Get-RegRaw "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection" "DeviceEnumerationPolicy"
    $s.dma   = if ($null -eq $dmaRaw) { "NOT SET" } elseif ($dmaRaw -eq 0) { "ENABLED" } elseif ($dmaRaw -eq 2) { "DISABLED" } else { "PARTIAL" }

    # Tamper & AV
    $tpRaw   = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" "TamperProtection"
    $s.tp    = if ($null -eq $tpRaw) { "NOT SET" } elseif ($tpRaw -eq 5) { "ENABLED" } elseif ($tpRaw -eq 0 -or $tpRaw -eq 4) { "DISABLED" } else { "UNKNOWN" }
    $s.rtp   = DisableFlagToStatus (Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring")
    $s.bm    = DisableFlagToStatus (Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" "DisableBehaviorMonitoring")
    $s.ioav  = DisableFlagToStatus (Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" "DisableIOAVProtection")
    $s.ss    = DisableFlagToStatus (Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" "DisableScriptScanning")
    $s.bafs  = DisableFlagToStatus (Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "DisableBlockAtFirstSeen")
    $cloudRaw = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SpynetReporting"
    $s.cloud  = if ($null -eq $cloudRaw) { "NOT SET" } elseif ($cloudRaw -ge 1) { "ENABLED" } else { "DISABLED" }
    $puaRaw  = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender" "PUAProtection"
    $s.pua   = if ($null -eq $puaRaw) { "NOT SET" } elseif ($puaRaw -ge 1) { "ENABLED" } else { "DISABLED" }
    $sampRaw = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent"
    $s.samp  = if ($null -eq $sampRaw) { "NOT SET" } elseif ($sampRaw -eq 0) { "DISABLED" } elseif ($sampRaw -ge 1) { "ENABLED" } else { "DISABLED" }
    $sbxRaw  = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender" "DisableSandboxing"
    $s.sbx   = if ($null -eq $sbxRaw) { "NOT SET" } elseif ($sbxRaw -eq 0) { "ENABLED" } else { "DISABLED" }

    # Exploit Guard
    $netRaw  = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection"
    $s.net   = if ($null -eq $netRaw) { "NOT SET" } elseif ($netRaw -eq 1) { "ENABLED" } elseif ($netRaw -eq 2) { "AUDIT" } else { "DISABLED" }
    $cfaRaw  = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" "EnableControlledFolderAccess"
    $s.cfa   = if ($null -eq $cfaRaw) { "NOT SET" } elseif ($cfaRaw -eq 1) { "ENABLED" } elseif ($cfaRaw -eq 2) { "AUDIT" } else { "DISABLED" }
    $asrRaw  = Get-RegRaw "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" "ExploitGuard_ASR_Rules"
    $s.asr   = if ($null -eq $asrRaw) { "NOT SET" } elseif ($asrRaw -eq 1) { "ENABLED" } else { "DISABLED" }
    $lsaRaw  = Get-RegRaw "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
    $s.lsa   = if ($null -eq $lsaRaw) { "NOT SET" } elseif ($lsaRaw -ge 1) { "ENABLED" } else { "DISABLED" }

    # SmartScreen
    $ssAppRaw  = Get-RegRaw "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled"
    $s.ssApp   = if ($null -eq $ssAppRaw) { "NOT SET" } elseif ($ssAppRaw -eq "Off" -or $ssAppRaw -eq 0) { "DISABLED" } else { "ENABLED" }
    $ssEdgeRaw = Get-RegRaw "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" "EnabledV9"
    $s.ssEdge  = if ($null -eq $ssEdgeRaw) { "NOT SET" } elseif ($ssEdgeRaw -eq 1) { "ENABLED" } else { "DISABLED" }

    # Firewall
    $s.fwDomain = "NOT SET"; $s.fwPrivate = "NOT SET"; $s.fwPublic = "NOT SET"
    try {
        $fw          = Get-NetFirewallProfile -ErrorAction Stop
        $s.fwDomain  = if (($fw | Where-Object { $_.Name -eq "Domain"  }).Enabled) { "ENABLED" } else { "DISABLED" }
        $s.fwPrivate = if (($fw | Where-Object { $_.Name -eq "Private" }).Enabled) { "ENABLED" } else { "DISABLED" }
        $s.fwPublic  = if (($fw | Where-Object { $_.Name -eq "Public"  }).Enabled) { "ENABLED" } else { "DISABLED" }
    } catch {}

    return $s
}

# ── Menu ─────────────────────────────────────────────────────────────────────

function Show-Menu {
    Clear-Host
    Write-Host ""
    Write-Host "  +=============================================================+" -ForegroundColor DarkGreen
    Write-Host "  |                                                             |" -ForegroundColor DarkGreen
    Print-LogoLine "  _    ___      _______ _____      _    _ "
    Print-LogoLine " | |  | \ \    / / ____|_   _|    | |  | |"
    Print-LogoLine " | |__| |\ \  / / |      | |______| |  | |"
    Print-LogoLine " |  __  | \ \/ /| |      | |______| |  | |"
    Print-LogoLine " | |  | |  \  / | |____ _| |_     | |__| |"
    Print-LogoLine " |_|  |_|   \/   \_____|_____|     \____/ "
    Write-Host "  |                                                             |" -ForegroundColor DarkGreen
    Write-Host "  |      Web: samsam.lol       GitHub: itzzz_ryze              |" -ForegroundColor DarkGreen
    Write-Host "  |                                                             |" -ForegroundColor DarkGreen
    Write-Host "  +=============================================================+" -ForegroundColor DarkGreen
    Write-Host ""

    $s = Get-AllStatus

    # Core Isolation
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |  CORE ISOLATION                                              |" -ForegroundColor DarkCyan
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Print-Status "Memory Integrity (HVCI):"           $s.mi
    Print-Status "Vulnerable Driver Blocklist:"       $s.db
    Print-Status "Virtualization-Based Security:"     $s.vbs
    Print-Status "Credential Guard:"                  $s.cg
    Print-Status "Kernel Stack Protection:"           $s.ks
    Print-Status "Smart App Control:"                 $s.sac
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    # Driver & Boot
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |  DRIVER & BOOT SECURITY                                      |" -ForegroundColor DarkCyan
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Print-Status "Driver Signature Enforcement:"      $s.dse
    Print-Status "Test Signing Mode:"                 $s.tsm
    Print-Status "Hyper-V:"                           $s.hyperv
    Print-Status "Secure Boot:"                       $s.sb
    Print-Status "Kernel DMA Protection:"             $s.dma
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    # Defender
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |  WINDOWS DEFENDER - ANTIVIRUS                                |" -ForegroundColor DarkCyan
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Print-Status "Tamper Protection:"                 $s.tp
    Print-Status "Real-Time Protection:"              $s.rtp
    Print-Status "Behavior Monitoring:"               $s.bm
    Print-Status "Cloud-Delivered Protection:"        $s.cloud
    Print-Status "Block at First Seen:"               $s.bafs
    Print-Status "IOAV Protection (Downloads):"       $s.ioav
    Print-Status "Script Scanning:"                   $s.ss
    Print-Status "PUA Protection:"                    $s.pua
    Print-Status "Automatic Sample Submission:"       $s.samp
    Print-Status "Defender Sandbox:"                  $s.sbx
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    # Exploit Guard
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |  EXPLOIT GUARD & ADVANCED PROTECTION                         |" -ForegroundColor DarkCyan
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Print-Status "Network Protection:"                $s.net
    Print-Status "Controlled Folder Access:"          $s.cfa
    Print-Status "Attack Surface Reduction (ASR):"    $s.asr
    Print-Status "LSA Protection:"                    $s.lsa
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    # Network & Browser
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |  NETWORK & BROWSER PROTECTION                                |" -ForegroundColor DarkCyan
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Print-Status "SmartScreen (Apps & Files):"        $s.ssApp
    Print-Status "SmartScreen (Edge):"                $s.ssEdge
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    # Firewall
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |  WINDOWS FIREWALL                                            |" -ForegroundColor DarkCyan
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Print-Status "Firewall - Domain Profile:"         $s.fwDomain
    Print-Status "Firewall - Private Profile:"        $s.fwPrivate
    Print-Status "Firewall - Public Profile:"         $s.fwPublic
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    # Options
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  Press  " -NoNewline -ForegroundColor DarkGray
    Write-Host "0" -NoNewline -ForegroundColor Red
    Write-Host "  -->  DISABLE  Driver Blocklist + Memory Integrity |" -ForegroundColor DarkGray
    Write-Host "  |  Press  " -NoNewline -ForegroundColor DarkGray
    Write-Host "1" -NoNewline -ForegroundColor Green
    Write-Host "  -->  ENABLE   Driver Blocklist + Memory Integrity |" -ForegroundColor DarkGray
    Write-Host "  |  Press  " -NoNewline -ForegroundColor DarkGray
    Write-Host "2" -NoNewline -ForegroundColor Yellow
    Write-Host "  -->  REBOOT   into UEFI / Firmware Settings       |" -ForegroundColor DarkGray
    Write-Host "  |  Press  " -NoNewline -ForegroundColor DarkGray
    Write-Host "3" -NoNewline -ForegroundColor Cyan
    Write-Host "  -->  REBOOT   into Startup Settings (DSE screen)  |" -ForegroundColor DarkGray
    Write-Host "  |  Press  " -NoNewline -ForegroundColor DarkGray
    Write-Host "4" -NoNewline -ForegroundColor Magenta
    Write-Host "  -->  TOGGLE   Hyper-V on / off                    |" -ForegroundColor DarkGray
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""
}

# ── Disable HVCI + VDB ───────────────────────────────────────────────────────

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
    Write-Host "      HVCI Utils handles it in ONE restart." -ForegroundColor Green
    Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""
}

# ── Enable HVCI + VDB ────────────────────────────────────────────────────────

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

# ── UEFI reboot ──────────────────────────────────────────────────────────────

function Do-UEFI {
    Clear-Host
    Write-Host ""
    Write-Host "  +=============================================================+" -ForegroundColor DarkYellow
    Write-Host "  |                                                             |" -ForegroundColor DarkYellow
    Write-Host "  |          _   _ _____ _____ ___                              |" -ForegroundColor Yellow
    Write-Host "  |         | | | | ____|  ___|_ _|                            |" -ForegroundColor Yellow
    Write-Host "  |         | | | |  _| | |_   | |                             |" -ForegroundColor Yellow
    Write-Host "  |         | |_| | |___|  _|  | |                             |" -ForegroundColor Yellow
    Write-Host "  |          \___/|_____|_|    |___|                            |" -ForegroundColor Yellow
    Write-Host "  |                                                             |" -ForegroundColor DarkYellow
    Write-Host "  +=============================================================+" -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "  [*] Rebooting directly into UEFI / Firmware Settings." -ForegroundColor Gray
    Write-Host "  [*] Command: shutdown /r /fw /t 0" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [!] Your PC will reboot straight into BIOS/UEFI." -ForegroundColor Yellow
    Write-Host "  [!] No OS will load - you will land in firmware settings." -ForegroundColor Yellow
    Write-Host ""
}

# ── Startup Settings (DSE screen) ────────────────────────────────────────────

function Do-StartupSettings {
    Clear-Host
    Write-Host ""
    Write-Host "  +=============================================================+" -ForegroundColor DarkCyan
    Write-Host "  |                                                             |" -ForegroundColor DarkCyan
    Write-Host "  |    ___  _____  _    ____  _____   _   _ ____               |" -ForegroundColor Cyan
    Write-Host "  |   / __||_   _|/ \  |  _ \|_   _| | | | |  _ \             |" -ForegroundColor Cyan
    Write-Host "  |   \__ \  | | / _ \ | |_) | | |   | | | | |_) |            |" -ForegroundColor Cyan
    Write-Host "  |   |___/  |_|/_/ \_\|_| __/  |_|  | |_| |  __/             |" -ForegroundColor Cyan
    Write-Host "  |               ____  ______|_|      \___/|_|                |" -ForegroundColor Cyan
    Write-Host "  |              / ___|| ____|_   _|___ |_|  _  _  ____ ____   |" -ForegroundColor Cyan
    Write-Host "  |              \___ \|  _|  | |_/_   _||  | || |/ ___/ ___|  |" -ForegroundColor Cyan
    Write-Host "  |               ___) | |___  |  _|| |  | | || | |  | |  _   |" -ForegroundColor Cyan
    Write-Host "  |              |____/|_____| |_|  |_|  |_|_||_|\___\____|   |" -ForegroundColor Cyan
    Write-Host "  |                                                             |" -ForegroundColor DarkCyan
    Write-Host "  +=============================================================+" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  [*] Rebooting into Windows Startup Settings." -ForegroundColor Gray
    Write-Host "  [*] Command: shutdown /r /o /t 0" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [*] After reboot: Troubleshoot --> Advanced Options" -ForegroundColor Gray
    Write-Host "      --> Startup Settings --> Restart" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [*] Then press the number for what you need:" -ForegroundColor Gray
    Write-Host "      4  - Enable Safe Mode" -ForegroundColor DarkGray
    Write-Host "      5  - Enable Safe Mode with Networking" -ForegroundColor DarkGray
    Write-Host "      6  - Enable Safe Mode with Command Prompt" -ForegroundColor DarkGray
    Write-Host "      7  - Disable Driver Signature Enforcement" -ForegroundColor Yellow
    Write-Host "      8  - Disable Early Launch Anti-Malware" -ForegroundColor DarkGray
    Write-Host "      9  - Disable Automatic Restart after Failure" -ForegroundColor DarkGray
    Write-Host ""
}

# ── Toggle Hyper-V ───────────────────────────────────────────────────────────

function Do-HyperV {
    Clear-Host
    Write-Host ""
    Write-Host "  +=============================================================+" -ForegroundColor DarkMagenta
    Write-Host "  |                                                             |" -ForegroundColor DarkMagenta
    Write-Host "  |    _   _ __   __ ____  _____  ____       __     __         |" -ForegroundColor Magenta
    Write-Host "  |   | | | |\ \ / /|  _ \| ____||  _ \     \ \   / /         |" -ForegroundColor Magenta
    Write-Host "  |   | |_| | \ V / | |_) |  _|  | |_) |____\ \ / /          |" -ForegroundColor Magenta
    Write-Host "  |   |  _  |  | |  |  __/| |___ |  _ <|_____\ V /           |" -ForegroundColor Magenta
    Write-Host "  |   |_| |_|  |_|  |_|   |_____||_| \_\      \_/            |" -ForegroundColor Magenta
    Write-Host "  |                                                             |" -ForegroundColor DarkMagenta
    Write-Host "  +=============================================================+" -ForegroundColor DarkMagenta
    Write-Host ""

    # Detect current Hyper-V state
    $currentState = "Auto"
    try {
        $bcd = bcdedit /enum 2>$null
        foreach ($line in $bcd) {
            if ($line -match "hypervisorlaunchtype\s+Off") { $currentState = "Off" }
        }
    } catch {}

    if ($currentState -eq "Off") {
        Write-Host "  [*] Hyper-V is currently: " -NoNewline -ForegroundColor Gray
        Write-Host "DISABLED" -ForegroundColor Red
        Write-Host "  [~] Enabling Hyper-V..." -ForegroundColor Yellow
        Write-Host ""
        try {
            $result = bcdedit /set hypervisorlaunchtype Auto 2>&1
            Write-Host "  [+] Hyper-V  -->  " -NoNewline -ForegroundColor Gray
            Write-Host "ENABLED" -ForegroundColor Green
            Write-Host "      bcdedit set hypervisorlaunchtype to Auto." -ForegroundColor DarkGray
        } catch { Write-Host "  [!] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    } else {
        Write-Host "  [*] Hyper-V is currently: " -NoNewline -ForegroundColor Gray
        Write-Host "ENABLED" -ForegroundColor Green
        Write-Host "  [~] Disabling Hyper-V..." -ForegroundColor Yellow
        Write-Host ""
        try {
            $result = bcdedit /set hypervisorlaunchtype Off 2>&1
            Write-Host "  [+] Hyper-V  -->  " -NoNewline -ForegroundColor Gray
            Write-Host "DISABLED" -ForegroundColor Red
            Write-Host "      bcdedit set hypervisorlaunchtype to Off." -ForegroundColor DarkGray
        } catch { Write-Host "  [!] Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }

    Write-Host ""
    Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  [!] A restart is required to apply Hyper-V changes." -ForegroundColor Yellow
    Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""
}

# ── Countdown ────────────────────────────────────────────────────────────────

function Do-Countdown([string]$mode) {
    for ($i = 6; $i -gt 0; $i--) {
        switch ($mode) {
            "uefi"    { Write-Host "  [!] Rebooting to UEFI in $i seconds...     (Close window to cancel)" -ForegroundColor Yellow }
            "startup" { Write-Host "  [!] Rebooting to Startup Settings in $i seconds...  (Close to cancel)" -ForegroundColor Yellow }
            default   { Write-Host "  [!] Restarting in $i seconds...             (Close window to cancel)" -ForegroundColor Yellow }
        }
        Start-Sleep 1
    }
    switch ($mode) {
        "uefi"    { shutdown /r /fw /t 0 }
        "startup" { shutdown /r /o /t 0  }
        default   { shutdown /r /t 0 /f  }
    }
}

# ── Main loop ────────────────────────────────────────────────────────────────

while ($true) {
    Show-Menu
    $key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
    if     ($key -eq '0') { Do-Disable;       Do-Countdown "normal";  break }
    elseif ($key -eq '1') { Do-Enable;        Do-Countdown "normal";  break }
    elseif ($key -eq '2') { Do-UEFI;          Do-Countdown "uefi";    break }
    elseif ($key -eq '3') { Do-StartupSettings; Do-Countdown "startup"; break }
    elseif ($key -eq '4') { Do-HyperV;        Do-Countdown "normal";  break }
}
