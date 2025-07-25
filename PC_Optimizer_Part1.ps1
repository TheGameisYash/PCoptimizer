# PC Optimizer Pro v3.1 - PowerShell Edition (Enhanced & Fixed) - Part 1

param(
    [switch]$AsAdmin
)

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    if (-NOT $AsAdmin) {
        Write-Host "[!] Requesting administrator privileges..." -ForegroundColor Yellow
        Start-Process PowerShell -Verb RunAs -ArgumentList ("-File", $MyInvocation.MyCommand.Path, "-AsAdmin")
        exit
    }
}

# Configuration
$script:CONFIG = @{
    SERVER_URL = "https://optimize-blush.vercel.app"
    LICENSE_FILE = "$env:ProgramData\pc_optimizer.lic"
    LOG_FILE = "$env:TEMP\optimizer_log.txt"
    BACKUP_DIR = "$env:ProgramData\PC_Optimizer_Backups"
    MIN_ADMIN_VERSION = "3.1"
}

# Status markers
$script:SYMBOLS = @{
    OK = "[OK]"
    WARN = "[!]"
    ERR = "[X]"
    INFO = "[i]"
    RUN = "[>]"
}

# Initialize directories and logging
function Initialize-System {
    if (-not (Test-Path $script:CONFIG.BACKUP_DIR)) {
        New-Item -ItemType Directory -Path $script:CONFIG.BACKUP_DIR -Force | Out-Null
    }
    
    Add-Content -Path $script:CONFIG.LOG_FILE -Value "[$(Get-Date)] PC Optimizer Pro v$($script:CONFIG.MIN_ADMIN_VERSION) started"
    
    if (-not (Test-Path $script:CONFIG.LICENSE_FILE)) {
        Set-Content -Path $script:CONFIG.LICENSE_FILE -Value "Version: $($script:CONFIG.MIN_ADMIN_VERSION)"
    }
}

# Logging function
function Write-Log {
    param([string]$Level, [string]$Message)
    Add-Content -Path $script:CONFIG.LOG_FILE -Value "[$(Get-Date)] [$Level] $Message"
}

# UI Helper Functions
function Show-Header {
    param([string]$Title)
    Clear-Host
    Write-Host "+------------------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "| $Title" -ForegroundColor Cyan
    Write-Host "+------------------------------------------------------------------------------+" -ForegroundColor Cyan
}

function Show-Footer {
    param([string]$Prompt)
    Write-Host "+------------------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "| $Prompt" -ForegroundColor Cyan
    Write-Host "+------------------------------------------------------------------------------+" -ForegroundColor Cyan
}

function Write-Status {
    param([string]$Type, [string]$Message)
    $color = switch ($Type) {
        "OK" { "Green" }
        "WARN" { "Yellow" }
        "ERR" { "Red" }
        "INFO" { "Cyan" }
        "RUN" { "Magenta" }
        default { "White" }
    }
    
    Write-Host "$($script:SYMBOLS.$Type) $Message" -ForegroundColor $color
}

# Enhanced HWID Detection (PowerShell native)
function Get-HardwareID {
    Write-Status "RUN" "Detecting hardware signature..."
    $hwid = $null
    
    try {
        # Method 1: System UUID (Most reliable)
        $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
        if ($systemInfo -and $systemInfo.UUID -and $systemInfo.UUID -ne "00000000-0000-0000-0000-000000000000") {
            $hwid = $systemInfo.UUID
            Write-Log "INFO" "HWID detected using UUID method"
        }
    } catch {}
    
    if (-not $hwid) {
        try {
            # Method 2: Motherboard Serial
            $motherboard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
            if ($motherboard -and $motherboard.SerialNumber -and $motherboard.SerialNumber.Trim() -ne "") {
                $hwid = $motherboard.SerialNumber.Trim()
                Write-Log "INFO" "HWID detected using motherboard serial"
            }
        } catch {}
    }
    
    if (-not $hwid) {
        try {
            # Method 3: BIOS Serial
            $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
            if ($bios -and $bios.SerialNumber -and $bios.SerialNumber.Trim() -ne "") {
                $hwid = $bios.SerialNumber.Trim()
                Write-Log "INFO" "HWID detected using BIOS serial"
            }
        } catch {}
    }
    
    if (-not $hwid) {
        try {
            # Method 4: CPU ID
            $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($cpu -and $cpu.ProcessorId) {
                $hwid = $cpu.ProcessorId
                Write-Log "INFO" "HWID detected using CPU ID"
            }
        } catch {}
    }
    
    # Fallback method
    if (-not $hwid) {
        $hwid = "$env:COMPUTERNAME" + "_" + "$env:USERNAME" + "_" + (Get-Random -Maximum 99999)
        Write-Log "WARNING" "Generated fallback HWID"
    }
    
    # Clean and limit HWID
    $hwid = $hwid -replace '\s', ''
    if ($hwid.Length -gt 64) {
        $hwid = $hwid.Substring(0, 64)
    }
    
    Write-Status "OK" "Hardware ID: $($hwid.Substring(0, [Math]::Min(12, $hwid.Length)))..."
    return $hwid
}

# License validation
function Test-License {
    param([string]$License, [string]$HWID)
    
    if (-not (Test-Path $script:CONFIG.LICENSE_FILE)) {
        return $false
    }
    
    $licenseContent = Get-Content $script:CONFIG.LICENSE_FILE -ErrorAction SilentlyContinue
    if ($licenseContent -and $licenseContent[0] -eq "Version: $($script:CONFIG.MIN_ADMIN_VERSION)") {
        return $false
    }
    
    $parts = $licenseContent[0] -split '\s+'
    if ($parts.Length -ge 2) {
        $storedLicense = $parts[0]
        $storedHWID = $parts[1]
        
        if ($storedHWID -eq $HWID -and $storedLicense -eq $License) {
            Write-Status "RUN" "Validating premium license..."
            try {
                $response = Invoke-WebRequest -Uri "$($script:CONFIG.SERVER_URL)/api/validate?license=$License&hwid=$HWID" -UseBasicParsing -TimeoutSec 15
                if ($response.Content -eq "VALID") {
                    Write-Status "OK" "Premium license validated successfully"
                    Write-Log "INFO" "License validation successful"
                    return $true
                }
            } catch {
                Write-Status "WARN" "Server timeout - Working in offline premium mode"
                return $true
            }
        } else {
            Write-Status "WARN" "Hardware change detected or license mismatch"
            Remove-Item $script:CONFIG.LICENSE_FILE -Force -ErrorAction SilentlyContinue
        }
    }
    
    return $false
}

# --- SYSTEM INFORMATION ---
function Get-SystemInfo {
    Show-Header "COMPREHENSIVE SYSTEM INFORMATION"
    Write-Status "RUN" "Gathering system information..."
    Write-Host ""
    
    Write-Host "COMPUTER INFORMATION:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    
    Write-Host "Computer Name     : $env:COMPUTERNAME"
    Write-Host "Operating System  : $($os.Caption)"
    Write-Host "OS Version        : $($os.Version)"
    Write-Host "System Type       : $($os.OSArchitecture)"
    Write-Host "Manufacturer      : $($computer.Manufacturer)"
    Write-Host "Model             : $($computer.Model)"
    Write-Host ("Total RAM         : {0:N2} GB" -f ($computer.TotalPhysicalMemory / 1GB))
    Write-Host "Boot Time         : $($os.ConvertToDateTime($os.LastBootUpTime))"
    Write-Host ""
    
    Write-Host "PROCESSOR INFORMATION:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    Write-Host "Processor Name    : $($cpu.Name)"
    Write-Host "Physical Cores    : $($cpu.NumberOfCores)"
    Write-Host "Logical Cores     : $($cpu.NumberOfLogicalProcessors)"
    Write-Host ("Max Clock Speed   : {0:N2} GHz" -f ($cpu.MaxClockSpeed/1000))
    Write-Host "Current Load      : $($cpu.LoadPercentage)%"
    Write-Host ""
    
    Write-Host "MEMORY INFORMATION:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    $totalRAM = [Math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeRAM = [Math]::Round($os.FreePhysicalMemory / 1MB, 2)
    $usedRAM = $totalRAM - $freeRAM
    $memUsage = [Math]::Round(($usedRAM / $totalRAM) * 100, 1)
    
    Write-Host ("Total RAM         : {0:N2} GB" -f $totalRAM)
    Write-Host ("Available RAM     : {0:N2} GB" -f $freeRAM)
    Write-Host ("Used RAM          : {0:N2} GB ({1}%)" -f $usedRAM, $memUsage)
    Write-Host ""
    
    Write-Host "SYSTEM IDENTIFICATION:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host "Hardware ID       : $script:HWID"
    Write-Host ("License Status    : {0}" -f (if($script:isPremium) { 'Premium Active' } else { 'Free Version' }))
    Write-Host "Current User      : $env:USERNAME"
    Write-Host ("Domain/Workgroup  : {0}" -f $computer.Domain)
    
    Write-Status "OK" "System information gathered successfully!"
    Write-Log "INFO" "System info viewed"
    Write-Host ""
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# --- Continue with Part 2 if ready ---
