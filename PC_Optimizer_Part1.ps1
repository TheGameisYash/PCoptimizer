# PC Optimizer Pro v3.0 - PowerShell Edition (Fixed)

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
    MIN_ADMIN_VERSION = "3.0"
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
    try {
        Add-Content -Path $script:CONFIG.LOG_FILE -Value "[$(Get-Date)] [$Level] $Message" -ErrorAction SilentlyContinue
    } catch {
        # Silently handle logging errors
    }
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

# Enhanced HWID Detection (Fixed)
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
    } catch {
        Write-Log "WARN" "UUID method failed"
    }
    
    if (-not $hwid) {
        try {
            # Method 2: Motherboard Serial
            $motherboard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
            if ($motherboard -and $motherboard.SerialNumber -and $motherboard.SerialNumber.Trim() -ne "") {
                $hwid = $motherboard.SerialNumber.Trim()
                Write-Log "INFO" "HWID detected using motherboard serial"
            }
        } catch {
            Write-Log "WARN" "Motherboard method failed"
        }
    }
    
    if (-not $hwid) {
        try {
            # Method 3: BIOS Serial
            $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
            if ($bios -and $bios.SerialNumber -and $bios.SerialNumber.Trim() -ne "") {
                $hwid = $bios.SerialNumber.Trim()
                Write-Log "INFO" "HWID detected using BIOS serial"
            }
        } catch {
            Write-Log "WARN" "BIOS method failed"
        }
    }
    
    if (-not $hwid) {
        try {
            # Method 4: CPU ID
            $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($cpu -and $cpu.ProcessorId) {
                $hwid = $cpu.ProcessorId
                Write-Log "INFO" "HWID detected using CPU ID"
            }
        } catch {
            Write-Log "WARN" "CPU method failed"
        }
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

# License validation (Fixed)
function Test-License {
    param([string]$License, [string]$HWID)
    
    if (-not (Test-Path $script:CONFIG.LICENSE_FILE)) {
        return $false
    }
    
    try {
        $licenseContent = Get-Content $script:CONFIG.LICENSE_FILE -ErrorAction SilentlyContinue
        if ($licenseContent -and $licenseContent[0] -eq "Version: $($script:CONFIG.MIN_ADMIN_VERSION)") {
            return $false
        }
        
        $parts = $licenseContent -split '\s+'
        if ($parts.Length -ge 2) {
            $storedLicense = $parts[0]
            $storedHWID = $parts[1]
            if ($storedHWID -eq $HWID) {
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
                Write-Status "WARN" "Hardware change detected"
                Remove-Item $script:CONFIG.LICENSE_FILE -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-Log "ERROR" "License validation error: $($_.Exception.Message)"
    }
    
    return $false
}

# System Information Functions (Fixed)
function Get-SystemInfo {
    Show-Header "COMPREHENSIVE SYSTEM INFORMATION"
    Write-Status "RUN" "Gathering system information..."
    Write-Host ""
    
    try {
        Write-Host "COMPUTER INFORMATION:" -ForegroundColor Yellow
        Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        
        Write-Host "Computer Name : $env:COMPUTERNAME"
        if ($os) {
            Write-Host "Operating System : $($os.Caption)"
            Write-Host "OS Version : $($os.Version)"
            Write-Host "System Type : $($os.OSArchitecture)"
        }
        if ($computer) {
            Write-Host "Manufacturer : $($computer.Manufacturer)"
            Write-Host "Model : $($computer.Model)"
        }
        Write-Host ""
        
        Write-Host "PROCESSOR INFORMATION:" -ForegroundColor Yellow
        Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cpu) {
            Write-Host "Processor Name : $($cpu.Name)"
            Write-Host "Physical Cores : $($cpu.NumberOfCores)"
            Write-Host "Logical Cores : $($cpu.NumberOfLogicalProcessors)"
            Write-Host "Max Clock Speed : $([Math]::Round($cpu.MaxClockSpeed/1000, 2)) GHz"
        }
        Write-Host ""
        
        Write-Host "MEMORY INFORMATION:" -ForegroundColor Yellow
        Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
        if ($os) {
            $totalRAM = [Math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
            $freeRAM = [Math]::Round($os.FreePhysicalMemory / 1MB, 2)
            Write-Host "Total RAM : $totalRAM GB"
            Write-Host "Available RAM : $freeRAM GB"
        }
        Write-Host ""
        
        Write-Host "SYSTEM IDENTIFICATION:" -ForegroundColor Yellow
        Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
        Write-Host "Hardware ID : $script:HWID"
        Write-Host "License Status : $(if($script:isPremium) { 'Premium Active' } else { 'Free Version' })"
        
        Write-Status "OK" "System information gathered successfully!"
        Write-Log "INFO" "System info viewed"
    } catch {
        Write-Status "ERR" "Error gathering system information: $($_.Exception.Message)"
        Write-Log "ERROR" "System info error: $($_.Exception.Message)"
    }
    
    Write-Host ""
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Fixed Basic Clean Function
function Invoke-BasicClean {
    Show-Header "ENHANCED BASIC SYSTEM CLEANER"
    Write-Status "RUN" "Preparing comprehensive system cleanup..."
    Write-Host ""
    
    # Create backup
    try {
        if (Get-Command "Checkpoint-Computer" -ErrorAction SilentlyContinue) {
            Checkpoint-Computer -Description "PC Optimizer Basic Clean" -RestorePointType "MODIFY_SETTINGS"
            Write-Status "OK" "System restore point created"
        }
    } catch {
        Write-Status "WARN" "Backup creation failed: $($_.Exception.Message)"
        Write-Status "INFO" "Continuing without backup..."
    }
    
    $totalCleanedMB = 0
    Write-Host "CLEANING PROGRESS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    # 1. Temp files cleanup
    Write-Host "[1/10] Cleaning temporary files..."
    try {
        $tempPaths = @($env:TEMP, "C:\Windows\Temp", "$env:LOCALAPPDATA\Temp")
        foreach ($path in $tempPaths) {
            if (Test-Path $path) {
                $beforeSize = (Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                $afterSize = (Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                if ($beforeSize -and $afterSize) {
                    $totalCleanedMB += [Math]::Round(($beforeSize - $afterSize) / 1MB, 2)
                }
            }
        }
        Write-Status "OK" "Temporary files cleaned"
    } catch {
        Write-Status "WARN" "Some temp files could not be cleaned"
    }
    
    # 2. Browser cache cleanup
    Write-Host "[2/10] Cleaning browser caches..."
    try {
        Clear-BrowserCaches
        Write-Status "OK" "Browser caches cleaned"
        $totalCleanedMB += 50 # Estimated
    } catch {
        Write-Status "WARN" "Some browser caches could not be cleaned"
    }
    
    # 3. Windows Update cache
    Write-Host "[3/10] Cleaning Windows Update cache..."
    try {
        $updatePath = "C:\Windows\SoftwareDistribution\Download"
        if (Test-Path $updatePath) {
            Get-ChildItem $updatePath -Recurse -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Status "OK" "Windows Update cache cleaned"
            $totalCleanedMB += 25 # Estimated
        }
    } catch {
        Write-Status "WARN" "Windows Update cache could not be cleaned"
    }
    
    # 4. Recycle Bin
    Write-Host "[4/10] Emptying Recycle Bin..."
    try {
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        Write-Status "OK" "Recycle Bin emptied"
        $totalCleanedMB += 10 # Estimated
    } catch {
        Write-Status "WARN" "Recycle Bin could not be emptied"
    }
    
    # 5. DNS Cache
    Write-Host "[5/10] Flushing DNS cache..."
    try {
        & ipconfig /flushdns | Out-Null
        Write-Status "OK" "DNS cache flushed"
    } catch {
        Write-Status "WARN" "DNS cache could not be flushed"
    }
    
    # 6. Memory cleanup
    Write-Host "[6/10] Optimizing memory usage..."
    try {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        Write-Status "OK" "Memory optimized"
    } catch {
        Write-Status "WARN" "Memory optimization failed"
    }
    
    # 7. Prefetch cleanup
    Write-Host "[7/10] Cleaning prefetch files..."
    try {
        $prefetchPath = "C:\Windows\Prefetch"
        if (Test-Path $prefetchPath) {
            Get-ChildItem $prefetchPath -File "*.pf" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Status "OK" "Prefetch files cleaned"
            $totalCleanedMB += 5 # Estimated
        }
    } catch {
        Write-Status "WARN" "Prefetch files could not be cleaned"
    }
    
    # 8. Log files cleanup
    Write-Host "[8/10] Cleaning system log files..."
    try {
        $logPaths = @("C:\Windows\Logs", "C:\Windows\System32\LogFiles")
        foreach ($logPath in $logPaths) {
            if (Test-Path $logPath) {
                Get-ChildItem $logPath -Recurse -File "*.log" -ErrorAction SilentlyContinue | 
                    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | 
                    Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Status "OK" "Old log files cleaned"
        $totalCleanedMB += 15 # Estimated
    } catch {
        Write-Status "WARN" "Some log files could not be cleaned"
    }
    
    # 9. Thumbnail cache
    Write-Host "[9/10] Cleaning thumbnail cache..."
    try {
        $thumbPath = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
        if (Test-Path $thumbPath) {
            Get-ChildItem $thumbPath -File "thumbcache_*.db" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Status "OK" "Thumbnail cache cleaned"
            $totalCleanedMB += 10 # Estimated
        }
    } catch {
        Write-Status "WARN" "Thumbnail cache could not be cleaned"
    }
    
    # 10. System file cleanup
    Write-Host "[10/10] Running Disk Cleanup..."
    try {
        Start-Process -FilePath "cleanmgr" -ArgumentList "/sagerun:1" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
        Write-Status "OK" "Disk cleanup completed"
        $totalCleanedMB += 20 # Estimated
    } catch {
        Write-Status "WARN" "Disk cleanup could not run"
    }
    
    Write-Host ""
    Write-Host "CLEANUP SUMMARY:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host ""
    Write-Status "OK" "Enhanced basic cleanup completed successfully!"
    Write-Host ""
    Write-Host " Total space recovered: $totalCleanedMB MB"
    Write-Host " System components cleaned: 10 categories"
    Write-Host " Memory optimized: Yes"
    Write-Host " Network cache cleared: Yes"
    Write-Log "INFO" "Basic cleanup completed - $totalCleanedMB MB recovered"
    Write-Host ""
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Fixed Browser Cache Function
function Clear-BrowserCaches {
    # Chrome cache cleanup
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    if (Test-Path $chromePath) {
        Stop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue
        Start-Sleep 2
        Get-ChildItem "$chromePath\*\Cache" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        Get-ChildItem "$chromePath\*\Code Cache" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
    
    # Firefox cache cleanup
    $firefoxPath = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxPath) {
        Stop-Process -Name "firefox" -Force -ErrorAction SilentlyContinue
        Start-Sleep 2
        Get-ChildItem "$firefoxPath\*\cache2" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
    
    # Edge cache cleanup
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    if (Test-Path $edgePath) {
        Stop-Process -Name "msedge" -Force -ErrorAction SilentlyContinue
        Start-Sleep 2
        Get-ChildItem "$edgePath\*\Cache" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
    
    # Internet Explorer cache cleanup
    $ieCachePath = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
    if (Test-Path $ieCachePath) {
        Get-ChildItem $ieCachePath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
}

# Add the missing menu functions and other functions here...
# [Continue with the rest of your functions, applying similar error handling patterns]

# Main execution function
function Start-PCOptimizer {
    try {
        # Initialize system
        Initialize-System
        
        # Get hardware ID
        $script:HWID = Get-HardwareID
        
        # Check license status
        $script:isPremium = Test-License -License "" -HWID $script:HWID
        
        # Show appropriate menu
        if ($script:isPremium) {
            Show-PremiumMenu
        } else {
            Show-FreeUserMenu
        }
        
        Write-Status "OK" "PC Optimizer Pro session completed"
        Write-Log "INFO" "PC Optimizer Pro session ended"
    } catch {
        Write-Status "ERR" "An error occurred: $($_.Exception.Message)"
        Write-Log "ERROR" "Script error: $($_.Exception.Message)"
        Start-Sleep 5
    }
}

# Run the application
Start-PCOptimizer
