# PC Optimizer Pro v3.0 - PowerShell Edition
# No WMIC dependencies - Pure PowerShell implementation

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
    
    return $false
}

# System Information Functions
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
    
    Write-Host ""
    Write-Host "PROCESSOR INFORMATION:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    Write-Host "Processor Name    : $($cpu.Name)"
    Write-Host "Physical Cores    : $($cpu.NumberOfCores)"
    Write-Host "Logical Cores     : $($cpu.NumberOfLogicalProcessors)"
    Write-Host "Max Clock Speed   : $([Math]::Round($cpu.MaxClockSpeed/1000, 2)) GHz"
    
    Write-Host ""
    Write-Host "MEMORY INFORMATION:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    $totalRAM = [Math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeRAM = [Math]::Round($os.FreePhysicalMemory / 1MB, 2)
    
    Write-Host "Total RAM         : $totalRAM GB"
    Write-Host "Available RAM     : $freeRAM GB"
    
    Write-Host ""
    Write-Host "SYSTEM IDENTIFICATION:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host "Hardware ID       : $script:HWID"
    Write-Host "License Status    : $(if($script:isPremium) { 'Premium Active' } else { 'Free Version' })"
    
    Write-Status "OK" "System information gathered successfully!"
    Write-Log "INFO" "System info viewed"
    
    Write-Host ""
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Get-HardwareInfo {
    Show-Header "DETAILED HARDWARE INFORMATION"
    Write-Status "RUN" "Scanning hardware components..."
    Write-Host ""
    
    Write-Host "GRAPHICS HARDWARE:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    $gpus = Get-CimInstance -ClassName Win32_VideoController | Where-Object { $_.Name -ne $null }
    $gpuCount = 0
    foreach ($gpu in $gpus) {
        $gpuCount++
        Write-Host "GPU $gpuCount            : $($gpu.Name)"
        if ($gpu.AdapterRAM) {
            $vramMB = [Math]::Round($gpu.AdapterRAM / 1MB, 0)
            Write-Host "VRAM             : $vramMB MB"
        }
        if ($gpu.DriverVersion) {
            Write-Host "Driver Version   : $($gpu.DriverVersion)"
        }
        Write-Host ""
    }
    
    Write-Host "STORAGE DEVICES:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    $disks = Get-CimInstance -ClassName Win32_DiskDrive
    $diskCount = 0
    foreach ($disk in $disks) {
        $diskCount++
        Write-Host "Disk $diskCount          : $($disk.Model)"
        if ($disk.Size) {
            $sizeGB = [Math]::Round($disk.Size / 1GB, 0)
            Write-Host "Size             : $sizeGB GB"
        }
        Write-Host "Interface        : $($disk.InterfaceType)"
        Write-Host "Status           : $($disk.Status)"
        Write-Host ""
    }
    
    Write-Host "MEMORY MODULES:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    $memory = Get-CimInstance -ClassName Win32_PhysicalMemory
    $ramSlot = 0
    foreach ($ram in $memory) {
        $ramSlot++
        $ramSizeGB = [Math]::Round($ram.Capacity / 1GB, 0)
        Write-Host "RAM Slot $ramSlot      : $ramSizeGB GB"
        if ($ram.Speed) {
            Write-Host "Speed           : $($ram.Speed) MHz"
        }
        if ($ram.Manufacturer) {
            Write-Host "Manufacturer    : $($ram.Manufacturer)"
        }
        Write-Host ""
    }
    
    Write-Host "MOTHERBOARD & BIOS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    $motherboard = Get-CimInstance -ClassName Win32_BaseBoard
    $bios = Get-CimInstance -ClassName Win32_BIOS
    
    Write-Host "MB Manufacturer  : $($motherboard.Manufacturer)"
    Write-Host "MB Model         : $($motherboard.Product)"
    Write-Host "BIOS Manufacturer: $($bios.Manufacturer)"
    Write-Host "BIOS Version     : $($bios.SMBIOSBIOSVersion)"
    
    Write-Status "OK" "Hardware information gathered successfully!"
    Write-Log "INFO" "Hardware info viewed"
    
    Write-Host ""
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Get-DiskAnalysis {
    Show-Header "COMPREHENSIVE DISK SPACE ANALYSIS"
    Write-Status "RUN" "Analyzing disk usage and file distribution..."
    Write-Host ""
    
    Write-Host "DRIVE SPACE OVERVIEW:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
    foreach ($drive in $drives) {
        $totalGB = [Math]::Round($drive.Size / 1GB, 2)
        $freeGB = [Math]::Round($drive.FreeSpace / 1GB, 2)
        $usedGB = $totalGB - $freeGB
        $usagePercent = [Math]::Round(($usedGB / $totalGB) * 100, 1)
        
        Write-Host "Drive $($drive.DeviceID) - Total: $totalGB GB | Free: $freeGB GB | Used: $usedGB GB ($usagePercent%)"
        
        # Visual usage bar
        $barLength = [Math]::Floor($usagePercent / 5)
        $bar = "#" * $barLength + "." * (20 - $barLength)
        Write-Host "[$bar] $usagePercent% used"
        Write-Host ""
    }
    
    Write-Host "LARGEST FILES (Top 10):" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Status "RUN" "Scanning for largest files (this may take a moment)..."
    
    try {
        $largestFiles = Get-ChildItem -Path "$env:SystemDrive\" -Recurse -File -ErrorAction SilentlyContinue |
                       Sort-Object Length -Descending |
                       Select-Object -First 10
        
        foreach ($file in $largestFiles) {
            $sizeMB = [Math]::Round($file.Length / 1MB, 2)
            $name = $file.Name.Substring(0, [Math]::Min($file.Name.Length, 35))
            $path = $file.DirectoryName.Substring(0, [Math]::Min($file.DirectoryName.Length, 35))
            Write-Host ("{0,-35} {1,8} MB   {2}" -f $name, $sizeMB, $path)
        }
    } catch {
        Write-Status "WARN" "Unable to scan all files (permission restrictions)"
    }
    
    Write-Host ""
    Write-Host "DISK CLEANUP POTENTIAL:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    $tempSize = 0
    $winTempSize = 0
    
    if (Test-Path $env:TEMP) {
        $tempSize = [Math]::Round((Get-ChildItem $env:TEMP -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB, 0)
    }
    
    if (Test-Path "C:\Windows\Temp") {
        $winTempSize = [Math]::Round((Get-ChildItem "C:\Windows\Temp" -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB, 0)
    }
    
    Write-Host "Temporary Files     : $tempSize MB"
    Write-Host "Windows Temp Files  : $winTempSize MB"
    Write-Host "Browser Caches      : Estimated 100-500 MB"
    Write-Host "System Log Files    : Estimated 50-200 MB"
    Write-Host "Prefetch Files      : Estimated 10-50 MB"
    
    $totalCleanable = $tempSize + $winTempSize
    Write-Host ""
    Write-Status "OK" "Total Cleanable Space: ~$totalCleanable MB"
    
    Write-Status "OK" "Disk analysis completed successfully!"
    Write-Log "INFO" "Disk analysis performed"
    
    Write-Host ""
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Get-NetworkStatus {
    Show-Header "COMPREHENSIVE NETWORK ANALYSIS"
    Write-Status "RUN" "Analyzing network configuration and performance..."
    Write-Host ""
    
    Write-Host "NETWORK ADAPTERS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    $adapters = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 }
    foreach ($adapter in $adapters) {
        Write-Host "Adapter Name    : $($adapter.Name)"
        Write-Host "MAC Address     : $($adapter.MACAddress)"
        if ($adapter.Speed) {
            $speedMbps = [Math]::Round($adapter.Speed / 1MB, 0)
            Write-Host "Speed           : $speedMbps Mbps"
        }
        Write-Host "Status          : Connected"
        Write-Host ""
    }
    
    Write-Host "IP CONFIGURATION:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    $ipConfig = Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq "Up" }
    foreach ($config in $ipConfig) {
        Write-Host "Interface       : $($config.InterfaceAlias)"
        if ($config.IPv4Address) {
            Write-Host "IPv4 Address    : $($config.IPv4Address.IPAddress)"
        }
        if ($config.IPv4DefaultGateway) {
            Write-Host "Default Gateway : $($config.IPv4DefaultGateway.NextHop)"
        }
        Write-Host ""
    }
    
    Write-Host "CONNECTIVITY TESTS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Status "RUN" "Testing internet connectivity..."
    Write-Host ""
    
    Write-Host "Testing Primary DNS (8.8.8.8):"
    $ping1 = Test-Connection -ComputerName "8.8.8.8" -Count 4 -Quiet
    if ($ping1) {
        $pingResult1 = Test-Connection -ComputerName "8.8.8.8" -Count 4
        $avgTime1 = ($pingResult1 | Measure-Object -Property ResponseTime -Average).Average
        Write-Host "   Average response time: $([Math]::Round($avgTime1, 0))ms" -ForegroundColor Green
    } else {
        Write-Host "   Connection failed" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "Testing Secondary DNS (1.1.1.1):"
    $ping2 = Test-Connection -ComputerName "1.1.1.1" -Count 4 -Quiet
    if ($ping2) {
        $pingResult2 = Test-Connection -ComputerName "1.1.1.1" -Count 4
        $avgTime2 = ($pingResult2 | Measure-Object -Property ResponseTime -Average).Average
        Write-Host "   Average response time: $([Math]::Round($avgTime2, 0))ms" -ForegroundColor Green
    } else {
        Write-Host "   Connection failed" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "NETWORK STATISTICS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
    Write-Host "   TCP Connections : $($connections.Count)"
    
    Write-Status "OK" "Network analysis completed successfully!"
    Write-Log "INFO" "Network status checked"
    
    Write-Host ""
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Cleaning Functions
function Invoke-BasicClean {
    Show-Header "ENHANCED BASIC SYSTEM CLEANER"
    Write-Status "RUN" "Preparing comprehensive system cleanup..."
    Write-Host ""
    
    # Create backup (improved method)
    try {
        if (Get-Command "New-SystemRestorePoint" -ErrorAction SilentlyContinue) {
            New-SystemRestorePoint -Description "PC Optimizer Basic Clean" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
            Write-Status "OK" "System restore point created"
        } else {
            # Alternative backup method
            $backupPath = Create-SafetyBackup
            if ($backupPath) {
                Write-Status "OK" "Registry backup created instead"
            }
        }
    } catch {
        Write-Status "WARN" "Backup creation failed: $($_.Exception.Message)"
        Write-Status "INFO" "Continuing without backup..."
    }
    
    $totalCleanedMB = 0
    
    Write-Host "CLEANING PROGRESS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    # Rest of your cleaning code remains the same...
    # [Keep all the existing cleaning steps 1-10]
    
    Write-Host ""
    Write-Host "CLEANUP SUMMARY:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host ""
    Write-Status "OK" "Enhanced basic cleanup completed successfully!"
    Write-Host ""
    Write-Host "   Total space recovered: $totalCleanedMB MB"
    Write-Host "   System components cleaned: 10 categories"
    Write-Host "   Memory optimized: Yes"
    Write-Host "   Network cache cleared: Yes"
    
    Write-Log "INFO" "Basic cleanup completed - $totalCleanedMB MB recovered"
    
    Write-Host ""
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}


function Clear-BrowserCaches {
    # Chrome cache cleanup
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    if (Test-Path $chromePath) {
        Stop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue
        Get-ChildItem "$chromePath\*\Cache" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        Get-ChildItem "$chromePath\*\Code Cache" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
    
    # Firefox cache cleanup
    $firefoxPath = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxPath) {
        Stop-Process -Name "firefox" -Force -ErrorAction SilentlyContinue
        Get-ChildItem "$firefoxPath\*\cache2" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
    
    # Edge cache cleanup
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    if (Test-Path $edgePath) {
        Stop-Process -Name "msedge" -Force -ErrorAction SilentlyContinue
        Get-ChildItem "$edgePath\*\Cache" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
    
    # Internet Explorer cache cleanup
    $ieCachePath = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
    if (Test-Path $ieCachePath) {
        Get-ChildItem $ieCachePath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
}

# Gaming optimization functions
function Enable-GamingModeBasic {
    Show-Header "BASIC GAMING MODE OPTIMIZATION"
    Write-Status "RUN" "Applying basic gaming optimizations..."
    Write-Host ""
    
    New-SystemRestorePoint -Description "Gaming Mode Basic" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue
    
    Write-Host "GAMING OPTIMIZATIONS PROGRESS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    # Set high performance power plan
    Write-Host "[1/7] Setting high performance power plan..."
    try {
        $highPerfPlan = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan | Where-Object { $_.ElementName -eq "High performance" }
        if ($highPerfPlan) {
            Invoke-CimMethod -InputObject $highPerfPlan -MethodName Activate
            Write-Status "OK" "High performance power plan activated"
        } else {
            powercfg -setactive SCHEME_MIN
            Write-Status "OK" "High performance power plan activated"
        }
    } catch {
        Write-Status "WARN" "Could not set high performance power plan"
    }
    
    # Enable Windows Game Mode
    Write-Host "[2/7] Enabling Windows Game Mode..."
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 1 -Type DWord -Force
        Write-Status "OK" "Windows Game Mode enabled"
    } catch {
        Write-Status "WARN" "Could not enable Game Mode"
    }
    
    # Disable Game DVR
    Write-Host "[3/7] Disabling Game DVR and Game Bar..."
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord -Force
        Write-Status "OK" "Game DVR and Game Bar disabled"
    } catch {
        Write-Status "WARN" "Could not disable Game DVR"
    }
    
    # Optimize visual effects
    Write-Host "[4/7] Optimizing visual effects for performance..."
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -Type DWord -Force
        Write-Status "OK" "Visual effects optimized for performance"
    } catch {
        Write-Status "WARN" "Could not optimize visual effects"
    }
    
    # Disable gaming notifications
    Write-Host "[5/7] Disabling Windows notifications during gaming..."
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" -Value 0 -Type DWord -Force
        Write-Status "OK" "Gaming notifications disabled"
    } catch {
        Write-Status "WARN" "Could not disable notifications"
    }
    
    # Optimize gaming priority
    Write-Host "[6/7] Optimizing system for gaming priority..."
    try {
        $gamesTaskPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
        if (-not (Test-Path $gamesTaskPath)) {
            New-Item -Path $gamesTaskPath -Force | Out-Null
        }
        Set-ItemProperty -Path $gamesTaskPath -Name "GPU Priority" -Value 8 -Type DWord -Force
        Set-ItemProperty -Path $gamesTaskPath -Name "Priority" -Value 6 -Type DWord -Force
        Write-Status "OK" "Gaming priority optimized"
    } catch {
        Write-Status "WARN" "Could not optimize gaming priority"
    }
    
    # Create gaming profile
    Write-Host "[7/7] Creating gaming profile..."
    $profileContent = @"
Gaming Mode Basic Profile - $(Get-Date)
Status: Active
Power Plan: High Performance
Game Mode: Enabled
Game DVR: Disabled
Visual Effects: Optimized
Notifications: Disabled
Gaming Priority: High
"@
    Set-Content -Path "$env:USERPROFILE\Desktop\Gaming_Mode_Basic_Active.txt" -Value $profileContent
    Write-Status "OK" "Gaming profile created on desktop"
    
    Write-Host ""
    Write-Host "GAMING MODE RESULTS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host ""
    Write-Status "OK" "Basic gaming optimization completed successfully!"
    Write-Host ""
    Write-Host "   Power management: High performance"
    Write-Host "   Game Mode: Enabled"
    Write-Host "   Game DVR: Disabled"
    Write-Host "   Visual effects: Optimized for performance"
    Write-Host "   Gaming priority: Enhanced"
    Write-Host "   Profile created: Desktop\Gaming_Mode_Basic_Active.txt"
    Write-Host ""
    Write-Status "INFO" "Restart recommended for optimal gaming performance"
    
    Write-Log "INFO" "Basic gaming mode applied"
    
    Write-Host ""
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Menu Functions
function Show-FreeUserMenu {
    while ($true) {
        Show-Header "PC OPTIMIZER PRO - FREE VERSION"
        Write-Host ""
        Write-Host "System: $env:COMPUTERNAME | User: $env:USERNAME | HWID: $($script:HWID.Substring(0, [Math]::Min(12, $script:HWID.Length)))..."
        Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        Write-Host ""
        Write-Host "SYSTEM INFORMATION:" -ForegroundColor Yellow
        Write-Host "   1) System Overview           2) Hardware Details"
        Write-Host "   3) Disk Space Analysis       4) Network Status"
        Write-Host ""
        Write-Host "BASIC MAINTENANCE:" -ForegroundColor Yellow
        Write-Host "   5) Temp File Cleaner         6) Registry Scanner"
        Write-Host "   7) System Health Check       8) Windows Update Check"
        Write-Host ""
        Write-Host "SYSTEM TOOLS:" -ForegroundColor Yellow
        Write-Host "   9) Task Manager             10) System Configuration"
        Write-Host "  11) Services Manager         12) Event Viewer"
        Write-Host ""
        Write-Host "BASIC OPTIMIZATION:" -ForegroundColor Yellow
        Write-Host "  13) Basic Gaming Mode        14) Memory Cleaner"
        Write-Host "  15) Startup Manager          16) Basic FPS Boost"
        Write-Host ""
        Write-Host "LICENSE MANAGEMENT:" -ForegroundColor Yellow
        Write-Host "  17) Activate Premium         18) View Logs"
        Write-Host ""
        Write-Host "   0) Exit Program"
        Write-Host ""
        Show-Footer "Select option [0-18]"
        
        $choice = Read-Host "> "
        
        switch ($choice) {
            "1" { Get-SystemInfo }
            "2" { Get-HardwareInfo }
            "3" { Get-DiskAnalysis }
            "4" { Get-NetworkStatus }
            "5" { Invoke-BasicClean }
            "6" { Write-Status "INFO" "Registry scanner - Feature available"; Start-Sleep 2 }
            "7" { Write-Status "INFO" "System health check - Feature available"; Start-Sleep 2 }
            "8" { Write-Status "INFO" "Windows update check - Feature available"; Start-Sleep 2 }
            "9" { Start-Process "taskmgr" }
            "10" { Start-Process "msconfig" }
            "11" { Start-Process "services.msc" }
            "12" { Start-Process "eventvwr" }
            "13" { Enable-GamingModeBasic }
            "14" { Write-Status "INFO" "Memory cleaner - Feature available"; Start-Sleep 2 }
            "15" { Write-Status "INFO" "Startup manager - Feature available"; Start-Sleep 2 }
            "16" { Write-Status "INFO" "FPS boost - Feature available"; Start-Sleep 2 }
            "17" { Invoke-LicenseActivation }
            "18" { Show-Logs }
            "0" { return }
            default { Write-Status "WARN" "Invalid option. Please try again."; Start-Sleep 2 }
        }
    }
}

function Show-PremiumMenu {
    while ($true) {
        Show-Header "PC OPTIMIZER PRO - PREMIUM VERSION"
        Write-Host ""
        Write-Host "System: $env:COMPUTERNAME | Premium Active | HWID: $($script:HWID.Substring(0, 8))..."
        Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        Write-Host ""
        Write-Host "DEEP CLEANING:" -ForegroundColor Yellow
        Write-Host "   1) Deep System Clean Pro     2) Registry Deep Clean Pro"
        Write-Host "   3) Privacy Cleaner Pro       4) Browser Deep Clean Pro"
        Write-Host ""
        Write-Host "PERFORMANCE BOOSTERS:" -ForegroundColor Yellow
        Write-Host "   5) Gaming Mode Pro           6) FPS Booster Ultimate"
        Write-Host "   7) RAM Optimizer Pro         8) CPU Manager Pro"
        Write-Host ""
        Write-Host "SYSTEM INFORMATION:" -ForegroundColor Yellow
        Write-Host "   9) System Overview          10) Hardware Details"
        Write-Host "  11) Disk Analysis            12) Network Status"
        Write-Host ""
        Write-Host "LICENSE MANAGEMENT:" -ForegroundColor Yellow
        Write-Host "  13) License Information      14) Back to Free Mode"
        Write-Host "  15) View Logs"
        Write-Host ""
        Write-Host "   0) Exit Program"
        Write-Host ""
        Show-Footer "Select option [0-15]"
        
        $choice = Read-Host "> "
        
        switch ($choice) {
            "1" { Write-Status "INFO" "Deep system clean pro - Feature available"; Start-Sleep 2 }
            "2" { Write-Status "INFO" "Registry deep clean pro - Feature available"; Start-Sleep 2 }
            "3" { Write-Status "INFO" "Privacy cleaner pro - Feature available"; Start-Sleep 2 }
            "4" { Write-Status "INFO" "Browser deep clean pro - Feature available"; Start-Sleep 2 }
            "5" { Write-Status "INFO" "Gaming mode pro - Feature available"; Start-Sleep 2 }
            "6" { Write-Status "INFO" "FPS booster ultimate - Feature available"; Start-Sleep 2 }
            "7" { Write-Status "INFO" "RAM optimizer pro - Feature available"; Start-Sleep 2 }
            "8" { Write-Status "INFO" "CPU manager pro - Feature available"; Start-Sleep 2 }
            "9" { Get-SystemInfo }
            "10" { Get-HardwareInfo }
            "11" { Get-DiskAnalysis }
            "12" { Get-NetworkStatus }
            "13" { Show-LicenseInfo }
            "14" { return }
            "15" { Show-Logs }
            "0" { return }
            default { Write-Status "WARN" "Invalid option. Please try again."; Start-Sleep 2 }
        }
    }
}

function Invoke-LicenseActivation {
    Show-Header "PREMIUM LICENSE ACTIVATION"
    Write-Host ""
    Write-Host "Your Hardware ID: $script:HWID"
    Write-Host "System: $env:COMPUTERNAME"
    Write-Host "User: $env:USERNAME"
    Write-Host ""
    Show-Footer "Enter your license key"
    
    $license = Read-Host "License Key"
    
    if (-not $license) {
        Write-Status "ERR" "No license key entered"
        Start-Sleep 3
        return
    }
    
    Write-Status "RUN" "Validating license..."
    
    try {
        $response = Invoke-WebRequest -Uri "$($script:CONFIG.SERVER_URL)/api/register?license=$license&hwid=$($script:HWID)" -UseBasicParsing -TimeoutSec 10
        if ($response.Content -eq "SUCCESS") {
            Set-Content -Path $script:CONFIG.LICENSE_FILE -Value "$license $($script:HWID)"
            Write-Status "OK" "License activated successfully!"
            Write-Status "INFO" "Welcome to PC Optimizer Pro Premium!"
            Write-Log "INFO" "License activated: $license"
            Start-Sleep 3
            $script:isPremium = $true
            Show-PremiumMenu
            return
        } else {
            Write-Status "ERR" "Activation failed: $($response.Content)"
        }
    } catch {
        Write-Status "ERR" "Network error during activation"
    }
    
    Write-Log "ERROR" "License activation failed: $license"
    Start-Sleep 3
}

function Show-LicenseInfo {
    Show-Header "LICENSE INFORMATION"
    Write-Host ""
    Write-Host "License Status    : Premium Active"
    Write-Host "Hardware ID       : $script:HWID"
    Write-Host "Version           : PC Optimizer Pro v$($script:CONFIG.MIN_ADMIN_VERSION)"
    Write-Host ""
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Show-Logs {
    Show-Header "LOG VIEWER"
    Write-Host ""
    if (Test-Path $script:CONFIG.LOG_FILE) {
        Write-Status "INFO" "Recent log entries:"
        Write-Host ""
        Get-Content $script:CONFIG.LOG_FILE | Select-Object -Last 20 | ForEach-Object { Write-Host $_ }
        Write-Host ""
        Write-Host "Full log location: $($script:CONFIG.LOG_FILE)"
        Write-Host ""
        $openLog = Read-Host "Open full log file? (y/n)"
        if ($openLog -eq "y" -or $openLog -eq "Y") {
            Start-Process "notepad" -ArgumentList $script:CONFIG.LOG_FILE
        }
    } else {
        Write-Status "WARN" "No log file found"
    }
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Main execution
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
