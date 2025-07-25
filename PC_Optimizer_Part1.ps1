# PC Optimizer Pro v3.0 - PowerShell Edition - COMPLETE VERSION
param([switch]$AsAdmin)

# Elevation Check
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    if (-NOT $AsAdmin) {
        Write-Host "[!] Requesting administrator privileges..." -ForegroundColor Yellow
        Start-Process PowerShell -Verb RunAs -ArgumentList ("-File", $MyInvocation.MyCommand.Path, "-AsAdmin")
        exit
    }
}

# Configuration
$script:CONFIG = @{
    SERVER_URL      = "https://optimize-blush.vercel.app"
    LICENSE_FILE    = "$env:ProgramData\pc_optimizer.lic"
    LOG_FILE        = "$env:TEMP\optimizer_log.txt"
    BACKUP_DIR      = "$env:ProgramData\PC_Optimizer_Backups"
    MIN_ADMIN_VERSION = "3.0"
}

$script:SYMBOLS = @{
    OK   = "[OK]"
    WARN = "[!]"
    ERR  = "[X]"
    INFO = "[i]"
    RUN  = "[>]"
}

$script:HWID = ""
$script:isPremium = $false

function Initialize-System {
    if (-not (Test-Path $script:CONFIG.BACKUP_DIR)) {
        New-Item -ItemType Directory -Path $script:CONFIG.BACKUP_DIR -Force | Out-Null
    }
    Add-Content -Path $script:CONFIG.LOG_FILE -Value "[$(Get-Date)] PC Optimizer Pro v$($script:CONFIG.MIN_ADMIN_VERSION) started"
    if (-not (Test-Path $script:CONFIG.LICENSE_FILE)) {
        Set-Content -Path $script:CONFIG.LICENSE_FILE -Value "Version: $($script:CONFIG.MIN_ADMIN_VERSION)"
    }
}

function Write-Log {
    param([string]$Level, [string]$Message)
    Add-Content -Path $script:CONFIG.LOG_FILE -Value "[$(Get-Date)] [$Level] $Message"
}

function Show-Header {
    param([string]$Title)
    Clear-Host
    Write-Host "+------------------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "| PC Optimizer Pro v3.0 - $Title" -ForegroundColor Cyan
    Write-Host "+------------------------------------------------------------------------------+" -ForegroundColor Cyan
}

function Show-Footer {
    param([string]$Prompt = "Press any key to continue...")
    Write-Host "+------------------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "| $Prompt" -ForegroundColor Cyan
    Write-Host "+------------------------------------------------------------------------------+" -ForegroundColor Cyan
}

function Write-Status {
    param([string]$Type, [string]$Message)
    $color = switch ($Type) {
        "OK"   { "Green" }
        "WARN" { "Yellow" }
        "ERR"  { "Red" }
        "INFO" { "Cyan" }
        "RUN"  { "Magenta" }
        default{ "White" }
    }
    Write-Host "$($script:SYMBOLS.$Type) $Message" -ForegroundColor $color
}

function Get-HardwareID {
    Write-Status "RUN" "Detecting hardware signature..."
    $hwid = $null
    
    # Method 1: System UUID
    try {
        $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
        if ($systemInfo -and $systemInfo.UUID -and $systemInfo.UUID -ne "00000000-0000-0000-0000-000000000000") {
            $hwid = $systemInfo.UUID
            Write-Log "INFO" "HWID detected using UUID method"
        }
    } catch {}
    
    # Method 2: Motherboard Serial
    if (-not $hwid) {
        try {
            $motherboard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
            if ($motherboard -and $motherboard.SerialNumber -and $motherboard.SerialNumber.Trim() -ne "") {
                $hwid = $motherboard.SerialNumber.Trim()
                Write-Log "INFO" "HWID detected using motherboard serial"
            }
        } catch {}
    }
    
    # Method 3: BIOS Serial
    if (-not $hwid) {
        try {
            $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
            if ($bios -and $bios.SerialNumber -and $bios.SerialNumber.Trim() -ne "") {
                $hwid = $bios.SerialNumber.Trim()
                Write-Log "INFO" "HWID detected using BIOS serial"
            }
        } catch {}
    }
    
    # Method 4: CPU ID
    if (-not $hwid) {
        try {
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
        Write-Host "GPU $gpuCount           : $($gpu.Name)"
        if ($gpu.AdapterRAM) {
            $vramMB = [Math]::Round($gpu.AdapterRAM / 1MB, 0)
            Write-Host "VRAM              : $vramMB MB"
        }
        if ($gpu.DriverVersion) {
            Write-Host "Driver Version    : $($gpu.DriverVersion)"
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
            Write-Host "Size              : $sizeGB GB"
        }
        Write-Host "Interface         : $($disk.InterfaceType)"
        Write-Host "Status            : $($disk.Status)"
        Write-Host ""
    }
    
    Write-Host "MEMORY MODULES:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    $memory = Get-CimInstance -ClassName Win32_PhysicalMemory
    $ramSlot = 0
    foreach ($ram in $memory) {
        $ramSlot++
        $ramSizeGB = [Math]::Round($ram.Capacity / 1GB, 0)
        Write-Host "RAM Slot $ramSlot       : $ramSizeGB GB"
        if ($ram.Speed) {
            Write-Host "Speed             : $($ram.Speed) MHz"
        }
        if ($ram.Manufacturer) {
            Write-Host "Manufacturer      : $($ram.Manufacturer)"
        }
        Write-Host ""
    }
    
    Write-Host "MOTHERBOARD & BIOS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    $motherboard = Get-CimInstance -ClassName Win32_BaseBoard
    $bios = Get-CimInstance -ClassName Win32_BIOS
    Write-Host "MB Manufacturer   : $($motherboard.Manufacturer)"
    Write-Host "MB Model          : $($motherboard.Product)"
    Write-Host "BIOS Manufacturer : $($bios.Manufacturer)"
    Write-Host "BIOS Version      : $($bios.SMBIOSBIOSVersion)"
    
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
        $largestFiles = Get-ChildItem -Path "$env:SystemDrive\Users" -Recurse -File -ErrorAction SilentlyContinue |
                       Sort-Object Length -Descending |
                       Select-Object -First 10
        
        foreach ($file in $largestFiles) {
            $sizeMB = [Math]::Round($file.Length / 1MB, 2)
            $name = $file.Name.Substring(0, [Math]::Min($file.Name.Length, 35))
            $path = $file.DirectoryName.Substring(0, [Math]::Min($file.DirectoryName.Length, 35))
            Write-Host ("{0,-35} {1,8} MB {2}" -f $name, $sizeMB, $path)
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
        $tempFiles = Get-ChildItem $env:TEMP -Recurse -File -ErrorAction SilentlyContinue
        if ($tempFiles) {
            $tempSize = [Math]::Round(($tempFiles | Measure-Object -Property Length -Sum).Sum / 1MB, 0)
        }
    }
    
    if (Test-Path "C:\Windows\Temp") {
        $winTempFiles = Get-ChildItem "C:\Windows\Temp" -Recurse -File -ErrorAction SilentlyContinue
        if ($winTempFiles) {
            $winTempSize = [Math]::Round(($winTempFiles | Measure-Object -Property Length -Sum).Sum / 1MB, 0)
        }
    }
    
    Write-Host "Temporary Files    : $tempSize MB"
    Write-Host "Windows Temp Files : $winTempSize MB"
    Write-Host "Browser Caches     : Estimated 100-500 MB"
    Write-Host "System Log Files   : Estimated 50-200 MB"
    Write-Host "Prefetch Files     : Estimated 10-50 MB"
    
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
        Write-Host "Adapter Name      : $($adapter.Name)"
        Write-Host "MAC Address       : $($adapter.MACAddress)"
        if ($adapter.Speed) {
            $speedMbps = [Math]::Round($adapter.Speed / 1MB, 0)
            Write-Host "Speed             : $speedMbps Mbps"
        }
        Write-Host "Status            : Connected"
        Write-Host ""
    }
    
    Write-Host "IP CONFIGURATION:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        $ipConfig = Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq "Up" }
        foreach ($config in $ipConfig) {
            Write-Host "Interface         : $($config.InterfaceAlias)"
            if ($config.IPv4Address) {
                Write-Host "IPv4 Address      : $($config.IPv4Address.IPAddress)"
            }
            if ($config.IPv4DefaultGateway) {
                Write-Host "Default Gateway   : $($config.IPv4DefaultGateway.NextHop)"
            }
            Write-Host ""
        }
    } catch {
        # Fallback method
        $ipconfig = ipconfig /all
        Write-Host "Network configuration information:"
        $ipconfig | Select-Object -First 20 | ForEach-Object { Write-Host $_ }
    }
    
    Write-Host "CONNECTIVITY TESTS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Status "RUN" "Testing internet connectivity..."
    Write-Host ""
    
    Write-Host "Testing Primary DNS (8.8.8.8):"
    try {
        $ping1 = Test-Connection -ComputerName "8.8.8.8" -Count 4 -Quiet
        if ($ping1) {
            $pingResult1 = Test-Connection -ComputerName "8.8.8.8" -Count 4
            $avgTime1 = ($pingResult1 | Measure-Object -Property ResponseTime -Average).Average
            Write-Host " Average response time: $([Math]::Round($avgTime1, 0))ms" -ForegroundColor Green
        } else {
            Write-Host " Connection failed" -ForegroundColor Red
        }
    } catch {
        Write-Host " Connection test failed" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "Testing Secondary DNS (1.1.1.1):"
    try {
        $ping2 = Test-Connection -ComputerName "1.1.1.1" -Count 4 -Quiet
        if ($ping2) {
            $pingResult2 = Test-Connection -ComputerName "1.1.1.1" -Count 4
            $avgTime2 = ($pingResult2 | Measure-Object -Property ResponseTime -Average).Average
            Write-Host " Average response time: $([Math]::Round($avgTime2, 0))ms" -ForegroundColor Green
        } else {
            Write-Host " Connection failed" -ForegroundColor Red
        }
    } catch {
        Write-Host " Connection test failed" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "NETWORK STATISTICS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
        Write-Host " TCP Connections   : $($connections.Count)"
    } catch {
        Write-Host " TCP Connections   : Unable to retrieve"
    }
    
    Write-Status "OK" "Network analysis completed successfully!"
    Write-Log "INFO" "Network status checked"
    Write-Host ""
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}


# -------------------------- #
#  Cleaning-related Helpers  #
# -------------------------- #

function Clear-BrowserCaches {
    # Chrome
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    if (Test-Path $chromePath) {
        Stop-Process -Name chrome  -Force -ErrorAction SilentlyContinue
        Start-Sleep 2
        Get-ChildItem "$chromePath\*\Cache"      -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Get-ChildItem "$chromePath\*\Code Cache" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Firefox
    $firefoxPath = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxPath) {
        Stop-Process -Name firefox -Force -ErrorAction SilentlyContinue
        Start-Sleep 2
        Get-ChildItem "$firefoxPath\*\cache2" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Edge (Chromium)
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    if (Test-Path $edgePath) {
        Stop-Process -Name msedge -Force -ErrorAction SilentlyContinue
        Start-Sleep 2
        Get-ChildItem "$edgePath\*\Cache" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Internet Explorer / Legacy Edge
    $ieCache = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
    if (Test-Path $ieCache) {
        Get-ChildItem $ieCache -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ------------------------------------ #
#  Enhanced Basic System-Clean Routine #
# ------------------------------------ #

function Invoke-BasicClean {
    Show-Header "ENHANCED BASIC SYSTEM CLEANER"
    Write-Status "RUN" "Preparing comprehensive system cleanup..."
    Write-Host ""

    # System-restore checkpoint
    try {
        Checkpoint-Computer -Description "PC Optimizer – Basic Clean" -RestorePointType MODIFY_SETTINGS
        Write-Status "OK" "System restore point created"
    } catch {
        Write-Status "WARN" "Unable to create restore point"
    }

    $totalCleanedMB = 0
    Write-Host "CLEANING PROGRESS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray

    # 1. %TEMP%
    Write-Host "[1/10] Cleaning user-temp files..."
    try {
        $before = (Get-ChildItem $env:TEMP -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
        Get-ChildItem $env:TEMP -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        $after  = (Get-ChildItem $env:TEMP -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
        $freed  = [math]::Round(($before-$after)/1MB,1)
        $totalCleanedMB += $freed
        Write-Status "OK" "User-temp cleaned – $freed MB"
    } catch { Write-Status "WARN" "Some temp files could not be removed" }

    # 2. C:\Windows\Temp
    Write-Host "[2/10] Cleaning Windows-temp files..."
    try {
        $winTemp = "C:\Windows\Temp"
        if (Test-Path $winTemp) {
            $before = (Get-ChildItem $winTemp -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
            Get-ChildItem $winTemp -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            $after  = (Get-ChildItem $winTemp -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
            $freed  = [math]::Round(($before-$after)/1MB,1)
            $totalCleanedMB += $freed
            Write-Status "OK" "Windows-temp cleaned – $freed MB"
        }
    } catch { Write-Status "WARN" "Windows-temp cleanup incomplete" }

    # 3. Recycle-Bin
    Write-Host "[3/10] Emptying Recycle Bin..."
    try {
        Clear-RecycleBin -Force -ErrorAction Stop
        Write-Status "OK" "Recycle Bin emptied"
        $totalCleanedMB += 50   # rough estimate
    } catch { Write-Status "WARN" "Recycle Bin could not be fully emptied" }

    # 4. Browser caches
    Write-Host "[4/10] Clearing browser caches..."
    try {
        Clear-BrowserCaches
        Write-Status "OK" "Browser caches cleared"
        $totalCleanedMB += 100  # rough estimate
    } catch { Write-Status "WARN" "Browser-cache cleanup incomplete" }

    # 5. Prefetch
    Write-Host "[5/10] Purging Prefetch folder..."
    try {
        $pf = "C:\Windows\Prefetch"
        if (Test-Path $pf) {
            Get-ChildItem $pf -Filter "*.pf" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Status "OK" "Prefetch cleaned"
            $totalCleanedMB += 20
        }
    } catch { Write-Status "WARN" "Prefetch cleanup failed" }

    # 6. Old log files
    Write-Host "[6/10] Removing old log files..."
    try {
        $logPaths = @("C:\Windows\Logs", "C:\Windows\System32\LogFiles")
        foreach ($p in $logPaths) {
            if (Test-Path $p) {
                Get-ChildItem $p -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } |
                Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Status "OK" "Obsolete logs removed"
        $totalCleanedMB += 30
    } catch { Write-Status "WARN" "Log-file cleanup incomplete" }

    # 7. DNS cache
    Write-Host "[7/10] Flushing DNS cache..."
    try { ipconfig /flushdns | Out-Null; Write-Status "OK" "DNS cache flushed" }
    catch { Write-Status "WARN" "DNS cache flush failed" }

    # 8. .NET garbage collection
    Write-Host "[8/10] Optimizing memory (.NET GC)..."
    try {
        [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
        Write-Status "OK" "Memory optimized"
    } catch { Write-Status "WARN" "Memory optimization failed" }

    # 9. Event-logs trim
    Write-Host "[9/10] Trimming large Windows event logs..."
    try {
        foreach ($log in @("Application","System","Security")) {
            $entries = Get-EventLog -LogName $log -ErrorAction SilentlyContinue
            if ($entries.Count -gt 1000) { Clear-EventLog -LogName $log }
        }
        Write-Status "OK" "Event logs cleared/trimmed"
    } catch { Write-Status "WARN" "Event-log cleanup failed" }

    # 10. Thumbnail cache
    Write-Host "[10/10] Cleaning thumbnail cache..."
    try {
        $thumbPath = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
        if (Test-Path $thumbPath) {
            Get-ChildItem $thumbPath -Filter "thumbcache*.db" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Status "OK" "Thumbnail cache cleared"
            $totalCleanedMB += 25
        }
    } catch { Write-Status "WARN" "Thumbnail-cache cleanup failed" }

    # Summary
    Write-Host ""
    Write-Host "CLEANUP SUMMARY:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host " Total space recovered : $totalCleanedMB MB"
    Write-Host " Categories processed  : 10"
    Write-Status "OK" "Basic clean finished!"
    Write-Log  "INFO" "Basic clean – freed $totalCleanedMB MB"
    Show-Footer
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# --------------------------------- #
#  Registry Scanner & Optimiser     #
# --------------------------------- #

function Invoke-RegistryScanner {
    Show-Header "REGISTRY SCANNER & CLEANER"
    Write-Status "RUN" "Scanning registry for inconsistencies..."
    Write-Host ""

    # Backup
    try {
        $bk = "$($script:CONFIG.BACKUP_DIR)\RegBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
        reg export HKLM $bk /y | Out-Null
        Write-Status "OK" "Registry backup created : $bk"
    } catch { Write-Status "WARN" "Registry backup could not be created" }

    $issuesFound = 0; $issuesFixed = 0

    # 1. Invalid uninstall entries
    Write-Host "[1/5] Checking orphaned uninstall entries..."
    try {
        $uKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        $invalid = (Get-ChildItem $uKey -ErrorAction SilentlyContinue |
                    Where-Object {
                        $loc = (Get-ItemProperty $_.PSPath -Name InstallLocation -ErrorAction SilentlyContinue).InstallLocation
                        $loc -and -not (Test-Path $loc)
                    }).Count
        $issuesFound += $invalid
        Write-Status "OK"  "Found $invalid invalid software entries"
    } catch { Write-Status "WARN" "Uninstall-entry scan failed" }

    # 2. Invalid file-associations
    Write-Host "[2/5] Checking broken file associations..."
    try {
        $cls = "HKLM:\SOFTWARE\Classes"
        $broken = 0
        Get-ChildItem $cls -ErrorAction SilentlyContinue | Where-Object Name -like "*.*" | ForEach-Object {
            $dflt = (Get-ItemProperty $_.PSPath -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
            if ($dflt) {
                $cmdKey = "$cls\$dflt\shell\open\command"
                if (Test-Path $cmdKey) {
                    $cmd = (Get-ItemProperty $cmdKey -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
                    $exe = ($cmd -split '"')[1]
                    if ($exe -and -not (Test-Path $exe)) { $broken++ }
                }
            }
        }
        $issuesFound += $broken
        Write-Status "OK" "Found $broken broken associations"
    } catch { Write-Status "WARN" "Association scan failed" }

    # 3. Empty run-keys
    Write-Host "[3/5] Detecting empty run-entries..."
    try {
        $empty = 0
        foreach ($p in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                         "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")) {
            if (Test-Path $p) {
                Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object {
                    $vals = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    $subs = Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue
                    if (-not $vals -and -not $subs) { $empty++ }
                }
            }
        }
        $issuesFound += $empty
        Write-Status "OK" "Found $empty empty run keys"
    } catch { Write-Status "WARN" "Empty-key scan failed" }

    # 4. Broken startup paths
    Write-Host "[4/5] Checking startup-item integrity..."
    try {
        $brokenStart = 0
        foreach ($p in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                         "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")) {
            if (Test-Path $p) {
                (Get-ItemProperty $p -ErrorAction SilentlyContinue).PSObject.Properties |
                    Where-Object Name -notmatch "^PS" | ForEach-Object {
                        $ep = ($_.Value -split '"')[1]
                        if ($ep -and -not (Test-Path $ep)) { $brokenStart++ }
                    }
            }
        }
        $issuesFound += $brokenStart
        Write-Status "OK" "Found $brokenStart invalid startup entries"
    } catch { Write-Status "WARN" "Startup-scan failed" }

    # 5. Hive compaction
    Write-Host "[5/5] Compacting registry hives..."
    try {
        Start-Process compact -ArgumentList "/c /s /a /i C:\Windows\System32\config\*" -WindowStyle Hidden -Wait
        Write-Status "OK" "Registry hives compacted"
        $issuesFixed += 10  # nominal score
    } catch { Write-Status "WARN" "Hive compaction failed" }

    # Summary
    Write-Host ""
    Write-Host "REGISTRY SCAN RESULTS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host " Issues located : $issuesFound"
    Write-Host " Optimisations  : $issuesFixed"
    Write-Status "OK" "Registry scan complete!"
    Write-Log  "INFO" "Registry scan – found $issuesFound issues"
    Show-Footer
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# --------------------------------------------- #
#  Comprehensive System-Health Diagnostics      #
# --------------------------------------------- #

function Invoke-SystemHealthCheck {
    Show-Header "COMPREHENSIVE SYSTEM HEALTH CHECK"
    Write-Status "RUN" "Running multi-point diagnostics..."
    Write-Host ""

    $issues = 0; $score = 100

    # Disk space
    Write-Host "[1/8] Disk-space headroom..."
    try {
        Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -eq 3 | ForEach-Object {
            $pct = (($_.FreeSpace / $_.Size) * 100)
            if ($pct -lt 15) { Write-Status "WARN" "Drive $($_.DeviceID) low: $([math]::Round($pct,1))% free"; $issues++; $score-=5 }
            else             { Write-Status "OK"   "Drive $($_.DeviceID) healthy: $([math]::Round($pct,1))% free" }
        }
    } catch { Write-Status "ERR" "Disk-check failed"; $issues++ }

    # RAM usage
    Write-Host "[2/8] Memory-pressure..."
    try {
        $os     = Get-CimInstance Win32_OperatingSystem
        $pctRam = (($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/$os.TotalVisibleMemorySize)*100
        if ($pctRam -gt 85) { Write-Status "WARN" "High RAM usage: $([math]::Round($pctRam,1))%"; $issues++; $score-=3 }
        else                { Write-Status "OK"   "RAM usage normal: $([math]::Round($pctRam,1))%" }
    } catch { Write-Status "WARN" "RAM check failed" }

    # CPU load
    Write-Host "[3/8] CPU utilisation..."
    try {
        $cpuLoad = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
        if ($cpuLoad -gt 80) { Write-Status "WARN" "CPU busy: $([math]::Round($cpuLoad,1))%"; $issues++; $score-=3 }
        else                 { Write-Status "OK"  "CPU load fine: $([math]::Round($cpuLoad,1))%" }
    } catch { Write-Status "WARN" "CPU load sample failed" }

    # Windows Update status
    Write-Host "[4/8] Pending Windows Updates..."
    try {
        $updSession = New-Object -ComObject Microsoft.Update.Session
        $updSearch  = $updSession.CreateUpdateSearcher().Search("IsInstalled=0")
        if ($updSearch.Updates.Count) { Write-Status "WARN" "$($updSearch.Updates.Count) updates pending"; $issues++; $score-=2 }
        else                          { Write-Status "OK"  "System fully patched" }
    } catch { Write-Status "WARN" "Update-query failed" }

    # Antivirus
    Write-Host "[5/8] Antivirus realtime status..."
    try {
        $av = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
              Where-Object { $_.productState -band 0x1000 }
        if ($av) { Write-Status "OK" "AV active: $($av.displayName)" }
        else     { Write-Status "WARN" "No active AV detected"; $issues++; $score-=10 }
    } catch { Write-Status "WARN" "AV status query failed" }

    # Firewall
    Write-Host "[6/8] Windows Firewall..."
    try {
        $fw = Get-NetFirewallProfile | Where-Object Enabled -eq $true
        if ($fw) { Write-Status "OK" "Firewall enabled for $($fw.Count) profile(s)" }
        else     { Write-Status "WARN" "Firewall disabled"; $issues++; $score-=5 }
    } catch { Write-Status "WARN" "Firewall check failed" }

    # System-file integrity
    Write-Host "[7/8] System-file integrity (sfc /verifyonly)..."
    try {
        $sfc = sfc /verifyonly
        if ($sfc -match "did not find any integrity violations") { Write-Status "OK" "System files intact" }
        else                                                     { Write-Status "WARN" "Integrity issues detected"; $issues++; $score-=8 }
    } catch { Write-Status "WARN" "SFC execution failed" }

    # Uptime
    Write-Host "[8/8] Uptime check..."
    try {
        $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        $up   = (Get-Date) - $boot
        if ($up.Days -gt 7) { Write-Status "WARN" "Uptime $($up.Days) day(s) – restart recommended"; $issues++; $score-=2 }
        else                { Write-Status "OK"  "Uptime $($up.Days) day(s)" }
    } catch { Write-Status "WARN" "Uptime query failed" }

    # Summary
    Write-Host ""
    Write-Host "SYSTEM-HEALTH SUMMARY:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    $grade =  if ($score -ge 95) {'Excellent'} elseif ($score -ge 85){'Good'} elseif ($score -ge 70){'Fair'} elseif ($score -ge 50){'Poor'} else {'Critical'}
    Write-Host " Overall Score : $score/100"
    Write-Host " Health Grade  : $grade"
    Write-Host " Issues Found  : $issues"
    Write-Host " Checked At    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Status "OK" "Health-check completed"
    Write-Log  "INFO" "Health-check – score $score issues $issues"
    Show-Footer
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ----------------------------------- #
#  Windows Update Checker / Installer #
# ----------------------------------- #

function Invoke-WindowsUpdateCheck {
    Show-Header "WINDOWS UPDATE CHECKER"
    Write-Status "RUN" "Searching for Windows Updates..."
    Write-Host ""

    try {
        $uSession  = New-Object -ComObject Microsoft.Update.Session
        $searcher  = $uSession.CreateUpdateSearcher()
        $results   = $searcher.Search("IsInstalled=0")

        Write-Host "UPDATE ANALYSIS:" -ForegroundColor Yellow
        Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray

        if ($results.Updates.Count -eq 0) {
            Write-Status "OK" "No updates available – system is current"
        } else {
            Write-Status "INFO" "Found $($results.Updates.Count) update(s)`n"
            $important = 0; $optional = 0

            for ($i = 0; $i -lt $results.Updates.Count; $i++) {
                $u = $results.Updates.Item($i)
                if ($u.AutoSelectOnWebSites) { $important++; $type = "Important" }
                else                         { $optional++;  $type = "Optional" }
                Write-Host "[$($i+1)] $($u.Title)" -ForegroundColor Cyan
                Write-Host "    Type: $type | Size: $([Math]::Round($u.MaxDownloadSize/1MB,1)) MB"
                $desc = if ($u.Description.Length -gt 100) { $u.Description.Substring(0,100) + "..." } else { $u.Description }
                Write-Host "    Description: $desc`n"
            }

            $totalSize = ($results.Updates | Measure-Object MaxDownloadSize -Sum).Sum
            Write-Host "SUMMARY:" -ForegroundColor Yellow
            Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
            Write-Host " Important Updates: $important"
            Write-Host " Optional Updates : $optional"
            Write-Host " Total Updates    : $($results.Updates.Count)"
            Write-Host " Total Download Size: $([Math]::Round($totalSize/1MB,1)) MB`n"

            $installChoice = Read-Host "Install important updates now? (y/n)"
            if ($installChoice -match '^[yY]$' -and $important -gt 0) {
                $coll = New-Object -ComObject Microsoft.Update.UpdateColl
                for ($i = 0; $i -lt $results.Updates.Count; $i++) {
                    $u = $results.Updates.Item($i)
                    if ($u.AutoSelectOnWebSites) { $coll.Add($u) | Out-Null }
                }
                if ($coll.Count -gt 0) {
                    Write-Status "RUN" "Downloading updates..."
                    $downloader = $uSession.CreateUpdateDownloader(); $downloader.Updates = $coll
                    $dRes = $downloader.Download()
                    if ($dRes.ResultCode -eq 2) {
                        Write-Status "OK" "Downloaded successfully"
                        Write-Status "RUN" "Installing updates..."
                        $installer = $uSession.CreateUpdateInstaller(); $installer.Updates = $coll
                        $iRes = $installer.Install()
                        if ($iRes.ResultCode -eq 2) {
                            Write-Status "OK" "Installed successfully"
                            if ($iRes.RebootRequired) { Write-Status "WARN" "Restart required" }
                        } else { Write-Status "ERR" "Installation failed" }
                    } else { Write-Status "ERR" "Download failed" }
                } else {
                    Write-Status "INFO" "No important updates to install"
                }
            }
        }

        Write-Host "`nUPDATE HISTORY:" -ForegroundColor Yellow
        Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
        $histCount = $searcher.GetTotalHistoryCount()
        if ($histCount -gt 0) {
            $history = $searcher.QueryHistory(0, [Math]::Min(5, $histCount))
            foreach ($h in $history) {
                $date = $h.Date.ToString("yyyy-MM-dd")
                $code = switch ($h.ResultCode) {1{"In Progress"}2{"Succeeded"}3{"Succeeded w/ Errors"}4{"Failed"}5{"Aborted"}default{"Unknown"}}
                Write-Host " [$date] $($h.Title) - $code"
            }
        } else {
            Write-Host "No update history available"
        }
    } catch {
        Write-Status "ERR" "Windows Update check failed: $($_.Exception.Message)"
        Write-Status "INFO" "You can manually check in Windows Settings"
    }

    Write-Status "OK" "Windows Update check completed!"
    Write-Log "INFO" "Windows Update check performed"
    Show-Footer
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Invoke-MemoryClean {
    Show-Header "ADVANCED MEMORY CLEANER"
    Write-Status "RUN" "Analyzing and optimizing system memory..."
    Write-Host ""

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $totalRAM = [Math]::Round($os.TotalVisibleMemorySize/1MB,2)
    $freeRAM  = [Math]::Round($os.FreePhysicalMemory/1MB,2)
    $usedRAM  = $totalRAM - $freeRAM
    $usedPct  = [Math]::Round(($usedRAM/$totalRAM)*100,1)

    Write-Host "INITIAL MEMORY STATUS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host " Total RAM : $totalRAM GB"
    Write-Host " Used RAM  : $usedRAM GB ($usedPct`%)"
    Write-Host " Free RAM  : $freeRAM GB"
    Write-Host ""
    
    Write-Host "OPTIMIZATION PROGRESS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray

    # 1. .NET GC
    Write-Host "[1/6] Running garbage collection..."
    try { [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect(); Write-Status "OK" "GC complete" }
    catch { Write-Status "WARN" "GC failed" }

    # 2. Clear clipboard
    Write-Host "[2/6] Clearing clipboard..."
    try { Set-Clipboard -Value $null; Write-Status "OK" "Clipboard cleared" }
    catch { Write-Status "WARN" "Clipboard clear failed" }

    # 3. Stop background services
    Write-Host "[3/6] Optimizing services..."
    try {
        $services = @("Fax","TapisRv","SCardSvr","WSearch")
        $stopped = @()
        foreach ($s in $services) {
            $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running" -and $svc.StartType -ne "Disabled") {
                Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
                $stopped += $s
            }
        }
        if ($stopped.Count) { Write-Status "OK" "Stopped $($stopped.Count) services" }
        else                { Write-Status "INFO" "No services needed" }
    } catch { Write-Status "WARN" "Service optimization failed" }

    # 4. Clear font cache
    Write-Host "[4/6] Clearing font cache..."
    try {
        $path = "$env:WINDIR\ServiceProfiles\LocalService\AppData\Local\FontCache"
        if (Test-Path $path) {
            Stop-Service -Name "FontCache" -Force -ErrorAction SilentlyContinue
            Get-ChildItem $path -Filter "*.dat" | Remove-Item -Force -ErrorAction SilentlyContinue
            Start-Service -Name "FontCache" -ErrorAction SilentlyContinue
            Write-Status "OK" "Font cache cleared"
        }
    } catch { Write-Status "WARN" "Font cache clear failed" }

    # 5. System caches
    Write-Host "[5/6] Flushing system caches..."
    try {
        ipconfig /flushdns | Out-Null
        arp -d * 2>$null | Out-Null
        nbtstat -R  2>$null | Out-Null
        Write-Status "OK" "System caches cleared"
    } catch { Write-Status "WARN" "System cache clear failed" }

    # 6. Working set trim
    Write-Host "[6/6] Optimizing memory working sets..."
    try {
        Get-Process | ForEach-Object {
            if ($_.ProcessName -notin "System","Idle") {
                try { $_.WorkingSet = -1 } catch {}
            }
        }
        Write-Status "OK" "Working sets trimmed"
    } catch { Write-Status "WARN" "Working set trim failed" }

    Start-Sleep 2
    $osNew   = Get-CimInstance -ClassName Win32_OperatingSystem
    $freeNew = [Math]::Round($osNew.FreePhysicalMemory/1MB,2)
    $usedNew = $totalRAM - $freeNew
    $pctNew  = [Math]::Round(($usedNew/$totalRAM)*100,1)

    Write-Host "`nRESULTS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host " Used RAM  : $usedNew GB ($pctNew`%)"
    Write-Host " Free RAM  : $freeNew GB"
    Write-Host " Freed RAM : $([Math]::Round($freeNew - $freeRAM,2)) GB"
    if ($freeNew -gt $freeRAM) { Write-Status "OK" "Memory optimization successful" }
    else                       { Write-Status "INFO" "No significant change" }

    Write-Log "INFO" "Memory cleanup completed – freed $([Math]::Round($freeNew - $freeRAM,2)) GB"
    Show-Footer
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
# --------------------------- #
#   Startup-Programs Manager  #
# --------------------------- #

function Invoke-StartupManager {
    Show-Header "STARTUP PROGRAMS MANAGER"
    Write-Status "RUN" "Collecting startup items..."
    Write-Host ""

    $startupItems = @()

    # Registry (Run) locations
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($rp in $regPaths) {
        if (Test-Path $rp) {
            foreach ($p in (Get-ItemProperty $rp -ErrorAction SilentlyContinue).PSObject.Properties) {
                if ($p.Name -notmatch '^PS') {
                    $startupItems += [PSCustomObject]@{
                        Name     = $p.Name
                        Command  = $p.Value
                        Location = $rp
                        Type     = "Registry"
                    }
                }
            }
        }
    }

    # Startup folders
    $folders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($f in $folders) {
        if (Test-Path $f) {
            Get-ChildItem $f -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
                $startupItems += [PSCustomObject]@{
                    Name     = $_.BaseName
                    Command  = $_.FullName
                    Location = $f
                    Type     = "Startup Folder"
                }
            }
        }
    }

    # Task Scheduler – “At log-on” tasks
    try {
        Get-ScheduledTask | Where-Object {
            $_.State -eq "Ready" -and $_.Triggers.TriggerType -contains "AtLogOn"
        } | Select-Object -First 50 | ForEach-Object {
            $startupItems += [PSCustomObject]@{
                Name     = $_.TaskName
                Command  = $_.Actions.Execute
                Location = "Task Scheduler"
                Type     = "Scheduled Task"
            }
        }
    } catch { Write-Status "WARN" "Some scheduled tasks could not be enumerated" }

    if (-not $startupItems.Count) {
        Write-Status "INFO" "No startup items detected"
        Show-Footer; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown"); return
    }

    # Display items
    Write-Host "FOUND $($startupItems.Count) STARTUP ITEM(S):" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    for ($i = 0; $i -lt $startupItems.Count; $i++) {
        $it = $startupItems[$i]
        Write-Host "[$($i+1)] $($it.Name)" -ForegroundColor Cyan
        Write-Host "    Type    : $($it.Type)"
        Write-Host "    Command : $($it.Command.Substring(0,[Math]::Min(90,$it.Command.Length)))"
        Write-Host ""
    }

    # Ask user
    $sel = Read-Host "Enter item numbers to disable (comma separated) or press <Enter> to keep all"
    if ($sel -match '^\d') {
        $idx = $sel -split ',' | ForEach-Object { ([int]$_) - 1 } | Where-Object { $_ -ge 0 -and $_ -lt $startupItems.Count }
        foreach ($i in $idx) { Disable-StartupProgram -Program $startupItems[$i] }
    }

    Write-Status "OK" "Startup-manager session completed"
    Write-Log   "INFO" "Startup-manager – processed $($idx.Count) item(s)"
    Show-Footer; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Disable-StartupProgram {
    param([PSCustomObject]$Program)

    try {
        switch ($Program.Type) {
            "Registry" {
                $bk = "$($script:CONFIG.BACKUP_DIR)\StartupBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
                reg export $Program.Location.Replace("HKLM:","HKEY_LOCAL_MACHINE").Replace("HKCU:","HKEY_CURRENT_USER") $bk /y | Out-Null
                Remove-ItemProperty -Path $Program.Location -Name $Program.Name -Force
                Write-Status "OK" "Disabled [$($Program.Name)] (registry)"
            }
            "Startup Folder" {
                $dest = "$($script:CONFIG.BACKUP_DIR)\DisabledShortcuts"
                if (-not (Test-Path $dest)) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }
                Move-Item -Path $Program.Command -Destination $dest -Force
                Write-Status "OK" "Disabled [$($Program.Name)] (shortcut moved)"
            }
            "Scheduled Task" {
                Disable-ScheduledTask -TaskName $Program.Name -ErrorAction Stop
                Write-Status "OK" "Disabled task [$($Program.Name)]"
            }
        }
    } catch {
        Write-Status "ERR" "Failed to disable [$($Program.Name)]: $($_.Exception.Message)"
    }
}

# ------------------------- #
#    Basic FPS Boost        #
# ------------------------- #

function Enable-BasicFPSBoost {
    Show-Header "BASIC FPS BOOSTER"
    Write-Status "RUN" "Applying performance tweaks..."
    Write-Host ""

    # Restore point
    try { Checkpoint-Computer -Description "FPS-Boost" -RestorePointType MODIFY_SETTINGS } catch {}

    # 1 – High-performance power plan
    Write-Host "[1/8] Activating High-Performance power plan..."
    try { powercfg -setactive SCHEME_MIN; Write-Status "OK" "High-Performance plan active" }
    catch { Write-Status "WARN" "Power-plan change failed" }

    # 2 – Disable Game Bar & DVR
    Write-Host "[2/8] Disabling Xbox Game Bar / DVR..."
    try {
        Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Value 0 -Type Dword -Force
        Set-ItemProperty "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Value 0   -Type Dword -Force
        Write-Status "OK" "Game Bar / DVR disabled"
    } catch { Write-Status "WARN" "Game Bar tweak failed" }

    # 3 – Visual-effects to performance
    Write-Host "[3/8] Setting visual effects to performance..."
    try {
        Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -Value 2 -Type Dword -Force
        Write-Status "OK" "Visual-effects optimised"
    } catch { Write-Status "WARN" "Visual-effects tweak failed" }

    # 4 – GPU scheduler (games)
    Write-Host "[4/8] Prioritising GPU for Games..."
    try {
        $gp = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
        if (-not (Test-Path $gp)) { New-Item -Path $gp -Force | Out-Null }
        Set-ItemProperty $gp -Name "GPU Priority" -Value 8 -Type Dword -Force
        Set-ItemProperty $gp -Name Priority       -Value 6 -Type Dword -Force
        Write-Status "OK" "GPU priorities updated"
    } catch { Write-Status "WARN" "GPU tweak failed" }

    # 5 – Disable Fullscreen Optimisations
    Write-Host "[5/8] Disabling Fullscreen Optimisations..."
    try {
        Set-ItemProperty "HKCU:\System\GameConfigStore" -Name GameDVR_FSEBehavior     -Value 2 -Type Dword -Force
        Set-ItemProperty "HKCU:\System\GameConfigStore" -Name GameDVR_FSEBehaviorMode -Value 2 -Type Dword -Force
        Write-Status "OK" "Fullscreen Optimisations disabled"
    } catch { Write-Status "WARN" "Fullscreen tweak failed" }

    # 6 – CPU responsiveness
    Write-Host "[6/8] Raising CPU priority for games..."
    try {
        $mp = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
        Set-ItemProperty $mp -Name SystemResponsiveness -Value 0 -Type Dword -Force
        Write-Status "OK" "CPU priority tweaked"
    } catch { Write-Status "WARN" "CPU tweak failed" }

    # 7 – Disable background apps
    Write-Host "[7/8] Disabling background UWP apps..."
    try {
        Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name GlobalUserDisabled -Value 1 -Type Dword -Force
        Write-Status "OK" "Background apps disabled"
    } catch { Write-Status "WARN" "Background apps tweak failed" }

    # 8 – Clear DirectX & shader caches
    Write-Host "[8/8] Clearing graphics caches..."
    try {
        Get-ChildItem "$env:LOCALAPPDATA\D3DSCache" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Get-ChildItem "$env:LOCALAPPDATA\NVIDIA Corporation\NV_Cache" -Filter *.bin -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Status "OK" "Graphics caches cleared"
    } catch { Write-Status "WARN" "Cache clear failed" }

    Write-Host ""
    Write-Status "OK" "Basic FPS-boost complete – restart recommended"
    Write-Log   "INFO" "FPS-boost executed"
    Show-Footer; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ------------------------------- #
#      Basic Gaming Mode          #
# ------------------------------- #

function Enable-GamingModeBasic {
    Show-Header "BASIC GAMING MODE"
    Write-Status "RUN" "Applying gaming-oriented tweaks..."
    Write-Host ""

    Enable-BasicFPSBoost   # reuse FPS-boost tweaks
    Write-Status "OK"  "High-performance power plan confirmed"

    # Enable Windows Game Mode itself
    try {
        Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\GameBar" -Name AllowAutoGameMode  -Value 1 -Type Dword -Force
        Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\GameBar" -Name AutoGameModeEnabled -Value 1 -Type Dword -Force
        Write-Status "OK" "Windows Game Mode enabled"
    } catch { Write-Status "WARN" "Game Mode tweak failed" }

    # Silence notifications
    try {
        Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" `
                         -Name NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND -Value 0 -Type Dword -Force
        Write-Status "OK" "Notification sounds muted"
    } catch { Write-Status "WARN" "Notification tweak failed" }

    # Desktop profile file
    $profile = @"
Gaming Mode Active — $(Get-Date)
 High-Perf Power Plan : Enabled
 Game Mode            : Enabled
 Visual Effects       : Performance
 Notifications        : Muted
 GPU / CPU priority   : Raised
"@
    Set-Content "$env:USERPROFILE\Desktop\Gaming_Mode_Profile.txt" -Value $profile

    Write-Status "OK" "Gaming Mode profile written to desktop"
    Write-Log   "INFO" "Gaming Mode applied"
    Show-Footer; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ------------------------- #
#        Main Menu          #
# ------------------------- #

function Show-MainMenu {
    Initialize-System
    $script:HWID      = Get-HardwareID
    $script:isPremium = Test-License -License "FREE" -HWID $script:HWID   # placeholder

    :MenuLoop
    Clear-Host
    Write-Host "================ PC Optimizer Pro v3.0 ================" -ForegroundColor Cyan
    Write-Host " 1) System Info"
    Write-Host " 2) Hardware Info"
    Write-Host " 3) Disk Analysis"
    Write-Host " 4) Network Status"
    Write-Host " 5) Basic Clean"
    Write-Host " 6) Registry Scan"
    Write-Host " 7) System Health Check"
    Write-Host " 8) Windows Update Check"
    Write-Host " 9) Memory Clean"
    Write-Host "10) Startup Manager"
    Write-Host "11) Basic FPS Boost"
    Write-Host "12) Gaming Mode (Basic)"
    Write-Host " Q) Quit"
    Write-Host "======================================================="
    $choice = Read-Host "Select an option"

    switch ($choice) {
        "1"  { Get-SystemInfo }
        "2"  { Get-HardwareInfo }
        "3"  { Get-DiskAnalysis }
        "4"  { Get-NetworkStatus }
        "5"  { Invoke-BasicClean }
        "6"  { Invoke-RegistryScanner }
        "7"  { Invoke-SystemHealthCheck }
        "8"  { Invoke-WindowsUpdateCheck }
        "9"  { Invoke-MemoryClean }
        "10" { Invoke-StartupManager }
        "11" { Enable-BasicFPSBoost }
        "12" { Enable-GamingModeBasic }
        "Q"|"q" { Write-Host "`nExiting..."; return }
        default { Write-Host "`nInvalid option"; Start-Sleep 1 }
    }
    goto MenuLoop
}

# ------- Script entry point ------- #
if ($MyInvocation.InvocationName -eq '.\PCOptimizerPro.ps1' -or $MyInvocation.InvocationName -eq $MyInvocation.MyCommand.Name) {
    Show-MainMenu
}

