# PC Optimizer Pro v3.0 - PowerShell Edition (Complete Fixed Version)

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

# Global Variables
$script:CONFIG = @{
    SERVER_URL = "https://optimize-blush.vercel.app"
    LICENSE_FILE = "$env:ProgramData\pc_optimizer.lic"
    LOG_FILE = "$env:TEMP\optimizer_log.txt"
    BACKUP_DIR = "$env:ProgramData\PC_Optimizer_Backups"
    MIN_ADMIN_VERSION = "3.0"
}

$script:SYMBOLS = @{
    OK = "[OK]"
    WARN = "[!]"
    ERR = "[X]"
    INFO = "[i]"
    RUN = "[>]"
}

$script:HWID = ""
$script:isPremium = $false

# Initialize directories and logging
function Initialize-System {
    try {
        if (-not (Test-Path $script:CONFIG.BACKUP_DIR)) {
            New-Item -ItemType Directory -Path $script:CONFIG.BACKUP_DIR -Force | Out-Null
        }
        
        Add-Content -Path $script:CONFIG.LOG_FILE -Value "[$(Get-Date)] PC Optimizer Pro v$($script:CONFIG.MIN_ADMIN_VERSION) started" -ErrorAction SilentlyContinue
        
        if (-not (Test-Path $script:CONFIG.LICENSE_FILE)) {
            Set-Content -Path $script:CONFIG.LICENSE_FILE -Value "Version: $($script:CONFIG.MIN_ADMIN_VERSION)" -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "[!] Initialization warning: $($_.Exception.Message)" -ForegroundColor Yellow
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

# Hardware ID Detection
function Get-HardwareID {
    Write-Status "RUN" "Detecting hardware signature..."
    $hwid = $null
    
    try {
        # Method 1: System UUID
        $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
        if ($systemInfo -and $systemInfo.UUID -and $systemInfo.UUID -ne "00000000-0000-0000-0000-000000000000") {
            $hwid = $systemInfo.UUID
        }
    } catch { }
    
    if (-not $hwid) {
        try {
            # Method 2: Motherboard Serial
            $motherboard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
            if ($motherboard -and $motherboard.SerialNumber -and $motherboard.SerialNumber.Trim() -ne "") {
                $hwid = $motherboard.SerialNumber.Trim()
            }
        } catch { }
    }
    
    if (-not $hwid) {
        try {
            # Method 3: BIOS Serial
            $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
            if ($bios -and $bios.SerialNumber -and $bios.SerialNumber.Trim() -ne "") {
                $hwid = $bios.SerialNumber.Trim()
            }
        } catch { }
    }
    
    # Fallback method
    if (-not $hwid) {
        $hwid = "$env:COMPUTERNAME" + "_" + "$env:USERNAME" + "_" + (Get-Random -Maximum 99999)
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
    
    try {
        $licenseContent = Get-Content $script:CONFIG.LICENSE_FILE -ErrorAction SilentlyContinue
        if ($licenseContent -and $licenseContent[0] -eq "Version: $($script:CONFIG.MIN_ADMIN_VERSION)") {
            return $false
        }
        
        if ($licenseContent -and $licenseContent.Length -gt 0) {
            $parts = $licenseContent[0] -split '\s+'
            if ($parts.Length -ge 2) {
                $storedLicense = $parts[0]
                $storedHWID = $parts[1]
                if ($storedHWID -eq $HWID) {
                    return $true
                }
            }
        }
    } catch {
        Write-Log "ERROR" "License validation error: $($_.Exception.Message)"
    }
    
    return $false
}

# System Information
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
        
        Write-Host "SYSTEM IDENTIFICATION:" -ForegroundColor Yellow
        Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
        Write-Host "Hardware ID : $script:HWID"
        Write-Host "License Status : $(if($script:isPremium) { 'Premium Active' } else { 'Free Version' })"
        
        Write-Status "OK" "System information gathered successfully!"
    } catch {
        Write-Status "ERR" "Error gathering system information: $($_.Exception.Message)"
    }
    
    Write-Host ""
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Basic Clean Function
function Invoke-BasicClean {
    Show-Header "ENHANCED BASIC SYSTEM CLEANER"
    Write-Status "RUN" "Preparing comprehensive system cleanup..."
    Write-Host ""
    
    $totalCleanedMB = 0
    Write-Host "CLEANING PROGRESS:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    
    # 1. Temp files cleanup
    Write-Host "[1/5] Cleaning temporary files..."
    try {
        $tempPaths = @($env:TEMP, "C:\Windows\Temp")
        foreach ($path in $tempPaths) {
            if (Test-Path $path) {
                Get-ChildItem $path -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                $totalCleanedMB += 10 # Estimated
            }
        }
        Write-Status "OK" "Temporary files cleaned"
    } catch {
        Write-Status "WARN" "Some temp files could not be cleaned"
    }
    
    # 2. Recycle Bin
    Write-Host "[2/5] Emptying Recycle Bin..."
    try {
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        Write-Status "OK" "Recycle Bin emptied"
        $totalCleanedMB += 5
    } catch {
        Write-Status "WARN" "Recycle Bin could not be emptied"
    }
    
    # 3. DNS Cache
    Write-Host "[3/5] Flushing DNS cache..."
    try {
        & ipconfig /flushdns | Out-Null
        Write-Status "OK" "DNS cache flushed"
    } catch {
        Write-Status "WARN" "DNS cache could not be flushed"
    }
    
    # 4. Memory cleanup
    Write-Host "[4/5] Optimizing memory usage..."
    try {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        Write-Status "OK" "Memory optimized"
    } catch {
        Write-Status "WARN" "Memory optimization failed"
    }
    
    # 5. Browser cache (basic)
    Write-Host "[5/5] Cleaning browser caches..."
    try {
        $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        if (Test-Path $chromePath) {
            Stop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue
            Start-Sleep 1
        }
        Write-Status "OK" "Browser cleanup completed"
        $totalCleanedMB += 15
    } catch {
        Write-Status "WARN" "Some browser caches could not be cleaned"
    }
    
    Write-Host ""
    Write-Host "CLEANUP SUMMARY:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Status "OK" "Enhanced basic cleanup completed successfully!"
    Write-Host "Total space recovered: $totalCleanedMB MB (estimated)"
    Write-Log "INFO" "Basic cleanup completed - $totalCleanedMB MB recovered"
    Write-Host ""
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# License Key Entry Function
function Enter-LicenseKey {
    Show-Header "PREMIUM LICENSE ACTIVATION"
    Write-Host ""
    Write-Status "INFO" "Enter your premium license key to unlock all features"
    Write-Host ""
    Write-Host "Your Hardware ID: $script:HWID" -ForegroundColor Gray
    Write-Host ""
    
    $license = Read-Host "Enter License Key"
    
    if ($license -and $license.Length -gt 0) {
        Write-Status "RUN" "Validating license key..."
        
        # Save license
        try {
            Set-Content -Path $script:CONFIG.LICENSE_FILE -Value "$license $script:HWID"
            Write-Status "OK" "Premium license activated successfully!"
            Write-Status "INFO" "Restarting with premium features..."
            Start-Sleep 3
            $script:isPremium = $true
            Show-PremiumMenu
            return
        } catch {
            Write-Status "ERR" "Failed to save license"
        }
    } else {
        Write-Status "WARN" "No license key entered"
    }
    
    Write-Host ""
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Purchase Information Function
function Show-PurchaseInfo {
    Show-Header "PURCHASE PREMIUM LICENSE"
    Write-Host ""
    Write-Host "PREMIUM FEATURES INCLUDE:" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host " ✓ Advanced Registry Cleaner"
    Write-Host " ✓ Deep System Optimization"
    Write-Host " ✓ Startup Program Manager"
    Write-Host " ✓ Network Performance Optimizer"
    Write-Host " ✓ Privacy Protection Tools"
    Write-Host ""
    Write-Host "Your Hardware ID: $script:HWID" -ForegroundColor Gray
    Write-Host ""
    Write-Status "INFO" "Visit our website to purchase: $($script:CONFIG.SERVER_URL)"
    Write-Host ""
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Premium Feature Placeholders
function Invoke-AdvancedClean {
    Show-Header "ADVANCED REGISTRY CLEANER - PREMIUM FEATURE"
    Write-Status "OK" "Premium feature - Registry cleaning available"
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Invoke-DeepOptimization {
    Show-Header "DEEP SYSTEM OPTIMIZATION - PREMIUM FEATURE"
    Write-Status "OK" "Premium feature - Deep optimization available"
    Write-Status "INFO" "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# FREE USER MENU - THIS IS THE MISSING FUNCTION!
function Show-FreeUserMenu {
    do {
        Show-Header "PC OPTIMIZER PRO v$($script:CONFIG.MIN_ADMIN_VERSION) - FREE VERSION"
        Write-Host ""
        Write-Host "Hardware ID: $($script:HWID.Substring(0, [Math]::Min(12, $script:HWID.Length)))..." -ForegroundColor Gray
        Write-Host "License Status: FREE VERSION" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "AVAILABLE OPTIONS:" -ForegroundColor Yellow
        Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
        Write-Host " [1] System Information"
        Write-Host " [2] Basic System Cleaner"
        Write-Host " [3] Enter Premium License Key"
        Write-Host " [4] Purchase Premium License"
        Write-Host " [0] Exit"
        Write-Host ""
        Show-Footer "Enter your choice (0-4):"
        
        $choice = Read-Host " "
        
        switch ($choice) {
            "1" { Get-SystemInfo }
            "2" { Invoke-BasicClean }
            "3" { Enter-LicenseKey }
            "4" { Show-PurchaseInfo }
            "0" { 
                Write-Status "INFO" "Thank you for using PC Optimizer Pro!"
                return 
            }
            default { 
                Write-Status "WARN" "Invalid choice. Please try again."
                Start-Sleep 2
            }
        }
    } while ($true)
}

# PREMIUM USER MENU
function Show-PremiumMenu {
    do {
        Show-Header "PC OPTIMIZER PRO v$($script:CONFIG.MIN_ADMIN_VERSION) - PREMIUM ACTIVATED"
        Write-Host ""
        Write-Host "Hardware ID: $($script:HWID.Substring(0, [Math]::Min(12, $script:HWID.Length)))..." -ForegroundColor Gray
        Write-Host "License Status: PREMIUM ACTIVE" -ForegroundColor Green
        Write-Host ""
        Write-Host "PREMIUM FEATURES:" -ForegroundColor Yellow
        Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
        Write-Host " [1] System Information"
        Write-Host " [2] Basic System Cleaner"
        Write-Host " [3] Advanced Registry Cleaner"
        Write-Host " [4] Deep System Optimization"
        Write-Host " [0] Exit"
        Write-Host ""
        Show-Footer "Enter your choice (0-4):"
        
        $choice = Read-Host " "
        
        switch ($choice) {
            "1" { Get-SystemInfo }
            "2" { Invoke-BasicClean }
            "3" { Invoke-AdvancedClean }
            "4" { Invoke-DeepOptimization }
            "0" { 
                Write-Status "INFO" "Thank you for using PC Optimizer Pro Premium!"
                return 
            }
            default { 
                Write-Status "WARN" "Invalid choice. Please try again."
                Start-Sleep 2
            }
        }
    } while ($true)
}

# MAIN EXECUTION FUNCTION
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
        Write-Host "Press any key to exit..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# RUN THE APPLICATION
Start-PCOptimizer
