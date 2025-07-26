<#
.SYNOPSIS
    PC Optimizer Pro - License Management and System Optimization Tool
.DESCRIPTION
    Complete PC optimization tool with license validation, registration, and system tweaks.
    Uses all API endpoints: validate, register, license-info, and hwid-reset.
.PARAMETER License
    The license key to validate or register
.PARAMETER Action
    Action to perform: validate, register, info, reset, or optimize
.EXAMPLE
    .\PC-Optimizer-Pro.ps1 -Action validate -License "ABCD-1234-EFGH-5678"
    .\PC-Optimizer-Pro.ps1 -Action optimize -License "ABCD-1234-EFGH-5678"
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('validate','register','info','reset','optimize')]
    [string]$Action = 'optimize',
    
    [Parameter(Mandatory=$false)]
    [string]$License
)

# Configuration
$script:CONFIG = @{
    SERVER_URL          = "https://p-coptimizer-web.vercel.app"
    LICENSE_FILE        = "$env:ProgramData\pc_optimizer.lic"
    LOG_FILE           = "$env:TEMP\optimizer_log.txt"
    BACKUP_DIR         = "$env:ProgramData\PC_Optimizer_Backups"
    MIN_ADMIN_VERSION  = "3.0"
    TIMEOUT_SEC        = 15
    VERSION            = "4.2.1"
}

# Global Variables
$script:HWID = $null
$script:IsActivated = $false

#region Logging Functions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to console with colors
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default { Write-Host $logEntry -ForegroundColor White }
    }
    
    # Write to log file
    try {
        $logEntry | Out-File -FilePath $script:CONFIG.LOG_FILE -Append -Encoding UTF8
    } catch {
        # Silently fail if can't write to log
    }
}

function Show-Banner {
    Clear-Host
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    PC OPTIMIZER PRO v$($script:CONFIG.VERSION)                    ║" -ForegroundColor Cyan  
    Write-Host "║              Advanced System Optimization Tool               ║" -ForegroundColor Cyan
    Write-Host "║                  https://pcoptimizer.pro                     ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}
#endregion

#region Hardware ID Functions
function Get-HWID {
    if ($script:HWID) { return $script:HWID }
    
    try {
        $cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).ProcessorId
        $motherboard = (Get-CimInstance Win32_BaseBoard).SerialNumber
        $disk = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").VolumeSerialNumber
        
        $hwString = "$cpu|$motherboard|$disk"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($hwString)
        $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
        $script:HWID = [System.BitConverter]::ToString($hash).Replace("-", "").Substring(0, 32)
        
        Write-Log "Generated HWID: $($script:HWID.Substring(0,8))..." "INFO"
        return $script:HWID
    } catch {
        Write-Log "Failed to generate HWID: $($_.Exception.Message)" "ERROR"
        throw "Cannot generate hardware ID"
    }
}
#endregion

#region API Functions
function Invoke-ApiRequest {
    param(
        [string]$Method,
        [string]$Endpoint,
        [hashtable]$Query = @{},
        [hashtable]$Body = @{}
    )
    
    $uri = $script:CONFIG.SERVER_URL + $Endpoint
    
    if ($Query.Count -gt 0) {
        $queryString = ($Query.GetEnumerator() | ForEach-Object { "$($_.Key)=$([Uri]::EscapeDataString($_.Value))" }) -join '&'
        $uri += "?$queryString"
    }
    
    try {
        $headers = @{
            'User-Agent' = "PC-Optimizer-Pro/$($script:CONFIG.VERSION)"
            'Accept' = 'application/json'
        }
        
        $params = @{
            Uri = $uri
            Method = $Method
            Headers = $headers
            UseBasicParsing = $true
            TimeoutSec = $script:CONFIG.TIMEOUT_SEC
        }
        
        if ($Method -eq 'POST' -and $Body.Count -gt 0) {
            $params.Body = ($Body | ConvertTo-Json -Compress)
            $params.ContentType = 'application/json'
        }
        
        Write-Log "API Request: $Method $uri" "INFO"
        $response = Invoke-WebRequest @params
        
        if ($response.StatusCode -eq 200) {
            $result = $response.Content | ConvertFrom-Json
            Write-Log "API Response: Success ($($response.StatusCode))" "SUCCESS"
            return $result
        } else {
            Write-Log "API Response: HTTP $($response.StatusCode)" "WARN"
            throw "Server returned status code: $($response.StatusCode)"
        }
    } catch {
        Write-Log "API Error: $($_.Exception.Message)" "ERROR"
        throw "API request failed: $($_.Exception.Message)"
    }
}

function Test-LicenseValidation {
    param([string]$License)
    
    Write-Log "Validating license: $($License.Substring(0,8))..." "INFO"
    $hwid = Get-HWID
    
    try {
        $result = Invoke-ApiRequest -Method 'GET' -Endpoint '/api/validate' -Query @{
            license = $License
            hwid = $hwid
        }
        
        if ($result.valid -eq $true) {
            Write-Log "License validation successful" "SUCCESS"
            return $true
        } else {
            Write-Log "License validation failed: $($result.message)" "ERROR"
            return $false
        }
    } catch {
        Write-Log "License validation error: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Register-NewLicense {
    param([string]$License)
    
    Write-Log "Registering license: $($License.Substring(0,8))..." "INFO"
    $hwid = Get-HWID
    
    try {
        $result = Invoke-ApiRequest -Method 'GET' -Endpoint '/api/register' -Query @{
            license = $License
            hwid = $hwid
        }
        
        if ($result.success -eq $true) {
            Write-Log "License registration successful" "SUCCESS"
            Save-License -License $License
            return $true
        } else {
            Write-Log "License registration failed: $($result.message)" "ERROR"
            return $false
        }
    } catch {
        Write-Log "License registration error: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-LicenseInformation {
    param([string]$License)
    
    Write-Log "Retrieving license information..." "INFO"
    
    try {
        $result = Invoke-ApiRequest -Method 'GET' -Endpoint '/api/license-info' -Query @{
            license = $License
        }
        
        Write-Log "License information retrieved successfully" "SUCCESS"
        return $result
    } catch {
        Write-Log "Failed to retrieve license information: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Request-HWIDReset {
    param([string]$License)
    
    Write-Log "Requesting HWID reset for license..." "INFO"
    
    try {
        $result = Invoke-ApiRequest -Method 'POST' -Endpoint '/api/request-hwid-reset' -Body @{
            license = $License
        }
        
        if ($result.success -eq $true) {
            Write-Log "HWID reset request submitted successfully" "SUCCESS"
            return $true
        } else {
            Write-Log "HWID reset request failed: $($result.message)" "ERROR"
            return $false
        }
    } catch {
        Write-Log "HWID reset request error: $($_.Exception.Message)" "ERROR"
        return $false
    }
}
#endregion

#region License Management
function Get-SavedLicense {
    if (Test-Path $script:CONFIG.LICENSE_FILE) {
        try {
            $license = Get-Content $script:CONFIG.LICENSE_FILE -Raw
            return $license.Trim()
        } catch {
            Write-Log "Failed to read saved license" "ERROR"
            return $null
        }
    }
    return $null
}

function Save-License {
    param([string]$License)
    
    try {
        # Ensure directory exists
        $dir = Split-Path $script:CONFIG.LICENSE_FILE -Parent
        if (!(Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
        
        $License | Out-File -FilePath $script:CONFIG.LICENSE_FILE -Encoding UTF8 -NoNewline
        Write-Log "License saved successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to save license: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Initialize-License {
    param([string]$ProvidedLicense)
    
    # Use provided license or try to get saved one
    $licenseToUse = $ProvidedLicense
    if ([string]::IsNullOrEmpty($licenseToUse)) {
        $licenseToUse = Get-SavedLicense
    }
    
    if ([string]::IsNullOrEmpty($licenseToUse)) {
        Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
        Write-Host "║                    LICENSE REQUIRED                        ║" -ForegroundColor Yellow
        Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "No license found. Please provide your license key:" -ForegroundColor Yellow
        $licenseToUse = Read-Host "License Key"
    }
    
    if ([string]::IsNullOrEmpty($licenseToUse)) {
        Write-Log "No license provided" "ERROR"
        return $false
    }
    
    # Validate the license
    if (Test-LicenseValidation -License $licenseToUse) {
        $script:IsActivated = $true
        Save-License -License $licenseToUse
        return $true
    } else {
        # Try to register if validation failed
        Write-Log "Attempting to register new license..." "INFO"
        if (Register-NewLicense -License $licenseToUse) {
            $script:IsActivated = $true
            return $true
        }
    }
    
    return $false
}
#endregion

#region System Optimization Functions
function Test-AdminRights {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

function Invoke-RegistryOptimization {
    Write-Log "Starting registry optimization..." "INFO"
    
    $optimizations = @(
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"
            Name = "Win32PrioritySeparation"
            Value = 0x26
            Type = "DWORD"
            Description = "Optimize CPU scheduling"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
            Name = "SystemResponsiveness"
            Value = 0x0A
            Type = "DWORD"  
            Description = "Improve system responsiveness"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
            Name = "GPU Priority"
            Value = 8
            Type = "DWORD"
            Description = "Boost gaming performance"
        }
    )
    
    foreach ($opt in $optimizations) {
        try {
            if (!(Test-Path $opt.Path)) {
                New-Item -Path $opt.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $opt.Path -Name $opt.Name -Value $opt.Value -Type $opt.Type -Force
            Write-Log "Applied: $($opt.Description)" "SUCCESS"
        } catch {
            Write-Log "Failed to apply: $($opt.Description) - $($_.Exception.Message)" "ERROR"
        }
    }
}

function Invoke-ServiceOptimization {
    Write-Log "Starting service optimization..." "INFO"
    
    $servicesToDisable = @(
        @{ Name = "Fax"; Description = "Fax Service" },
        @{ Name = "WSearch"; Description = "Windows Search" },
        @{ Name = "SysMain"; Description = "Superfetch" }
    )
    
    foreach ($svc in $servicesToDisable) {
        try {
            $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq 'Running') {
                Stop-Service -Name $svc.Name -Force
                Set-Service -Name $svc.Name -StartupType Disabled
                Write-Log "Disabled service: $($svc.Description)" "SUCCESS"
            }
        } catch {
            Write-Log "Failed to disable service: $($svc.Description)" "WARN"
        }
    }
}

function Invoke-TempCleanup {
    Write-Log "Starting temporary file cleanup..." "INFO"
    
    $tempPaths = @(
        $env:TEMP,
        "$env:WINDIR\Temp",
        "$env:WINDIR\Prefetch"
    )
    
    $totalFreed = 0
    foreach ($path in $tempPaths) {
        if (Test-Path $path) {
            try {
                $sizeBefore = (Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                $sizeAfter = (Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                $freed = ($sizeBefore - $sizeAfter) / 1MB
                $totalFreed += $freed
                Write-Log "Cleaned $path - Freed: $([math]::Round($freed, 2)) MB" "SUCCESS"
            } catch {
                Write-Log "Failed to clean $path" "WARN"
            }
        }
    }
    
    Write-Log "Total space freed: $([math]::Round($totalFreed, 2)) MB" "SUCCESS"
}

function Invoke-SystemOptimization {
    Write-Log "Starting complete system optimization..." "INFO"
    
    if (!(Test-AdminRights)) {
        Write-Log "Administrator rights required for full optimization" "ERROR"
        return $false
    }
    
    # Create backup
    $backupPath = Join-Path $script:CONFIG.BACKUP_DIR "backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    try {
        New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
        Write-Log "Created backup directory: $backupPath" "INFO"
    } catch {
        Write-Log "Failed to create backup directory" "WARN"
    }
    
    # Run optimizations
    Invoke-RegistryOptimization
    Invoke-ServiceOptimization  
    Invoke-TempCleanup
    
    Write-Log "System optimization completed!" "SUCCESS"
    return $true
}
#endregion

#region Main Execution
function Show-LicenseInfo {
    param([string]$License)
    
    $info = Get-LicenseInformation -License $License
    if ($info) {
        Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║                      LICENSE INFORMATION                   ║" -ForegroundColor Green  
        Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        
        $info.PSObject.Properties | ForEach-Object {
            Write-Host "$($_.Name): " -NoNewline -ForegroundColor Cyan
            Write-Host "$($_.Value)" -ForegroundColor White
        }
        Write-Host ""
    } else {
        Write-Host "Failed to retrieve license information." -ForegroundColor Red
    }
}

function Show-Menu {
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                    OPTIMIZATION MENU                       ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "[1] Run Full System Optimization" -ForegroundColor Yellow
    Write-Host "[2] View License Information" -ForegroundColor Yellow  
    Write-Host "[3] Request HWID Reset" -ForegroundColor Yellow
    Write-Host "[4] Registry Optimization Only" -ForegroundColor Yellow
    Write-Host "[5] Service Optimization Only" -ForegroundColor Yellow
    Write-Host "[6] Temporary File Cleanup Only" -ForegroundColor Yellow
    Write-Host "[Q] Quit" -ForegroundColor Red
    Write-Host ""
}

function Main {
    Show-Banner
    
    # Handle command line actions
    if ($Action -ne 'optimize') {
        if ([string]::IsNullOrEmpty($License)) {
            Write-Host "License parameter required for action: $Action" -ForegroundColor Red
            exit 1
        }
        
        switch ($Action) {
            'validate' {
                $result = Test-LicenseValidation -License $License
                Write-Host "License validation: " -NoNewline
                Write-Host (if ($result) { "VALID" } else { "INVALID" }) -ForegroundColor (if ($result) { "Green" } else { "Red" })
                exit (if ($result) { 0 } else { 1 })
            }
            'register' {
                $result = Register-NewLicense -License $License  
                Write-Host "License registration: " -NoNewline
                Write-Host (if ($result) { "SUCCESS" } else { "FAILED" }) -ForegroundColor (if ($result) { "Green" } else { "Red" })
                exit (if ($result) { 0 } else { 1 })
            }
            'info' {
                Show-LicenseInfo -License $License
                exit 0
            }
            'reset' {
                $result = Request-HWIDReset -License $License
                Write-Host "HWID reset request: " -NoNewline  
                Write-Host (if ($result) { "SUBMITTED" } else { "FAILED" }) -ForegroundColor (if ($result) { "Green" } else { "Red" })
                exit (if ($result) { 0 } else { 1 })
            }
        }
    }
    
    # Interactive mode - Initialize license
    if (!(Initialize-License -ProvidedLicense $License)) {
        Write-Host "❌ License activation failed. Cannot proceed." -ForegroundColor Red
        Write-Host "Please check your license key and try again." -ForegroundColor Yellow
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    Write-Host "✅ License activated successfully!" -ForegroundColor Green
    Write-Host "Hardware ID: $((Get-HWID).Substring(0,8))..." -ForegroundColor Cyan
    Write-Host ""
    
    # Interactive menu loop
    do {
        Show-Menu
        $choice = Read-Host "Select an option"
        
        switch ($choice.ToUpper()) {
            '1' {
                Write-Host "Starting full system optimization..." -ForegroundColor Yellow
                Invoke-SystemOptimization
                Read-Host "Press Enter to continue"
            }
            '2' {
                $currentLicense = Get-SavedLicense
                if ($currentLicense) {
                    Show-LicenseInfo -License $currentLicense
                } else {
                    Write-Host "No license found." -ForegroundColor Red
                }
                Read-Host "Press Enter to continue"
            }
            '3' {
                $currentLicense = Get-SavedLicense
                if ($currentLicense) {
                    Write-Host "Requesting HWID reset..." -ForegroundColor Yellow
                    $result = Request-HWIDReset -License $currentLicense
                    if ($result) {
                        Write-Host "✅ HWID reset request submitted successfully!" -ForegroundColor Green
                    } else {
                        Write-Host "❌ HWID reset request failed." -ForegroundColor Red
                    }
                } else {
                    Write-Host "No license found." -ForegroundColor Red
                }
                Read-Host "Press Enter to continue"
            }
            '4' {
                Write-Host "Starting registry optimization..." -ForegroundColor Yellow
                Invoke-RegistryOptimization
                Read-Host "Press Enter to continue"
            }
            '5' {
                Write-Host "Starting service optimization..." -ForegroundColor Yellow
                Invoke-ServiceOptimization
                Read-Host "Press Enter to continue"
            }
            '6' {
                Write-Host "Starting temporary file cleanup..." -ForegroundColor Yellow
                Invoke-TempCleanup
                Read-Host "Press Enter to continue"
            }
            'Q' {
                Write-Host "Thank you for using PC Optimizer Pro!" -ForegroundColor Green
                break
            }
            default {
                Write-Host "Invalid option. Please try again." -ForegroundColor Red
                Start-Sleep 2
            }
        }
        Clear-Host
        Show-Banner
    } while ($choice.ToUpper() -ne 'Q')
}

# Script entry point
try {
    Main
} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    Write-Host "A fatal error occurred. Check the log file for details: $($script:CONFIG.LOG_FILE)" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
#endregion
