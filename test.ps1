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

#region Helper Functions
function Get-SafePreview {
    param([string]$Text, [int]$Length = 8)
    if ([string]::IsNullOrEmpty($Text)) { return "N/A" }
    if ($Text.Length -ge $Length) { 
        return $Text.Substring(0, $Length) + "..."
    } else { 
        return $Text 
    }
}
#endregion

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
        
        Write-Log "Generated HWID: $(Get-SafePreview -Text $script:HWID -Length 8)" "INFO"
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
    
    $licensePreview = Get-SafePreview -Text $License -Length 8
    Write-Log "Validating license: $licensePreview" "INFO"
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
    
    $licensePreview = Get-SafePreview -Text $License -Length 8
    Write-Log "Registering license: $licensePreview" "INFO"
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

#region New Features
function Show-LicenseDashboard {
    param([string]$License)
    
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
    Write-Host "║                    LICENSE DASHBOARD                       ║" -ForegroundColor Blue
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Blue
    Write-Host ""
    
    # Get comprehensive license information
    try {
        $licenseInfo = Get-LicenseInformation -License $License
        $hwid = Get-HWID
        
        # Display license details
        Write-Host "License Key: " -NoNewline -ForegroundColor Cyan
        Write-Host "$(Get-SafePreview -Text $License -Length 12)" -ForegroundColor White
        
        Write-Host "Hardware ID: " -NoNewline -ForegroundColor Cyan  
        Write-Host "$(Get-SafePreview -Text $hwid -Length 12)" -ForegroundColor White
        
        if ($licenseInfo) {
            Write-Host "Status: " -NoNewline -ForegroundColor Cyan
            Write-Host "ACTIVE" -ForegroundColor Green
            
            # Display additional license info if available
            if ($licenseInfo.expiryDate) {
                Write-Host "Expires: " -NoNewline -ForegroundColor Cyan
                Write-Host "$($licenseInfo.expiryDate)" -ForegroundColor White
            }
            
            if ($licenseInfo.activationCount) {
                Write-Host "Activations: " -NoNewline -ForegroundColor Cyan
                Write-Host "$($licenseInfo.activationCount)" -ForegroundColor White
            }
        }
        
        # Test connection to server
        Write-Host "Server Status: " -NoNewline -ForegroundColor Cyan
        try {
            $pingResult = Test-NetConnection -ComputerName "p-coptimizer-web.vercel.app" -Port 443 -InformationLevel Quiet
            Write-Host (if ($pingResult) { "ONLINE" } else { "OFFLINE" }) -ForegroundColor (if ($pingResult) { "Green" } else { "Red" })
        } catch {
            Write-Host "UNKNOWN" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "Error retrieving dashboard data: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
}

function Start-LicenseHealthCheck {
    param([string]$License, [int]$IntervalMinutes = 30)
    
    Write-Log "Starting license health check (every $IntervalMinutes minutes)..." "INFO"
    
    while ($true) {
        try {
            $isValid = Test-LicenseValidation -License $License
            
            if ($isValid) {
                Write-Log "License health check: PASSED" "SUCCESS"
            } else {
                Write-Log "License health check: FAILED - License may be revoked" "ERROR"
                
                # Try to get license info for more details
                $info = Get-LicenseInformation -License $License
                if ($info -and $info.status) {
                    Write-Log "License status: $($info.status)" "WARN"
                }
            }
            
        } catch {
            Write-Log "License health check error: $($_.Exception.Message)" "ERROR"
        }
        
        Start-Sleep -Seconds ($IntervalMinutes * 60)
    }
}

function Invoke-BatchLicenseCheck {
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║                  BATCH LICENSE CHECKER                     ║" -ForegroundColor Magenta
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""
    
    Write-Host "Enter license keys (one per line, empty line to finish):" -ForegroundColor Yellow
    $licenses = @()
    
    do {
        $license = Read-Host "License $(($licenses.Count + 1))"
        if (![string]::IsNullOrEmpty($license)) {
            $licenses += $license.Trim()
        }
    } while (![string]::IsNullOrEmpty($license))
    
    if ($licenses.Count -eq 0) {
        Write-Host "No licenses provided." -ForegroundColor Red
        return
    }
    
    Write-Host "`nChecking $($licenses.Count) licenses...`n" -ForegroundColor Cyan
    
    foreach ($lic in $licenses) {
        Write-Host "Checking: $(Get-SafePreview -Text $lic)... " -NoNewline -ForegroundColor White
        
        try {
            $isValid = Test-LicenseValidation -License $lic
            Write-Host (if ($isValid) { "✅ VALID" } else { "❌ INVALID" }) -ForegroundColor (if ($isValid) { "Green" } else { "Red" })
        } catch {
            Write-Host "❓ ERROR" -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
}

function Backup-LicenseData {
    $backupPath = Join-Path $script:CONFIG.BACKUP_DIR "license_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    
    try {
        $currentLicense = Get-SavedLicense
        if ([string]::IsNullOrEmpty($currentLicense)) {
            Write-Log "No license to backup" "WARN"
            return $false
        }
        
        # Get license information
        $licenseInfo = Get-LicenseInformation -License $currentLicense
        
        $backupData = @{
            License = $currentLicense
            HWID = Get-HWID
            BackupDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            LicenseInfo = $licenseInfo
            Version = $script:CONFIG.VERSION
        }
        
        # Ensure backup directory exists
        $backupDir = Split-Path $backupPath -Parent
        if (!(Test-Path $backupDir)) {
            New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
        }
        
        $backupData | ConvertTo-Json -Depth 3 | Out-File -FilePath $backupPath -Encoding UTF8
        Write-Log "License backup created: $backupPath" "SUCCESS"
        return $true
        
    } catch {
        Write-Log "Failed to create license backup: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Restore-LicenseData {
    $backupFiles = Get-ChildItem -Path $script:CONFIG.BACKUP_DIR -Filter "license_backup_*.json" -ErrorAction SilentlyContinue
    
    if ($backupFiles.Count -eq 0) {
        Write-Host "No license backups found." -ForegroundColor Yellow
        return
    }
    
    Write-Host "Available license backups:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $backupFiles.Count; $i++) {
        Write-Host "[$($i + 1)] $($backupFiles[$i].Name)" -ForegroundColor White
    }
    
    $choice = Read-Host "Select backup to restore (1-$($backupFiles.Count))"
    $index = [int]$choice - 1
    
    if ($index -ge 0 -and $index -lt $backupFiles.Count) {
        try {
            $backupData = Get-Content -Path $backupFiles[$index].FullName -Raw | ConvertFrom-Json
            Save-License -License $backupData.License
            Write-Host "License restored successfully!" -ForegroundColor Green
        } catch {
            Write-Host "Failed to restore license: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "Invalid selection." -ForegroundColor Red
    }
}

function Show-HWIDManager {
    $currentLicense = Get-SavedLicense
    if ([string]::IsNullOrEmpty($currentLicense)) {
        Write-Host "No license found. Please activate first." -ForegroundColor Red
        return
    }
    
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                    HWID MANAGER                            ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    $hwid = Get-HWID
    Write-Host "Current Hardware ID: " -NoNewline -ForegroundColor Cyan
    Write-Host "$hwid" -ForegroundColor White
    Write-Host ""
    
    Write-Host "[1] View Full HWID" -ForegroundColor Yellow
    Write-Host "[2] Request HWID Reset" -ForegroundColor Yellow
    Write-Host "[3] Test HWID Validation" -ForegroundColor Yellow
    Write-Host "[4] Export HWID Info" -ForegroundColor Yellow
    Write-Host "[B] Back to Main Menu" -ForegroundColor Gray
    Write-Host ""
    
    $choice = Read-Host "Select option"
    
    switch ($choice) {
        '1' {
            Write-Host "`nFull Hardware ID: $hwid" -ForegroundColor White
            Write-Host "HWID Components:" -ForegroundColor Cyan
            try {
                $cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).ProcessorId
                $motherboard = (Get-CimInstance Win32_BaseBoard).SerialNumber
                $disk = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").VolumeSerialNumber
                
                Write-Host "  CPU ID: $cpu" -ForegroundColor Gray
                Write-Host "  Motherboard: $motherboard" -ForegroundColor Gray
                Write-Host "  Disk Serial: $disk" -ForegroundColor Gray
            } catch {
                Write-Host "  Error retrieving HWID components" -ForegroundColor Red
            }
        }
        '2' {
            Write-Host "`nRequesting HWID reset..." -ForegroundColor Yellow
            $result = Request-HWIDReset -License $currentLicense
            Write-Host (if ($result) { "✅ Reset request submitted" } else { "❌ Reset request failed" }) -ForegroundColor (if ($result) { "Green" } else { "Red" })
        }
        '3' {
            Write-Host "`nTesting HWID validation..." -ForegroundColor Yellow
            $result = Test-LicenseValidation -License $currentLicense
            Write-Host (if ($result) { "✅ HWID validation passed" } else { "❌ HWID validation failed" }) -ForegroundColor (if ($result) { "Green" } else { "Red" })
        }
        '4' {
            $exportPath = Join-Path $env:USERPROFILE "Desktop\HWID_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            @"
PC Optimizer Pro - HWID Export
Generated: $(Get-Date)
License: $(Get-SafePreview -Text $currentLicense)
Hardware ID: $hwid
"@ | Out-File -FilePath $exportPath -Encoding UTF8
            Write-Host "`nHWID info exported to: $exportPath" -ForegroundColor Green
        }
    }
    
    if ($choice -ne 'B') {
        Read-Host "`nPress Enter to continue"
    }
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
    Write-Host "[7] License Dashboard" -ForegroundColor Yellow
    Write-Host "[8] Batch License Checker" -ForegroundColor Yellow
    Write-Host "[9] HWID Manager" -ForegroundColor Yellow
    Write-Host "[B] Backup License Data" -ForegroundColor Yellow
    Write-Host "[R] Restore License Data" -ForegroundColor Yellow
    Write-Host "[H] Start Health Monitor" -ForegroundColor Yellow
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
    $hwid = Get-HWID
    $hwidPreview = Get-SafePreview -Text $hwid -Length 8
    Write-Host "Hardware ID: $hwidPreview" -ForegroundColor Cyan
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
            '7' {
                $currentLicense = Get-SavedLicense
                if ($currentLicense) {
                    Show-LicenseDashboard -License $currentLicense
                } else {
                    Write-Host "No license found." -ForegroundColor Red
                }
                Read-Host "Press Enter to continue"
            }
            '8' {
                Invoke-BatchLicenseCheck
                Read-Host "Press Enter to continue"
            }
            '9' {
                Show-HWIDManager
            }
            'B' {
                Write-Host "Creating license backup..." -ForegroundColor Yellow
                $result = Backup-LicenseData
                Write-Host (if ($result) { "✅ Backup created successfully" } else { "❌ Backup failed" }) -ForegroundColor (if ($result) { "Green" } else { "Red" })
                Read-Host "Press Enter to continue"
            }
            'R' {
                Write-Host "Restoring license data..." -ForegroundColor Yellow
                Restore-LicenseData
                Read-Host "Press Enter to continue"
            }
            'H' {
                $currentLicense = Get-SavedLicense
                if ($currentLicense) {
                    Write-Host "Starting license health monitor..." -ForegroundColor Yellow
                    Write-Host "Press Ctrl+C to stop monitoring" -ForegroundColor Gray
                    Start-LicenseHealthCheck -License $currentLicense -IntervalMinutes 5
                } else {
                    Write-Host "No license found." -ForegroundColor Red
                    Read-Host "Press Enter to continue"
                }
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
