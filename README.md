# PC Optimizer Pro v3.0 - PowerShell Edition

A comprehensive Windows system optimization and maintenance tool built entirely in PowerShell with premium licensing support. Enhance your PC's performance, clean system junk, and optimize gaming performance with an intuitive command-line interface.

![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)
![Windows](https://img.shields.io/badge/Windows-10%2F11-blue.svg)
![License](https://img.shields.io/badge/license-Freemium-green.svg)

## 🚀 Features

### Free Version
- **System Information Tools**
  - Comprehensive system overview with hardware details
  - Real-time disk space analysis and file distribution
  - Network connectivity diagnostics and adapter status
  - Hardware component detection (CPU, GPU, RAM, Storage)

- **Basic Maintenance**
  - Temporary file cleanup (user and system temp directories)
  - Browser cache cleaner (Chrome, Firefox, Edge, IE)
  - Memory optimization and process management
  - Windows system health monitoring

- **Basic Gaming Mode**
  - High-performance power plan activation
  - Windows Game Mode enablement
  - Game DVR and Game Bar disabling
  - Visual effects optimization for performance

- **System Tools Integration**
  - Quick access to Task Manager, Services, Event Viewer
  - System Configuration (msconfig) launcher
  - Startup program management

### Premium Version
- **Advanced Cleaning**
  - Deep system cleanup with registry optimization
  - Privacy cleaner for enhanced data protection
  - Browser deep clean across all major browsers
  - Automated cleanup scheduling

- **Performance Boosters**
  - Gaming Mode Pro with advanced optimizations
  - FPS Booster Ultimate for maximum frame rates
  - RAM Optimizer Pro with intelligent memory management
  - CPU Manager Pro for workload prioritization

- **License Management**
  - Hardware ID (HWID) binding for security
  - Online license validation with offline fallback
  - Automatic license renewal checks

## 📋 Requirements

- **Operating System**: Windows 10/11 (64-bit recommended)
- **PowerShell**: Version 5.1 or higher
- **Permissions**: Administrator privileges required
- **Internet**: Required for license activation and validation

## 💻 Installation

### Method 1: Direct Download
Download the script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/TheGameisYash/PCoptimizer/main/PC-Optimizer-Pro.ps1" -OutFile "PC-Optimizer-Pro.ps1"

Run with administrator privileges
.\PC-Optimizer-Pro.ps1

text

### Method 2: Clone Repository
Clone the repository
git clone https://github.com/TheGameisYash/PCoptimizer.git
cd PCoptimizer

Execute the script
.\PC-Optimizer-Pro.ps1

text

### Method 3: Right-Click Run
1. Download `PC-Optimizer-Pro.ps1`
2. Right-click the file
3. Select "Run with PowerShell"
4. Accept administrator elevation prompt

## 🎮 Usage

### Running the Tool
The script automatically requests administrator privileges if not already elevated:

.\PC-Optimizer-Pro.ps1

text

### Free Version Menu Options
SYSTEM INFORMATION:

System Overview 2) Hardware Details

Disk Space Analysis 4) Network Status

BASIC MAINTENANCE:
5) Temp File Cleaner 6) Registry Scanner
7) System Health Check 8) Windows Update Check

SYSTEM TOOLS:
9) Task Manager 10) System Configuration
11) Services Manager 12) Event Viewer

BASIC OPTIMIZATION:
13) Basic Gaming Mode 14) Memory Cleaner
15) Startup Manager 16) Basic FPS Boost

LICENSE MANAGEMENT:
17) Activate Premium 18) View Logs

text

### Activating Premium License
1. Launch PC Optimizer Pro
2. Select option **17** (Activate Premium)
3. Enter your license key when prompted
4. Your Hardware ID will be automatically bound to the license
5. Enjoy premium features immediately

## 🔧 Configuration

The tool uses the following configuration:

SERVER_URL = "https://p-coptimizer-web.vercel.app"
LICENSE_FILE = "$env:ProgramData\pc_optimizer.lic"
LOG_FILE = "$env:TEMP\optimizer_log.txt"
BACKUP_DIR = "$env:ProgramData\PC_Optimizer_Backups"

text

## 🛡️ Safety Features

- **Automatic System Restore Points**: Created before major optimizations
- **Registry Backups**: Automatic backup creation before modifications
- **Offline Mode**: Premium features work offline after initial validation
- **Detailed Logging**: All operations logged to `%TEMP%\optimizer_log.txt`
- **Reversible Changes**: Most optimizations can be reversed

## 🔑 Hardware ID Detection

The tool uses multiple methods to generate a unique Hardware ID:

1. System UUID (Primary method)
2. Motherboard Serial Number
3. BIOS Serial Number
4. CPU Processor ID
5. Fallback generation (if all methods fail)

Your HWID is displayed in the main menu and required for premium activation.

## 📊 What Gets Cleaned

### Basic Cleanup
- User temporary files (`%TEMP%`)
- Windows temporary files (`C:\Windows\Temp`)
- Prefetch files
- Recent documents cache
- Windows error reports
- Delivery optimization cache
- Browser caches (Chrome, Firefox, Edge, IE)
- Network DNS cache
- System log files

### Premium Cleanup (Premium Only)
- Deep registry cleaning
- Privacy traces removal
- Advanced browser data cleanup
- System restore point management
- Windows update cache optimization

## 🎯 Gaming Optimizations

### Basic Gaming Mode
- Activates High Performance power plan
- Enables Windows Game Mode
- Disables Game DVR and Game Bar
- Optimizes visual effects for performance
- Disables notifications during gaming
- Enhances GPU and CPU priority for games

### Gaming Mode Pro (Premium)
- All basic optimizations
- Advanced thread prioritization
- Background process suspension
- Network traffic optimization
- Real-time CPU core assignment
- Memory page file optimization

## 📝 Logs and Monitoring

View detailed operation logs:
- Access logs via option **18** in the main menu
- Log location: `%TEMP%\optimizer_log.txt`
- Logs include timestamps, operation types, and results

## ⚠️ Troubleshooting

### Script Won't Run
Set execution policy (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

text

### License Activation Fails
- Verify internet connectivity
- Check firewall settings for PowerShell
- Ensure correct license key entry
- Contact support if issue persists

### Administrator Rights Required
- Right-click PowerShell and select "Run as Administrator"
- The script will auto-elevate on next run

## 🌐 Server Integration

The tool connects to the license server at:
https://p-coptimizer-web.vercel.app

text

API endpoints:
- `/api/validate` - License validation
- `/api/register` - License activation

## 📄 License

This project uses a freemium model:
- **Free Version**: Available for personal use
- **Premium Version**: Requires paid license key
- License keys are bound to Hardware ID (HWID)

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 🐛 Known Issues

- Some antivirus software may flag the script (false positive due to system modifications)
- HWID detection may fail on virtual machines
- Network timeout may occur on slow connections

## 📞 Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/TheGameisYash/PCoptimizer/issues)
- **License Support**: Contact through license server
- **Documentation**: Check the repository wiki

## 🔄 Version History

### v3.0 (Current)
- Pure PowerShell implementation (removed WMIC dependencies)
- Enhanced HWID detection with multiple fallback methods
- Improved UI with color-coded status messages
- Added comprehensive hardware information display
- Implemented automatic backup creation
- Enhanced gaming mode with profile creation

## ⚡ Performance

- **Startup Time**: ~1-2 seconds (PowerShell-native implementation)
- **Cleanup Speed**: 5-30 seconds depending on system size
- **Memory Usage**: ~50-100 MB during operation
- **Disk Space Recovered**: Typically 500 MB - 5 GB

## 🛠️ Technical Details

- **Language**: PowerShell 5.1+
- **Architecture**: Modular function-based design
- **WMI Alternative**: Uses CIM cmdlets for better performance
- **Error Handling**: Comprehensive try-catch blocks with logging
- **Compatibility**: Windows 10 (1809+), Windows 11

## 💡 Tips

- Run the tool monthly for optimal system performance
- Always review logs after cleanup operations
- Create manual restore points before major optimizations
- Keep Windows and drivers updated for best results
- Monitor system performance after gaming mode activation

## 🙏 Acknowledgments

- PowerShell Community for optimization techniques
- Windows API documentation
- Open-source contributors

---

**⚠️ Disclaimer**: This tool modifies system settings and files. Always create backups and use at your own risk. The author is not responsible for any system damage or data loss.

---

**Made with ❤️ by [TheGameisYash](https://github.com/TheGameisYash)**
