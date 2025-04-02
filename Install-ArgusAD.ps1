#
# Install-ArgusAD.ps1
# Installation script for Argus-AD
#
# Copyright (c) 2025 MottaSec
#

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}

Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "              Argus-AD Installation" -ForegroundColor Cyan
Write-Host "                   by MottaSec" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host ""

# Check PowerShell version
$psVersion = $PSVersionTable.PSVersion
Write-Host "[*] Checking PowerShell version..." -ForegroundColor Cyan
if ($psVersion.Major -lt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -lt 1)) {
    Write-Host "[!] PowerShell 5.1 or later is required. Current version: $($psVersion.ToString())" -ForegroundColor Red
    exit
}
Write-Host "[+] PowerShell version $($psVersion.ToString()) is supported." -ForegroundColor Green

# Check for ActiveDirectory module
Write-Host "[*] Checking for ActiveDirectory module..." -ForegroundColor Cyan
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "[!] ActiveDirectory module not found. Installing..." -ForegroundColor Yellow
    
    try {
        # Check if RSAT is installed
        $rsatStatus = Get-WindowsCapability -Name Rsat.ActiveDirectory* -Online
        
        if ($rsatStatus.State -ne "Installed") {
            Write-Host "[*] Installing Remote Server Administration Tools (RSAT) for Active Directory..." -ForegroundColor Cyan
            Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online
            
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to install RSAT tools"
            }
            
            Write-Host "[+] RSAT tools installed successfully." -ForegroundColor Green
        }
        else {
            Write-Host "[+] RSAT tools are already installed." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[!] Failed to install ActiveDirectory module. Please install RSAT tools manually." -ForegroundColor Red
        Write-Host "    More information: https://docs.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools" -ForegroundColor Yellow
        exit
    }
}
else {
    Write-Host "[+] ActiveDirectory module is available." -ForegroundColor Green
}

# Create module directory if it doesn't exist
$modulePath = "$env:ProgramFiles\WindowsPowerShell\Modules\MottaSec-ArgusAD"

if (-not (Test-Path -Path $modulePath)) {
    Write-Host "[*] Creating module directory..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $modulePath -Force | Out-Null
    Write-Host "[+] Module directory created at $modulePath" -ForegroundColor Green
}
else {
    Write-Host "[*] Module directory already exists. Updating..." -ForegroundColor Cyan
}

# Copy files to module directory
Write-Host "[*] Copying files to module directory..." -ForegroundColor Cyan
Copy-Item -Path ".\src\*" -Destination $modulePath -Recurse -Force
Write-Host "[+] Files copied successfully." -ForegroundColor Green

# Create reports directory if it doesn't exist
$reportsPath = "$modulePath\reports"
if (-not (Test-Path -Path $reportsPath)) {
    Write-Host "[*] Creating reports directory..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $reportsPath -Force | Out-Null
    Write-Host "[+] Reports directory created." -ForegroundColor Green
}

# Import the module to verify installation
Write-Host "[*] Verifying installation..." -ForegroundColor Cyan
Import-Module -Name MottaSec-ArgusAD -Force

if (Get-Command -Name Invoke-ArgusAD -ErrorAction SilentlyContinue) {
    Write-Host "[+] Argus-AD installed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can now run Argus-AD using the command: Invoke-ArgusAD" -ForegroundColor White
    Write-Host ""
    Write-Host "For more information, visit: https://github.com/MottaSec/Argus-AD" -ForegroundColor White
}
else {
    Write-Host "[!] Installation verification failed. Please check for errors." -ForegroundColor Red
}

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "          Installation Complete - Thank You!" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan 