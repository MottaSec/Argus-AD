#
# Argus-AD.ps1
# Main script for Argus-AD
#
# Copyright (c) 2025 MottaSec
#

param (
    [Parameter(Mandatory=$false)]
    [string]$DomainName,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipSimpleMisconfigurations,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipPrivilegeEscalation,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipLateralMovement,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipHybridAD,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\reports"
)

# Check if ActiveDirectory module is available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "The ActiveDirectory module is required to run Argus-AD." -ForegroundColor Red
    Write-Host "Please install the RSAT tools or run the Install-ArgusAD.ps1 script." -ForegroundColor Yellow
    exit
}

# Import the module
$moduleImported = $false

# First check if it's installed in the standard location
if (Get-Module -ListAvailable -Name MottaSec-ArgusAD) {
    Import-Module -Name MottaSec-ArgusAD -Force
    $moduleImported = $true
}
# Otherwise, try importing from the local path
else {
    $localModulePath = Join-Path -Path $PSScriptRoot -ChildPath "src\MottaSec-ArgusAD.psd1"
    
    if (Test-Path -Path $localModulePath) {
        Import-Module -Name $localModulePath -Force
        $moduleImported = $true
    }
}

if (-not $moduleImported) {
    Write-Host "Failed to import the MottaSec-ArgusAD module." -ForegroundColor Red
    Write-Host "Please run the Install-ArgusAD.ps1 script or ensure the module files are in the correct location." -ForegroundColor Yellow
    exit
}

# Build the parameter hashtable for splatting
$parameters = @{}

if ($PSBoundParameters.ContainsKey('DomainName')) {
    $parameters['DomainName'] = $DomainName
}

if ($PSBoundParameters.ContainsKey('OutputPath')) {
    $parameters['OutputPath'] = $OutputPath
}

if ($SkipSimpleMisconfigurations) {
    $parameters['SkipSimpleMisconfigurations'] = $true
}

if ($SkipPrivilegeEscalation) {
    $parameters['SkipPrivilegeEscalation'] = $true
}

if ($SkipLateralMovement) {
    $parameters['SkipLateralMovement'] = $true
}

if ($SkipHybridAD) {
    $parameters['SkipHybridAD'] = $true
}

# Run Argus-AD
Invoke-ArgusAD @parameters 