#
# MottaSec-ArgusAD.psm1
# Main module file for Argus-AD
#
# Copyright (c) 2025 MottaSec
#

# Import required modules
try {
    # Try to import ActiveDirectory, but don't fail if it's not available
    # This will be intercepted by our mock module in the test environment
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module -Name ActiveDirectory -ErrorAction SilentlyContinue
    } else {
        Write-Verbose "ActiveDirectory module not available - mock version should be used in test environment"
    }
} catch {
    Write-Warning "Error importing ActiveDirectory module: $_"
}

# Import all Argus-AD modules
$moduleFiles = @(
    "MottaSec-Common.psm1",
    "MottaSec-DomainInfo.psm1",
    "MottaSec-SimpleConfig.psm1",
    "MottaSec-PrivEsc.psm1",
    "MottaSec-LateralMovement.psm1",
    "MottaSec-HybridAD.psm1",
    "MottaSec-Report.psm1",
    "MottaSec-Core.psm1"
)

foreach ($file in $moduleFiles) {
    $modulePath = Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath "modules") -ChildPath $file
    if (Test-Path -Path $modulePath) {
        Import-Module $modulePath -Force -Global
    }
    else {
        Write-Warning "Module file not found: $modulePath"
    }
}

function Invoke-ArgusAD {
    <#
    .SYNOPSIS
        Performs an Active Directory security assessment.
    
    .DESCRIPTION
        Argus-AD is an Active Directory security assessment tool designed for SYSADMINs and IT Admins. 
        It scans AD for misconfigurations, privilege escalation paths, and lateral movement opportunities.
    
    .PARAMETER DomainName
        Optional. The domain to scan. If not specified, the current domain is used.
    
    .PARAMETER SkipSimpleMisconfigurations
        Switch to skip the Simple Misconfigurations scan.
    
    .PARAMETER SkipPrivilegeEscalation
        Switch to skip the Privilege Escalation Paths scan.
    
    .PARAMETER SkipLateralMovement
        Switch to skip the Lateral Movement Opportunities scan.
    
    .PARAMETER SkipHybridAD
        Switch to skip the Hybrid/Cloud AD Issues scan.
    
    .PARAMETER OutputPath
        Optional. The path where reports should be saved. Defaults to './reports'.
    
    .EXAMPLE
        Invoke-ArgusAD
        
        Runs a full AD security assessment on the current domain.
    
    .EXAMPLE
        Invoke-ArgusAD -DomainName "contoso.com" -SkipHybridAD
        
        Runs an AD security assessment on contoso.com, skipping the Hybrid/Cloud AD Issues scan.
    #>
    [CmdletBinding()]
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
    
    $scanStartTime = Get-Date
    # Array to track failed checks
    $failedChecks = @()
    
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host "              Argus-AD Security Assessment Tool" -ForegroundColor Cyan
    Write-Host "                         by MottaSec" -ForegroundColor Cyan
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Create reports directory if it doesn't exist
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Display scan modules that will be run
    Write-Host "Scan modules to be executed:" -ForegroundColor Cyan
    Write-Host ""
    
    # Create a checklist of modules
    $modules = @{
        "SimpleMisconfigurations" = @{
            "Name" = "Simple Misconfigurations Scan"
            "Enabled" = (-not $SkipSimpleMisconfigurations) 
            "Status" = "Pending"
            "Findings" = 0
            "HasCritical" = $false
            "HasHigh" = $false
        }
        "PrivilegeEscalation" = @{
            "Name" = "Privilege Escalation Paths Scan"
            "Enabled" = (-not $SkipPrivilegeEscalation)
            "Status" = "Pending"
            "Findings" = 0
            "HasCritical" = $false
            "HasHigh" = $false
        }
        "LateralMovement" = @{
            "Name" = "Lateral Movement Opportunities Scan"
            "Enabled" = (-not $SkipLateralMovement)
            "Status" = "Pending"
            "Findings" = 0
            "HasCritical" = $false
            "HasHigh" = $false
        }
        "HybridAD" = @{
            "Name" = "Hybrid/Cloud AD Issues Scan"
            "Enabled" = (-not $SkipHybridAD)
            "Status" = "Pending"
            "Findings" = 0
            "HasCritical" = $false
            "HasHigh" = $false
        }
    }
    
    # Display initial checklist
    foreach ($key in $modules.Keys) {
        $module = $modules[$key]
        $status = if ($module.Enabled) { "[ ] Pending" } else { "[X] Skipped" }
        Write-Host "$status - $($module.Name)" -ForegroundColor $(if ($module.Enabled) { "White" } else { "Gray" })
    }
    Write-Host ""
    
    # 1. Gather domain information
    try {
        Write-Host "Gathering domain information..." -ForegroundColor Cyan
        $domainInfo = Get-MottaSecDomainInfo -DomainName $DomainName
        Write-Host "Domain information gathered successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Error gathering domain information: ${_}" -ForegroundColor Red
        $failedChecks += "Domain Information Gathering"
        Write-Host "Continuing with scan despite domain information errors..." -ForegroundColor Yellow
        # Create minimal domain info if failed
        $domainInfo = @{
            DomainName = if ($DomainName) { $DomainName } else { "Unknown" }
            NetBIOSName = "Unknown"
        }
    }
    Write-Host ""
    
    # All findings across all scans
    $allFindings = @()
    
    # Function to update and display module status
    function Update-ModuleStatus {
        param (
            [string]$ModuleKey,
            [string]$Status,
            [array]$Findings
        )
        
        $modules[$ModuleKey].Status = $Status
        $modules[$ModuleKey].Findings = $Findings.Count
        $modules[$ModuleKey].HasCritical = ($Findings | Where-Object { $_.Severity -eq "Critical" }).Count -gt 0
        $modules[$ModuleKey].HasHigh = ($Findings | Where-Object { $_.Severity -eq "High" }).Count -gt 0
        
        # Clear the console line
        Write-Host "`r                                                                               " -NoNewline
        
        # Display updated checklist
        Write-Host "`r" -NoNewline
        foreach ($key in $modules.Keys) {
            $module = $modules[$key]
            if (-not $module.Enabled) {
                Write-Host "[X] Skipped - $($module.Name)" -ForegroundColor Gray
                continue
            }
            
            $statusIcon = switch ($module.Status) {
                "Pending" { "[ ]" }
                "Running" { "[.]" }
                "Completed" { "[+]" }
                "Failed" { "[!]" }
                default { "[ ]" }
            }
            
            $statusColor = switch ($module.Status) {
                "Pending" { "White" }
                "Running" { "Yellow" }
                "Completed" { 
                    if ($module.HasCritical) { "Red" }
                    elseif ($module.HasHigh) { "DarkRed" }
                    elseif ($module.Findings -gt 0) { "Yellow" }
                    else { "Green" }
                }
                "Failed" { "Red" }
                default { "White" }
            }
            
            $statusMessage = switch ($module.Status) {
                "Completed" {
                    if ($module.Findings -eq 0) {
                        "Situation appears to be ok"
                    }
                    elseif ($module.HasCritical) {
                        "Situation is critical"
                    }
                    elseif ($module.HasHigh) {
                        "Situation is concerning"
                    }
                    else {
                        "Situation needs attention"
                    }
                }
                "Failed" { "Failed to complete scan" }
                default { "" }
            }
            
            $foundStr = if ($module.Findings -gt 0) { "($($module.Findings) findings)" } else { "" }
            Write-Host "$statusIcon $($module.Name) $foundStr $statusMessage" -ForegroundColor $statusColor
        }
    }
    
    # 2. Run Simple Misconfigurations scan
    if (-not $SkipSimpleMisconfigurations) {
        Write-Host "===============================================================" -ForegroundColor Cyan
        Write-Host "              Simple Misconfigurations Scan" -ForegroundColor Cyan
        Write-Host "===============================================================" -ForegroundColor Cyan
        
        $modules["SimpleMisconfigurations"].Status = "Running"
        Update-ModuleStatus -ModuleKey "SimpleMisconfigurations" -Status "Running" -Findings @()
        
        try {
            $simpleMisconfigFindings = Invoke-MottaSecSimpleConfigScan -DomainInfo $domainInfo
            $modules["SimpleMisconfigurations"].Status = "Completed"
            Update-ModuleStatus -ModuleKey "SimpleMisconfigurations" -Status "Completed" -Findings $simpleMisconfigFindings
            $allFindings += $simpleMisconfigFindings
        }
        catch {
            Write-Host "Error during Simple Misconfigurations scan: ${_}" -ForegroundColor Red
            $modules["SimpleMisconfigurations"].Status = "Failed"
            Update-ModuleStatus -ModuleKey "SimpleMisconfigurations" -Status "Failed" -Findings @()
            $failedChecks += "Simple Misconfigurations Scan"
        }
    }
    else {
        Write-Host "[*] Skipping Simple Misconfigurations scan as requested." -ForegroundColor Gray
    }
    
    # 3. Run Privilege Escalation Paths scan
    if (-not $SkipPrivilegeEscalation) {
        Write-Host "===============================================================" -ForegroundColor Cyan
        Write-Host "              Privilege Escalation Paths Scan" -ForegroundColor Cyan
        Write-Host "===============================================================" -ForegroundColor Cyan
        
        $modules["PrivilegeEscalation"].Status = "Running"
        Update-ModuleStatus -ModuleKey "PrivilegeEscalation" -Status "Running" -Findings @()
        
        try {
            $privEscFindings = Invoke-MottaSecPrivEscScan -DomainInfo $domainInfo
            $modules["PrivilegeEscalation"].Status = "Completed"
            Update-ModuleStatus -ModuleKey "PrivilegeEscalation" -Status "Completed" -Findings $privEscFindings
            $allFindings += $privEscFindings
        }
        catch {
            Write-Host "Error during Privilege Escalation Paths scan: ${_}" -ForegroundColor Red
            $modules["PrivilegeEscalation"].Status = "Failed"
            Update-ModuleStatus -ModuleKey "PrivilegeEscalation" -Status "Failed" -Findings @()
            $failedChecks += "Privilege Escalation Paths Scan"
        }
    }
    else {
        Write-Host "[*] Skipping Privilege Escalation Paths scan as requested." -ForegroundColor Gray
    }
    
    # 4. Run Lateral Movement Opportunities scan
    if (-not $SkipLateralMovement) {
        Write-Host "===============================================================" -ForegroundColor Cyan
        Write-Host "              Lateral Movement Opportunities Scan" -ForegroundColor Cyan
        Write-Host "===============================================================" -ForegroundColor Cyan
        
        $modules["LateralMovement"].Status = "Running"
        Update-ModuleStatus -ModuleKey "LateralMovement" -Status "Running" -Findings @()
        
        try {
            $lateralMovementFindings = Invoke-MottaSecLateralMovementScan -DomainInfo $domainInfo
            $modules["LateralMovement"].Status = "Completed"
            Update-ModuleStatus -ModuleKey "LateralMovement" -Status "Completed" -Findings $lateralMovementFindings
            $allFindings += $lateralMovementFindings
        }
        catch {
            Write-Host "Error during Lateral Movement Opportunities scan: ${_}" -ForegroundColor Red
            $modules["LateralMovement"].Status = "Failed"
            Update-ModuleStatus -ModuleKey "LateralMovement" -Status "Failed" -Findings @()
            $failedChecks += "Lateral Movement Opportunities Scan"
        }
    }
    else {
        Write-Host "[*] Skipping Lateral Movement Opportunities scan as requested." -ForegroundColor Gray
    }
    
    # 5. Run Hybrid/Cloud AD Issues scan
    if (-not $SkipHybridAD) {
        Write-Host "===============================================================" -ForegroundColor Cyan
        Write-Host "              Hybrid/Cloud AD Issues Scan" -ForegroundColor Cyan
        Write-Host "===============================================================" -ForegroundColor Cyan
        
        $modules["HybridAD"].Status = "Running"
        Update-ModuleStatus -ModuleKey "HybridAD" -Status "Running" -Findings @()
        
        try {
            $hybridADFindings = Invoke-MottaSecHybridADScan -DomainInfo $domainInfo
            $modules["HybridAD"].Status = "Completed"
            Update-ModuleStatus -ModuleKey "HybridAD" -Status "Completed" -Findings $hybridADFindings
            $allFindings += $hybridADFindings
        }
        catch {
            Write-Host "Error during Hybrid/Cloud AD Issues scan: ${_}" -ForegroundColor Red
            $modules["HybridAD"].Status = "Failed"
            Update-ModuleStatus -ModuleKey "HybridAD" -Status "Failed" -Findings @()
            $failedChecks += "Hybrid/Cloud AD Issues Scan"
        }
    }
    else {
        Write-Host "[*] Skipping Hybrid/Cloud AD Issues scan as requested." -ForegroundColor Gray
    }
    
    # 6. Generate reports
    try {
        Write-Host "===============================================================" -ForegroundColor Cyan
        Write-Host "                   Generating Reports" -ForegroundColor Cyan
        Write-Host "===============================================================" -ForegroundColor Cyan
        
        # Create timestamped report directory
        $reportDir = Join-Path -Path $OutputPath -ChildPath "_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
        
        # Generate reports
        Write-Host "[*] Generating Argus-AD reports..." -ForegroundColor Cyan
        
        # Call the reporting module
        $reportResult = New-MottaSecReport -ResultsArray $allFindings -DomainInfo $domainInfo -ScanStartTime $scanStartTime -FailedChecks $failedChecks -OutputPath $reportDir
        
        Write-Host "[+] Reports generated successfully:" -ForegroundColor Green
        Write-Host "    - Executive Summary: $($reportResult.SummaryPath)" -ForegroundColor Cyan
        Write-Host "    - CSV Report: $($reportResult.CSVPath)" -ForegroundColor Cyan
        Write-Host "    - HTML Report: $($reportResult.HTMLPath)" -ForegroundColor Cyan
        
        Write-Host "Reports generated successfully." -ForegroundColor Green
        Write-Host ""
    }
    catch {
        Write-Host "Error generating reports: ${_}" -ForegroundColor Red
        $failedChecks += "Report Generation"
    }
    
    $scanEndTime = Get-Date
    $scanDuration = $scanEndTime - $scanStartTime
    $scanDurationFormatted = $scanDuration.ToString('hh\:mm\:ss')
    
    # 7. Summary
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host "                       Scan Summary" -ForegroundColor Cyan
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host "Domain: $($domainInfo.DomainName)" -ForegroundColor White
    Write-Host "Scan Duration: $scanDurationFormatted" -ForegroundColor White
    Write-Host ""
    
    # Count findings by severity
    $criticalCount = ($allFindings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = ($allFindings | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = ($allFindings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = ($allFindings | Where-Object { $_.Severity -eq "Low" }).Count
    $infoCount = ($allFindings | Where-Object { $_.Severity -eq "Informational" -and -not $_.FailedCheck }).Count
    
    Write-Host "Total Issues Found: $($allFindings.Count)" -ForegroundColor White
    
    Write-Host "Severity Breakdown:" -ForegroundColor White
    Write-Host "  Critical:      $criticalCount" -ForegroundColor Red
    Write-Host "  High:          $highCount" -ForegroundColor DarkRed
    Write-Host "  Medium:        $mediumCount" -ForegroundColor Yellow
    Write-Host "  Low:           $lowCount" -ForegroundColor Blue
    Write-Host "  Informational: $infoCount" -ForegroundColor Gray
    
    # Report on failed checks if any
    if ($failedChecks.Count -gt 0) {
        Write-Host ""
        Write-Host "Warning: The following checks failed to complete:" -ForegroundColor Yellow
        foreach ($failedCheck in $failedChecks) {
            Write-Host "  - $failedCheck" -ForegroundColor Yellow
        }
        Write-Host "Some security issues may not have been detected. See logs for details." -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Thank you for using Argus-AD by MottaSec!" -ForegroundColor Cyan
    Write-Host "For remediation assistance, contact us about AEGIS-AD, our comprehensive AD security hardening solution." -ForegroundColor Cyan
    Write-Host "===============================================================" -ForegroundColor Cyan
    
    return [PSCustomObject]@{
        DomainInfo = $domainInfo
        Findings = $allFindings
        ReportPath = $reportDir
        ScanStartTime = $scanStartTime
        ScanEndTime = $scanEndTime
        ScanDuration = $scanDuration
    }
}

# Export module members
Export-ModuleMember -Function Invoke-ArgusAD 