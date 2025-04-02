#
# MottaSec-Report.psm1
# Reporting Module for Argus-AD
#
# Copyright (c) 2025 MottaSec
#

function New-MottaSecReport {
    <#
    .SYNOPSIS
        Generates reports from Argus-AD scan findings.
    
    .DESCRIPTION
        Creates HTML and CSV reports based on the findings from all scans.
    
    .PARAMETER ResultsArray
        Array of finding objects from all scans.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo.
    
    .PARAMETER ScanStartTime
        The time when the scan started.
    
    .PARAMETER FailedChecks
        Array of check names that failed to complete successfully.
    
    .PARAMETER OutputPath
        Output directory for reports.
    
    .OUTPUTS
        Path to the generated report directory.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [array]$ResultsArray,
        
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo,
        
        [Parameter(Mandatory=$true)]
        [DateTime]$ScanStartTime,
        
        [Parameter(Mandatory=$false)]
        [array]$FailedChecks = @(),
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "$PSScriptRoot\..\..\reports"
    )
    
    Write-Host "[*] Generating Argus-AD reports..." -ForegroundColor Cyan
    
    # Create report directory
    $reportTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $reportDir = "$OutputPath\_$reportTime"
    
    if (-not (Test-Path -Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }
    
    # Copy the logo to the report directory
    $logoSource = "$PSScriptRoot\..\..\src\assets\argus-logo.svg"
    $logoDestination = "$reportDir\argus-logo.svg"
    if (Test-Path -Path $logoSource) {
        Copy-Item -Path $logoSource -Destination $logoDestination -Force | Out-Null
    }
    else {
        Write-Warning "Could not find logo at $logoSource"
    }
    
    # Get scan duration
    $scanDuration = (Get-Date) - $ScanStartTime
    $scanDurationFormatted = $scanDuration.ToString('hh\:mm\:ss')
    
    # Count findings by severity
    $criticalCount = ($ResultsArray | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = ($ResultsArray | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = ($ResultsArray | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = ($ResultsArray | Where-Object { $_.Severity -eq "Low" }).Count
    $infoCount = ($ResultsArray | Where-Object { $_.Severity -eq "Informational" -and -not $_.FailedCheck }).Count
    
    # Count findings by category
    $simpleMisconfigCount = ($ResultsArray | Where-Object { $_.Category -eq "SimpleMisconfigurations" }).Count
    $privEscCount = ($ResultsArray | Where-Object { $_.Category -eq "PrivilegeEscalation" }).Count
    $lateralMovementCount = ($ResultsArray | Where-Object { $_.Category -eq "LateralMovement" }).Count
    $hybridADCount = ($ResultsArray | Where-Object { $_.Category -eq "HybridAD" }).Count
    
    # Generate HTML report
    $htmlReportPath = "$reportDir\Argus-AD_Report.html"
    $htmlTemplate = Get-MottaSecHTMLReportTemplate
    
    # Replace placeholders
    $htmlContent = $htmlTemplate
    $htmlContent = $htmlContent.Replace('{{DOMAIN_NAME}}', $DomainInfo.DomainName)
    $htmlContent = $htmlContent.Replace('{{DOMAIN_NETBIOS}}', $DomainInfo.DomainNetBIOSName)
    $htmlContent = $htmlContent.Replace('{{SCAN_DATE}}', $ScanStartTime.ToString("yyyy-MM-dd HH:mm:ss"))
    $htmlContent = $htmlContent.Replace('{{SCAN_DURATION}}', $scanDurationFormatted)
    $htmlContent = $htmlContent.Replace('{{DC_COUNT}}', $DomainInfo.DomainControllers.Count)
    $htmlContent = $htmlContent.Replace('{{DOMAIN_LEVEL}}', $DomainInfo.DomainFunctionalLevel)
    $htmlContent = $htmlContent.Replace('{{FOREST_NAME}}', $DomainInfo.ForestName)
    
    # Stats
    $htmlContent = $htmlContent.Replace('{{CRITICAL_COUNT}}', $criticalCount)
    $htmlContent = $htmlContent.Replace('{{HIGH_COUNT}}', $highCount)
    $htmlContent = $htmlContent.Replace('{{MEDIUM_COUNT}}', $mediumCount)
    $htmlContent = $htmlContent.Replace('{{LOW_COUNT}}', $lowCount)
    $htmlContent = $htmlContent.Replace('{{INFO_COUNT}}', $infoCount)
    
    $htmlContent = $htmlContent.Replace('{{SIMPLE_MISCONFIG_COUNT}}', $simpleMisconfigCount)
    $htmlContent = $htmlContent.Replace('{{PRIVESC_COUNT}}', $privEscCount)
    $htmlContent = $htmlContent.Replace('{{LATERAL_MOVEMENT_COUNT}}', $lateralMovementCount)
    $htmlContent = $htmlContent.Replace('{{HYBRID_AD_COUNT}}', $hybridADCount)
    
    # AAD Connect info
    $aadConnectStatus = if ($DomainInfo.IsAzureADConnectConfigured) { "Detected" } else { "Not Detected" }
    $htmlContent = $htmlContent.Replace('{{AAD_CONNECT_STATUS}}', $aadConnectStatus)
    
    # Add failed checks warning if applicable
    $failedChecksWarning = ""
    if ($FailedChecks.Count -gt 0) {
        $failedChecksWarning = @"
<div class="warning-alert">
    <h3>⚠️ Warning: Some checks failed to complete</h3>
    <p>The following checks did not complete successfully:</p>
    <ul>
"@
        foreach ($failedCheck in $FailedChecks) {
            $failedChecksWarning += "<li>$failedCheck</li>"
        }
        
        $failedChecksWarning += @"
    </ul>
    <p>Some security issues may not have been detected due to these failures.</p>
</div>
"@
    }
    $htmlContent = $htmlContent.Replace('{{FAILED_CHECKS_WARNING}}', $failedChecksWarning)
    
    # Generate findings HTML
    $findingsHTML = ""
    
    # Group findings by category
    $findingsByCategory = $ResultsArray | Where-Object { -not $_.FailedCheck } | Group-Object -Property Category
    
    foreach ($category in $findingsByCategory) {
        $categoryName = $category.Name
        $categoryDisplayName = switch ($categoryName) {
            "SimpleMisconfigurations" { "Simple Misconfigurations" }
            "PrivilegeEscalation" { "Privilege Escalation Paths" }
            "LateralMovement" { "Lateral Movement Opportunities" }
            "HybridAD" { "Hybrid/Cloud AD Issues" }
            default { $categoryName }
        }
        
        $findingsHTML += "<div class='category-section'><h2>$categoryDisplayName</h2>"
        
        # Group by subcategory within this category
        $findingsBySubcategory = $category.Group | Group-Object -Property Subcategory
        
        foreach ($subcategory in $findingsBySubcategory) {
            $subcategoryName = $subcategory.Name
            $finding = $subcategory.Group[0] # Take the first finding in this subcategory
            
            $severityClass = "severity-$($finding.Severity.ToLower())"
            
            $findingsHTML += @"
<div class="finding-card">
    <div class="finding-header $severityClass">
        <span class="severity-badge">$($finding.Severity)</span>
        <h3>$subcategoryName</h3>
    </div>
    <div class="finding-content">
        <p><strong>Description:</strong> $($finding.Description)</p>
        <p><strong>Impact:</strong> $($finding.Impact)</p>
        <p><strong>AEGIS-AD Remediation:</strong> $($finding.AegisRemediation)</p>
    </div>
</div>
"@
        }
        
        $findingsHTML += "</div>"
    }
    
    # Add failed checks section if there are any
    if ($FailedChecks.Count -gt 0) {
        $findingsHTML += "<div class='category-section'><h2>Scan Status Issues</h2>"
        
        # Get the failed check findings
        $failedCheckFindings = $ResultsArray | Where-Object { $_.FailedCheck }
        
        foreach ($finding in $failedCheckFindings) {
            $findingsHTML += @"
<div class="finding-card">
    <div class="finding-header severity-informational">
        <span class="severity-badge">Failed Check</span>
        <h3>$($finding.Subcategory)</h3>
    </div>
    <div class="finding-content">
        <p><strong>Description:</strong> $($finding.Description)</p>
        <p><strong>Impact:</strong> $($finding.Impact)</p>
        <p><strong>Recommendation:</strong> $($finding.AegisRemediation)</p>
    </div>
</div>
"@
        }
        
        $findingsHTML += "</div>"
    }
    
    $htmlContent = $htmlContent.Replace('{{FINDINGS_CONTENT}}', $findingsHTML)
    
    # Write HTML report
    $htmlContent | Out-File -FilePath $htmlReportPath -Encoding utf8
    
    # Generate CSV report
    $csvReportPath = "$reportDir\Argus-AD_Report.csv"
    $ResultsArray | Select-Object Category, Subcategory, Severity, Description, Impact, AegisRemediation |
        Export-Csv -Path $csvReportPath -NoTypeInformation
    
    # Generate executive summary
    $execSummaryPath = "$reportDir\Argus-AD_ExecutiveSummary.txt"
    $execSummary = @"
Argus-AD Security Assessment - Executive Summary
===============================================

Domain: $($DomainInfo.DomainName)
Scan Date: $($ScanStartTime.ToString("yyyy-MM-dd HH:mm:ss"))
Scan Duration: $scanDurationFormatted

FINDINGS SUMMARY
===============
Total Issues Found: $($ResultsArray.Count)

By Severity:
- Critical: $criticalCount
- High: $highCount
- Medium: $mediumCount
- Low: $lowCount
- Informational: $infoCount

By Category:
- Simple Misconfigurations: $simpleMisconfigCount
- Privilege Escalation Paths: $privEscCount
- Lateral Movement Opportunities: $lateralMovementCount
- Hybrid/Cloud AD Issues: $hybridADCount
"@

    # Add failed checks section to executive summary if applicable
    if ($FailedChecks.Count -gt 0) {
        $execSummary += @"

SCAN COMPLETION STATUS
=====================
Warning: The following checks did not complete successfully:
"@

        foreach ($failedCheck in $FailedChecks) {
            $execSummary += @"
- $failedCheck
"@
        }

        $execSummary += @"
Some security issues may not have been detected due to these failures.
"@
    }

    $execSummary += @"

TOP CRITICAL/HIGH FINDINGS
========================
"@
    
    # Add top 5 critical/high findings
    $topFindings = $ResultsArray | Where-Object { ($_.Severity -eq "Critical" -or $_.Severity -eq "High") -and -not $_.FailedCheck } | Select-Object -First 5
    
    foreach ($finding in $topFindings) {
        $execSummary += @"

[$($finding.Severity)] $($finding.Subcategory)
Description: $($finding.Description)
"@
    }
    
    $execSummary += @"

NEXT STEPS
=========
The findings in this report indicate several security issues that need to be addressed.
For assistance in remediating these issues, contact MottaSec to learn about AEGIS-AD,
our comprehensive Active Directory security hardening solution.

Contact: info@mottasec.com
"@
    
    # Write executive summary
    $execSummary | Out-File -FilePath $execSummaryPath -Encoding utf8
    
    # Write files
    Set-Content -Path $htmlReportPath -Value $htmlContent
    Export-Csv -Path $csvReportPath -InputObject $reportData -NoTypeInformation
    Set-Content -Path $execSummaryPath -Value $executiveSummary
    
    Write-Host "[+] Reports generated successfully:" -ForegroundColor Green
    Write-Host "    - Executive Summary: $execSummaryPath" -ForegroundColor Cyan
    Write-Host "    - CSV Report: $csvReportPath" -ForegroundColor Cyan
    Write-Host "    - HTML Report: $htmlReportPath" -ForegroundColor Cyan
    
    # Return an object with the report paths
    return [PSCustomObject]@{
        ReportPath = $reportDir
        SummaryPath = $execSummaryPath
        CSVPath = $csvReportPath
        HTMLPath = $htmlReportPath
    }
}

function Get-MottaSecHTMLReportTemplate {
    <#
    .SYNOPSIS
        Returns the HTML template for Argus-AD reports.
    #>
    return @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Argus-AD Security Assessment Report</title>
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --accent-color: #e67e22;
            --light-color: #ecf0f1;
            --dark-color: #34495e;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --info-color: #3498db;
            --critical-color: #c0392b;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }
        
        .container {
            width: 95%;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background-color: var(--primary-color);
            color: white;
            padding: 20px 0;
            margin-bottom: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .header-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 20px;
        }
        
        .logo-title {
            display: flex;
            align-items: center;
        }
        
        .logo {
            width: 60px;
            height: 60px;
            margin-right: 15px;
        }
        
        h1 {
            margin: 0;
            font-size: 1.8em;
        }
        
        .timestamp {
            text-align: right;
            font-size: 0.9em;
        }
        
        .summary-section {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            flex: 1;
            min-width: 250px;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .summary-title {
            margin-top: 0;
            color: var(--primary-color);
            border-bottom: 2px solid var(--secondary-color);
            padding-bottom: 10px;
        }
        
        .domain-info {
            display: flex;
            flex-wrap: wrap;
        }
        
        .domain-info div {
            flex: 1;
            min-width: 200px;
            margin-bottom: 15px;
        }
        
        .domain-info strong {
            color: var(--dark-color);
        }
        
        .severity-stats {
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .severity-item {
            text-align: center;
            padding: 10px;
            flex: 1;
            min-width: 70px;
            border-radius: 4px;
            color: white;
        }
        
        .severity-critical {
            background-color: var(--critical-color);
        }
        
        .severity-high {
            background-color: var(--danger-color);
        }
        
        .severity-medium {
            background-color: var(--warning-color);
        }
        
        .severity-low {
            background-color: var(--info-color);
        }
        
        .severity-informational {
            background-color: #7f8c8d;
        }
        
        .category-stats {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .category-item {
            flex: 1;
            min-width: 140px;
            padding: 10px;
            background-color: var(--secondary-color);
            color: white;
            border-radius: 4px;
            text-align: center;
        }
        
        .findings-section {
            margin-top: 30px;
        }
        
        .category-section {
            margin-bottom: 30px;
        }
        
        .category-section h2 {
            color: var(--primary-color);
            border-bottom: 2px solid var(--secondary-color);
            padding-bottom: 10px;
        }
        
        .finding-card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .finding-header {
            padding: 15px;
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .finding-header h3 {
            margin: 0;
            font-size: 1.2em;
        }
        
        .severity-badge {
            background-color: rgba(255, 255, 255, 0.2);
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: bold;
        }
        
        .finding-content {
            padding: 15px;
        }
        
        .finding-content p {
            margin: 10px 0;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            background-color: var(--primary-color);
            color: white;
            border-radius: 8px;
        }
        
        .footer a {
            color: var(--light-color);
        }
        
        .contact-info {
            margin-top: 20px;
            padding: 15px;
            border-radius: 8px;
            color: white;
            text-align: center;
            background-color: var(--accent-color);
        }
        
        .warning-alert {
            background-color: var(--warning-color);
            color: white;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .warning-alert h3 {
            margin-top: 0;
        }
        
        .warning-alert ul {
            margin-bottom: 0;
        }

        @media (max-width: 768px) {
            .header-content {
                flex-direction: column;
                text-align: center;
            }
            
            .logo-title {
                margin-bottom: 15px;
            }
            
            .timestamp {
                text-align: center;
            }
            
            .severity-item, .category-item {
                min-width: 80px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <div class="logo-title">
                    <img src="argus-logo.svg" class="logo" alt="Argus-AD Logo">
                    <div>
                        <h1>Argus-AD Security Assessment</h1>
                        <p>Comprehensive Active Directory Security Report</p>
                    </div>
                </div>
                <div class="timestamp">
                    <p>Scan Date: {{SCAN_DATE}}</p>
                    <p>Scan Duration: {{SCAN_DURATION}}</p>
                </div>
            </div>
        </div>
        
        {{FAILED_CHECKS_WARNING}}
        
        <div class="summary-section">
            <div class="summary-card">
                <h2 class="summary-title">Domain Information</h2>
                <div class="domain-info">
                    <div>
                        <p><strong>Domain Name:</strong> {{DOMAIN_NAME}}</p>
                        <p><strong>NetBIOS Name:</strong> {{DOMAIN_NETBIOS}}</p>
                    </div>
                    <div>
                        <p><strong>Domain Controllers:</strong> {{DC_COUNT}}</p>
                        <p><strong>Functional Level:</strong> {{DOMAIN_LEVEL}}</p>
                    </div>
                    <div>
                        <p><strong>Forest:</strong> {{FOREST_NAME}}</p>
                        <p><strong>Azure AD Connect:</strong> {{AAD_CONNECT_STATUS}}</p>
                    </div>
                </div>
            </div>
            
            <div class="summary-card">
                <h2 class="summary-title">Findings by Severity</h2>
                <div class="severity-stats">
                    <div class="severity-item severity-critical">
                        <div class="severity-count">{{CRITICAL_COUNT}}</div>
                        <div>Critical</div>
                    </div>
                    <div class="severity-item severity-high">
                        <div class="severity-count">{{HIGH_COUNT}}</div>
                        <div>High</div>
                    </div>
                    <div class="severity-item severity-medium">
                        <div class="severity-count">{{MEDIUM_COUNT}}</div>
                        <div>Medium</div>
                    </div>
                    <div class="severity-item severity-low">
                        <div class="severity-count">{{LOW_COUNT}}</div>
                        <div>Low</div>
                    </div>
                    <div class="severity-item severity-informational">
                        <div class="severity-count">{{INFO_COUNT}}</div>
                        <div>Info</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="summary-section">
            <div class="summary-card">
                <h2 class="summary-title">Findings by Category</h2>
                <div class="category-stats">
                    <div class="category-item">
                        <div class="category-count">{{SIMPLE_MISCONFIG_COUNT}}</div>
                        <div>Simple Misconfigurations</div>
                    </div>
                    <div class="category-item">
                        <div class="category-count">{{PRIVESC_COUNT}}</div>
                        <div>Privilege Escalation</div>
                    </div>
                    <div class="category-item">
                        <div class="category-count">{{LATERAL_MOVEMENT_COUNT}}</div>
                        <div>Lateral Movement</div>
                    </div>
                    <div class="category-item">
                        <div class="category-count">{{HYBRID_AD_COUNT}}</div>
                        <div>Hybrid/Cloud AD</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="contact-info">
            <h3>Need help securing your Active Directory?</h3>
            <p>Contact MottaSec to learn about AEGIS-AD, our comprehensive Active Directory security hardening solution.</p>
        </div>
        
        <div class="findings-section">
            <h2>Detailed Findings</h2>
            
            {{FINDINGS_CONTENT}}
        </div>
        
        <div class="footer">
            <p>Generated by Argus-AD - The Active Directory Security Assessment Tool</p>
            <p>© 2025 MottaSec - <a href="https://github.com/MottaSec/Argus-AD">https://github.com/MottaSec/Argus-AD</a></p>
        </div>
    </div>
</body>
</html>
"@
}

# Export functions
Export-ModuleMember -Function New-MottaSecReport 