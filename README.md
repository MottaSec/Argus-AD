# Argus-AD

<img src="src/assets/argus-logo.svg" alt="Argus-AD Logo" width="200" align="right"/>

## Active Directory Security Assessment Tool

Argus-AD is a comprehensive Active Directory security assessment tool designed for SYSADMINs and IT Admins to identify misconfigurations, privilege escalation paths, lateral movement opportunities, and hybrid identity issues in their Active Directory environments.

[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)

## Overview

Named after the many-eyed giant from Greek mythology, Argus-AD helps you see security issues in your Active Directory environment that might otherwise go unnoticed. The tool is designed to be:

- **Non-intrusive**: Read-only assessment with no modifications to your environment
- **User-friendly**: Simple to run with clear, actionable reports
- **Comprehensive**: Checks for a wide range of AD security issues
- **Practical**: Provides meaningful context about why issues matter and references to how they can be fixed

## What Argus-AD Checks For

### 1. Simple Misconfigurations

This module identifies common Active Directory security misconfigurations that are easy targets for attackers:

- **Weak Password Policies**: Identifies password policies that don't meet industry standards (complexity, length, history, etc.)
- **Kerberos Weaknesses**: Finds accounts vulnerable to Kerberoasting and AS-REP Roasting
- **Dormant Accounts**: Locates inactive user and computer accounts that can be potential entry points
- **Privileged Account Issues**: Finds privileged accounts with improper password policies or protection measures
- **LAPS Implementation**: Checks if Local Administrator Password Solution is properly deployed
- **Domain Controller Security**: Assesses basic DC security settings for common vulnerabilities
- **Service Account Configuration**: Identifies service accounts with improper settings (privileges, expiration, etc.)
- **Weak Encryption Support**: Identifies support for deprecated or weak encryption protocols

### 2. Privilege Escalation Paths

This module discovers potential paths for attackers to elevate privileges within your domain:

- **Delegation Issues**: Identifies risky delegation configurations (unconstrained, constrained, resource-based)
- **ACL Weaknesses**: Finds improper permissions on AD objects that could enable privilege escalation
- **GPO Vulnerabilities**: Locates Group Policy Objects with weak permissions or dangerous configurations
- **Shadow Admin Rights**: Discovers non-obvious paths to administrative access through nested permissions
- **AdminSDHolder Issues**: Identifies problems with the AdminSDHolder protection mechanism
- **DCSync Capability**: Finds accounts with permissions to perform DCSync attacks
- **Certificate Template Vulnerabilities**: Identifies certificate templates with misconfigured settings that can enable privilege escalation

### 3. Lateral Movement Opportunities

This module identifies opportunities for attackers to move laterally within your network:

- **Tiered Administration Violations**: Detects violations of the Microsoft tiered administration model
- **Local Admin Rights**: Identifies excessive distribution of local administrator rights
- **Credential Caching**: Evaluates credential caching configurations that could enable credential theft
- **Privileged Authentication**: Assesses how privileged accounts authenticate across systems
- **NTLM Relay Opportunities**: Identifies configurations that could enable NTLM relay attacks
- **Session Security**: Evaluates protection mechanisms like SMB signing, RDP security, etc.
- **Trust Relationships**: Analyzes domain trust relationships for security implications

### 4. Hybrid/Cloud AD Issues

This module checks for misconfigurations in Azure AD Connect and hybrid identity setups:

- **Azure AD Connect Configuration**: Evaluates the security of Azure AD Connect deployment
- **Sync Account Permissions**: Checks if the Azure AD Connect sync account has appropriate permissions
- **Privileged Account Sync**: Identifies privileged on-premises accounts synced to Azure AD
- **Password Hash Sync Settings**: Reviews password hash synchronization security settings
- **Pass-through Authentication**: Evaluates pass-through authentication configuration security
- **Federation Security**: Assesses the security of federation services if configured
- **MFA Recommendations**: Provides guidance on multi-factor authentication implementation
- **Conditional Access Recommendations**: Suggests conditional access policies based on best practices

## Installation

### Prerequisites

- Windows PowerShell 5.1 or later
- Active Directory PowerShell module
- Domain Administrator or equivalent privileges (for full functionality)

### Option 1: Direct Install

1. Clone the repository:

```
git clone https://github.com/MottaSec/Argus-AD.git
```

2. Navigate to the Argus-AD directory:

```
cd Argus-AD
```

3. Run the installation script with administrator privileges:

```powershell
.\Install-ArgusAD.ps1
```

This will install the necessary components and make the module available to all users on the system.

### Option 2: Manual Import

If you prefer not to run the installer, you can manually import the module:

1. Clone or download the repository
2. Import the module directly:

```powershell
Import-Module .\src\MottaSec-ArgusAD.psd1
```

## Usage

### Basic Usage

To run a complete scan on the current domain:

```powershell
Invoke-ArgusAD
```

This will execute all scan modules and generate comprehensive reports in the default `reports` directory.

### Scan a Specific Domain

To scan a specific domain other than the current one:

```powershell
Invoke-ArgusAD -DomainName contoso.com
```

### Selective Scanning

You can choose which scan categories to run by using the skip parameters:

```powershell
# Skip Hybrid AD scan
Invoke-ArgusAD -SkipHybridAD

# Skip multiple categories
Invoke-ArgusAD -SkipLateralMovement -SkipHybridAD

# Run only Simple Misconfigurations scan
Invoke-ArgusAD -SkipPrivilegeEscalation -SkipLateralMovement -SkipHybridAD
```

### Custom Output Location

To save reports to a custom location:

```powershell
Invoke-ArgusAD -OutputPath "C:\SecAudits\ADScan"
```

### Running from PowerShell Script

For convenience, you can also run the tool using the Argus-AD.ps1 script:

```powershell
.\Argus-AD.ps1 -DomainName contoso.com -SkipHybridAD
```

## Reports and Output

Argus-AD generates three types of reports for each scan:

### 1. HTML Report

A comprehensive, interactive HTML report with:
- Executive summary and domain information
- Findings organized by category
- Severity ratings and statistics
- Detailed descriptions, impacts, and remediation notes
- Interactive filtering and navigation

### 2. CSV Report

A detailed CSV file containing all findings for further analysis, filtering, or integration with other tools.

### 3. Executive Summary

A text-based executive summary with:
- Key domain statistics
- Summary of findings by severity and category
- List of critical and high-severity findings
- Next steps and recommendations

Reports are saved in the `reports` directory by default, in a subfolder named with the domain name and timestamp.

### Example Reports

The repository includes an example report in the `reports/CONTOSO_2025-04-01_09-30-45` directory. This sample contains a complete set of reports (HTML, CSV, and Executive Summary) that demonstrate what to expect from an Argus-AD scan and how the reports should look when properly generated. Reviewing these examples can help you understand the tool's output format and the types of findings it can detect.

## Understanding Results

### Severity Ratings

Argus-AD uses the following severity ratings:

- **Critical**: Issues that pose an immediate threat and should be addressed urgently
- **High**: Serious vulnerabilities that significantly increase security risk
- **Medium**: Important issues that should be addressed in the near term
- **Low**: Minor security issues that represent best practice improvements
- **Informational**: Items that are not vulnerabilities but provide useful security context

### Finding Structure

Each finding includes:
- **Category**: The module that identified the issue
- **Subcategory**: The specific check or vulnerability type
- **Description**: A detailed explanation of the issue
- **Impact**: The security implications or potential exploitation path
- **AEGIS-AD Remediation**: How the issue could be remediated with AEGIS-AD

## Best Practices

### Before Running

1. **Plan ahead**: Schedule the scan during off-hours if possible
2. **Permissions**: Ensure you have appropriate permissions (Domain Admin recommended)
3. **Review limitations**: Understand that some checks may be limited by permissions
4. **Notification**: Inform relevant teams that you're conducting a security assessment

### After Scanning

1. **Prioritize findings**: Focus on Critical and High-severity issues first
2. **Develop a plan**: Create a remediation roadmap based on risk and complexity
3. **Test changes**: Test remediation steps in a test environment before applying to production
4. **Re-scan**: After making changes, re-run Argus-AD to validate improvements

## Security Considerations

Argus-AD is a read-only assessment tool that does not make changes to your environment. However:

- The scan results contain sensitive security information and should be protected accordingly
- Running the tool requires elevated privileges, which should be carefully managed
- Consider using a dedicated privileged workstation for security assessments

## Remediation

Argus-AD focuses on identifying issues, not fixing them. For remediation assistance, MottaSec offers AEGIS-AD, our comprehensive Active Directory security hardening solution. AEGIS-AD can:

- Systematically address issues found by Argus-AD
- Implement security best practices beyond what's covered in the scan
- Provide ongoing protection and monitoring
- Deploy security improvements with minimal disruption

Contact MottaSec for more information about AEGIS-AD.

## Frequently Asked Questions

### How long does a scan take?

Scan duration depends on the size and complexity of your AD environment:
- Small environments (under 1000 objects): 5-15 minutes
- Medium environments (1000-10000 objects): 15-45 minutes
- Large environments (10000+ objects): 45+ minutes

### Will the scan impact performance?

Argus-AD is designed to be lightweight and non-intrusive, but it does query Active Directory. In very large or already-stressed environments, you may want to run it during off-hours.

### Does the tool make any changes to AD?

No. Argus-AD is strictly a read-only assessment tool and makes no changes to your AD environment.

### What permissions are required?

While some basic checks can run with lower privileges, Domain Admin (or equivalent) permissions are recommended for full functionality.

### Can I customize the checks?

The current version does not support customizing individual checks, but you can select which categories to run using the skip parameters.

## Troubleshooting

### Module Import Issues

If you encounter module import issues:

```powershell
# Ensure the ActiveDirectory module is installed
Get-WindowsCapability -Name Rsat.ActiveDirectory* -Online

# Install if needed
Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online
```

### Permission Errors

If you see permission errors, ensure you're running with Domain Admin privileges or equivalent.

### Report Generation Fails

If report generation fails:
1. Ensure the output directory is writable
2. Check for adequate disk space
3. Verify you have permissions to the target directory

## Support and Community

For questions, support, or to learn more about our AD security solutions:

- Email: info@mottasec.com
- Website: [https://www.mottasec.com](https://www.mottasec.com)
- GitHub Issues: [https://github.com/MottaSec/Argus-AD/issues](https://github.com/MottaSec/Argus-AD/issues)

## License

Copyright (c) 2025 MottaSec. All rights reserved.

## Disclaimer

This tool is provided for educational and legitimate security assessment purposes only. Always ensure you have proper authorization before scanning any Active Directory environment.

Use of Argus-AD is at your own risk. MottaSec is not responsible for any damage or issues that may arise from using this tool. 