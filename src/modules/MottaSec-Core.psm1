#
# MottaSec-Core.psm1
# Core functions for Argus-AD
#
# Copyright (c) 2025 MottaSec
#

function Get-MottaSecDomainInfo {
    <#
    .SYNOPSIS
        Gets basic information about the Active Directory domain.
    
    .DESCRIPTION
        Collects domain information including domain name, forest name, domain controllers,
        functional level, and other relevant details needed for the scans.
    
    .OUTPUTS
        PSObject with domain information
    #>
    
    Write-Host "[*] Collecting domain information..." -ForegroundColor Cyan
    
    try {
        $domain = Get-ADDomain
        $forest = Get-ADForest
        $domainControllers = Get-ADDomainController -Filter *
        
        # Get domain password policy
        $passwordPolicy = Get-ADDefaultDomainPasswordPolicy
        
        # Domain functional level as string
        $domainLevel = [string]$domain.DomainMode
        $forestLevel = [string]$forest.ForestMode
        
        # Create result object
        $domainInfo = [PSCustomObject]@{
            DomainName = $domain.DNSRoot
            DomainNetBIOSName = $domain.NetBIOSName
            DomainSID = $domain.DomainSID.Value
            ForestName = $forest.Name
            DomainFunctionalLevel = $domainLevel
            ForestFunctionalLevel = $forestLevel
            PDCEmulator = $domain.PDCEmulator
            DomainControllers = $domainControllers
            PasswordPolicy = $passwordPolicy
            ScanTime = Get-Date
            IsAzureADConnectConfigured = $false # Will be checked in Hybrid module
        }
        
        # Output basic domain info
        Write-Host "[+] Domain Name: $($domainInfo.DomainName)" -ForegroundColor Green
        Write-Host "[+] Domain Functional Level: $($domainInfo.DomainFunctionalLevel)" -ForegroundColor Green
        Write-Host "[+] Forest Name: $($domainInfo.ForestName)" -ForegroundColor Green
        Write-Host "[+] PDC Emulator: $($domainInfo.PDCEmulator)" -ForegroundColor Green
        Write-Host "[+] Domain Controllers: $($domainInfo.DomainControllers.Count)" -ForegroundColor Green
        
        return $domainInfo
    }
    catch {
        Write-Host "[!] Error collecting domain information: $_" -ForegroundColor Red
        throw "Failed to collect domain information. Ensure you have sufficient permissions and the Active Directory module is loaded."
    }
}

function New-ArgusADFinding {
    <#
    .SYNOPSIS
        Creates a standardized finding object for the report.
    
    .DESCRIPTION
        Used by all scan modules to create uniform finding objects that
        can be processed by the reporting module.
    
    .PARAMETER Category
        The category of the finding (Simple Misconfiguration, Privilege Escalation, etc.)
    
    .PARAMETER Subcategory
        The specific subcategory or check name
    
    .PARAMETER Severity
        The severity of the finding (Critical, High, Medium, Low, Informational)
    
    .PARAMETER Description
        A description of the finding
    
    .PARAMETER RawData
        The raw data collected during the scan that led to this finding
    
    .PARAMETER Impact
        The potential security impact of this finding
    
    .PARAMETER AegisRemediation
        Description of how AEGIS-AD could remediate this issue
    
    .OUTPUTS
        PSObject representing a standardized finding
    #>
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("SimpleMisconfigurations", "PrivilegeEscalation", "LateralMovement", "HybridAD")]
        [string]$Category,
        
        [Parameter(Mandatory=$true)]
        [string]$Subcategory,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Critical", "High", "Medium", "Low", "Informational")]
        [string]$Severity,
        
        [Parameter(Mandatory=$true)]
        [string]$Description,
        
        [Parameter(Mandatory=$false)]
        [object]$RawData = $null,
        
        [Parameter(Mandatory=$true)]
        [string]$Impact,
        
        [Parameter(Mandatory=$true)]
        [string]$AegisRemediation
    )
    
    return [PSCustomObject]@{
        Category = $Category
        Subcategory = $Subcategory
        Severity = $Severity
        Description = $Description
        RawData = $RawData
        Impact = $Impact
        AegisRemediation = $AegisRemediation
        Timestamp = Get-Date
    }
}

function Get-MottaSecUserAccountControl {
    <#
    .SYNOPSIS
        Translates UserAccountControl flags into human-readable format
    
    .DESCRIPTION
        Converts the numeric UserAccountControl value into a list of
        enabled flags for better understanding and reporting
    
    .PARAMETER Value
        The numeric UserAccountControl value
    
    .OUTPUTS
        PSObject with boolean values for each flag
    #>
    param (
        [Parameter(Mandatory=$true)]
        [int]$Value
    )
    
    $flags = [ordered]@{
        SCRIPT                         = 0x0001
        ACCOUNTDISABLE                 = 0x0002
        HOMEDIR_REQUIRED               = 0x0008
        LOCKOUT                        = 0x0010
        PASSWD_NOTREQD                 = 0x0020
        PASSWD_CANT_CHANGE             = 0x0040
        ENCRYPTED_TEXT_PWD_ALLOWED     = 0x0080
        TEMP_DUPLICATE_ACCOUNT         = 0x0100
        NORMAL_ACCOUNT                 = 0x0200
        INTERDOMAIN_TRUST_ACCOUNT      = 0x0800
        WORKSTATION_TRUST_ACCOUNT      = 0x1000
        SERVER_TRUST_ACCOUNT           = 0x2000
        DONT_EXPIRE_PASSWORD           = 0x10000
        MNS_LOGON_ACCOUNT              = 0x20000
        SMARTCARD_REQUIRED             = 0x40000
        TRUSTED_FOR_DELEGATION         = 0x80000
        NOT_DELEGATED                  = 0x100000
        USE_DES_KEY_ONLY               = 0x200000
        DONT_REQ_PREAUTH               = 0x400000
        PASSWORD_EXPIRED               = 0x800000
        TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
        PARTIAL_SECRETS_ACCOUNT        = 0x4000000
    }
    
    $result = [PSCustomObject]@{}
    
    foreach ($flag in $flags.Keys) {
        Add-Member -InputObject $result -MemberType NoteProperty -Name $flag -Value (($Value -band $flags[$flag]) -ne 0)
    }
    
    return $result
}

function Format-MottaSecSeverityColor {
    <#
    .SYNOPSIS
        Returns an ANSI color code for a given severity level
    
    .DESCRIPTION
        Used for console output to color-code severity levels
    
    .PARAMETER Severity
        The severity level (Critical, High, Medium, Low, Informational)
    
    .OUTPUTS
        String with ANSI color code
    #>
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Critical", "High", "Medium", "Low", "Informational")]
        [string]$Severity
    )
    
    switch ($Severity) {
        "Critical" { return "Red" }
        "High" { return "Magenta" }
        "Medium" { return "Yellow" }
        "Low" { return "Cyan" }
        "Informational" { return "Gray" }
        default { return "White" }
    }
}

function Write-MottaSecFinding {
    <#
    .SYNOPSIS
        Writes a finding to the console with appropriate coloring
    
    .DESCRIPTION
        Helper function to display findings in a consistent format
    
    .PARAMETER Finding
        The finding object to display
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$Finding
    )
    
    $severityColor = Format-MottaSecSeverityColor -Severity $Finding.Severity
    
    Write-Host "`n[!] Finding: $($Finding.Subcategory)" -ForegroundColor White
    Write-Host "    Severity: " -NoNewline
    Write-Host "$($Finding.Severity)" -ForegroundColor $severityColor
    Write-Host "    Description: $($Finding.Description)" -ForegroundColor White
    Write-Host "    Impact: $($Finding.Impact)" -ForegroundColor White
}

function Test-MottaSecIsAdmin {
    <#
    .SYNOPSIS
        Checks if the current PowerShell session is running with administrator privileges
    
    .DESCRIPTION
        Verifies whether the tool has been launched with the necessary permissions
    
    .OUTPUTS
        Boolean indicating if running as admin
    #>
    
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Export all functions
Export-ModuleMember -Function Get-MottaSecDomainInfo, New-ArgusADFinding, Get-MottaSecUserAccountControl,
                              Format-MottaSecSeverityColor, Write-MottaSecFinding, Test-MottaSecIsAdmin 