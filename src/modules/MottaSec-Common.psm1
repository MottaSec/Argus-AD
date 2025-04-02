#
# MottaSec-Common.psm1
# Common utilities for Argus-AD
#
# Copyright (c) 2025 MottaSec
#

function New-ArgusADFinding {
    <#
    .SYNOPSIS
        Creates a new finding object.
    
    .DESCRIPTION
        Creates a standardized finding object for Argus-AD.
    
    .PARAMETER Category
        The category of the finding (e.g., SimpleMisconfigurations, PrivilegeEscalation).
    
    .PARAMETER Subcategory
        The specific subcategory or name of the finding.
    
    .PARAMETER Severity
        The severity level (Critical, High, Medium, Low, Informational).
    
    .PARAMETER Description
        A description of the finding.
    
    .PARAMETER RawData
        The raw data associated with the finding.
    
    .PARAMETER Impact
        Description of the security impact of this finding.
    
    .PARAMETER AegisRemediation
        Remediation action that AEGIS-AD can perform.
    
    .OUTPUTS
        PSCustomObject representing the finding
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
        FindingTime = Get-Date
    }
}

function Write-MottaSecFinding {
    <#
    .SYNOPSIS
        Outputs a finding to the console with appropriate formatting.
    
    .PARAMETER Finding
        The finding object to output.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$Finding
    )
    
    $severityColor = switch ($Finding.Severity) {
        "Critical" { "Red" }
        "High" { "DarkRed" }
        "Medium" { "Yellow" }
        "Low" { "Blue" }
        "Informational" { "Gray" }
        default { "White" }
    }
    
    Write-Host "[$($Finding.Severity)] $($Finding.Subcategory)" -ForegroundColor $severityColor
    Write-Host "Description: $($Finding.Description)" -ForegroundColor White
    Write-Host "Impact: $($Finding.Impact)" -ForegroundColor White
    Write-Host "AEGIS-AD Remediation: $($Finding.AegisRemediation)" -ForegroundColor Cyan
    Write-Host ""
}

function Get-MottaSecUserAccountControl {
    <#
    .SYNOPSIS
        Decodes the UserAccountControl value to a human-readable format.
    
    .PARAMETER Value
        The numeric UserAccountControl value.
    
    .OUTPUTS
        PSObject with boolean properties for each flag.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [int]$Value
    )
    
    return [PSCustomObject]@{
        SCRIPT = [bool]($Value -band 0x0001)
        ACCOUNTDISABLE = [bool]($Value -band 0x0002)
        HOMEDIR_REQUIRED = [bool]($Value -band 0x0008)
        LOCKOUT = [bool]($Value -band 0x0010)
        PASSWD_NOTREQD = [bool]($Value -band 0x0020)
        PASSWD_CANT_CHANGE = [bool]($Value -band 0x0040)
        ENCRYPTED_TEXT_PWD_ALLOWED = [bool]($Value -band 0x0080)
        TEMP_DUPLICATE_ACCOUNT = [bool]($Value -band 0x0100)
        NORMAL_ACCOUNT = [bool]($Value -band 0x0200)
        INTERDOMAIN_TRUST_ACCOUNT = [bool]($Value -band 0x0800)
        WORKSTATION_TRUST_ACCOUNT = [bool]($Value -band 0x1000)
        SERVER_TRUST_ACCOUNT = [bool]($Value -band 0x2000)
        DONT_EXPIRE_PASSWORD = [bool]($Value -band 0x10000)
        MNS_LOGON_ACCOUNT = [bool]($Value -band 0x20000)
        SMARTCARD_REQUIRED = [bool]($Value -band 0x40000)
        TRUSTED_FOR_DELEGATION = [bool]($Value -band 0x80000)
        NOT_DELEGATED = [bool]($Value -band 0x100000)
        USE_DES_KEY_ONLY = [bool]($Value -band 0x200000)
        DONT_REQ_PREAUTH = [bool]($Value -band 0x400000)
        PASSWORD_EXPIRED = [bool]($Value -band 0x800000)
        TRUSTED_TO_AUTH_FOR_DELEGATION = [bool]($Value -band 0x1000000)
        PARTIAL_SECRETS_ACCOUNT = [bool]($Value -band 0x4000000)
    }
}

function Test-MottaSecIsAdministrator {
    <#
    .SYNOPSIS
        Checks if the current user is running with administrative privileges.
    
    .OUTPUTS
        Boolean indicating if the user is an administrator.
    #>
    
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-MottaSecADModule {
    <#
    .SYNOPSIS
        Checks if the ActiveDirectory module is installed and available.
    
    .OUTPUTS
        Boolean indicating if the module is available.
    #>
    
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        return $true
    }
    else {
        return $false
    }
}

function Get-MottaSecPasswordPolicy {
    <#
    .SYNOPSIS
        Retrieves the password policy for a domain.
    
    .PARAMETER DomainName
        The domain to retrieve the policy for.
    
    .OUTPUTS
        PSObject containing password policy settings.
    #>
    param (
        [Parameter(Mandatory=$false)]
        [string]$DomainName
    )
    
    try {
        if ([string]::IsNullOrEmpty($DomainName)) {
            $policy = Get-ADDefaultDomainPasswordPolicy
        }
        else {
            $policy = Get-ADDefaultDomainPasswordPolicy -Server $DomainName
        }
        
        return $policy
    }
    catch {
        Write-Warning "Failed to retrieve password policy: $_"
        return $null
    }
}

function Get-MottaSecEffectivePermissions {
    <#
    .SYNOPSIS
        Gets effective AD permissions for an object.
    
    .PARAMETER Identity
        The AD object to check permissions for.
    
    .PARAMETER Principal
        The security principal to check.
    
    .OUTPUTS
        Array of permission objects.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$Identity,
        
        [Parameter(Mandatory=$true)]
        [string]$Principal
    )
    
    try {
        $acl = Get-Acl -Path "AD:\$Identity"
        $permissions = $acl.Access | Where-Object { $_.IdentityReference -like "*$Principal*" }
        return $permissions
    }
    catch {
        Write-Warning "Failed to get permissions: $_"
        return @()
    }
}

function Get-MottaSecDangerousPermission {
    <#
    .SYNOPSIS
        Checks if a permission is considered dangerous.
    
    .PARAMETER Permission
        The permission object to check.
    
    .OUTPUTS
        Boolean indicating if the permission is dangerous.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [System.DirectoryServices.ActiveDirectoryAccessRule]$Permission
    )
    
    # Define dangerous permissions
    $dangerousRights = @(
        "GenericAll",
        "GenericWrite", 
        "WriteOwner", 
        "WriteDacl", 
        "AllExtendedRights"
    )
    
    # Check if permission is in the dangerous list
    foreach ($right in $dangerousRights) {
        if ($Permission.ActiveDirectoryRights -like "*$right*") {
            return $true
        }
    }
    
    return $false
}

# Export functions
Export-ModuleMember -Function New-ArgusADFinding
Export-ModuleMember -Function Write-MottaSecFinding
Export-ModuleMember -Function Get-MottaSecUserAccountControl
Export-ModuleMember -Function Test-MottaSecIsAdministrator
Export-ModuleMember -Function Test-MottaSecADModule
Export-ModuleMember -Function Get-MottaSecPasswordPolicy
Export-ModuleMember -Function Get-MottaSecEffectivePermissions
Export-ModuleMember -Function Get-MottaSecDangerousPermission 