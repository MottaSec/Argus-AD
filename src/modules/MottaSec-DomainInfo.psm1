#
# MottaSec-DomainInfo.psm1
# Domain information gathering module for Argus-AD
#
# Copyright (c) 2025 MottaSec
#

function Get-MottaSecDomainInfo {
    <#
    .SYNOPSIS
        Gathers information about the Active Directory domain.
    
    .DESCRIPTION
        Collects essential information about the AD domain including domain controllers,
        functional levels, trust relationships, and other key attributes.
    
    .PARAMETER DomainName
        Optional. The domain to scan. If not specified, the current domain is used.
    
    .OUTPUTS
        PSObject containing domain information.
    #>
    param (
        [Parameter(Mandatory=$false)]
        [string]$DomainName
    )
    
    Write-Host "[*] Gathering domain information..." -ForegroundColor Cyan
    
    try {
        # Get domain information
        if ([string]::IsNullOrEmpty($DomainName)) {
            $domain = Get-ADDomain
        }
        else {
            $domain = Get-ADDomain -Identity $DomainName
        }
        
        Write-Host "[+] Found domain: $($domain.DNSRoot)" -ForegroundColor Green
        
        # Get forest information
        $forest = Get-ADForest -Identity $domain.Forest
        
        # Get domain controllers
        $domainControllers = Get-ADDomainController -Filter * -Server $domain.DNSRoot
        
        Write-Host "[+] Found $($domainControllers.Count) domain controllers" -ForegroundColor Green
        
        # Get trust relationships
        $trusts = Get-ADTrust -Filter * -Server $domain.DNSRoot -ErrorAction SilentlyContinue
        
        if ($null -ne $trusts) {
            Write-Host "[+] Found $($trusts.Count) trust relationships" -ForegroundColor Green
        }
        else {
            Write-Host "[+] No trust relationships found" -ForegroundColor Yellow
            $trusts = @()
        }
        
        # Get password policy
        $passwordPolicy = Get-MottaSecPasswordPolicy -DomainName $domain.DNSRoot
        
        Write-Host "[+] Retrieved domain password policy" -ForegroundColor Green
        
        # Get privileged groups
        $privilegedGroups = @(
            @{ Name = "Enterprise Admins"; SID = "$($domain.DomainSID)-519" },
            @{ Name = "Domain Admins"; SID = "$($domain.DomainSID)-512" },
            @{ Name = "Schema Admins"; SID = "$($domain.DomainSID)-518" },
            @{ Name = "Administrators"; SID = "S-1-5-32-544" },
            @{ Name = "Backup Operators"; SID = "S-1-5-32-551" },
            @{ Name = "Account Operators"; SID = "S-1-5-32-548" },
            @{ Name = "Server Operators"; SID = "S-1-5-32-549" },
            @{ Name = "Print Operators"; SID = "S-1-5-32-550" },
            @{ Name = "Certificate Admins"; SID = "$($domain.DomainSID)-517" },
            @{ Name = "Group Policy Creator Owners"; SID = "$($domain.DomainSID)-520" }
        )
        
        # Get FSMO roles
        $fsmoRoles = [PSCustomObject]@{
            PDCEmulator = $domain.PDCEmulator
            RIDMaster = $domain.RIDMaster
            InfrastructureMaster = $domain.InfrastructureMaster
            DomainNamingMaster = $forest.DomainNamingMaster
            SchemaMaster = $forest.SchemaMaster
        }
        
        Write-Host "[+] Retrieved FSMO role information" -ForegroundColor Green
        
        # Additional information that may be useful for the assessment
        $domainInfo = [PSCustomObject]@{
            DomainName = $domain.DNSRoot
            DomainNetBIOSName = $domain.NetBIOSName
            DomainSID = $domain.DomainSID.Value
            ForestName = $forest.Name
            DomainFunctionalLevel = $domain.DomainMode
            ForestFunctionalLevel = $forest.ForestMode
            DomainControllers = $domainControllers
            PasswordPolicy = $passwordPolicy
            TrustRelationships = $trusts
            PrivilegedGroups = $privilegedGroups
            FSMORoles = $fsmoRoles
            DCCount = $domainControllers.Count
            IsAzureADConnectConfigured = $false # Will be set by HybridAD module
        }
        
        Write-Host "[+] Domain information gathering complete" -ForegroundColor Green
        return $domainInfo
    }
    catch {
        Write-Host "[!] Error gathering domain information: $_" -ForegroundColor Red
        throw $_
    }
}

# Export functions
Export-ModuleMember -Function Get-MottaSecDomainInfo 