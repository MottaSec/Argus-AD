#
# MottaSec-HybridAD.psm1
# Hybrid/Cloud AD Issues Module for Argus-AD
#
# Copyright (c) 2025 MottaSec
#

function Invoke-MottaSecHybridADScan {
    <#
    .SYNOPSIS
        Scans for Hybrid/Cloud AD integration issues.
    
    .DESCRIPTION
        Checks for misconfigurations in Azure AD Connect and hybrid identity setup.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Array of finding objects
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    $findings = @()
    
    Write-Host "[*] Starting Hybrid/Cloud AD Issues Scan..." -ForegroundColor Cyan
    
    # Check if Azure AD Connect is configured
    Write-Host "[*] Checking if Azure AD Connect is configured..." -ForegroundColor Cyan
    $DomainInfo.IsAzureADConnectConfigured = Test-MottaSecIsAzureADConnectConfigured
    
    if ($DomainInfo.IsAzureADConnectConfigured) {
        # Check for AAD Connect sync account misconfiguration
        $findings += Test-MottaSecAADConnectSyncAccount -DomainInfo $DomainInfo
        
        # Check for privileged accounts synced to Azure AD
        $findings += Test-MottaSecPrivilegedAccountsSyncedToAzureAD -DomainInfo $DomainInfo
    }
    else {
        Write-Host "[*] Azure AD Connect not detected. Skipping hybrid identity checks." -ForegroundColor Yellow
    }
    
    # These checks are more informational and recommendations since we can't directly
    # check Azure AD settings without additional modules and permissions
    $findings += Get-MottaSecAzureADRecommendations -DomainInfo $DomainInfo
    
    Write-Host "[+] Hybrid/Cloud AD Issues Scan completed. Found $($findings.Count) issues." -ForegroundColor Green
    
    return $findings
}

function Test-MottaSecIsAzureADConnectConfigured {
    <#
    .SYNOPSIS
        Checks if Azure AD Connect is configured in the environment.
    
    .DESCRIPTION
        Looks for indicators that Azure AD Connect is being used to sync identities.
    
    .OUTPUTS
        Boolean indicating if Azure AD Connect appears to be configured
    #>
    
    Write-Host "[*] Checking for Azure AD Connect configuration..." -ForegroundColor Cyan
    
    try {
        # Look for the Azure AD Connect sync account (typically named MSOL_*)
        $aadConnectSyncAccount = Get-ADUser -Filter "Name -like 'MSOL_*'" -ErrorAction SilentlyContinue
        
        if ($null -ne $aadConnectSyncAccount) {
            Write-Host "[+] Azure AD Connect sync account found: $($aadConnectSyncAccount.Name)" -ForegroundColor Green
            return $true
        }
        
        # Look for Azure AD Connect service in the domain
        $aadConnectService = Get-ADComputer -Filter "Description -like '*Azure AD Connect*' -or Description -like '*AAD Connect*' -or Description -like '*DirSync*'" -ErrorAction SilentlyContinue
        
        if ($null -ne $aadConnectService) {
            Write-Host "[+] Azure AD Connect service computer found: $($aadConnectService.Name)" -ForegroundColor Green
            return $true
        }
        
        # Look for user attributes that are typically populated by Azure AD Connect
        $userWithCloudAttributes = Get-ADUser -Filter * -Properties msDS-cloudExtensionAttribute1, msExchRecipientTypeDetails -ResultSetSize 1 -ErrorAction SilentlyContinue
        
        if ($null -ne $userWithCloudAttributes -and 
            ($null -ne $userWithCloudAttributes."msDS-cloudExtensionAttribute1" -or 
             $null -ne $userWithCloudAttributes.msExchRecipientTypeDetails)) {
            Write-Host "[+] Found users with Azure AD-specific attributes, indicating Azure AD Connect is likely configured." -ForegroundColor Green
            return $true
        }
        
        Write-Host "[*] No clear evidence of Azure AD Connect configuration found." -ForegroundColor Yellow
        return $false
    }
    catch {
        Write-Host "[!] Error checking for Azure AD Connect configuration: $_" -ForegroundColor Red
        return $false
    }
}

function Test-MottaSecAADConnectSyncAccount {
    <#
    .SYNOPSIS
        Checks for Azure AD Connect sync account misconfigurations.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if misconfiguration is found
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking Azure AD Connect sync account configuration..." -ForegroundColor Cyan
    
    try {
        # Look for the Azure AD Connect sync account (typically named MSOL_*)
        $aadConnectSyncAccounts = Get-ADUser -Filter "Name -like 'MSOL_*'" -Properties Name, Description, MemberOf, Enabled, PasswordLastSet, UserAccountControl
        
        if ($null -eq $aadConnectSyncAccounts -or $aadConnectSyncAccounts.Count -eq 0) {
            Write-Host "[*] No Azure AD Connect sync accounts found with standard naming convention." -ForegroundColor Yellow
            return $null
        }
        
        $issuesFound = @()
        
        foreach ($syncAccount in $aadConnectSyncAccounts) {
            # Check if the account is in any administrative groups
            $isAdmin = $false
            $adminGroups = @()
            
            foreach ($groupDN in $syncAccount.MemberOf) {
                $group = Get-ADGroup -Identity $groupDN
                
                if ($group.Name -eq "Domain Admins" -or $group.Name -eq "Enterprise Admins" -or $group.Name -eq "Administrators") {
                    $isAdmin = $true
                    $adminGroups += $group.Name
                }
            }
            
            # Check other potential issues
            $userAccountControl = Get-MottaSecUserAccountControl -Value $syncAccount.UserAccountControl
            
            $issues = @()
            
            if ($isAdmin) {
                $issues += "Account is a member of privileged groups: $($adminGroups -join ', ')"
            }
            
            if ($userAccountControl.DONT_EXPIRE_PASSWORD) {
                # This is actually expected for AAD Connect, but we'll note it
                $issues += "Password set to never expire"
            }
            
            if ($userAccountControl.PASSWD_NOTREQD) {
                $issues += "No password required flag is set"
            }
            
            if (-not $syncAccount.Enabled) {
                $issues += "Account is disabled"
            }
            
            if ($issues.Count -gt 0) {
                $issuesFound += [PSCustomObject]@{
                    AccountName = $syncAccount.Name
                    Issues = $issues
                    Description = $syncAccount.Description
                    PasswordLastSet = $syncAccount.PasswordLastSet
                    IsEnabled = $syncAccount.Enabled
                    UserAccountControl = $userAccountControl
                }
            }
        }
        
        if ($issuesFound.Count -gt 0) {
            $severity = "High"
            if ($issuesFound | Where-Object { $_.Issues -contains "Account is a member of privileged groups: Domain Admins" }) {
                $severity = "Critical"
            }
            
            $finding = New-ArgusADFinding -Category "HybridAD" `
                                        -Subcategory "Azure AD Connect Sync Account Misconfiguration" `
                                        -Severity $severity `
                                        -Description "Found $($issuesFound.Count) Azure AD Connect sync accounts with security misconfigurations, including excessive privileges or security flag issues." `
                                        -RawData $issuesFound `
                                        -Impact "The Azure AD Connect sync account has elevated permissions in AD by design (including DCSync rights). If it is additionally placed in privileged groups or misconfigured, it becomes an even more critical target for attackers, potentially allowing complete domain compromise." `
                                        -AegisRemediation "AEGIS-AD can review the sync account configuration, remove unnecessary group memberships, ensure proper account protection, and isolate the Azure AD Connect server according to Microsoft best practices."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        # Also check if we can find the AAD Connect server and assess its security
        $aadConnectServers = Get-ADComputer -Filter "Description -like '*Azure AD Connect*' -or Description -like '*AAD Connect*' -or Description -like '*DirSync*'" -Properties Name, Description, OperatingSystem, Created, LastLogonDate
        
        if ($null -ne $aadConnectServers -and $aadConnectServers.Count -gt 0) {
            Write-Host "[*] Found $($aadConnectServers.Count) potential Azure AD Connect servers." -ForegroundColor Cyan
            
            # We can't directly check the server security from AD, but we can note it for awareness
            $serverInfo = [PSCustomObject]@{
                Servers = $aadConnectServers | Select-Object Name, Description, OperatingSystem, Created, LastLogonDate
                Recommendation = "Azure AD Connect servers should be treated as Tier 0 assets, with the same security controls as a Domain Controller."
            }
            
            $finding = New-ArgusADFinding -Category "HybridAD" `
                                        -Subcategory "Azure AD Connect Server Security" `
                                        -Severity "Informational" `
                                        -Description "Found $($aadConnectServers.Count) potential Azure AD Connect servers. These should be secured as Tier 0 assets." `
                                        -RawData $serverInfo `
                                        -Impact "The Azure AD Connect server holds the credentials needed to synchronize with Azure AD and has high privileges in the on-premises AD. If compromised, it can lead to complete control over both environments." `
                                        -AegisRemediation "AEGIS-AD can assist in implementing a secure tier model that treats the AAD Connect server as a Tier 0 asset, with restricted access, enhanced monitoring, and regular security patches."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] Azure AD Connect sync account configuration appears secure." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking Azure AD Connect sync account: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecPrivilegedAccountsSyncedToAzureAD {
    <#
    .SYNOPSIS
        Checks for privileged on-premises accounts likely synced to Azure AD.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if privileged accounts are synced
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking for privileged accounts likely synced to Azure AD..." -ForegroundColor Cyan
    
    try {
        # Define privileged groups to check
        $privilegedGroups = @(
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators"
        )
        
        $potentiallySyncedAdmins = @()
        
        # Check each privileged group
        foreach ($groupName in $privilegedGroups) {
            try {
                $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
                
                if ($null -ne $group) {
                    $members = Get-ADGroupMember -Identity $groupName -Recursive | Where-Object { $_.objectClass -eq 'user' }
                    
                    foreach ($member in $members) {
                        $user = Get-ADUser -Identity $member.SamAccountName -Properties Name, UserPrincipalName, Description, mail, Enabled, IsCriticalSystemObject, msExchRecipientTypeDetails, "msDS-cloudExtensionAttribute1"
                        
                        # Check if the account is likely synced
                        # Look for indicators such as:
                        # 1. Email address with a domain matching UPN suffix
                        # 2. Cloud-specific attributes set
                        # 3. Not marked as a critical system object (built-in)
                        
                        $isLikelySynced = $false
                        $syncIndicators = @()
                        
                        if ($null -ne $user.mail -and $user.mail -ne "") {
                            $isLikelySynced = $true
                            $syncIndicators += "Has email address"
                        }
                        
                        if ($null -ne $user."msDS-cloudExtensionAttribute1" -or $null -ne $user.msExchRecipientTypeDetails) {
                            $isLikelySynced = $true
                            $syncIndicators += "Has cloud extension attributes"
                        }
                        
                        if ($user.UserPrincipalName -match "\.onmicrosoft\.com$") {
                            $isLikelySynced = $true
                            $syncIndicators += "Has .onmicrosoft.com UPN"
                        }
                        
                        if ($isLikelySynced -and $user.Enabled -and -not $user.IsCriticalSystemObject) {
                            $potentiallySyncedAdmins += [PSCustomObject]@{
                                Name = $user.Name
                                UserPrincipalName = $user.UserPrincipalName
                                PrivilegedGroup = $groupName
                                SyncIndicators = $syncIndicators -join ", "
                                Description = $user.Description
                            }
                        }
                    }
                }
            }
            catch {
                Write-Host "[!] Failed to check members of group ${groupName}: ${_}" -ForegroundColor Yellow
                continue
            }
        }
        
        if ($potentiallySyncedAdmins.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "HybridAD" `
                                        -Subcategory "Privileged Accounts Synced to Azure AD" `
                                        -Severity "High" `
                                        -Description "Found $($potentiallySyncedAdmins.Count) privileged on-premises accounts that appear to be synced to Azure AD." `
                                        -RawData $potentiallySyncedAdmins `
                                        -Impact "Syncing highly privileged on-premises accounts to Azure AD creates dual vulnerability. If the account is compromised in either environment, both environments are at risk. Best practice is to maintain separate identities for privileged access in each environment." `
                                        -AegisRemediation "AEGIS-AD can implement a separation of admin accounts, creating dedicated cloud-only accounts for Azure administration and configuring Azure AD Connect filtering to prevent syncing privileged on-premises accounts."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No privileged accounts appear to be synced to Azure AD." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking privileged synced accounts: $_" -ForegroundColor Red
        return $null
    }
}

function Get-MottaSecAzureADRecommendations {
    <#
    .SYNOPSIS
        Provides informational recommendations for Azure AD security.
    
    .DESCRIPTION
        Since we can't directly assess Azure AD without the appropriate modules 
        and access, this function provides recommendations based on common issues.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Array of informational finding objects
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Generating Azure AD security recommendations..." -ForegroundColor Cyan
    
    $findings = @()
    
    # MFA Recommendation
    $finding = New-ArgusADFinding -Category "HybridAD" `
                                -Subcategory "Azure AD MFA Enforcement" `
                                -Severity "Informational" `
                                -Description "Ensure Multi-Factor Authentication (MFA) is enforced for all privileged accounts in Azure AD and ideally for all users." `
                                -RawData @{
                                    Recommendation = "Enable MFA for all administrator accounts at minimum. Consider Security Defaults or Conditional Access policies to enforce MFA broadly."
                                } `
                                -Impact "Without MFA, cloud accounts are vulnerable to password spray, credential stuffing, and phishing attacks, which are some of the most common initial compromise vectors." `
                                -AegisRemediation "AEGIS-AD can assist in implementing Azure AD MFA for all user accounts, with custom Conditional Access policies based on security requirements and user behavior patterns."
    
    Write-MottaSecFinding -Finding $finding
    $findings += $finding
    
    # Legacy Authentication Recommendation
    $finding = New-ArgusADFinding -Category "HybridAD" `
                                -Subcategory "Legacy Authentication Protocols" `
                                -Severity "Informational" `
                                -Description "Block legacy authentication protocols in Azure AD, which bypass MFA and other modern security controls." `
                                -RawData @{
                                    Recommendation = "Use Conditional Access or Security Defaults to block legacy authentication protocols like POP, IMAP, SMTP Auth, and older Office clients."
                                } `
                                -Impact "Legacy authentication protocols can't enforce MFA and are frequently targeted in credential stuffing attacks, allowing attackers to bypass even robust MFA implementations." `
                                -AegisRemediation "AEGIS-AD can identify and upgrade applications using legacy authentication, then implement policies to block these protocols while ensuring business continuity."
    
    Write-MottaSecFinding -Finding $finding
    $findings += $finding
    
    # PIM Recommendation
    $finding = New-ArgusADFinding -Category "HybridAD" `
                                -Subcategory "Privileged Identity Management" `
                                -Severity "Informational" `
                                -Description "Implement Azure AD Privileged Identity Management (PIM) for just-in-time privileged access, rather than permanent admin assignments." `
                                -RawData @{
                                    Recommendation = "Configure Azure AD PIM to require approval, justification, and time-limited activation for privileged roles."
                                } `
                                -Impact "Standing access to privileged roles increases the attack surface. If any privileged account is compromised, attackers have persistent access to sensitive operations in Azure AD." `
                                -AegisRemediation "AEGIS-AD can design and implement a comprehensive PIM strategy that balances security with usability, ensuring privileged access is properly controlled and monitored."
    
    Write-MottaSecFinding -Finding $finding
    $findings += $finding
    
    # App Registration Recommendation
    $finding = New-ArgusADFinding -Category "HybridAD" `
                                -Subcategory "Application Registration Controls" `
                                -Severity "Informational" `
                                -Description "Restrict Azure AD application registrations and ensure proper governance of app permissions." `
                                -RawData @{
                                    Recommendation = "Configure 'Users can register applications' to No in Azure AD, and implement an approval process for application registrations and consent grants."
                                } `
                                -Impact "Unrestricted application registration allows users to create OAuth apps that could request excessive permissions. Attackers exploit this to create persistence mechanisms through malicious applications." `
                                -AegisRemediation "AEGIS-AD can implement proper controls around application registration, develop an app governance strategy, and configure monitoring for suspicious application consent grants."
    
    Write-MottaSecFinding -Finding $finding
    $findings += $finding
    
    # Conditional Access Recommendation
    $finding = New-ArgusADFinding -Category "HybridAD" `
                                -Subcategory "Conditional Access Strategy" `
                                -Severity "Informational" `
                                -Description "Implement a comprehensive Conditional Access strategy for Azure AD authentication." `
                                -RawData @{
                                    Recommendation = "Configure Conditional Access policies to enforce MFA, compliant devices, approved locations, and risk-based authentication."
                                } `
                                -Impact "Without Conditional Access, Azure AD relies on simple username/password authentication, which is vulnerable to numerous attack vectors. This creates an easily exploitable perimeter for cloud resources." `
                                -AegisRemediation "AEGIS-AD can design and implement a complete Conditional Access framework tailored to your organization's risk profile, compliance needs, and user experience requirements."
    
    Write-MottaSecFinding -Finding $finding
    $findings += $finding
    
    Write-Host "[+] Generated Azure AD security recommendations." -ForegroundColor Green
    
    return $findings
}

# Export functions
Export-ModuleMember -Function Invoke-MottaSecHybridADScan 