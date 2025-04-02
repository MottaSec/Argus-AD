#
# MottaSec-LateralMovement.psm1
# Lateral Movement Opportunities Module for Argus-AD
#
# Copyright (c) 2025 MottaSec
#

function Invoke-MottaSecLateralMovementScan {
    <#
    .SYNOPSIS
        Scans for lateral movement opportunities in Active Directory.
    
    .DESCRIPTION
        Checks for configurations in Active Directory that could facilitate lateral movement.
    
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
    
    Write-Host "[*] Starting Lateral Movement Opportunities Scan..." -ForegroundColor Cyan
    
    # Check for tiered administration violations
    $findings += Test-MottaSecTieredAdminViolations -DomainInfo $DomainInfo
    
    # Check for local administrator password reuse (LAPS assessment)
    # Note: This is already covered in SimpleMisconfigurations, but we'll reference it here for the report
    Write-Host "[*] Referencing LAPS check from Simple Misconfigurations scan..." -ForegroundColor Cyan
    
    # Check for excessive local admin rights
    $findings += Test-MottaSecExcessiveLocalAdminRights -DomainInfo $DomainInfo
    
    # Check for NTLM relay opportunities (SMB/LDAP signing)
    # Note: This is already covered in SimpleMisconfigurations, but we'll reference it here for the report
    Write-Host "[*] Referencing NTLM Relay check from Simple Misconfigurations scan..." -ForegroundColor Cyan
    
    # Check for credential caching and harvesting opportunities
    $findings += Test-MottaSecCredentialCaching -DomainInfo $DomainInfo
    
    Write-Host "[+] Lateral Movement Opportunities Scan completed. Found $($findings.Count) issues." -ForegroundColor Green
    
    return $findings
}

function Test-MottaSecTieredAdminViolations {
    <#
    .SYNOPSIS
        Checks for violations of tiered administration model.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if tiered admin violations are found
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking for tiered administration violations..." -ForegroundColor Cyan
    
    try {
        # Define Tier 0 groups (highly privileged)
        $tier0Groups = @(
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Backup Operators",
            "Account Operators",
            "Server Operators",
            "Print Operators",
            "Domain Controllers" # The group containing all DCs
        )
        
        # Get members of Tier 0 groups
        $tier0Accounts = @()
        $tier0GroupMembers = @()
        
        foreach ($groupName in $tier0Groups) {
            try {
                $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
                
                if ($null -ne $group) {
                    $members = Get-ADGroupMember -Identity $groupName -Recursive | Where-Object { $_.objectClass -eq 'user' }
                    $tier0GroupMembers += $members
                    
                    foreach ($member in $members) {
                        if ($tier0Accounts -notcontains $member.SamAccountName) {
                            $tier0Accounts += $member.SamAccountName
                        }
                    }
                }
            }
            catch {
                Write-Host "[!] Failed to get members of group ${groupName}: ${_}" -ForegroundColor Yellow
                continue
            }
        }
        
        # Check for logon violations
        # Note: In a real environment, this would check logon events from lower-tier systems
        # For our tool, we'll check if Tier 0 admin credentials are used on member servers/workstations
        
        # Check if there's a GPO restricting admin logons to appropriate tiers
        $tieringViolations = @()
        
        # Try to find GPOs that restrict admin logons
        $adminLogonRestrictionGPOs = Get-GPO -All | Where-Object { $_.DisplayName -like "*admin*" -and ($_.DisplayName -like "*tier*" -or $_.DisplayName -like "*restrict*" -or $_.DisplayName -like "*logon*") }
        
        # Check if admin accounts have logon restrictions
        $logonRightsPolicies = @()
        
        if ($adminLogonRestrictionGPOs.Count -gt 0) {
            foreach ($gpo in $adminLogonRestrictionGPOs) {
                try {
                    $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml
                    
                    # Check for user right assignments in the GPO
                    if ($gpoReport -match "DenyLogonLocally|DenyLogonThroughRemoteDesktopServices|DenyBatchLogon|DenyServiceLogon") {
                        $logonRightsPolicies += $gpo.DisplayName
                    }
                }
                catch {
                    Write-Host "[!] Failed to get GPO report for $($gpo.DisplayName): $_" -ForegroundColor Yellow
                }
            }
        }
        
        # Get all domain-joined computers
        $computers = Get-ADComputer -Filter {Enabled -eq $true} -Properties OperatingSystem, Description
        
        # Categorize computers by tier
        $tier0Computers = @()
        $tier1Computers = @()
        $tier2Computers = @()
        
        foreach ($computer in $computers) {
            # Domain Controllers are Tier 0
            if ($computer.OperatingSystem -like "*Domain Controller*") {
                $tier0Computers += $computer
            }
            # Servers are generally Tier 1
            elseif ($computer.OperatingSystem -like "*Server*") {
                $tier1Computers += $computer
            }
            # Workstations are Tier 2
            else {
                $tier2Computers += $computer
            }
        }
        
        # For our assessment, if there are no specific tiered admin GPOs, we'll consider it a violation
        if ($logonRightsPolicies.Count -eq 0) {
            $tieringViolations += [PSCustomObject]@{
                Type = "MissingTieredAdminPolicies"
                Description = "No Group Policy Objects found that restrict administrator logons by tier."
                Impact = "Tier 0 administrators can likely log on to lower-tier systems, creating significant lateral movement risk."
            }
            
            # Create a sample report of tier 0 admins and where they could potentially log on
            $sampleReport = @()
            foreach ($adminAccount in $tier0Accounts | Select-Object -First 5) {
                $sampleReport += [PSCustomObject]@{
                    AdminAccount = $adminAccount
                    CanLogOnToTier1 = $true
                    CanLogOnToTier2 = $true
                    Tier1Count = $tier1Computers.Count
                    Tier2Count = $tier2Computers.Count
                }
            }
            
            $finding = New-ArgusADFinding -Category "LateralMovement" `
                                        -Subcategory "No Tiered Administration Implementation" `
                                        -Severity "High" `
                                        -Description "No tiered administration model appears to be implemented. Tier 0 administrators can likely log on to lower-tier systems, creating significant lateral movement risk." `
                                        -RawData @{
                                            Tier0Accounts = $tier0Accounts
                                            MissingPolicies = $true
                                            SampleLogonReport = $sampleReport
                                            Tier0ComputerCount = $tier0Computers.Count
                                            Tier1ComputerCount = $tier1Computers.Count
                                            Tier2ComputerCount = $tier2Computers.Count
                                        } `
                                        -Impact "Without a tiered administration model, highly privileged credentials are at risk of theft when administrators log on to less secure systems. Attackers can compromise a workstation or server and steal domain admin credentials from memory." `
                                        -AegisRemediation "AEGIS-AD can implement a proper tiered administration model using Group Policy, Privileged Access Workstations (PAWs), and Just-In-Time administration to restrict credential exposure."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] Tiered administration policies are in place." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking tiered administration: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecExcessiveLocalAdminRights {
    <#
    .SYNOPSIS
        Checks for excessive local administrator rights across the domain.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if excessive local admin rights are found
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking for excessive local administrator rights..." -ForegroundColor Cyan
    
    try {
        # Check for domain groups that likely grant local admin rights
        $potentialAdminGroups = @()
        
        # Common group naming patterns that often indicate local admin access
        $adminPatterns = @(
            "*workstation admin*",
            "*server admin*",
            "*desktop admin*",
            "*local admin*",
            "*computer admin*",
            "*helpdesk*",
            "*it support*",
            "*desktop support*",
            "*level 1*",
            "*level 2*",
            "*tech support*"
        )
        
        # Get groups that match these patterns
        foreach ($pattern in $adminPatterns) {
            $groups = Get-ADGroup -Filter "Name -like '$pattern'" -Properties Description, Member
            $potentialAdminGroups += $groups
        }
        
        # Look for groups with references to workstations or servers in descriptions
        $descriptionPatterns = @(
            "*admin*",
            "*administrator*"
        )
        
        foreach ($pattern in $descriptionPatterns) {
            $groups = Get-ADGroup -Filter "Description -like '$pattern'" -Properties Description, Member
            foreach ($group in $groups) {
                if ($potentialAdminGroups -notcontains $group) {
                    $potentialAdminGroups += $group
                }
            }
        }
        
        # Process the groups
        $adminGroupsWithMembers = @()
        
        foreach ($group in $potentialAdminGroups) {
            try {
                $members = Get-ADGroupMember -Identity $group -Recursive | Where-Object { $_.objectClass -eq 'user' }
                
                $adminGroupsWithMembers += [PSCustomObject]@{
                    GroupName = $group.Name
                    Description = $group.Description
                    MemberCount = $members.Count
                    Members = $members | ForEach-Object { $_.SamAccountName }
                }
            }
            catch {
                Write-Host "[!] Failed to get members of group $($group.Name): $_" -ForegroundColor Yellow
            }
        }
        
        # Look for GPOs that might grant local admin rights
        $adminGPOs = @()
        
        # Get all GPOs and check for Restricted Groups or similar settings
        $allGPOs = Get-GPO -All
        
        foreach ($gpo in $allGPOs) {
            try {
                $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml
                
                # Look for restricted groups settings that add to local admins
                if ($gpoReport -match "Restricted Groups" -or 
                    $gpoReport -match "S-1-5-32-544" -or # Local Administrators SID
                    $gpoReport -match "Administrators</q:Name>" -or
                    $gpoReport -match "LocalAdmins" -or
                    ($gpoReport -match "Group" -and $gpoReport -match "Admin")) {
                    
                    $adminGPOs += [PSCustomObject]@{
                        GPOName = $gpo.DisplayName
                        GPOID = $gpo.Id
                        Description = $gpo.Description
                    }
                }
            }
            catch {
                Write-Host "[!] Failed to get GPO report for $($gpo.DisplayName): $_" -ForegroundColor Yellow
            }
        }
        
        # If we found suspicious groups or GPOs, report them
        if ($adminGroupsWithMembers.Count -gt 0 -or $adminGPOs.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "LateralMovement" `
                                        -Subcategory "Excessive Local Admin Rights" `
                                        -Severity "High" `
                                        -Description "Found $($adminGroupsWithMembers.Count) groups likely granting local admin rights to multiple users, and $($adminGPOs.Count) GPOs that appear to manage local admin membership." `
                                        -RawData @{
                                            AdminGroups = $adminGroupsWithMembers
                                            AdminGPOs = $adminGPOs
                                        } `
                                        -Impact "Excessive local admin rights create lateral movement paths across the environment. If an attacker compromises a user with widespread local admin access, they can move laterally to many systems and potentially steal additional credentials." `
                                        -AegisRemediation "AEGIS-AD can implement a comprehensive strategy to minimize local admin rights, including Just-In-Time access, purpose-specific admin accounts, and limiting the scope of admin groups to specific system collections."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No obvious excessive local admin rights detected." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking local admin rights: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecCredentialCaching {
    <#
    .SYNOPSIS
        Checks for credential caching and harvesting opportunities.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if credential caching issues are found
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking for credential caching configuration..." -ForegroundColor Cyan
    
    try {
        # Check for GPOs controlling credential caching
        $credentialCachingGPOs = @()
        $allGPOs = Get-GPO -All
        
        foreach ($gpo in $allGPOs) {
            try {
                $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml
                
                # Look for settings related to credential caching
                if ($gpoReport -match "CachedLogonsCount" -or
                    $gpoReport -match "WDigest" -or
                    $gpoReport -match "CredSSP" -or
                    $gpoReport -match "Credential|Credentials" -or
                    $gpoReport -match "LSA Protection") {
                    
                    $credentialCachingGPOs += [PSCustomObject]@{
                        GPOName = $gpo.DisplayName
                        GPOID = $gpo.Id
                        Description = $gpo.Description
                    }
                }
            }
            catch {
                Write-Host "[!] Failed to get GPO report for $($gpo.DisplayName): $_" -ForegroundColor Yellow
            }
        }
        
        # Check default domain controllers policy for credential protection
        $hasDCCredentialProtection = $false
        
        try {
            $defaultDCPolicy = Get-GPO -Name "Default Domain Controllers Policy" -ErrorAction SilentlyContinue
            
            if ($null -ne $defaultDCPolicy) {
                $dcPolicyReport = Get-GPOReport -Guid $defaultDCPolicy.Id -ReportType Xml
                
                # Check for LSA Protection, WDigest, etc.
                if ($dcPolicyReport -match "RunAsPPL" -or
                    $dcPolicyReport -match "CredentialGuard" -or
                    ($dcPolicyReport -match "WDigest" -and $dcPolicyReport -match "UseLogonCredential" -and $dcPolicyReport -match "0")) {
                    $hasDCCredentialProtection = $true
                }
            }
        }
        catch {
            Write-Host "[!] Failed to check Default Domain Controllers Policy: $_" -ForegroundColor Yellow
        }
        
        # If we don't find GPOs specifically protecting credentials, that's a finding
        if ($credentialCachingGPOs.Count -eq 0 -or !$hasDCCredentialProtection) {
            $severity = "High"
            $description = ""
            
            if ($credentialCachingGPOs.Count -eq 0) {
                $description += "No Group Policy Objects found that properly configure credential caching limitations. "
            }
            
            if (!$hasDCCredentialProtection) {
                $description += "Domain Controllers do not appear to have additional credential protection settings like LSA Protection enabled. "
            }
            
            $description += "This increases the risk of credential theft through memory dumping attacks."
            
            $finding = New-ArgusADFinding -Category "LateralMovement" `
                                        -Subcategory "Credential Caching and Harvesting Opportunities" `
                                        -Severity $severity `
                                        -Description $description `
                                        -RawData @{
                                            CredentialCachingGPOs = $credentialCachingGPOs
                                            DCCredentialProtection = $hasDCCredentialProtection
                                        } `
                                        -Impact "Windows caches credentials in memory by default, making them vulnerable to extraction by attackers using tools like Mimikatz. Without GPOs limiting credential caching or protecting credential storage, lateral movement becomes much easier after the initial compromise." `
                                        -AegisRemediation "AEGIS-AD can implement comprehensive credential protection GPOs that: limit cached credentials, disable WDigest, enable LSA Protection, and implement additional protections like Credential Guard where supported."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] Credential caching appears to be properly configured." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking credential caching: $_" -ForegroundColor Red
        return $null
    }
}

# Export functions
Export-ModuleMember -Function Invoke-MottaSecLateralMovementScan 