#
# MottaSec-PrivEsc.psm1
# Privilege Escalation Paths Module for Argus-AD
#
# Copyright (c) 2025 MottaSec
#

function Invoke-MottaSecPrivEscScan {
    <#
    .SYNOPSIS
        Scans for privilege escalation paths in Active Directory.
    
    .DESCRIPTION
        Checks for configurations in Active Directory that could lead to privilege escalation.
    
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
    
    Write-Host "[*] Starting Privilege Escalation Paths Scan..." -ForegroundColor Cyan
    
    # Check for excessive DCSync permissions
    $findings += Test-MottaSecExcessiveDCSync -DomainInfo $DomainInfo
    
    # Check for abusive ACLs on important objects
    $findings += Test-MottaSecAbusiveACLs -DomainInfo $DomainInfo
    
    # Check for AdminSDHolder tampering
    $findings += Test-MottaSecAdminSDHolder -DomainInfo $DomainInfo
    
    # Check for Kerberos delegation misconfigurations
    $findings += Test-MottaSecKerberosDelegation -DomainInfo $DomainInfo
    
    # Check for Resource-Based Constrained Delegation abuse
    $findings += Test-MottaSecRBCDAbuse -DomainInfo $DomainInfo
    
    # Check for Kerberoastable service accounts
    $findings += Test-MottaSecKerberoastableAccounts
    
    # Check for excessive membership in privileged groups
    $findings += Test-MottaSecExcessivePrivilegedMembership
    
    Write-Host "[+] Privilege Escalation Paths Scan completed. Found $($findings.Count) issues." -ForegroundColor Green
    
    return $findings
}

function Test-MottaSecExcessiveDCSync {
    <#
    .SYNOPSIS
        Checks for accounts with DCSync permissions.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if excessive permissions are found
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking for excessive DCSync permissions..." -ForegroundColor Cyan
    
    try {
        # Get domain object
        $domainDN = (Get-ADDomain).DistinguishedName
        
        # Get ACL of domain object
        $acl = Get-Acl -Path "AD:\$domainDN"
        
        # Rights that could enable DCSync
        $replicationRights = @(
            "DS-Replication-Get-Changes", # 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
            "DS-Replication-Get-Changes-All", # 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
            "DS-Replication-Get-Changes-In-Filtered-Set" # 89e95b76-444d-4c62-991a-0facbeda640c
        )
        
        # Get domain controllers' SIDs
        $dcSIDs = @()
        foreach ($dc in $DomainInfo.DomainControllers) {
            $dcObject = Get-ADComputer -Identity $dc.Name
            $dcSIDs += $dcObject.SID.Value
        }
        
        # Get expected service accounts that need replication rights
        $aadConnectAccounts = Get-ADUser -Filter "Name -like 'MSOL_*'" | Select-Object -ExpandProperty SID | ForEach-Object { $_.Value }
        
        # Add domain controller computer accounts and other known legit accounts
        $allowedSIDs = $dcSIDs + $aadConnectAccounts + @(
            "$($DomainInfo.DomainSID)-516", # Domain Controllers group
            "$($DomainInfo.DomainSID)-498", # Enterprise Read-Only Domain Controllers
            "S-1-5-32-544"                  # Administrators (Built-in)
        )
        
        # Check for unexpected accounts with replication rights
        $suspiciousAccounts = @()
        
        foreach ($ace in $acl.Access) {
            $rightName = $ace.ObjectType.ToString()
            
            if ($replicationRights -contains $rightName -or $rightName -eq "00000000-0000-0000-0000-000000000000") {
                $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                
                # Skip if this is an expected SID
                if ($allowedSIDs -contains $sid) {
                    continue
                }
                
                try {
                    $account = $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value
                    
                    $suspiciousAccounts += [PSCustomObject]@{
                        Account = $account
                        SID = $sid
                        Right = $rightName
                        AccessControlType = $ace.AccessControlType
                    }
                }
                catch {
                    # SID could not be translated to an account name
                    $suspiciousAccounts += [PSCustomObject]@{
                        Account = $sid
                        SID = $sid
                        Right = $rightName
                        AccessControlType = $ace.AccessControlType
                    }
                }
            }
        }
        
        if ($suspiciousAccounts.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "PrivilegeEscalation" `
                                        -Subcategory "Excessive DCSync Permissions" `
                                        -Severity "Critical" `
                                        -Description "Found $($suspiciousAccounts.Count) non-standard accounts with permissions that could allow DCSync attacks." `
                                        -RawData $suspiciousAccounts `
                                        -Impact "Accounts with these permissions can use the DCSync attack to extract password hashes for all domain accounts, including domain administrators and the KRBTGT account. This effectively gives complete access to the domain." `
                                        -AegisRemediation "AEGIS-AD can remove these excessive permissions, limiting replication rights to only domain controllers and specifically approved service accounts like Azure AD Connect."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No excessive DCSync permissions detected." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking DCSync permissions: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecAbusiveACLs {
    <#
    .SYNOPSIS
        Checks for abusive ACLs on important AD objects.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if abusive ACLs are found
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking for abusive ACLs on critical objects..." -ForegroundColor Cyan
    
    try {
        # Critical groups to check
        $criticalGroups = @(
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "Server Operators"
        )
        
        # Dangerous rights that could lead to privilege escalation
        $dangerousRights = @(
            "GenericAll",
            "GenericWrite",
            "WriteOwner",
            "WriteDACL",
            "WriteProperty",
            "Self"
        )
        
        $abusiveACLs = @()
        
        # Check ACLs on critical groups
        foreach ($groupName in $criticalGroups) {
            try {
                $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
                
                if ($null -ne $group) {
                    $acl = Get-Acl -Path "AD:\$($group.DistinguishedName)"
                    
                    # Get domain admins, enterprise admins SIDs for later comparison
                    $adminSIDs = @()
                    foreach ($adminGroup in $criticalGroups) {
                        try {
                            $adminGroupObj = Get-ADGroup -Identity $adminGroup -ErrorAction SilentlyContinue
                            if ($null -ne $adminGroupObj) {
                                $adminSIDs += $adminGroupObj.SID.Value
                            }
                        }
                        catch {
                            # Group not found, continue
                        }
                    }
                    
                    # Add built-in administrators
                    $adminSIDs += "S-1-5-32-544"
                    
                    # Add domain controllers
                    $adminSIDs += "$($DomainInfo.DomainSID)-516"
                    
                    # Add system
                    $adminSIDs += "S-1-5-18"
                    
                    foreach ($ace in $acl.Access) {
                        foreach ($rightName in $dangerousRights) {
                            if ($ace.ActiveDirectoryRights -match $rightName) {
                                try {
                                    $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                                    
                                    # Skip if this is an expected admin account
                                    if ($adminSIDs -contains $sid) {
                                        continue
                                    }
                                    
                                    $account = $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value
                                    
                                    $abusiveACLs += [PSCustomObject]@{
                                        ObjectName = $group.Name
                                        ObjectDN = $group.DistinguishedName
                                        Account = $account
                                        SID = $sid
                                        Right = $ace.ActiveDirectoryRights
                                        AccessControlType = $ace.AccessControlType
                                    }
                                }
                                catch {
                                    # SID could not be translated or other error
                                    # Still add it with the SID if possible
                                    try {
                                        $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                                        
                                        $abusiveACLs += [PSCustomObject]@{
                                            ObjectName = $group.Name
                                            ObjectDN = $group.DistinguishedName
                                            Account = $sid
                                            SID = $sid
                                            Right = $ace.ActiveDirectoryRights
                                            AccessControlType = $ace.AccessControlType
                                        }
                                    }
                                    catch {
                                        # Continue to next ACE
                                    }
                                }
                                
                                # Break the inner loop once we've recorded this ACE
                                break
                            }
                        }
                    }
                }
            }
            catch {
                Write-Host "[!] Failed to check ACLs for group ${groupName}: ${_}" -ForegroundColor Yellow
                continue
            }
        }
        
        # Also check domain object
        $domainDN = (Get-ADDomain).DistinguishedName
        $acl = Get-Acl -Path "AD:\$domainDN"
        
        foreach ($ace in $acl.Access) {
            foreach ($rightName in $dangerousRights) {
                if ($ace.ActiveDirectoryRights -match $rightName) {
                    try {
                        $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        
                        # Skip if this is an expected admin account
                        if ($adminSIDs -contains $sid) {
                            continue
                        }
                        
                        $account = $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value
                        
                        $abusiveACLs += [PSCustomObject]@{
                            ObjectName = "Domain Root"
                            ObjectDN = $domainDN
                            Account = $account
                            SID = $sid
                            Right = $ace.ActiveDirectoryRights
                            AccessControlType = $ace.AccessControlType
                        }
                    }
                    catch {
                        # Continue to next ACE
                    }
                    
                    # Break the inner loop once we've recorded this ACE
                    break
                }
            }
        }
        
        if ($abusiveACLs.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "PrivilegeEscalation" `
                                        -Subcategory "Abusive ACLs on Critical Objects" `
                                        -Severity "Critical" `
                                        -Description "Found $($abusiveACLs.Count) potentially abusive Access Control Entries on critical AD objects that could lead to privilege escalation." `
                                        -RawData $abusiveACLs `
                                        -Impact "These ACLs grant non-administrative accounts permissions to modify critical groups or objects. Attackers could exploit these permissions to add themselves to privileged groups or change security settings, leading to domain compromise." `
                                        -AegisRemediation "AEGIS-AD can review and remediate these excessive permissions, implementing least-privilege ACLs on all critical AD objects and monitoring for ACL changes."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No abusive ACLs detected on critical AD objects." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking abusive ACLs: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecAdminSDHolder {
    <#
    .SYNOPSIS
        Checks for AdminSDHolder tampering.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if AdminSDHolder has been tampered with
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking for AdminSDHolder tampering..." -ForegroundColor Cyan
    
    try {
        # Get AdminSDHolder object
        $domainDN = (Get-ADDomain).DistinguishedName
        $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
        
        # Get ACL of AdminSDHolder
        $acl = Get-Acl -Path "AD:\$adminSDHolderDN"
        
        # Dangerous rights that could lead to privilege escalation
        $dangerousRights = @(
            "GenericAll",
            "GenericWrite",
            "WriteOwner",
            "WriteDACL",
            "WriteProperty"
        )
        
        # Expected admin SIDs that should have rights
        $adminSIDs = @(
            "$($DomainInfo.DomainSID)-512", # Domain Admins
            "$($DomainInfo.DomainSID)-519", # Enterprise Admins
            "$($DomainInfo.DomainSID)-516", # Domain Controllers
            "S-1-5-32-544",                 # Administrators (Built-in)
            "S-1-5-18"                      # System
        )
        
        $suspiciousACEs = @()
        
        foreach ($ace in $acl.Access) {
            foreach ($rightName in $dangerousRights) {
                if ($ace.ActiveDirectoryRights -match $rightName) {
                    try {
                        $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        
                        # Skip if this is an expected admin account
                        if ($adminSIDs -contains $sid) {
                            continue
                        }
                        
                        $account = $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value
                        
                        $suspiciousACEs += [PSCustomObject]@{
                            Account = $account
                            SID = $sid
                            Right = $ace.ActiveDirectoryRights
                            AccessControlType = $ace.AccessControlType
                        }
                    }
                    catch {
                        # Try to at least record the SID
                        try {
                            $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                            
                            $suspiciousACEs += [PSCustomObject]@{
                                Account = $sid
                                SID = $sid
                                Right = $ace.ActiveDirectoryRights
                                AccessControlType = $ace.AccessControlType
                            }
                        }
                        catch {
                            # Continue to next ACE
                        }
                    }
                    
                    # Break the inner loop once we've recorded this ACE
                    break
                }
            }
        }
        
        # Also check for accounts with AdminCount=1 but not in protected groups
        $protectedGroupSIDs = @(
            "$($DomainInfo.DomainSID)-512", # Domain Admins
            "$($DomainInfo.DomainSID)-519", # Enterprise Admins
            "$($DomainInfo.DomainSID)-518", # Schema Admins
            "$($DomainInfo.DomainSID)-516", # Domain Controllers
            "S-1-5-32-544",                 # Administrators
            "S-1-5-32-548",                 # Account Operators
            "S-1-5-32-549",                 # Server Operators
            "S-1-5-32-550",                 # Print Operators
            "S-1-5-32-551"                  # Backup Operators
        )
        
        $adminCountUsers = Get-ADUser -Filter 'AdminCount -eq 1' -Properties AdminCount, MemberOf
        $suspiciousAdminCountUsers = @()
        
        foreach ($user in $adminCountUsers) {
            $inProtectedGroup = $false
            
            # Get the user's group memberships
            $groupMemberships = $user.MemberOf | ForEach-Object {
                Get-ADGroup -Identity $_ -Properties ObjectSID 
            }
            
            # Check if the user is in any protected group
            foreach ($group in $groupMemberships) {
                if ($protectedGroupSIDs -contains $group.ObjectSID.Value) {
                    $inProtectedGroup = $true
                    break
                }
            }
            
            if (-not $inProtectedGroup) {
                $suspiciousAdminCountUsers += [PSCustomObject]@{
                    Name = $user.Name
                    UserPrincipalName = $user.UserPrincipalName
                    DistinguishedName = $user.DistinguishedName
                    SID = $user.ObjectSID.Value
                }
            }
        }
        
        if ($suspiciousACEs.Count -gt 0 -or $suspiciousAdminCountUsers.Count -gt 0) {
            $severity = "Critical"
            $description = ""
            
            if ($suspiciousACEs.Count -gt 0) {
                $description += "Found $($suspiciousACEs.Count) suspicious Access Control Entries on the AdminSDHolder object. "
            }
            
            if ($suspiciousAdminCountUsers.Count -gt 0) {
                $description += "Found $($suspiciousAdminCountUsers.Count) users with AdminCount=1 that are not members of any protected groups. "
            }
            
            $description += "These issues could indicate AdminSDHolder tampering, which affects the security of all privileged accounts."
            
            $finding = New-ArgusADFinding -Category "PrivilegeEscalation" `
                                        -Subcategory "AdminSDHolder Tampering" `
                                        -Severity $severity `
                                        -Description $description `
                                        -RawData @{ 
                                            SuspiciousACEs = $suspiciousACEs
                                            SuspiciousAdminCountUsers = $suspiciousAdminCountUsers
                                        } `
                                        -Impact "AdminSDHolder controls the permissions of all privileged accounts in the domain. Tampering can allow persistent backdoor access to privileged accounts, even if the attacker is removed from privileged groups." `
                                        -AegisRemediation "AEGIS-AD can restore the AdminSDHolder object to its default secure state, remove unauthorized AdminCount flags, and implement monitoring for AdminSDHolder changes."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No AdminSDHolder tampering detected." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking AdminSDHolder: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecKerberosDelegation {
    <#
    .SYNOPSIS
        Checks for Kerberos delegation misconfigurations.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if delegation issues are found
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking for Kerberos delegation misconfigurations..." -ForegroundColor Cyan
    
    try {
        $findings = @()
        
        # Check for unconstrained delegation
        $unconstrainedDelegationComputers = Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties DNSHostName, Description, msDS-AllowedToDelegateTo, ServicePrincipalName
        $unconstrainedDelegationUsers = Get-ADUser -Filter 'TrustedForDelegation -eq $true' -Properties DisplayName, Description, msDS-AllowedToDelegateTo, ServicePrincipalName
        
        if ($unconstrainedDelegationComputers.Count -gt 0 -or $unconstrainedDelegationUsers.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "PrivilegeEscalation" `
                                        -Subcategory "Unconstrained Kerberos Delegation" `
                                        -Severity "High" `
                                        -Description "Found $($unconstrainedDelegationComputers.Count) computers and $($unconstrainedDelegationUsers.Count) user accounts with unconstrained Kerberos delegation enabled." `
                                        -RawData @{
                                            Computers = $unconstrainedDelegationComputers
                                            Users = $unconstrainedDelegationUsers
                                        } `
                                        -Impact "Unconstrained delegation allows a compromised server to capture authentication tickets (TGTs) from any user that connects to it, including domain administrators. An attacker who controls such a server can impersonate any user to any service in the domain." `
                                        -AegisRemediation "AEGIS-AD can identify systems that legitimately need delegation, convert them to constrained delegation, and disable unconstrained delegation across the environment."
            
            Write-MottaSecFinding -Finding $finding
            $findings += $finding
        }
        
        # Check for constrained delegation to sensitive services
        $sensitiveDelegationTargets = @(
            "*LDAP*", # LDAP service on domain controllers
            "*CIFS*", # File services
            "*HOST*", # Various Windows services
            "*RPCSS*", # RPC services
            "*WSMAN*"  # WinRM services
        )
        
        # Get computers with constrained delegation
        $constrainedDelegationComputers = Get-ADComputer -Filter 'msDS-AllowedToDelegateTo -like "*"' -Properties DNSHostName, Description, msDS-AllowedToDelegateTo
        
        # Get users with constrained delegation
        $constrainedDelegationUsers = Get-ADUser -Filter 'msDS-AllowedToDelegateTo -like "*"' -Properties DisplayName, Description, msDS-AllowedToDelegateTo
        
        $sensitiveConstrainedDelegation = @()
        
        # Check computers
        foreach ($computer in $constrainedDelegationComputers) {
            foreach ($delegationTarget in $computer.'msDS-AllowedToDelegateTo') {
                foreach ($sensitiveTarget in $sensitiveDelegationTargets) {
                    if ($delegationTarget -like $sensitiveTarget) {
                        $sensitiveConstrainedDelegation += [PSCustomObject]@{
                            AccountName = $computer.Name
                            AccountType = "Computer"
                            DelegationTarget = $delegationTarget
                            DNSHostName = $computer.DNSHostName
                            Description = $computer.Description
                        }
                        break
                    }
                }
            }
        }
        
        # Check users
        foreach ($user in $constrainedDelegationUsers) {
            foreach ($delegationTarget in $user.'msDS-AllowedToDelegateTo') {
                foreach ($sensitiveTarget in $sensitiveDelegationTargets) {
                    if ($delegationTarget -like $sensitiveTarget) {
                        $sensitiveConstrainedDelegation += [PSCustomObject]@{
                            AccountName = $user.Name
                            AccountType = "User"
                            DelegationTarget = $delegationTarget
                            UserPrincipalName = $user.UserPrincipalName
                            Description = $user.Description
                        }
                        break
                    }
                }
            }
        }
        
        if ($sensitiveConstrainedDelegation.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "PrivilegeEscalation" `
                                        -Subcategory "Sensitive Constrained Delegation" `
                                        -Severity "High" `
                                        -Description "Found $($sensitiveConstrainedDelegation.Count) accounts configured for constrained delegation to sensitive services like LDAP, CIFS, or HOST on domain controllers or servers." `
                                        -RawData $sensitiveConstrainedDelegation `
                                        -Impact "Constrained delegation to sensitive services can allow an attacker who compromises the delegating account to access critical services on domain controllers or servers. This could lead to domain compromise if the delegation targets include services like LDAP on a domain controller." `
                                        -AegisRemediation "AEGIS-AD can review and reconfigure these delegation settings to follow the principle of least privilege, ensuring only necessary services are accessible via delegation."
            
            Write-MottaSecFinding -Finding $finding
            $findings += $finding
        }
        
        # Return combined findings
        if ($findings.Count -gt 0) {
            return $findings
        }
        
        Write-Host "[+] No Kerberos delegation misconfigurations detected." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking Kerberos delegation: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecRBCDAbuse {
    <#
    .SYNOPSIS
        Checks for Resource-Based Constrained Delegation misconfigurations.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if RBCD issues are found
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking for Resource-Based Constrained Delegation misconfigurations..." -ForegroundColor Cyan
    
    try {
        # Get all computer accounts with msDS-AllowedToActOnBehalfOfOtherIdentity set
        $rbcdComputers = Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like "*"} -Properties DNSHostName, msDS-AllowedToActOnBehalfOfOtherIdentity, Description
        
        # Get domain controller names for later comparison
        $dcNames = $DomainInfo.DomainControllers | ForEach-Object { $_.Name }
        
        $rbcdIssues = @()
        
        foreach ($computer in $rbcdComputers) {
            # Check if this is a domain controller
            $isDC = $dcNames -contains $computer.Name
            
            # Parse the security descriptor to get the delegated principals
            $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($computer.'msDS-AllowedToActOnBehalfOfOtherIdentity', 0)
            
            foreach ($ace in $sd.DiscretionaryAcl) {
                try {
                    $sid = $ace.SecurityIdentifier
                    $principal = $sid.Translate([System.Security.Principal.NTAccount]).Value
                    
                    # Check if this is a regular user or suspicious account
                    try {
                        $account = Get-ADUser -Identity $sid -ErrorAction SilentlyContinue
                        $accountType = "User"
                    }
                    catch {
                        try {
                            $account = Get-ADComputer -Identity $sid -ErrorAction SilentlyContinue
                            $accountType = "Computer"
                        }
                        catch {
                            $accountType = "Unknown"
                        }
                    }
                    
                    # If this is a DC or the delegated account type is suspicious for the target, flag it
                    if ($isDC -or $accountType -eq "User") {
                        $rbcdIssues += [PSCustomObject]@{
                            ComputerName = $computer.Name
                            IsDomainController = $isDC
                            DelegatedPrincipal = $principal
                            PrincipalSID = $sid.Value
                            PrincipalType = $accountType
                            DNSHostName = $computer.DNSHostName
                            Description = $computer.Description
                        }
                    }
                }
                catch {
                    # Could not translate SID, still log it
                    $rbcdIssues += [PSCustomObject]@{
                        ComputerName = $computer.Name
                        IsDomainController = $isDC
                        DelegatedPrincipal = $ace.SecurityIdentifier.Value
                        PrincipalSID = $ace.SecurityIdentifier.Value
                        PrincipalType = "Unknown"
                        DNSHostName = $computer.DNSHostName
                        Description = $computer.Description
                    }
                }
            }
        }
        
        if ($rbcdIssues.Count -gt 0) {
            # Check if any of these issues involve domain controllers
            $dcIssues = $rbcdIssues | Where-Object { $_.IsDomainController -eq $true }
            
            $severity = "High"
            if ($dcIssues.Count -gt 0) {
                $severity = "Critical"
            }
            
            $finding = New-ArgusADFinding -Category "PrivilegeEscalation" `
                                        -Subcategory "Resource-Based Constrained Delegation Abuse" `
                                        -Severity $severity `
                                        -Description "Found $($rbcdIssues.Count) potentially risky Resource-Based Constrained Delegation configurations, of which $($dcIssues.Count) involve domain controllers." `
                                        -RawData $rbcdIssues `
                                        -Impact "Resource-Based Constrained Delegation allows the delegated principals to impersonate any domain user (including administrators) when accessing the target computer. If the target is a domain controller or other sensitive server, this can lead to domain compromise." `
                                        -AegisRemediation "AEGIS-AD can audit and remove unnecessary RBCD configurations, especially those involving domain controllers or delegating to user accounts."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No Resource-Based Constrained Delegation misconfigurations detected." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking Resource-Based Constrained Delegation: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecKerberoastableAccounts {
    <#
    .SYNOPSIS
        Checks for Kerberoastable service accounts.
    
    .OUTPUTS
        Finding object if vulnerable service accounts are found
    #>
    
    Write-Host "[*] Checking for Kerberoastable service accounts..." -ForegroundColor Cyan
    
    try {
        # Get all user accounts with Service Principal Names (SPNs)
        $kerberoastableUsers = Get-ADUser -Filter {ServicePrincipalName -like "*" -and Enabled -eq $true} -Properties ServicePrincipalName, Description, PasswordLastSet, memberOf
        
        # Check if any of these users are members of privileged groups
        $privilegedGroups = @(
            "*Domain Admins*",
            "*Enterprise Admins*",
            "*Schema Admins*",
            "*Administrators*",
            "*Backup Operators*",
            "*Account Operators*",
            "*Server Operators*"
        )
        
        $privilegedKerberoastableUsers = @()
        $staleKerberoastableUsers = @()
        
        foreach ($user in $kerberoastableUsers) {
            # Check for membership in privileged groups
            $isPrivileged = $false
            
            foreach ($group in $user.memberOf) {
                foreach ($pattern in $privilegedGroups) {
                    if ($group -like $pattern) {
                        $isPrivileged = $true
                        $privilegedKerberoastableUsers += $user
                        break
                    }
                }
                
                if ($isPrivileged) {
                    break
                }
            }
            
            # Check for old password
            $passwordStaleThreshold = (Get-Date).AddDays(-90)
            if ($user.PasswordLastSet -lt $passwordStaleThreshold) {
                $staleKerberoastableUsers += $user
            }
        }
        
        if ($kerberoastableUsers.Count -gt 0) {
            $severity = "Medium"
            
            if ($privilegedKerberoastableUsers.Count -gt 0) {
                $severity = "Critical"
            }
            elseif ($staleKerberoastableUsers.Count -gt 0) {
                $severity = "High"
            }
            
            $finding = New-ArgusADFinding -Category "PrivilegeEscalation" `
                                        -Subcategory "Kerberoastable Service Accounts" `
                                        -Severity $severity `
                                        -Description "Found $($kerberoastableUsers.Count) user accounts with Service Principal Names (SPNs) that are vulnerable to Kerberoasting. Of these, $($privilegedKerberoastableUsers.Count) are members of privileged groups and $($staleKerberoastableUsers.Count) have passwords older than 90 days." `
                                        -RawData @{
                                            AllUsers = $kerberoastableUsers | Select-Object Name, UserPrincipalName, SamAccountName, PasswordLastSet, Description, ServicePrincipalName
                                            PrivilegedUsers = $privilegedKerberoastableUsers | Select-Object Name, UserPrincipalName, SamAccountName, PasswordLastSet, Description, ServicePrincipalName
                                            StaleUsers = $staleKerberoastableUsers | Select-Object Name, UserPrincipalName, SamAccountName, PasswordLastSet, Description, ServicePrincipalName
                                        } `
                                        -Impact "Kerberoastable accounts can have their passwords cracked offline after requesting service tickets. If these accounts have weak passwords or are privileged, attackers can gain elevated access in the domain." `
                                        -AegisRemediation "AEGIS-AD can convert legacy service accounts to Group Managed Service Accounts (gMSAs) which use complex, automatically rotated passwords, and remove unnecessary SPNs from user accounts."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No vulnerable Kerberoastable accounts detected." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking Kerberoastable accounts: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecExcessivePrivilegedMembership {
    <#
    .SYNOPSIS
        Checks for excessive membership in privileged groups.
    
    .OUTPUTS
        Finding object if excessive memberships are found
    #>
    
    Write-Host "[*] Checking for excessive membership in privileged groups..." -ForegroundColor Cyan
    
    try {
        # Define privileged groups to check
        $privilegedGroups = @(
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators"
        )
        
        # Define secondary privileged groups
        $secondaryPrivilegedGroups = @(
            "Account Operators",
            "Backup Operators",
            "Server Operators",
            "Print Operators",
            "DnsAdmins"
        )
        
        $allPrivilegedGroups = $privilegedGroups + $secondaryPrivilegedGroups
        
        # Thresholds for different environment sizes
        # Small environments (<1000 users): 3-5 Domain Admins
        # Medium environments (1000-5000 users): 5-7 Domain Admins
        # Large environments (>5000 users): 7-10 Domain Admins
        
        # Get total user count to determine environment size
        $totalUsers = (Get-ADUser -Filter * -ResultSetSize 1).Count
        
        # Set threshold based on environment size
        $thresholds = @{
            "Domain Admins" = if ($totalUsers -lt 1000) { 5 } elseif ($totalUsers -lt 5000) { 7 } else { 10 }
            "Enterprise Admins" = if ($totalUsers -lt 1000) { 3 } elseif ($totalUsers -lt 5000) { 5 } else { 7 }
            "Schema Admins" = if ($totalUsers -lt 1000) { 2 } elseif ($totalUsers -lt 5000) { 3 } else { 5 }
            "Administrators" = if ($totalUsers -lt 1000) { 7 } elseif ($totalUsers -lt 5000) { 10 } else { 15 }
        }
        
        $groupStats = @()
        $excessiveGroups = @()
        $serviceAccountsInPrivilegedGroups = @()
        $dormantUsersInPrivilegedGroups = @()
        
        # Check membership of each privileged group
        foreach ($groupName in $allPrivilegedGroups) {
            try {
                $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
                
                if ($null -ne $group) {
                    $members = Get-ADGroupMember -Identity $groupName -Recursive | Where-Object { $_.objectClass -eq 'user' }
                    
                    # Record group stats
                    $groupStat = [PSCustomObject]@{
                        GroupName = $groupName
                        MemberCount = $members.Count
                        IsExcessive = $false
                    }
                    
                    # Check if this is a primary privileged group and if it exceeds threshold
                    if ($privilegedGroups -contains $groupName -and $thresholds.ContainsKey($groupName) -and $members.Count -gt $thresholds[$groupName]) {
                        $groupStat.IsExcessive = $true
                        $excessiveGroups += $groupStat
                    }
                    
                    $groupStats += $groupStat
                    
                    # Check for service accounts (based on naming conventions)
                    $serviceAccountPatterns = @(
                        "*svc*",
                        "*service*",
                        "*_sa",
                        "*-sa",
                        "*admin*", # This is general and might catch legitimate admin accounts
                        "*bot*",
                        "*app*"
                    )
                    
                    foreach ($member in $members) {
                        $user = Get-ADUser -Identity $member.SamAccountName -Properties Name, Description, ServicePrincipalName, LastLogonDate, PasswordLastSet
                        
                        # Check if this looks like a service account
                        foreach ($pattern in $serviceAccountPatterns) {
                            if ($user.SamAccountName -like $pattern -or ($null -ne $user.ServicePrincipalName -and $user.ServicePrincipalName.Count -gt 0)) {
                                $serviceAccountsInPrivilegedGroups += [PSCustomObject]@{
                                    UserName = $user.Name
                                    SamAccountName = $user.SamAccountName
                                    Description = $user.Description
                                    GroupName = $groupName
                                    HasSPN = ($null -ne $user.ServicePrincipalName -and $user.ServicePrincipalName.Count -gt 0)
                                }
                                break
                            }
                        }
                        
                        # Check for dormant users (haven't logged in recently)
                        $dormantThreshold = (Get-Date).AddDays(-45)
                        if ($null -ne $user.LastLogonDate -and $user.LastLogonDate -lt $dormantThreshold) {
                            $dormantUsersInPrivilegedGroups += [PSCustomObject]@{
                                UserName = $user.Name
                                SamAccountName = $user.SamAccountName
                                LastLogon = $user.LastLogonDate
                                PasswordLastSet = $user.PasswordLastSet
                                GroupName = $groupName
                            }
                        }
                    }
                }
            }
            catch {
                Write-Host "[!] Failed to check membership for group ${groupName}: ${_}" -ForegroundColor Yellow
                continue
            }
        }
        
        $findings = @()
        
        # Check for excessive group membership
        if ($excessiveGroups.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "PrivilegeEscalation" `
                                        -Subcategory "Excessive Membership in Privileged Groups" `
                                        -Severity "High" `
                                        -Description "Found $($excessiveGroups.Count) privileged groups with an unusually high number of members, which violates the principle of least privilege." `
                                        -RawData @{
                                            ExcessiveGroups = $excessiveGroups
                                            AllGroupStats = $groupStats
                                        } `
                                        -Impact "Excessive privileged group membership increases the attack surface and the likelihood of compromise. Each additional member represents another potential entry point for attackers to gain highly privileged access." `
                                        -AegisRemediation "AEGIS-AD can review privileged group memberships, implement a tiered administration model, and establish processes for just-in-time privilege elevation rather than permanent membership."
            
            Write-MottaSecFinding -Finding $finding
            $findings += $finding
        }
        
        # Check for service accounts in privileged groups
        if ($serviceAccountsInPrivilegedGroups.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "PrivilegeEscalation" `
                                        -Subcategory "Service Accounts in Privileged Groups" `
                                        -Severity "High" `
                                        -Description "Found $($serviceAccountsInPrivilegedGroups.Count) apparent service accounts that are members of highly privileged groups." `
                                        -RawData $serviceAccountsInPrivilegedGroups `
                                        -Impact "Service accounts in privileged groups pose a serious security risk as they often have weaker passwords, may run on less secure systems, and are frequent targets for attackers. Compromising such an account grants immediate privileged access." `
                                        -AegisRemediation "AEGIS-AD can remove service accounts from privileged groups and implement a least-privilege model using dedicated task-specific accounts with only the permissions they need."
            
            Write-MottaSecFinding -Finding $finding
            $findings += $finding
        }
        
        # Check for dormant users in privileged groups
        if ($dormantUsersInPrivilegedGroups.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "PrivilegeEscalation" `
                                        -Subcategory "Dormant Users in Privileged Groups" `
                                        -Severity "Medium" `
                                        -Description "Found $($dormantUsersInPrivilegedGroups.Count) user accounts in privileged groups that have not logged in for at least 45 days." `
                                        -RawData $dormantUsersInPrivilegedGroups `
                                        -Impact "Dormant privileged accounts often indicate abandoned accounts or excessive permissions. These accounts may have outdated passwords and are unlikely to be monitored, making them ideal targets for compromise." `
                                        -AegisRemediation "AEGIS-AD can identify and remove dormant users from privileged groups, implementing regular access reviews to ensure only currently needed accounts retain privileges."
            
            Write-MottaSecFinding -Finding $finding
            $findings += $finding
        }
        
        if ($findings.Count -gt 0) {
            return $findings
        }
        
        Write-Host "[+] No excessive memberships in privileged groups detected." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for excessive privileged group membership: $_" -ForegroundColor Red
        return $null
    }
}

# Export functions
Export-ModuleMember -Function Invoke-MottaSecPrivEscScan 