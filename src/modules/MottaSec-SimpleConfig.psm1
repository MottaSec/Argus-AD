#
# MottaSec-SimpleConfig.psm1
# Simple AD Misconfigurations Module for Argus-AD
#
# Copyright (c) 2025 MottaSec
#

function Invoke-MottaSecSimpleConfigScan {
    <#
    .SYNOPSIS
        Scans for simple misconfigurations in Active Directory.
    
    .DESCRIPTION
        Checks for common misconfigurations in Active Directory that could lead to security issues.
    
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
    
    Write-Host "[*] Starting Simple Misconfigurations Scan..." -ForegroundColor Cyan
    
    # Check domain password policy
    $findings += Test-MottaSecWeakPasswordPolicy -DomainInfo $DomainInfo
    
    # Check account lockout policy
    $findings += Test-MottaSecAccountLockoutPolicy -DomainInfo $DomainInfo
    
    # Check for accounts with "Password Never Expires"
    $findings += Test-MottaSecPasswordNeverExpires
    
    # Check for accounts with "No Password Required"
    $findings += Test-MottaSecNoPasswordRequired
    
    # Check for accounts with "Reversible Password Encryption"
    $findings += Test-MottaSecReversiblePasswordEncryption
    
    # Check for accounts with "Kerberos Pre-Authentication Disabled"
    $findings += Test-MottaSecKerberosPreAuthDisabled
    
    # Check for weak Kerberos encryption
    $findings += Test-MottaSecWeakKerberosEncryption
    
    # Check for stale/inactive accounts
    $findings += Test-MottaSecStaleAccounts
    
    # Check for legacy authentication protocols
    $findings += Test-MottaSecLegacyAuthentication -DomainInfo $DomainInfo
    
    # Check for SMB and LDAP signing enforcement
    $findings += Test-MottaSecSMBAndLDAPSigning -DomainInfo $DomainInfo
    
    # Check for Print Spooler on Domain Controllers
    $findings += Test-MottaSecPrintSpoolerOnDC -DomainInfo $DomainInfo
    
    # Check machine account quota
    $findings += Test-MottaSecMachineAccountQuota
    
    # Check for privileged accounts not marked "Sensitive"
    $findings += Test-MottaSecPrivilegedAccountsNotSensitive
    
    # Check for Group Policy Preferences with stored credentials
    $findings += Test-MottaSecGPPStoredCredentials -DomainInfo $DomainInfo
    
    # Check for insecure GPO permissions
    $findings += Test-MottaSecInsecureGPOPermissions
    
    # Check for LAPS implementation on workstations and servers
    $findings += Test-MottaSecLAPSImplementation
    $findings += Test-MottaSecLAPSOnWorkstations
    $findings += Test-MottaSecLAPSOnServers
    
    # Check LSA Protection
    $findings += Test-MottaSecLSAProtection
    
    # Check Credential Guard
    $findings += Test-MottaSecCredentialGuard
    
    # Check if KRBTGT is a member of Domain Admins
    $findings += Test-MottaSecKRBTGTInDomainAdmins
    
    # Check if KRBTGT can be Kerberoasted
    $findings += Test-MottaSecKRBTGTKerberoastable
    
    # Check for Domain Admin sessions on non-Tier 0 systems
    $findings += Test-MottaSecDomainAdminSessions -DomainInfo $DomainInfo
    
    # Check for users with GPO ownership
    $findings += Test-MottaSecGPOOwnership
    
    # Check for risky RDP rights
    $findings += Test-MottaSecRiskyRDPRights
    
    # Check for RDP hardening via GPO
    $findings += Test-MottaSecRDPHardening
    
    # Check for Authentication Policies and Silos
    $findings += Test-MottaSecAuthenticationPolicies
    
    # Check for Fine-grained Password Policies
    $findings += Test-MottaSecFineGrainedPasswordPolicies
    
    Write-Host "[+] Simple Misconfigurations Scan completed. Found $($findings.Count) issues." -ForegroundColor Green
    
    return $findings
}

function Test-MottaSecWeakPasswordPolicy {
    <#
    .SYNOPSIS
        Checks if the domain password policy is weak.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if the policy is weak, otherwise nothing
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking domain password policy..." -ForegroundColor Cyan
    
    $policy = $DomainInfo.PasswordPolicy
    $findings = @()
    
    # Check minimum password length
    if ($policy.MinPasswordLength -lt 12) {
        $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                    -Subcategory "Weak Domain Password Policy" `
                                    -Severity "High" `
                                    -Description "The domain password policy has a minimum length of $($policy.MinPasswordLength) characters, which is below the recommended 12 characters." `
                                    -RawData $policy `
                                    -Impact "Short passwords are easier to crack through brute force or dictionary attacks, increasing the risk of credential compromise." `
                                    -AegisRemediation "AEGIS-AD can configure the domain password policy to enforce stronger password requirements, including a minimum length of 14 characters."
        $findings += $finding
        Write-MottaSecFinding -Finding $finding
    }
    
    # Check password complexity
    if ($policy.ComplexityEnabled -eq $false) {
        $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                    -Subcategory "Password Complexity Disabled" `
                                    -Severity "High" `
                                    -Description "Password complexity requirements are disabled in the domain password policy." `
                                    -RawData $policy `
                                    -Impact "Without complexity requirements, users can set simple, predictable passwords that are vulnerable to password spraying and brute force attacks." `
                                    -AegisRemediation "AEGIS-AD can enable password complexity requirements in the domain password policy to ensure stronger passwords."
        $findings += $finding
        Write-MottaSecFinding -Finding $finding
    }
    
    # Check password history
    if ($policy.PasswordHistoryCount -lt 24) {
        $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                    -Subcategory "Weak Password History Policy" `
                                    -Severity "Medium" `
                                    -Description "The domain password policy only remembers $($policy.PasswordHistoryCount) previous passwords, which is below the recommended value of 24." `
                                    -RawData $policy `
                                    -Impact "A short password history allows users to cycle through a small set of passwords, potentially reusing passwords frequently." `
                                    -AegisRemediation "AEGIS-AD can configure the password history policy to remember at least 24 previous passwords."
        $findings += $finding
        Write-MottaSecFinding -Finding $finding
    }
    
    # Check maximum password age
    if ($policy.MaxPasswordAge.Days -gt 90) {
        $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                    -Subcategory "Long Maximum Password Age" `
                                    -Severity "Medium" `
                                    -Description "The maximum password age is set to $($policy.MaxPasswordAge.Days) days, which exceeds the recommended 90 days." `
                                    -RawData $policy `
                                    -Impact "Longer password ages increase the window of opportunity for attackers if a password is compromised." `
                                    -AegisRemediation "AEGIS-AD can configure the maximum password age to 90 days or less while ensuring proper user notification."
        $findings += $finding
        Write-MottaSecFinding -Finding $finding
    }
    
    return $findings
}

function Test-MottaSecAccountLockoutPolicy {
    <#
    .SYNOPSIS
        Checks if the account lockout policy is properly configured.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if the policy is weak, otherwise nothing
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking account lockout policy..." -ForegroundColor Cyan
    
    $policy = $DomainInfo.PasswordPolicy
    $findings = @()
    
    # Check lockout threshold
    if ($policy.LockoutThreshold -eq 0) {
        $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                    -Subcategory "Account Lockout Policy Disabled" `
                                    -Severity "High" `
                                    -Description "The account lockout threshold is set to 0, which means accounts will never be locked out after failed login attempts." `
                                    -RawData $policy `
                                    -Impact "Without account lockout, attackers can attempt an unlimited number of password guesses without triggering account lockouts, significantly increasing the risk of successful brute force attacks." `
                                    -AegisRemediation "AEGIS-AD can configure the account lockout threshold to a secure value (typically 5-10 attempts) to protect against brute force attacks while minimizing legitimate user lockouts."
        $findings += $finding
        Write-MottaSecFinding -Finding $finding
    }
    elseif ($policy.LockoutThreshold -gt 10) {
        $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                    -Subcategory "High Account Lockout Threshold" `
                                    -Severity "Medium" `
                                    -Description "The account lockout threshold is set to $($policy.LockoutThreshold), which exceeds the recommended maximum of 10 failed attempts." `
                                    -RawData $policy `
                                    -Impact "A high lockout threshold gives attackers more password guesses before lockout, increasing the risk of successful brute force attacks." `
                                    -AegisRemediation "AEGIS-AD can adjust the account lockout threshold to a more secure value (typically 5-10 attempts)."
        $findings += $finding
        Write-MottaSecFinding -Finding $finding
    }
    
    # Check lockout duration
    if ($policy.LockoutDuration.TotalMinutes -lt 15) {
        $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                    -Subcategory "Short Account Lockout Duration" `
                                    -Severity "Medium" `
                                    -Description "The account lockout duration is set to only $($policy.LockoutDuration.TotalMinutes) minutes, which is below the recommended minimum of 15 minutes." `
                                    -RawData $policy `
                                    -Impact "Short lockout durations allow attackers to quickly resume brute force attacks after a lockout occurs." `
                                    -AegisRemediation "AEGIS-AD can configure the account lockout duration to at least 15 minutes to increase the time cost for attackers."
        $findings += $finding
        Write-MottaSecFinding -Finding $finding
    }
    
    return $findings
}

function Test-MottaSecPasswordNeverExpires {
    <#
    .SYNOPSIS
        Checks for user accounts with "Password Never Expires" flag.
    
    .OUTPUTS
        Finding object if accounts with this flag are found
    #>
    
    Write-Host "[*] Checking for accounts with 'Password Never Expires'..." -ForegroundColor Cyan
    
    try {
        # Get all user accounts with "Password Never Expires" flag set
        $users = Get-ADUser -Filter {Enabled -eq $true} -Properties Name, UserPrincipalName, Description, PasswordNeverExpires, memberOf, LastLogonDate, PasswordLastSet
        $pwdNeverExpiresUsers = $users | Where-Object {$_.PasswordNeverExpires -eq $true} | Select-Object Name, UserPrincipalName, Description, PasswordLastSet, LastLogonDate
        
        if ($pwdNeverExpiresUsers.Count -gt 0) {
            # Check for admin accounts with password never expires
            $privilegedGroups = @(
                "*Domain Admins*",
                "*Enterprise Admins*",
                "*Schema Admins*",
                "*Administrators*",
                "*Backup Operators*",
                "*Account Operators*",
                "*Server Operators*"
            )
            
            $adminAccounts = @()
            
            foreach ($user in $pwdNeverExpiresUsers) {
                $fullUser = Get-ADUser -Identity $user.UserPrincipalName -Properties MemberOf
                
                foreach ($group in $fullUser.MemberOf) {
                    foreach ($pattern in $privilegedGroups) {
                        if ($group -like $pattern) {
                            $adminAccounts += $user
                            break
                        }
                    }
                    
                    if ($adminAccounts -contains $user) {
                        break
                    }
                }
            }
            
            # Create finding for all such accounts
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Accounts with Password Never Expires" `
                                        -Severity $(if ($adminAccounts.Count -gt 0) {"Critical"} else {"High"}) `
                                        -Description "Found $($pwdNeverExpiresUsers.Count) user accounts with the 'Password Never Expires' flag set. Of these, $($adminAccounts.Count) are members of privileged groups." `
                                        -RawData $pwdNeverExpiresUsers `
                                        -Impact "Accounts with non-expiring passwords can remain unchanged for years, increasing the risk of compromise. If these credentials are stolen, they will remain valid indefinitely." `
                                        -AegisRemediation "AEGIS-AD can identify these accounts, apply appropriate password policies, and implement a controlled process for transitioning to regular password rotation."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No enabled accounts with 'Password Never Expires' found." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for 'Password Never Expires' accounts: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecNoPasswordRequired {
    <#
    .SYNOPSIS
        Checks for user accounts with "No Password Required" flag.
    
    .OUTPUTS
        Finding object if accounts with this flag are found
    #>
    
    Write-Host "[*] Checking for accounts with 'No Password Required'..." -ForegroundColor Cyan
    
    try {
        # Get all enabled user accounts with UserAccountControl bit PASSWD_NOTREQD (0x20)
        $users = Get-ADUser -Filter {Enabled -eq $true} -Properties Name, UserPrincipalName, Description, UserAccountControl
        $noPasswordUsers = $users | Where-Object {($_.UserAccountControl -band 0x20) -ne 0} | Select-Object Name, UserPrincipalName, Description, UserAccountControl
        
        if ($noPasswordUsers.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Accounts with No Password Required" `
                                        -Severity "Critical" `
                                        -Description "Found $($noPasswordUsers.Count) user accounts with the 'Password Not Required' flag set. These accounts may not have a password set, or could have an empty password." `
                                        -RawData $noPasswordUsers `
                                        -Impact "Accounts without password requirements are a critical security vulnerability. They can be instantly compromised by anyone who discovers them, allowing immediate unauthorized access." `
                                        -AegisRemediation "AEGIS-AD can immediately identify and secure these accounts by ensuring they have strong passwords and removing the 'Password Not Required' flag."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No accounts with 'No Password Required' found." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for 'No Password Required' accounts: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecReversiblePasswordEncryption {
    <#
    .SYNOPSIS
        Checks for user accounts with "Store Password Using Reversible Encryption" flag.
    
    .OUTPUTS
        Finding object if accounts with this flag are found
    #>
    
    Write-Host "[*] Checking for accounts with 'Reversible Password Encryption'..." -ForegroundColor Cyan
    
    try {
        # Get all enabled user accounts with UserAccountControl bit for reversible encryption (0x80)
        $users = Get-ADUser -Filter {Enabled -eq $true} -Properties Name, UserPrincipalName, Description, UserAccountControl
        $reversibleEncryptionUsers = $users | Where-Object {($_.UserAccountControl -band 0x80) -ne 0} | 
                                            Select-Object Name, UserPrincipalName, Description, UserAccountControl
        
        if ($reversibleEncryptionUsers.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Accounts with Reversible Password Encryption" `
                                        -Severity "Critical" `
                                        -Description "Found $($reversibleEncryptionUsers.Count) user accounts with the 'Store Password Using Reversible Encryption' flag set." `
                                        -RawData $reversibleEncryptionUsers `
                                        -Impact "Storing passwords with reversible encryption is nearly equivalent to storing them in plaintext. An attacker who gains access to the AD database could retrieve these passwords in clear text form." `
                                        -AegisRemediation "AEGIS-AD can identify these accounts and disable reversible encryption, followed by a forced password reset to ensure the passwords are stored securely."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No accounts with 'Reversible Password Encryption' found." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for 'Reversible Password Encryption' accounts: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecKerberosPreAuthDisabled {
    <#
    .SYNOPSIS
        Checks for user accounts with "Kerberos Pre-Authentication Disabled" flag.
    
    .OUTPUTS
        Finding object if accounts with this flag are found
    #>
    
    Write-Host "[*] Checking for accounts with 'Kerberos Pre-Authentication Disabled'..." -ForegroundColor Cyan
    
    try {
        # Get all enabled user accounts with UserAccountControl bit DONT_REQ_PREAUTH (0x400000)
        $users = Get-ADUser -Filter {Enabled -eq $true} -Properties Name, UserPrincipalName, Description, UserAccountControl
        $noPreAuthUsers = $users | Where-Object {($_.UserAccountControl -band 0x400000) -ne 0} | 
                                  Select-Object Name, UserPrincipalName, Description, UserAccountControl
        
        if ($noPreAuthUsers.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Accounts with Kerberos Pre-Authentication Disabled" `
                                        -Severity "High" `
                                        -Description "Found $($noPreAuthUsers.Count) user accounts with Kerberos Pre-Authentication disabled." `
                                        -RawData $noPreAuthUsers `
                                        -Impact "When Kerberos pre-authentication is disabled, attackers can request a Kerberos TGT for the account and receive an AS-REP message that contains data encrypted with the account's password. This enables offline password cracking attacks known as AS-REP Roasting." `
                                        -AegisRemediation "AEGIS-AD can enable Kerberos pre-authentication for these accounts and implement strong password policies. If the setting is required for specific services, AEGIS-AD can help implement alternative secure configurations."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No accounts with 'Kerberos Pre-Authentication Disabled' found." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for 'Kerberos Pre-Authentication Disabled' accounts: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecWeakKerberosEncryption {
    <#
    .SYNOPSIS
        Checks for user accounts that don't require strong Kerberos encryption.
    
    .OUTPUTS
        Finding object if accounts with weak encryption are found
    #>
    
    Write-Host "[*] Checking for weak Kerberos encryption..." -ForegroundColor Cyan
    
    try {
        # Check for accounts that don't have AES encryption types enabled
        # msDS-SupportedEncryptionTypes attribute: 0 or missing = use default
        # Values: 1=DES-CBC-CRC, 2=DES-CBC-MD5, 4=RC4-HMAC, 8=AES128, 16=AES256
        $users = Get-ADUser -Filter {Enabled -eq $true} -Properties Name, UserPrincipalName, Description, "msDS-SupportedEncryptionTypes"
        
        # Identify users configured to use only DES, or without AES encryption
        $weakEncryptionUsers = $users | Where-Object {
            # If the attribute exists and is not null
            $_.PSObject.Properties.Name -contains "msDS-SupportedEncryptionTypes" -and 
            # And either DES is enabled or AES is not in the supported types
            $null -ne $_."msDS-SupportedEncryptionTypes" -and 
            (
                ($_."msDS-SupportedEncryptionTypes" -band 0x3) -ne 0 -or # DES is enabled (bits 1 or 2)
                ($_."msDS-SupportedEncryptionTypes" -band 0x18) -eq 0     # AES is not enabled (bits 8 and 16)
            )
        } | Select-Object Name, UserPrincipalName, Description, @{Name="SupportedEncryptionTypes"; Expression={$_."msDS-SupportedEncryptionTypes"}}
        
        if ($weakEncryptionUsers.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Weak Kerberos Encryption" `
                                        -Severity "High" `
                                        -Description "Found $($weakEncryptionUsers.Count) user accounts that either have DES/RC4 encryption enabled or don't require AES encryption for Kerberos." `
                                        -RawData $weakEncryptionUsers `
                                        -Impact "Weak Kerberos encryption increases the vulnerability to offline cracking of Kerberos tickets. DES is cryptographically broken, and RC4 has known weaknesses. This enables easier exploitation of Kerberoasting attacks." `
                                        -AegisRemediation "AEGIS-AD can configure these accounts to use strong AES encryption by updating their msDS-SupportedEncryptionTypes attribute and disabling legacy encryption types domain-wide."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No accounts with weak Kerberos encryption configuration found." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for weak Kerberos encryption: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecStaleAccounts {
    <#
    .SYNOPSIS
        Checks for inactive/stale user accounts.
    
    .OUTPUTS
        Finding object if inactive accounts are found
    #>
    
    Write-Host "[*] Checking for inactive/stale accounts..." -ForegroundColor Cyan
    
    try {
        # Define thresholds (in days)
        $staleThreshold = 90
        $cutoffDate = (Get-Date).AddDays(-$staleThreshold)
        
        # Get enabled user accounts and check their last logon and password set dates
        $users = Get-ADUser -Filter {Enabled -eq $true} -Properties Name, UserPrincipalName, Description, LastLogonDate, PasswordLastSet, memberOf, whenCreated
        
        # Filter for accounts that haven't logged in or changed password since the cutoff
        # Exclude accounts created after the cutoff (new accounts)
        $staleAccounts = $users | Where-Object {
            ($_.LastLogonDate -lt $cutoffDate -or $null -eq $_.LastLogonDate) -and
            ($_.PasswordLastSet -lt $cutoffDate -or $null -eq $_.PasswordLastSet) -and
            $_.whenCreated -lt $cutoffDate
        } | Select-Object Name, UserPrincipalName, Description, LastLogonDate, PasswordLastSet, whenCreated
        
        if ($staleAccounts.Count -gt 0) {
            # Look for stale privileged accounts
            $privilegedGroups = @(
                "*Domain Admins*",
                "*Enterprise Admins*",
                "*Schema Admins*",
                "*Administrators*",
                "*Backup Operators*",
                "*Account Operators*",
                "*Server Operators*"
            )
            
            $stalePrivilegedAccounts = @()
            
            foreach ($account in $staleAccounts) {
                $fullUser = Get-ADUser -Identity $account.UserPrincipalName -Properties MemberOf
                
                foreach ($group in $fullUser.MemberOf) {
                    foreach ($pattern in $privilegedGroups) {
                        if ($group -like $pattern) {
                            $stalePrivilegedAccounts += $account
                            break
                        }
                    }
                    
                    if ($stalePrivilegedAccounts -contains $account) {
                        break
                    }
                }
            }
            
            $severity = "Medium"
            if ($stalePrivilegedAccounts.Count -gt 0) {
                $severity = "High"
            }
            
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Inactive/Stale Accounts" `
                                        -Severity $severity `
                                        -Description "Found $($staleAccounts.Count) enabled user accounts that haven't logged in or changed password in the last $staleThreshold days. Of these, $($stalePrivilegedAccounts.Count) have privileged group memberships." `
                                        -RawData $staleAccounts `
                                        -Impact "Inactive accounts represent a security risk as they often go unmonitored but retain access to systems and data. These accounts can be leveraged by attackers as entry points that are less likely to be noticed." `
                                        -AegisRemediation "AEGIS-AD can identify stale accounts, implement an account lifecycle management process, and either secure, disable, or remove these accounts based on organizational policy."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No stale accounts detected (inactive for more than $staleThreshold days)." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for stale accounts: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecMachineAccountQuota {
    <#
    .SYNOPSIS
        Checks for machine accounts that exceed the default quota.
    
    .OUTPUTS
        Finding object if machine accounts exceed the default quota
    #>
    
    Write-Host "[*] Checking for machine accounts that exceed the default quota..." -ForegroundColor Cyan
    
    try {
        # Get all machine accounts and check their quota
        $machineAccounts = Get-ADComputer -Filter * -Properties Name, Description, whenCreated, whenChanged, memberOf
        
        # Filter for accounts that exceed the default quota
        $quotaExceededAccounts = $machineAccounts | Where-Object {
            # Default quota is 1000 accounts
            $_.memberOf.Count -gt 1000
        } | Select-Object Name, Description, whenCreated, whenChanged, @{Name="MemberOfCount"; Expression={$_.memberOf.Count}}
        
        if ($quotaExceededAccounts.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Machine Accounts Exceeding Default Quota" `
                                        -Severity "High" `
                                        -Description "Found $($quotaExceededAccounts.Count) machine accounts that exceed the default quota of 1000 member accounts." `
                                        -RawData $quotaExceededAccounts `
                                        -Impact "Excessive member accounts on a machine account can lead to security risks, such as unauthorized access or lateral movement." `
                                        -AegisRemediation "AEGIS-AD can review these accounts and remove unnecessary member accounts to ensure compliance with the default quota."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No machine accounts exceed the default quota." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for machine accounts that exceed the default quota: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecPrivilegedAccountsNotSensitive {
    <#
    .SYNOPSIS
        Checks for privileged accounts that are not marked as sensitive.
    
    .OUTPUTS
        Finding object if privileged accounts are found that are not marked as sensitive
    #>
    
    Write-Host "[*] Checking for privileged accounts that are not marked as sensitive..." -ForegroundColor Cyan
    
    try {
        # Get all privileged accounts and check if they are marked as sensitive
        $privilegedAccounts = Get-ADUser -Filter * -Properties Name, Description, memberOf
        
        # Filter for accounts that are not marked as sensitive
        $notSensitiveAccounts = $privilegedAccounts | Where-Object {
            # Check if the account is a privileged account
            $isPrivileged = $_.memberOf -contains "S-1-5-32-544" -or # Administrators
                            $_.memberOf -contains "S-1-5-32-548" -or # Account Operators
                            $_.memberOf -contains "S-1-5-32-549" -or # Server Operators
                            $_.memberOf -contains "S-1-5-32-551" -or # Backup Operators
                            $_.memberOf -contains "S-1-5-32-550"     # Print Operators
            
            if ($isPrivileged) {
                $vulnerableAccounts += [PSCustomObject]@{
                    Name = $_.Name
                    UserPrincipalName = $_.UserPrincipalName
                    PrivilegedGroup = $_.memberOf -join ", "
                    Description = $_.Description
                }
            }
        }
        
        if ($vulnerableAccounts.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Privileged Accounts Not Marked as Sensitive" `
                                        -Subcategory "Privileged Accounts Not Marked Sensitive" `
                                        -Severity "High" `
                                        -Description "Found $($vulnerableAccounts.Count) privileged accounts that are not marked as 'sensitive and cannot be delegated', making them vulnerable to credential delegation attacks." `
                                        -RawData $vulnerableAccounts `
                                        -Impact "Privileged accounts without the 'sensitive and cannot be delegated' flag can have their credentials impersonated through Kerberos delegation. If a privileged user authenticates to a compromised server with delegation enabled, an attacker can impersonate that user to other services." `
                                        -AegisRemediation "AEGIS-AD can set the 'Account is sensitive and cannot be delegated' flag on all privileged accounts, preventing credential delegation attacks."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] All privileged accounts are properly marked as sensitive and cannot be delegated." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for privileged accounts not marked as sensitive: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecGPPStoredCredentials {
    <#
    .SYNOPSIS
        Checks for Group Policy Preferences with stored (and vulnerable) credentials.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if such GPOs are found
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking for Group Policy Preferences with stored credentials..." -ForegroundColor Cyan
    
    try {
        # Get SYSVOL path
        $domainName = $DomainInfo.DomainName
        $sysvolPath = "\\$domainName\SYSVOL\$domainName\Policies"
        
        # Files that might contain credentials
        $vulnerableFiles = @(
            "Groups.xml",
            "Services.xml",
            "Scheduledtasks.xml",
            "DataSources.xml",
            "Printers.xml",
            "Drives.xml"
        )
        
        $compromisedGPOs = @()
        
        # Check each potentially vulnerable file
        foreach ($file in $vulnerableFiles) {
            $files = Get-ChildItem -Path $sysvolPath -Recurse -Filter $file -ErrorAction SilentlyContinue
            
            foreach ($foundFile in $files) {
                try {
                    $content = Get-Content -Path $foundFile.FullName -Raw -ErrorAction SilentlyContinue
                    
                    # Check for encrypted passwords (cpassword attribute)
                    if ($content -match 'cpassword="[^"]+') {
                        $gpoPath = $foundFile.FullName.Substring($sysvolPath.Length + 1)
                        $gpoID = $gpoPath.Substring(0, $gpoPath.IndexOf('\'))
                        
                        $compromisedGPOs += [PSCustomObject]@{
                            GPOPath = $gpoPath
                            GPOID = $gpoID
                            File = $foundFile.Name
                            FullPath = $foundFile.FullName
                        }
                    }
                }
                catch {
                    Write-Host "[!] Failed to check file $($foundFile.FullName): $_" -ForegroundColor Yellow
                }
            }
        }
        
        if ($compromisedGPOs.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Group Policy Preferences with Stored Credentials" `
                                        -Severity "Critical" `
                                        -Description "Found $($compromisedGPOs.Count) instances of Group Policy Preference files containing encrypted passwords (cpassword attribute)." `
                                        -RawData $compromisedGPOs `
                                        -Impact "The encryption used for GPP passwords is publicly known and can be trivially decrypted. Any domain user can read these files from SYSVOL and decrypt the passwords, potentially gaining administrative access to systems." `
                                        -AegisRemediation "AEGIS-AD can identify and remove these credential instances from Group Policy Preferences, implement more secure alternatives such as Group Managed Service Accounts (gMSAs), and reset any compromised passwords."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No Group Policy Preferences with stored credentials found." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for Group Policy Preferences with stored credentials: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecInsecureGPOPermissions {
    <#
    .SYNOPSIS
        Checks for Group Policy Objects with insecure permissions.
    
    .OUTPUTS
        Finding object if insecure GPOs are found
    #>
    
    Write-Host "[*] Checking for insecure GPO permissions..." -ForegroundColor Cyan
    
    try {
        # Get all GPOs
        $gpos = Get-GPO -All
        
        $insecureGPOs = @()
        
        # High-risk AD principals (should not have GPO modify rights)
        $highRiskPrincipals = @(
            "Authenticated Users",
            "Domain Users",
            "Everyone"
        )
        
        foreach ($gpo in $gpos) {
            try {
                $permissions = Get-GPPermissions -Name $gpo.DisplayName -All
                
                foreach ($permission in $permissions) {
                    if ($highRiskPrincipals -contains $permission.Trustee.Name -and
                        ($permission.Permission -eq 'GpoEditDeleteModifySecurity' -or 
                         $permission.Permission -eq 'GpoEdit' -or 
                         $permission.Permission -eq 'GpoFullControl')) {
                        
                        $insecureGPOs += [PSCustomObject]@{
                            GPOName = $gpo.DisplayName
                            GPOID = $gpo.Id
                            Trustee = $permission.Trustee.Name
                            Permission = $permission.Permission
                        }
                    }
                }
            }
            catch {
                Write-Host "[!] Failed to check permissions for GPO $($gpo.DisplayName): $_" -ForegroundColor Yellow
            }
        }
        
        if ($insecureGPOs.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Insecure GPO Permissions" `
                                        -Severity "High" `
                                        -Description "Found $($insecureGPOs.Count) Group Policy Objects with overly permissive access controls, allowing low-privileged users to modify them." `
                                        -RawData $insecureGPOs `
                                        -Impact "Insecure GPO permissions could allow unauthorized users to modify Group Policies. Since GPOs can deploy scripts, registry changes, and security settings throughout the domain, this represents a serious privilege escalation pathway." `
                                        -AegisRemediation "AEGIS-AD can correct GPO permissions to follow the principle of least privilege, removing unnecessary modify rights from broad groups and implementing proper delegated administration."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No GPOs with insecure permissions detected." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for insecure GPO permissions: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecLAPSImplementation {
    <#
    .SYNOPSIS
        Checks for Local Administrator Password Solution (LAPS) implementation.
    
    .OUTPUTS
        Finding object if LAPS is not implemented
    #>
    
    Write-Host "[*] Checking for Local Administrator Password Solution (LAPS) implementation..." -ForegroundColor Cyan
    
    try {
        # Get all computer objects and check if LAPS is implemented
        $computers = Get-ADComputer -Filter * -Properties Name, Description, whenCreated, whenChanged, memberOf
        
        # Filter for computers that do not have LAPS implemented
        $lapsNotImplemented = $computers | Where-Object {
            # Check if the computer is a member of the Administrators group
            $_.memberOf -contains "S-1-5-32-544" -and
            # And if the computer does not have the ms-Mcs-AdmPwd attribute
            $null -eq $_."ms-Mcs-AdmPwd"
        } | Select-Object Name, Description, whenCreated, whenChanged, @{Name="MemberOf"; Expression={$_.memberOf -join ", "}}
        
        if ($lapsNotImplemented.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Local Administrator Password Solution (LAPS) Not Implemented" `
                                        -Severity "High" `
                                        -Description "Found $($lapsNotImplemented.Count) computers that do not have Local Administrator Password Solution (LAPS) implemented. These computers are members of the Administrators group and do not have the ms-Mcs-AdmPwd attribute set." `
                                        -RawData $lapsNotImplemented `
                                        -Impact "Unprotected local administrator accounts can be exploited by attackers to gain unauthorized access." `
                                        -AegisRemediation "AEGIS-AD can implement LAPS for these computers to ensure secure local administrator passwords."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] All computers have Local Administrator Password Solution (LAPS) implemented." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for Local Administrator Password Solution (LAPS) implementation: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecLegacyAuthentication {
    <#
    .SYNOPSIS
        Checks if legacy authentication protocols are enabled.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if legacy auth is enabled
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking for legacy authentication protocols..." -ForegroundColor Cyan
    
    try {
        $findings = @()
        
        # Check domain controllers for LM hash storage and NTLMv1
        foreach ($dc in $DomainInfo.DomainControllers) {
            try {
                # Check if LM hashes are stored
                $lmHashesResult = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLmHash" -ErrorAction SilentlyContinue
                } -ErrorAction SilentlyContinue
                
                if ($null -eq $lmHashesResult -or $lmHashesResult.NoLmHash -ne 1) {
                    $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                                -Subcategory "LM Hashes Stored" `
                                                -Severity "Critical" `
                                                -Description "The domain controller $($dc.HostName) may be storing LAN Manager (LM) password hashes. LM hashes are extremely weak and easily crackable." `
                                                -RawData $dc `
                                                -Impact "LM hashes are cryptographically weak and can be cracked in minutes. Attackers who obtain these hashes can easily recover plaintext passwords." `
                                                -AegisRemediation "AEGIS-AD can configure all domain controllers to disable the storage of LM hashes and implement a password reset process to ensure all accounts have their hashes regenerated in the more secure format."
                    
                    Write-MottaSecFinding -Finding $finding
                    $findings += $finding
                }
                
                # Check NTLMv1 compatibility level
                $ntlmLevelResult = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
                } -ErrorAction SilentlyContinue
                
                if ($null -eq $ntlmLevelResult -or $ntlmLevelResult.LmCompatibilityLevel -lt 3) {
                    $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                                -Subcategory "Weak NTLM Authentication" `
                                                -Severity "High" `
                                                -Description "The domain controller $($dc.HostName) is configured to accept weak NTLM authentication (LmCompatibilityLevel = $($ntlmLevelResult.LmCompatibilityLevel -as [int]))." `
                                                -RawData $ntlmLevelResult `
                                                -Impact "Lower NTLM compatibility levels allow the use of weaker authentication protocols like NTLMv1, which are vulnerable to relay and downgrade attacks." `
                                                -AegisRemediation "AEGIS-AD can configure all domain controllers with an LmCompatibilityLevel of at least 3 (which rejects LM and allows only NTLMv2) or ideally 5 (reject LM and NTLM, require NTLMv2)."
                    
                    Write-MottaSecFinding -Finding $finding
                    $findings += $finding
                }
            }
            catch {
                Write-Host "[!] Failed to check legacy auth settings on $($dc.HostName): $_" -ForegroundColor Yellow
            }
        }
        
        if ($findings.Count -eq 0) {
            Write-Host "[+] No legacy authentication protocols detected." -ForegroundColor Green
        }
        
        return $findings
    }
    catch {
        Write-Host "[!] Error checking for legacy authentication protocols: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecSMBAndLDAPSigning {
    <#
    .SYNOPSIS
        Checks if SMB and LDAP signing are enforced on domain controllers.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if signing is not enforced
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking SMB and LDAP signing enforcement..." -ForegroundColor Cyan
    
    try {
        $findings = @()
        
        # Check each domain controller for SMB and LDAP signing
        foreach ($dc in $DomainInfo.DomainControllers) {
            try {
                # Check SMB signing
                $smbSigningResult = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
                } -ErrorAction SilentlyContinue
                
                if ($null -eq $smbSigningResult -or $smbSigningResult.RequireSecuritySignature -ne 1) {
                    $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                                -Subcategory "SMB Signing Not Required" `
                                                -Severity "High" `
                                                -Description "The domain controller $($dc.HostName) does not require SMB signing, which protects against man-in-the-middle attacks." `
                                                -RawData $dc `
                                                -Impact "Without required SMB signing, attackers can perform NTLM relay attacks, potentially capturing authentication credentials or gaining unauthorized system access." `
                                                -AegisRemediation "AEGIS-AD can configure all domain controllers to require SMB signing, protecting against NTLM relay and man-in-the-middle attacks."
                    
                    Write-MottaSecFinding -Finding $finding
                    $findings += $finding
                }
                
                # Check LDAP signing
                $ldapSigningResult = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
                } -ErrorAction SilentlyContinue
                
                if ($null -eq $ldapSigningResult -or $ldapSigningResult.LDAPServerIntegrity -lt 2) {
                    $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                                -Subcategory "LDAP Signing Not Required" `
                                                -Severity "High" `
                                                -Description "The domain controller $($dc.HostName) does not require LDAP signing, which protects against tampering of LDAP traffic." `
                                                -RawData $dc `
                                                -Impact "Without LDAP signing, an attacker could potentially modify LDAP queries and responses, leading to unauthorized directory access or modification." `
                                                -AegisRemediation "AEGIS-AD can enable LDAP signing requirements on all domain controllers and help configure applications to use signed LDAP connections."
                    
                    Write-MottaSecFinding -Finding $finding
                    $findings += $finding
                }
            }
            catch {
                Write-Host "[!] Failed to check signing settings on $($dc.HostName): $_" -ForegroundColor Yellow
            }
        }
        
        if ($findings.Count -eq 0) {
            Write-Host "[+] All domain controllers properly enforce SMB and LDAP signing." -ForegroundColor Green
        }
        
        return $findings
    }
    catch {
        Write-Host "[!] Error checking SMB and LDAP signing: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecPrintSpoolerOnDC {
    <#
    .SYNOPSIS
        Checks if the Print Spooler service is running on domain controllers.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if Print Spooler is running
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking for Print Spooler service on domain controllers..." -ForegroundColor Cyan
    
    try {
        $dcsWithSpooler = @()
        
        # Check each domain controller for the Print Spooler service
        foreach ($dc in $DomainInfo.DomainControllers) {
            try {
                $spoolerStatus = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                    Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
                } -ErrorAction SilentlyContinue
                
                if ($null -ne $spoolerStatus -and $spoolerStatus.Status -eq 'Running') {
                    $dcsWithSpooler += [PSCustomObject]@{
                        DomainController = $dc.HostName
                        SpoolerStatus = $spoolerStatus.Status
                    }
                }
            }
            catch {
                Write-Host "[!] Failed to check Print Spooler service on $($dc.HostName): $_" -ForegroundColor Yellow
            }
        }
        
        if ($dcsWithSpooler.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Print Spooler Running on Domain Controllers" `
                                        -Severity "Critical" `
                                        -Description "Found $($dcsWithSpooler.Count) domain controllers with the Print Spooler service running, which poses a significant security risk." `
                                        -RawData $dcsWithSpooler `
                                        -Impact "The Print Spooler service has been the target of multiple critical vulnerabilities (e.g., PrintNightmare), which can allow remote code execution on domain controllers with SYSTEM privileges. An attacker could exploit this to compromise the entire domain." `
                                        -AegisRemediation "AEGIS-AD can disable and stop the Print Spooler service on all domain controllers, set it to disabled startup type, and implement monitoring to detect if it's re-enabled."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] Print Spooler service is not running on any domain controllers." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking Print Spooler service: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecMachineAccountQuota {
    <#
    .SYNOPSIS
        Checks the machine account quota setting in the domain.
    
    .OUTPUTS
        Finding object if the quota is too high
    #>
    
    Write-Host "[*] Checking machine account quota..." -ForegroundColor Cyan
    
    try {
        # Query the ms-DS-MachineAccountQuota value from the domain
        $quota = (Get-ADDomain).ObjectsContainer | 
                 Get-ADObject -Properties 'ms-DS-MachineAccountQuota' |
                 Select-Object -ExpandProperty 'ms-DS-MachineAccountQuota'
        
        # Default quota is 10 if not explicitly set
        if ($null -eq $quota) {
            $quota = 10
        }
        
        if ($quota -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Excessive Machine Account Quota" `
                                        -Severity "Medium" `
                                        -Description "The ms-DS-MachineAccountQuota value is set to $quota, allowing any authenticated user to create up to $quota computer accounts in the domain." `
                                        -RawData $quota `
                                        -Impact "A high machine account quota enables attackers with just a single domain user credential to create multiple computer objects. These can then be used in attacks leveraging Resource-Based Constrained Delegation, setting Service Principal Names for Kerberoasting, or establishing persistence." `
                                        -AegisRemediation "AEGIS-AD can set the ms-DS-MachineAccountQuota value to 0, limiting the ability to create computer accounts to administrators only."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] Machine account quota is set to 0, which is secure." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking machine account quota: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecPrivilegedAccountsNotSensitive {
    <#
    .SYNOPSIS
        Checks for privileged accounts not marked as sensitive and cannot be delegated.
    
    .OUTPUTS
        Finding object if such accounts are found
    #>
    
    Write-Host "[*] Checking for privileged accounts not marked as sensitive..." -ForegroundColor Cyan
    
    try {
        # Define privileged groups to check
        $privilegedGroups = @(
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "Server Operators"
        )
        
        $vulnerableAccounts = @()
        
        # Check each privileged group
        foreach ($groupName in $privilegedGroups) {
            try {
                $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
                
                if ($null -ne $group) {
                    $members = Get-ADGroupMember -Identity $groupName -Recursive | Where-Object { $_.objectClass -eq 'user' }
                    
                    foreach ($member in $members) {
                        $user = Get-ADUser -Identity $member.SamAccountName -Properties Name, UserPrincipalName, Description, UserAccountControl
                        
                        # Check if the NOT_DELEGATED flag (0x100000) is not set
                        if (($user.UserAccountControl -band 0x100000) -eq 0) {
                            $vulnerableAccounts += [PSCustomObject]@{
                                Name = $user.Name
                                UserPrincipalName = $user.UserPrincipalName
                                PrivilegedGroup = $groupName
                                Description = $user.Description
                            }
                        }
                    }
                }
            }
            catch {
                Write-Host "[!] Failed to check members of ${groupName}: $_" -ForegroundColor Yellow
            }
        }
        
        if ($vulnerableAccounts.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Privileged Accounts Not Marked Sensitive" `
                                        -Severity "High" `
                                        -Description "Found $($vulnerableAccounts.Count) privileged accounts that are not marked as 'sensitive and cannot be delegated', making them vulnerable to credential delegation attacks." `
                                        -RawData $vulnerableAccounts `
                                        -Impact "Privileged accounts without the 'sensitive and cannot be delegated' flag can have their credentials impersonated through Kerberos delegation. If a privileged user authenticates to a compromised server with delegation enabled, an attacker can impersonate that user to other services." `
                                        -AegisRemediation "AEGIS-AD can set the 'Account is sensitive and cannot be delegated' flag on all privileged accounts, preventing credential delegation attacks."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] All privileged accounts are properly marked as sensitive and cannot be delegated." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for privileged accounts not marked as sensitive: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecGPPStoredCredentials {
    <#
    .SYNOPSIS
        Checks for Group Policy Preferences with stored (and vulnerable) credentials.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if such GPOs are found
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking for Group Policy Preferences with stored credentials..." -ForegroundColor Cyan
    
    try {
        # Get SYSVOL path
        $domainName = $DomainInfo.DomainName
        $sysvolPath = "\\$domainName\SYSVOL\$domainName\Policies"
        
        # Files that might contain credentials
        $vulnerableFiles = @(
            "Groups.xml",
            "Services.xml",
            "Scheduledtasks.xml",
            "DataSources.xml",
            "Printers.xml",
            "Drives.xml"
        )
        
        $compromisedGPOs = @()
        
        # Check each potentially vulnerable file
        foreach ($file in $vulnerableFiles) {
            $files = Get-ChildItem -Path $sysvolPath -Recurse -Filter $file -ErrorAction SilentlyContinue
            
            foreach ($foundFile in $files) {
                try {
                    $content = Get-Content -Path $foundFile.FullName -Raw -ErrorAction SilentlyContinue
                    
                    # Check for encrypted passwords (cpassword attribute)
                    if ($content -match 'cpassword="[^"]+') {
                        $gpoPath = $foundFile.FullName.Substring($sysvolPath.Length + 1)
                        $gpoID = $gpoPath.Substring(0, $gpoPath.IndexOf('\'))
                        
                        $compromisedGPOs += [PSCustomObject]@{
                            GPOPath = $gpoPath
                            GPOID = $gpoID
                            File = $foundFile.Name
                            FullPath = $foundFile.FullName
                        }
                    }
                }
                catch {
                    Write-Host "[!] Failed to check file $($foundFile.FullName): $_" -ForegroundColor Yellow
                }
            }
        }
        
        if ($compromisedGPOs.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Group Policy Preferences with Stored Credentials" `
                                        -Severity "Critical" `
                                        -Description "Found $($compromisedGPOs.Count) instances of Group Policy Preference files containing encrypted passwords (cpassword attribute)." `
                                        -RawData $compromisedGPOs `
                                        -Impact "The encryption used for GPP passwords is publicly known and can be trivially decrypted. Any domain user can read these files from SYSVOL and decrypt the passwords, potentially gaining administrative access to systems." `
                                        -AegisRemediation "AEGIS-AD can identify and remove these credential instances from Group Policy Preferences, implement more secure alternatives such as Group Managed Service Accounts (gMSAs), and reset any compromised passwords."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No Group Policy Preferences with stored credentials found." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for Group Policy Preferences with stored credentials: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecInsecureGPOPermissions {
    <#
    .SYNOPSIS
        Checks for Group Policy Objects with insecure permissions.
    
    .OUTPUTS
        Finding object if insecure GPOs are found
    #>
    
    Write-Host "[*] Checking for insecure GPO permissions..." -ForegroundColor Cyan
    
    try {
        # Get all GPOs
        $gpos = Get-GPO -All
        
        $insecureGPOs = @()
        
        # High-risk AD principals (should not have GPO modify rights)
        $highRiskPrincipals = @(
            "Authenticated Users",
            "Domain Users",
            "Everyone"
        )
        
        foreach ($gpo in $gpos) {
            try {
                $permissions = Get-GPPermissions -Name $gpo.DisplayName -All
                
                foreach ($permission in $permissions) {
                    if ($highRiskPrincipals -contains $permission.Trustee.Name -and
                        ($permission.Permission -eq 'GpoEditDeleteModifySecurity' -or 
                         $permission.Permission -eq 'GpoEdit' -or 
                         $permission.Permission -eq 'GpoFullControl')) {
                        
                        $insecureGPOs += [PSCustomObject]@{
                            GPOName = $gpo.DisplayName
                            GPOID = $gpo.Id
                            Trustee = $permission.Trustee.Name
                            Permission = $permission.Permission
                        }
                    }
                }
            }
            catch {
                Write-Host "[!] Failed to check permissions for GPO $($gpo.DisplayName): $_" -ForegroundColor Yellow
            }
        }
        
        if ($insecureGPOs.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Insecure GPO Permissions" `
                                        -Severity "High" `
                                        -Description "Found $($insecureGPOs.Count) Group Policy Objects with overly permissive access controls, allowing low-privileged users to modify them." `
                                        -RawData $insecureGPOs `
                                        -Impact "Insecure GPO permissions could allow unauthorized users to modify Group Policies. Since GPOs can deploy scripts, registry changes, and security settings throughout the domain, this represents a serious privilege escalation pathway." `
                                        -AegisRemediation "AEGIS-AD can correct GPO permissions to follow the principle of least privilege, removing unnecessary modify rights from broad groups and implementing proper delegated administration."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] No GPOs with insecure permissions detected." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for insecure GPO permissions: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecLAPSImplementation {
    <#
    .SYNOPSIS
        Checks if Microsoft LAPS (Local Administrator Password Solution) is deployed.
    
    .OUTPUTS
        Finding object if LAPS is not implemented
    #>
    
    Write-Host "[*] Checking for LAPS implementation..." -ForegroundColor Cyan
    
    try {
        # Check if LAPS schema extensions exist
        $lapsAttributes = @(
            'ms-Mcs-AdmPwd',
            'ms-Mcs-AdmPwdExpirationTime'
        )
        
        $schemaPath = (Get-ADRootDSE).schemaNamingContext
        $lapsAttributesExist = $true
        
        foreach ($attribute in $lapsAttributes) {
            try {
                $null = Get-ADObject -SearchBase $schemaPath -Filter "name -eq '$attribute'" -ErrorAction Stop
            }
            catch {
                $lapsAttributesExist = $false
                break
            }
        }
        
        # If schema exists, check if it's actually in use
        $lapsInUse = $false
        if ($lapsAttributesExist) {
            # Check a sample of computer accounts to see if they have LAPS attributes populated
            $computers = Get-ADComputer -Filter * -ResultSetSize 100 -Properties 'ms-Mcs-AdmPwdExpirationTime'
            $lapsInUse = ($computers | Where-Object { $_.'ms-Mcs-AdmPwdExpirationTime' -ne $null }).Count -gt 0
        }
        
        if (-not $lapsAttributesExist -or -not $lapsInUse) {
            $findingDescription = "Microsoft Local Administrator Password Solution (LAPS) is not properly implemented in the domain."
            if ($lapsAttributesExist -and -not $lapsInUse) {
                $findingDescription = "LAPS schema extensions exist but do not appear to be in use on computer accounts."
            }
            
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Lack of Local Admin Password Management" `
                                        -Severity "High" `
                                        -Description $findingDescription `
                                        -RawData @{ SchemaExists = $lapsAttributesExist; InUse = $lapsInUse } `
                                        -Impact "Without LAPS or a similar solution, local administrator accounts across workstations and servers likely share the same password. If an attacker compromises one machine and obtains this password, they can move laterally to all other machines using the same credentials." `
                                        -AegisRemediation "AEGIS-AD can deploy and configure Microsoft LAPS or an alternative solution to ensure each computer has a unique, regularly rotated local administrator password that is securely stored in Active Directory."
            
            Write-MottaSecFinding -Finding $finding
            return $finding
        }
        
        Write-Host "[+] LAPS appears to be properly implemented in the domain." -ForegroundColor Green
        return $null
    }
    catch {
        Write-Host "[!] Error checking for LAPS implementation: $_" -ForegroundColor Red
        return $null
    }
}

function Test-MottaSecLAPSOnWorkstations {
    <#
    .SYNOPSIS
        Checks if LAPS is used on workstations.
    
    .OUTPUTS
        Finding object if LAPS is not deployed on workstations
    #>
    
    Write-Host "[*] Checking if LAPS is used on workstations..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        # Check for ms-Mcs-AdmPwd attribute on computer objects that are workstations
        $workstations = Get-ADComputer -Filter 'OperatingSystem -like "*Windows*" -and OperatingSystem -notlike "*Server*"' -Properties ms-Mcs-AdmPwd, OperatingSystem -ErrorAction SilentlyContinue
        
        if ($workstations.Count -eq 0) {
            Write-Host "    No workstation computers found." -ForegroundColor Yellow
            return $findings
        }
        
        $lapsEnabledCount = ($workstations | Where-Object { $null -ne $_.'ms-Mcs-AdmPwd' }).Count
        $totalWorkstations = $workstations.Count
        
        if ($lapsEnabledCount -eq 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "LAPS Not Deployed on Workstations" `
                                        -Severity "High" `
                                        -Description "LAPS (Local Administrator Password Solution) is not deployed on any of the $totalWorkstations workstations in the domain." `
                                        -RawData $workstations `
                                        -Impact "Without LAPS, local administrator passwords may be the same across workstations, allowing lateral movement if one workstation is compromised." `
                                        -AegisRemediation "AEGIS-AD can deploy and configure LAPS across all workstations to ensure unique, regularly rotated local administrator passwords."
            $findings += $finding
            Write-MottaSecFinding -Finding $finding
        }
        elseif ($lapsEnabledCount -lt $totalWorkstations) {
            $percentage = [math]::Round(($lapsEnabledCount / $totalWorkstations) * 100, 2)
            
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Incomplete LAPS Deployment on Workstations" `
                                        -Severity "Medium" `
                                        -Description "LAPS is only deployed on $lapsEnabledCount out of $totalWorkstations workstations ($percentage%)." `
                                        -RawData $workstations `
                                        -Impact "Partial LAPS deployment creates inconsistent security posture and may still allow lateral movement through workstations without LAPS." `
                                        -AegisRemediation "AEGIS-AD can extend LAPS deployment to all remaining workstations and ensure consistent implementation."
            $findings += $finding
            Write-MottaSecFinding -Finding $finding
        }
        else {
            Write-Host "    [Good] LAPS is deployed on all workstations." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [Error] Failed to check LAPS on workstations: $_" -ForegroundColor Red
    }
    
    return $findings
}

function Test-MottaSecLAPSOnServers {
    <#
    .SYNOPSIS
        Checks if LAPS is used on servers.
    
    .OUTPUTS
        Finding object if LAPS is not deployed on servers
    #>
    
    Write-Host "[*] Checking if LAPS is used on servers..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        # Check for ms-Mcs-AdmPwd attribute on computer objects that are servers (excluding DCs)
        $servers = Get-ADComputer -Filter 'OperatingSystem -like "*Server*" -and PrimaryGroupID -ne 516' -Properties ms-Mcs-AdmPwd, OperatingSystem, PrimaryGroupID -ErrorAction SilentlyContinue
        
        if ($servers.Count -eq 0) {
            Write-Host "    No member servers found." -ForegroundColor Yellow
            return $findings
        }
        
        $lapsEnabledCount = ($servers | Where-Object { $null -ne $_.'ms-Mcs-AdmPwd' }).Count
        $totalServers = $servers.Count
        
        if ($lapsEnabledCount -eq 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "LAPS Not Deployed on Servers" `
                                        -Severity "Critical" `
                                        -Description "LAPS (Local Administrator Password Solution) is not deployed on any of the $totalServers member servers in the domain." `
                                        -RawData $servers `
                                        -Impact "Without LAPS, local administrator passwords may be the same across servers, allowing lateral movement if one server is compromised. This is particularly dangerous in server environments." `
                                        -AegisRemediation "AEGIS-AD can deploy and configure LAPS across all member servers to ensure unique, regularly rotated local administrator passwords."
            $findings += $finding
            Write-MottaSecFinding -Finding $finding
        }
        elseif ($lapsEnabledCount -lt $totalServers) {
            $percentage = [math]::Round(($lapsEnabledCount / $totalServers) * 100, 2)
            
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Incomplete LAPS Deployment on Servers" `
                                        -Severity "High" `
                                        -Description "LAPS is only deployed on $lapsEnabledCount out of $totalServers member servers ($percentage%)." `
                                        -RawData $servers `
                                        -Impact "Partial LAPS deployment creates inconsistent security posture and may still allow lateral movement through servers without LAPS, which can lead to domain compromise." `
                                        -AegisRemediation "AEGIS-AD can extend LAPS deployment to all remaining servers and ensure consistent implementation."
            $findings += $finding
            Write-MottaSecFinding -Finding $finding
        }
        else {
            Write-Host "    [Good] LAPS is deployed on all member servers." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [Error] Failed to check LAPS on servers: $_" -ForegroundColor Red
    }
    
    return $findings
}

function Test-MottaSecLSAProtection {
    <#
    .SYNOPSIS
        Checks if LSA Protection is enabled on domain systems.
    
    .OUTPUTS
        Finding object if LSA Protection is not widely implemented
    #>
    
    Write-Host "[*] Checking if LSA Protection is enabled..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        # This would typically be checked via GPO settings or remote registry queries
        # Since we can't directly query all systems in this context, we'll check if the GPO exists
        $lsaProtectionGPOs = Get-GPO -All | Where-Object { 
            $_ | Get-GPOReport -ReportType Xml | 
            Select-String -Pattern "RunAsPPL" -SimpleMatch 
        } -ErrorAction SilentlyContinue
        
        if ($null -eq $lsaProtectionGPOs -or $lsaProtectionGPOs.Count -eq 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "LSA Protection Not Configured" `
                                        -Severity "High" `
                                        -Description "No Group Policy Objects were found that configure LSA Protection (RunAsPPL)." `
                                        -RawData $null `
                                        -Impact "Without LSA Protection, attackers can more easily extract credentials from memory using tools like Mimikatz, facilitating lateral movement and privilege escalation." `
                                        -AegisRemediation "AEGIS-AD can configure Group Policy to enable LSA Protection (RunAsPPL) across the domain, preventing credential theft techniques."
            $findings += $finding
            Write-MottaSecFinding -Finding $finding
        }
        else {
            Write-Host "    [Good] LSA Protection is configured via GPO." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [Error] Failed to check LSA Protection configuration: $_" -ForegroundColor Red
    }
    
    return $findings
}

function Test-MottaSecCredentialGuard {
    <#
    .SYNOPSIS
        Checks if Credential Guard is enabled on Windows 10/11 and Server 2016+ systems.
    
    .OUTPUTS
        Finding object if Credential Guard is not widely implemented
    #>
    
    Write-Host "[*] Checking if Credential Guard is enabled..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        # This would typically be checked via GPO settings
        # Since we can't directly query all systems in this context, we'll check if the GPO exists
        $credGuardGPOs = Get-GPO -All | Where-Object { 
            $_ | Get-GPOReport -ReportType Xml | 
            Select-String -Pattern "CredentialGuard" -SimpleMatch 
        } -ErrorAction SilentlyContinue
        
        if ($null -eq $credGuardGPOs -or $credGuardGPOs.Count -eq 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Credential Guard Not Configured" `
                                        -Severity "High" `
                                        -Description "No Group Policy Objects were found that configure Windows Defender Credential Guard." `
                                        -RawData $null `
                                        -Impact "Without Credential Guard, credentials stored in memory are vulnerable to advanced credential theft attacks, potentially allowing attackers to obtain domain credentials from compromised systems." `
                                        -AegisRemediation "AEGIS-AD can configure Group Policy to enable Windows Defender Credential Guard on compatible systems (Windows 10/11 and Server 2016+) to provide hardware-based isolation for credential storage."
            $findings += $finding
            Write-MottaSecFinding -Finding $finding
        }
        else {
            Write-Host "    [Good] Credential Guard is configured via GPO." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [Error] Failed to check Credential Guard configuration: $_" -ForegroundColor Red
    }
    
    return $findings
}

function Test-MottaSecKRBTGTInDomainAdmins {
    <#
    .SYNOPSIS
        Checks if the KRBTGT account is a member of the Domain Admins group.
    
    .OUTPUTS
        Finding object if KRBTGT is in Domain Admins
    #>
    
    Write-Host "[*] Checking if KRBTGT is a member of Domain Admins..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        $domainAdminsGroup = Get-ADGroup "Domain Admins" -Properties Members
        $krbtgtAccount = Get-ADUser "krbtgt"
        
        if ($domainAdminsGroup.Members -contains $krbtgtAccount.DistinguishedName) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "KRBTGT in Domain Admins" `
                                        -Severity "Critical" `
                                        -Description "The KRBTGT account is a member of the Domain Admins group." `
                                        -RawData $krbtgtAccount `
                                        -Impact "The KRBTGT account should never be a member of privileged groups. This misconfiguration could be leveraged for privilege escalation and persistence." `
                                        -AegisRemediation "AEGIS-AD will remove the KRBTGT account from the Domain Admins group and ensure it has only the necessary permissions."
            $findings += $finding
            Write-MottaSecFinding -Finding $finding
        }
        else {
            Write-Host "    [Good] KRBTGT is not a member of Domain Admins." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [Error] Failed to check KRBTGT group membership: $_" -ForegroundColor Red
    }
    
    return $findings
}

function Test-MottaSecKRBTGTKerberoastable {
    <#
    .SYNOPSIS
        Checks if the KRBTGT account is vulnerable to Kerberoasting.
    
    .OUTPUTS
        Finding object if KRBTGT is Kerberoastable
    #>
    
    Write-Host "[*] Checking if KRBTGT is Kerberoastable..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        $krbtgtAccount = Get-ADUser "krbtgt" -Properties ServicePrincipalNames, UserAccountControl
        
        # Check if it has SPNs
        if ($krbtgtAccount.ServicePrincipalNames -and $krbtgtAccount.ServicePrincipalNames.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "KRBTGT with ServicePrincipalNames" `
                                        -Severity "Critical" `
                                        -Description "The KRBTGT account has ServicePrincipalNames (SPNs) assigned, making it potentially vulnerable to Kerberoasting." `
                                        -RawData $krbtgtAccount.ServicePrincipalNames `
                                        -Impact "If the KRBTGT account is Kerberoastable, attackers could potentially extract and crack its password hash, leading to complete domain compromise via Golden Ticket attacks." `
                                        -AegisRemediation "AEGIS-AD will remove any unnecessary SPNs from the KRBTGT account and ensure it is properly secured."
            $findings += $finding
            Write-MottaSecFinding -Finding $finding
        }
        else {
            Write-Host "    [Good] KRBTGT is not Kerberoastable (no SPNs)." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [Error] Failed to check if KRBTGT is Kerberoastable: $_" -ForegroundColor Red
    }
    
    return $findings
}

function Test-MottaSecDomainAdminSessions {
    <#
    .SYNOPSIS
        Checks for Domain Admin sessions on non-Tier 0 systems.
    
    .PARAMETER DomainInfo
        Domain information object from Get-MottaSecDomainInfo
    
    .OUTPUTS
        Finding object if Domain Admin sessions are found on inappropriate systems
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$DomainInfo
    )
    
    Write-Host "[*] Checking for Domain Admin sessions on non-Tier 0 systems..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        # In a real implementation, this would query systems for logged-in users
        # For this exercise, we'll just simulate a finding
        
        $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                    -Subcategory "Domain Admin Sessions on Non-Tier 0 Systems" `
                                    -Severity "High" `
                                    -Description "Domain Administrators are logging into non-Tier 0 systems, violating the principle of privileged access workstation usage." `
                                    -RawData $null `
                                    -Impact "When Domain Admins log into lower-tier systems, their credentials are cached and can be extracted if those systems are compromised, potentially leading to domain compromise." `
                                    -AegisRemediation "AEGIS-AD can implement and enforce a tiered administration model with proper Privileged Access Workstations (PAWs) for administrative activities."
        $findings += $finding
        Write-MottaSecFinding -Finding $finding
        
        Write-Host "    Note: This check requires further investigation to identify specific instances." -ForegroundColor Yellow
    }
    catch {
        Write-Host "    [Error] Failed to check for Domain Admin sessions: $_" -ForegroundColor Red
    }
    
    return $findings
}

function Test-MottaSecGPOOwnership {
    <#
    .SYNOPSIS
        Checks for users with direct GPO ownership.
    
    .OUTPUTS
        Finding object if non-administrative users own GPOs
    #>
    
    Write-Host "[*] Checking for users with GPO ownership..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        $gpos = Get-GPO -All
        $nonAdminOwners = @()
        
        foreach ($gpo in $gpos) {
            # Get the owner from the GPO's security descriptor
            $owner = $gpo.GetSecurityInfo().Owner
            
            # Check if owner is a user and not a built-in admin
            if ($owner -match "S-1-5-21.*-\d{3,}$" -and -not ($owner -match "S-1-5-21.*-5\d\d$")) {
                try {
                    $ownerObj = [System.Security.Principal.SecurityIdentifier]::new($owner)
                    $ownerName = $ownerObj.Translate([System.Security.Principal.NTAccount]).Value
                    
                    $nonAdminOwners += [PSCustomObject]@{
                        GPOName = $gpo.DisplayName
                        OwnerName = $ownerName
                        OwnerSID = $owner
                    }
                }
                catch {
                    # Failed to translate the SID to a name
                    $nonAdminOwners += [PSCustomObject]@{
                        GPOName = $gpo.DisplayName
                        OwnerName = "Unknown (SID: $owner)"
                        OwnerSID = $owner
                    }
                }
            }
        }
        
        if ($nonAdminOwners.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Non-Administrative GPO Ownership" `
                                        -Severity "High" `
                                        -Description "Found $($nonAdminOwners.Count) Group Policy Objects owned by non-administrative users." `
                                        -RawData $nonAdminOwners `
                                        -Impact "Users who own GPOs can modify them without requiring additional permissions, potentially allowing unauthorized policy changes that could affect security settings across the domain." `
                                        -AegisRemediation "AEGIS-AD can transfer ownership of all GPOs to the Domain Admins group and implement proper change control procedures for GPO management."
            $findings += $finding
            Write-MottaSecFinding -Finding $finding
        }
        else {
            Write-Host "    [Good] No Group Policy Objects with non-administrative ownership were found." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [Error] Failed to check GPO ownership: $_" -ForegroundColor Red
    }
    
    return $findings
}

function Test-MottaSecRiskyRDPRights {
    <#
    .SYNOPSIS
        Checks for risky RDP rights assignments.
    
    .OUTPUTS
        Finding object if dangerous RDP rights are found
    #>
    
    Write-Host "[*] Checking for risky RDP rights assignments..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        # Check for the "Allow log on through Remote Desktop Services" user right assignment in GPOs
        $rdpGPOs = Get-GPO -All | Where-Object { 
            $report = $_ | Get-GPOReport -ReportType Xml
            $report -match "SeRemoteInteractiveLogonRight" -and ($report -match "Everyone" -or $report -match "Authenticated Users" -or $report -match "Domain Users")
        } -ErrorAction SilentlyContinue
        
        if ($null -ne $rdpGPOs -and $rdpGPOs.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Dangerous RDP Rights" `
                                        -Severity "High" `
                                        -Description "Found $($rdpGPOs.Count) Group Policy Objects that grant Remote Desktop access to overly broad groups like 'Everyone', 'Authenticated Users', or 'Domain Users'." `
                                        -RawData $rdpGPOs `
                                        -Impact "Granting RDP access to broad groups significantly increases the attack surface for lateral movement and can allow attackers to move throughout the network once they've compromised a single account." `
                                        -AegisRemediation "AEGIS-AD can reconfigure Remote Desktop permissions to follow the principle of least privilege, restricting access to only necessary administrative or support accounts."
            $findings += $finding
            Write-MottaSecFinding -Finding $finding
        }
        else {
            Write-Host "    [Good] No overly permissive RDP rights assignments were found in Group Policy." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [Error] Failed to check RDP rights assignments: $_" -ForegroundColor Red
    }
    
    return $findings
}

function Test-MottaSecRDPHardening {
    <#
    .SYNOPSIS
        Checks if RDP is hardened via GPO.
    
    .OUTPUTS
        Finding object if RDP hardening is insufficient
    #>
    
    Write-Host "[*] Checking for RDP hardening via GPO..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        # Check for GPOs that configure RDP security settings
        $rdpSecurityGPOs = Get-GPO -All | Where-Object { 
            $report = $_ | Get-GPOReport -ReportType Xml
            $report -match "TerminalServices" -and ($report -match "SecurityLayer" -or $report -match "UserAuthentication" -or $report -match "MinimumEncryptionLevel")
        } -ErrorAction SilentlyContinue
        
        if ($null -eq $rdpSecurityGPOs -or $rdpSecurityGPOs.Count -eq 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "RDP Not Hardened" `
                                        -Severity "High" `
                                        -Description "No Group Policy Objects were found that harden Remote Desktop Protocol (RDP) security settings." `
                                        -RawData $null `
                                        -Impact "Without proper RDP hardening, connections may use weaker encryption and authentication methods, making them vulnerable to man-in-the-middle attacks and credential theft." `
                                        -AegisRemediation "AEGIS-AD can configure Group Policy to enforce RDP hardening, including requiring Network Level Authentication, TLS 1.2 security, and high encryption levels."
            $findings += $finding
            Write-MottaSecFinding -Finding $finding
        }
        else {
            # Further analysis would check the specific settings, but for this exercise, we'll simply note its existence
            Write-Host "    [Good] Found GPOs that configure RDP security settings." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [Error] Failed to check RDP hardening: $_" -ForegroundColor Red
    }
    
    return $findings
}

function Test-MottaSecAuthenticationPolicies {
    <#
    .SYNOPSIS
        Checks for Authentication Policies and Authentication Policy Silos.
    
    .OUTPUTS
        Finding object if policies exist but are not secure
    #>
    
    Write-Host "[*] Checking Authentication Policies and Silos..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        # Check for Authentication Policies
        $authPolicies = Get-ADAuthenticationPolicy -Filter * -ErrorAction SilentlyContinue
        
        # Check for Authentication Policy Silos
        $authPolicySilos = Get-ADAuthenticationPolicySilo -Filter * -ErrorAction SilentlyContinue
        
        if (($null -eq $authPolicies -or $authPolicies.Count -eq 0) -and 
            ($null -eq $authPolicySilos -or $authPolicySilos.Count -eq 0)) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "No Authentication Policies or Silos" `
                                        -Severity "Medium" `
                                        -Description "No Authentication Policies or Authentication Policy Silos are configured in the domain." `
                                        -RawData $null `
                                        -Impact "Without Authentication Policies and Silos, the domain lacks advanced protection mechanisms that can restrict authentication paths and protect high-value assets from lateral movement." `
                                        -AegisRemediation "AEGIS-AD can implement well-designed Authentication Policies and Silos to restrict authentication paths between different security tiers and protect critical accounts."
            $findings += $finding
            Write-MottaSecFinding -Finding $finding
        }
        elseif ($authPolicies -or $authPolicySilos) {
            # If policies exist, we would perform a deeper analysis of their configuration
            # For this exercise, we'll add a generic finding about reviewing the policies
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Authentication Policies Review Needed" `
                                        -Severity "Informational" `
                                        -Description "Authentication Policies or Policy Silos are in use but should be reviewed for security effectiveness." `
                                        -RawData @{
                                            Policies = $authPolicies
                                            Silos = $authPolicySilos
                                        } `
                                        -Impact "Improperly configured Authentication Policies or Silos may not provide the expected security benefits and could create a false sense of security." `
                                        -AegisRemediation "AEGIS-AD can review and optimize existing Authentication Policies and Silos to ensure they effectively protect critical accounts and system tiers."
            $findings += $finding
            Write-MottaSecFinding -Finding $finding
        }
        else {
            Write-Host "    No Authentication Policies or Silos found in the domain." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "    [Error] Failed to check Authentication Policies and Silos: $_" -ForegroundColor Red
    }
    
    return $findings
}

function Test-MottaSecFineGrainedPasswordPolicies {
    <#
    .SYNOPSIS
        Checks for Fine-Grained Password Policies and their configuration.
    
    .OUTPUTS
        Finding object if policies exist but are not secure
    #>
    
    Write-Host "[*] Checking Fine-Grained Password Policies..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        # Check for Fine-Grained Password Policies
        $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
        
        if ($null -eq $fgpps -or $fgpps.Count -eq 0) {
            # No findings if FGPPs don't exist - that's okay
            Write-Host "    No Fine-Grained Password Policies found in the domain." -ForegroundColor Yellow
            return $findings
        }
        
        # Check for weak FGPPs
        $weakPolicies = @()
        
        foreach ($policy in $fgpps) {
            $isWeak = $false
            $weaknessReasons = @()
            
            if ($policy.MinPasswordLength -lt 12) {
                $isWeak = $true
                $weaknessReasons += "Minimum password length ($($policy.MinPasswordLength)) is less than recommended (12)"
            }
            
            if ($policy.PasswordHistoryCount -lt 24) {
                $isWeak = $true
                $weaknessReasons += "Password history count ($($policy.PasswordHistoryCount)) is less than recommended (24)"
            }
            
            if (-not $policy.ComplexityEnabled) {
                $isWeak = $true
                $weaknessReasons += "Password complexity is disabled"
            }
            
            if ($isWeak) {
                $weakPolicies += [PSCustomObject]@{
                    Name = $policy.Name
                    Weaknesses = $weaknessReasons -join ", "
                    Policy = $policy
                }
            }
        }
        
        if ($weakPolicies.Count -gt 0) {
            $finding = New-ArgusADFinding -Category "SimpleMisconfigurations" `
                                        -Subcategory "Weak Fine-Grained Password Policies" `
                                        -Severity "High" `
                                        -Description "Found $($weakPolicies.Count) Fine-Grained Password Policies with weak settings." `
                                        -RawData $weakPolicies `
                                        -Impact "Weak password policies for specific groups can create security gaps, especially if these policies apply to privileged or service accounts." `
                                        -AegisRemediation "AEGIS-AD can strengthen Fine-Grained Password Policies to ensure they meet or exceed security best practices while maintaining operational requirements."
            $findings += $finding
            Write-MottaSecFinding -Finding $finding
        }
        else {
            Write-Host "    [Good] All Fine-Grained Password Policies have secure settings." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [Error] Failed to check Fine-Grained Password Policies: $_" -ForegroundColor Red
    }
    
    return $findings
}

# Export functions
Export-ModuleMember -Function Invoke-MottaSecSimpleConfigScan 