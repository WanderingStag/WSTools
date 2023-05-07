#get more open commands here: https://sysadminstricks.com/tricks/most-useful-microsoft-management-console-snap-in-control-files-msc-files.html
Function Find-EmptyGroup {
<#
.Synopsis
    This function will show empty groups.
.Description
    This function will show empty groups in your domain.
.Example
    Find-EmptyGroups -SearchBase "OU=test,dc=yourdomain,dc=com"
    This function searches the test OU under the yourdomain.com domain and saves a csv with empty groups to c:\test\emptygroups.csv.
.Parameter SearchBase
    Specific OU to search. If not included, the entire domain will be searched.
.Notes
    AUTHOR: Skyler Hart
    CREATED: 01/18/2014 11:50:00
    LASTEDIT: 2022-09-01 21:59:13
    KEYWORDS: Groups, empty groups, group management
    REQUIRES:
        #Requires -Modules ActiveDirectory
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
      [string]$SearchBase
     )

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        if (!([string]::IsNullOrWhiteSpace($SearchBase))) {
            Get-ADGroup -Filter * -Properties CN,GroupScope,GroupCategory,ManagedBy,SamAccountName,whenCreated,CanonicalName,Members -SearchBase $SearchBase | Where-Object {-Not $_.Members} |
            Select-Object CN,GroupScope,GroupCategory,ManagedBy,SamAccountName,whenCreated,CanonicalName
        }
        else {
            $sb = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
            Get-ADGroup -Filter * -Properties CN,GroupScope,GroupCategory,ManagedBy,SamAccountName,whenCreated,CanonicalName,Members -SearchBase $sb | Where-Object {-Not $_.Members} |
            Select-Object CN,GroupScope,GroupCategory,ManagedBy,SamAccountName,whenCreated,CanonicalName
        }
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run Find-EmptyGroup."
    }
}#find emptygroups


Function Find-HiddenGALUser {
<#
   .Synopsis
    This function gets all users that are hidden from the GAL.
   .Description
    This function gets all users that are hidden from the Global Address List (GAL) in a domain or you can specify an OU to search.
   .Example
    Find-HiddenGALUsers -SearchBase "OU=Test,DC=mydomain,DC=com"
    This function gets all users that are hidden from the GAL in a domain or you can specify an OU to search.
   .Parameter SearchBase
    Specific OU to search. If not included, the entire domain will be searched.
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 01/18/2014 02:50:00
    LASTEDIT: 2022-09-01 22:30:56
    KEYWORDS: Hidden Users, User, Exchange, GAL, Global Address List
    REQUIRES:
        #Requires -Modules ActiveDirectory
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [string]$SearchBase
    )

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        if (!([string]::IsNullOrWhiteSpace($SearchBase))) {
            Get-ADUser -Filter * -Properties givenName,Surname,SamAccountname,EmailAddress,msExchHideFromAddressLists -SearchBase $SearchBase | Where-Object {$_.msExchHideFromAddressLists -eq "TRUE"} |
            Select-Object givenName,Surname,SamAccountname,EmailAddress,msExchHideFromAddressLists
        }
        else {
            $sb = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
            Get-ADUser -Filter * -Properties givenName,Surname,SamAccountname,EmailAddress,msExchHideFromAddressLists -SearchBase $sb | Where-Object {$_.msExchHideFromAddressLists -eq "TRUE"} |
            Select-Object givenName,Surname,SamAccountname,EmailAddress,msExchHideFromAddressLists
        }
    }
    else {
        Write-Warning "Active Directory module is not installed."
    }
}#get hidden GAL users


function Find-SID {
<#
    .Synopsis
        This function finds what Active Directory object the specified SID belongs to.
    .Description
        This function finds what Active Directory object the specified SID belongs to.
    .Example
        Find-SID "S-1-5-21-1454471165-1004335555-1606985555-5555"
        Finds what Active Directory object the specified SID belongs to.
    .Parameter SID
        Mandatory parameter. Specify the SID you want to search for.
    .Notes
        AUTHOR: Skyler Hart
        CREATED: 01/19/2014 01:45:00
        LASTEDIT: 08/15/2018 22:47:26
        KEYWORDS: SID
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$true,
            Position=0
        )]
        [string]$SID
    )
    $objSID = New-Object System.Security.Principal.SecurityIdentifier `
        ("$SID")
    $obj = $objSID.Translate( [System.Security.Principal.NTAccount])
    $obj.Value
}#find objectfromsid


function Get-ADComplianceReport {
    <#
    .SYNOPSIS
        Checks attributes on Active Directory objects against a set of compliance rules.

    .DESCRIPTION
        Checks attributes on Active Directory objects against a set of compliance rules and provides a report. It also
        takes several attributes and makes them human readable.

    .PARAMETER UserSearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for user objects.

    .PARAMETER UserGroupSearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for user objects.

    .PARAMETER AdminSearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for user objects.

    .PARAMETER AdminGroupSearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for user objects.

    .PARAMETER ComputerSearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for user objects.

    .PARAMETER MSASearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for user objects.

    .PARAMETER OrganizationalSearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for user objects.

    .PARAMETER ServerSearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for user objects.

    .PARAMETER ServiceAccountSearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for user objects.

    .PARAMETER SaveADReports
        Will save data pulled from Active Directory to reports for each object matching their type to path in
        ReportFolder parameter.

    .PARAMETER ReportFolder
        Specify where you want to save reports to. If you do not specify a path and use either the SaveADReports or
        SaveReport switches this defaults to C:\Scripts.

    .PARAMETER SaveReport
        Will save the report in csv format. If a path isn't specified using the ReportFolder parameter it will save to
        C:\Scripts.

    .EXAMPLE
        C:\PS>Get-ADComplianceReport
        Example of how to use this cmdlet. Will default to OUs in config file.

    .EXAMPLE
        C:\PS>Get-ADComplianceReport -UserSearchBase 'OU=Example User OU,DC=wstools,DC=dev'
        Will search the 'OU=Example User OU,DC=wstools,DC=dev' OU for user objects and report on them.

    .EXAMPLE
        C:\PS>Get-ADComplianceReport -UserSearchBase 'OU=Example User OU,DC=wstools,DC=dev' -SaveReport
        Will search the 'OU=Example User OU,DC=wstools,DC=dev' OU for user objects and because the -ReportFolder parameter
        is not used to specify a path, it will save the report to C:\Scripts.

    .INPUTS
        System.String

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .COMPONENT
        WSTools

    .FUNCTIONALITY
        Active Directory, compliance, report, InTh, Insider Threat, remediation, security

    .NOTES
        Author: Skyler Hart
        Created: 2019-07-02 13:32:53
        Last Edit: 2023-05-06 21:50:15
        Requires:
            -Module ActiveDirectory

    .LINK
        https://wstools.dev
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('User','Users')]
        [string[]]$UserSearchBase,

        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true
        )]
        [string[]]$UserGroupSearchBase,

        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Admin','Admins')]
        [string[]]$AdminSearchBase,

        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true
        )]
        [string[]]$AdminGroupSearchBase,

        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Computer','Computers')]
        [string[]]$ComputerSearchBase,

        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('MSA','MSAs','gMSA','sMSA')]
        [string[]]$MSASearchBase,

        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Orgs','Organizational','Shared')]
        [string[]]$OrganizationalSearchBase,

        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Servers','MemberServer','MemberServers','DomainControllers')]
        [string[]]$ServerSearchBase,

        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('ServiceAccounts')]
        [string[]]$ServiceAccountSearchBase,

        [switch]$SaveADReports,

        [string]$ReportFolder,

        [switch]$SaveReport
    )

    Begin {
        Write-Verbose "Validating AD module installed"
        if ($null -eq (Get-Module -ListAvailable ActiveDir*).Path) {
            throw "Active Directory module not found. Active directory must be installed to use this function."
        }

        <# For testing or using locally. Make sure to comment out or remove config file section below.
        $AdminSearchBase = @('OU=Example,DC=wstools,DC=dev','OU=Example 2,DC=wstools,DC=dev')
        $AdminGroupSearchBase = @()
        $ComputerSearchBase = @()
        $MSASearchBase = @()
        $OrganizationalSearchBase = @()
        $ServerSearchBase = @()
        $ServiceAccountSearchBase = @()
        $UserSearchBase = @()
        $UserGroupSearchBase = @()
        #>

        if (!($AdminSearchBase -or $AdminGroupSearchBase -or $ComputerSearchBase -or $MSASearchBase -or $OrganizationalSearchBase -or
            $ServerSearchBase -or $ServiceAccountSearchBase -or $UserSearchBase -or $UserGroupSearchBase)) {
            $config = $Global:WSToolsConfig
            if (!([string]::IsNullOrWhiteSpace($config))) {
                Write-Verbose "Config file is setup. Using values in config file."
                $AdminSearchBase = $config.AdminOUs
                $AdminGroupSearchBase = $config.AdminGroupOUs
                $ComputerSearchBase = $config.ComputerOUs
                $MSASearchBase = $config.MSAOUs
                $OrganizationalSearchBase = $config.OrgAccountOUs
                $ServerSearchBase = $config.ServerOUs
                $ServiceAccountSearchBase = $config.ServiceAccountOUs
                $UserSearchBase = $config.UserOUs
                $UserGroupSearchBase = $config.UserGroupOUs
                $ReportFolder = $config.ScriptWD
            }
        }

        if (!($ReportFolder)) {$ReportFolder = "C:\Scripts"}

        $date = Get-Date
        $dateformatted = Get-Date -f yyyyMMdd
        [datetime]$crqcheckdate = "9/1/2018"    # used when checking msExchExtensionAttribute18 on service accounts, if account was created after this date then a Change Request (CRQ) number is required to be in msExchExtensionAttribute18
        $30 = ($date).AddDays(-(30))
        $45 = ($date).AddDays(-(45))
        $60 = ($date).AddDays(-(60))
        $90 = ($date).AddDays(-(90))
        $defaultinactivedays = $30
    }
    Process {
        Write-Verbose "Beginning process block"

        Write-Verbose "Getting Admins from Active Directory"
        if ($AdminSearchBase.Count -gt 0) {
            [array]$Admins = foreach ($SearchBase in $AdminSearchBase) {Get-ADUser -Filter * -Properties * -SearchBase $SearchBase | Add-Member -MemberType NoteProperty -Name ObjectType -Value "Admin" -PassThru -Force}
        }

        Write-Verbose "Getting Computers from Active Directory"
        if ($ComputerSearchBase.Count -gt 0) {
            [array]$Computers = foreach ($SearchBase in $ComputerSearchBase) {Get-ADComputer -Filter * -Properties * -SearchBase $SearchBase | Add-Member -MemberType NoteProperty -Name ObjectType -Value "Computer" -PassThru -Force}
        }

        Write-Verbose "Getting Groups from Active Directory"
        if ($AdminGroupSearchBase.Count -gt 0 -or $UserGroupSearchBase.Count -gt 0) {
            [array]$Groups = foreach ($SearchBase in $AdminGroupSearchBase) {Get-ADGroup -Filter * -Properties * -SearchBase $SearchBase | Add-Member -MemberType NoteProperty -Name ObjectType -Value "Admin Group" -PassThru -Force}
            $Groups += foreach ($SearchBase in $UserGroupSearchBase) {Get-ADGroup -Filter * -Properties * -SearchBase $SearchBase | Add-Member -MemberType NoteProperty -Name ObjectType -Value "User Group" -PassThru -Force}
        }

        Write-Verbose "Getting Managed Service Accounts from Active Directory"
        if ($MSASearchBase.Count -gt 0) {
            [array]$ServiceAccounts = foreach ($SearchBase in $MSASearchBase) {Get-ADServiceAccount -Filter * -Properties * -SearchBase $SearchBase | Add-Member -MemberType NoteProperty -Name ObjectType -Value "Managed Service Account" -PassThru -Force}
            if ($env:userdnsdomain -match "area52") {$ServiceAccounts = $ServiceAccounts | Where-Object {$_.Name -like "msa.tvyx*"}}
        }

        Write-Verbose "Getting Org Boxes from Active Directory"
        if ($OrganizationalSearchBase.Count -gt 0) {
            [array]$Orgs = foreach ($SearchBase in $OrganizationalSearchBase) {Get-ADUser -Filter * -Properties * -SearchBase $SearchBase | Add-Member -MemberType NoteProperty -Name ObjectType -Value "Org Box" -PassThru -Force}
        }

        Write-Verbose "Getting Servers from Active Directory"
        if ($ServerSearchBase.Count -gt 0) {
            [array]$Servers = foreach ($SearchBase in $ServerSearchBase) {Get-ADComputer -Filter * -Properties * -SearchBase $SearchBase | Add-Member -MemberType NoteProperty -Name ObjectType -Value "Server" -PassThru -Force}
        }

        Write-Verbose "Getting Service Accounts from Active Directory"
        if ($ServiceAccountSearchBase.Count -gt 0) {
            $ServiceAccounts += foreach ($SearchBase in $ServiceAccountSearchBase) {Get-ADUser -Filter * -Properties * -SearchBase $SearchBase | Add-Member -MemberType NoteProperty -Name ObjectType -Value "Service Account" -PassThru -Force}
        }

        Write-Verbose "Getting Users from Active Directory"
        if ($UserSearchBase.Count -gt 0) {
            [array]$Users = foreach ($SearchBase in $UserSearchBase) {Get-ADUser -Filter * -Properties * -SearchBase $SearchBase | Add-Member -MemberType NoteProperty -Name ObjectType -Value "User" -PassThru -Force}
        }

        if ($SaveADReports) {
            Write-Verbose "Saving AD reports"
            if (!(Test-Path $ReportFolder)) {New-Item $ReportFolder -ItemType Directory}

            $Admins | Export-Csv $ReportFolder\$dateformatted`_ComplianceRAW_Admin.csv
            $Computers | Export-Csv $ReportFolder\$dateformatted`_ComplianceRAW_Computer.csv
            $Groups | Export-Csv $ReportFolder\$dateformatted`_ComplianceRAW_Group.csv
            $Orgs | Export-Csv $ReportFolder\$dateformatted`_ComplianceRAW_Org.csv
            $Servers | Export-Csv $ReportFolder\$dateformatted`_ComplianceRAW_Servers.csv
            $ServiceAccounts | Export-Csv $ReportFolder\$dateformatted`_ComplianceRAW_ServiceAccount.csv
            $Users | Export-Csv $ReportFolder\$dateformatted`_ComplianceRAW_User.csv
        }

        if ($SaveReport) {
            if (!(Test-Path $ReportFolder)) {New-Item $ReportFolder -ItemType Directory}
        }

        Write-Verbose "Combining Objects"
        [array]$Objects = $Admins + $Computers + $Groups + $Orgs + $Servers + $ServiceAccounts + $Users
        $Objects = $Objects | Where-Object {$null -ne $_.SamAccountName}

        Write-Verbose "Reformatting attributes and performing checks"
        $i = 0
        $number = $Objects.Count
        $Report = foreach ($obj in $Objects) {
            # Progress Bar
            if ($number -gt "1") {
                $i++
                $amount = ($i / $number)
                $perc1 = $amount.ToString("P")
                Write-Progress -activity "Reformatting and performing checks on object attributes" -status "Object $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $Objects.Count)  * 100)
            }# if length

            # Clear variables
            Write-Verbose "Clearing variables"
            if ($DaysSinceChange) {Remove-Variable DaysSinceChange | Out-Null}
            if ($DaysSinceCreation) {Remove-Variable DaysSinceCreation | Out-Null}
            if ($DaysSinceLastLogon) {Remove-Variable DaysSinceLastLogon | Out-Null}
            if ($DaysSinceLogonTimestamp) {Remove-Variable DaysSinceLogonTimestamp | Out-Null}
            if ($DaysSinceModified) {Remove-Variable DaysSinceModified | Out-Null}
            if ($DaysSincePasswordLastSet) {Remove-Variable DaysSincePasswordLastSet | Out-Null}
            if ($DaysSincepwdLastSetTime) {Remove-Variable DaysSincepwdLastSetTime | Out-Null}
            if ($issues) {Remove-Variable Issues | Out-Null}
            if ($ManagerInfo) {Remove-Variable ManagerInfo | Out-Null}
            if ($ManagerName) {Remove-Variable ManagerName | Out-Null}
            if ($ManagerEmail) {Remove-Variable ManagerEmail | Out-Null}
            if ($members) {Remove-Variable members | Out-Null}
            if ($LastLogonTime) {Remove-Variable LastLogonTime | Out-Null}
            if ($org) {Remove-Variable org | Out-Null}
            if ($ProtectedObject) {Remove-Variable ProtectedObject | Out-Null}
            if ($pwdLastSet) {Remove-Variable pwdLastSet | Out-Null}
            if ($pwdLastSetTime) {Remove-Variable pwdLastSetTime | Out-Null}
            if ($SmartCardRequired) {Remove-Variable SmartCardRequired | Out-Null}
            if ($time) {Remove-Variable time | Out-Null}


            Write-Verbose "Object: $($obj.Name)"
            switch ($obj.ObjectType) {
                Admin {
                    $pastdate = $45
                    $email = $null
                }
                {'Admin Group','User Group' -contains $_} {
                    $pastdate = $90
                    $email = $obj.mail
                }
                Computer {
                    $pastdate = $90
                    $email = $null
                }
                "Managed Service Account" {
                    $pastdate = $60
                    $email = $null
                }
                "Org Box" {
                    $pastdate = $90
                    $email = $obj.EmailAddress
                }
                Server {
                    $pastdate = $30
                    $email = $null
                }
                "Service Account" {
                    $pastdate = $60
                    $email = $null
                }
                User {
                    $pastdate = $90
                    $email = $obj.EmailAddress
                }
                Default {$pastdate = $defaultinactivedays}
            }

            if ($obj.adminCount) {$ProtectedObject = $true}
            else {$ProtectedObject = $false}

            $DaysSinceModified = [math]::Round((-(New-TimeSpan -Start $date -End ($obj.Modified))).TotalDays)
            Write-Verbose " - Modified: $($obj.Modified)"
            Write-Verbose " - Days since modified: $($DaysSinceModified)"

            switch ($obj.ObjectClass) {
                {'Group' -contains $_} {
                    $GroupCategory = $obj.GroupCategory
                    $GroupScope = $obj.GroupScope
                    $LastLogonDate = $null
                    $members = $obj.Members
                    $manager = $obj.ManagedBy
                    $obj.PasswordLastSet = $null
                    $obj.PasswordNeverExpires = $null
                    $obj.PasswordNotRequired = $null
                }
                Default {
                    $manager = $obj.Manager
                    $GroupScope = $null
                    $GroupCategory = $null

                    Write-Verbose " - Password Last Set: $($obj.PasswordLastSet)"
                    if ([string]::IsNullOrWhiteSpace($obj.PasswordLastSet)) {
                        $DaysSincePasswordLastSet = $null
                    }
                    else {$DaysSincePasswordLastSet = [math]::Round((-(New-TimeSpan -Start $date -End $obj.PasswordLastSet)).TotalDays)}
                    Write-Verbose " - Days since password last set: $($DaysSincePasswordLastSet)"

                    $pwdLastSet = $obj.pwdLastSet
                    if ([string]::IsNullOrWhiteSpace($pwdLastSet)) {
                        $pwdLastSetTime = $null
                        $DaysSincepwdLastSetTime = $null
                    }
                    else {
                        $pwdLastSetTime = [datetime]::FromFileTime("$pwdLastSet")
                        if ([string]::IsNullOrWhiteSpace($pwdLastSetTime)) {
                            $DaysSincepwdLastSetTime = $null
                        }
                        else {
                            $DaysSincepwdLastSetTime = [math]::Round((-(New-TimeSpan -Start $date -End $pwdLastSetTime)).TotalDays)
                        }
                    }
                    Write-Verbose " - pwdLastSet: $($pwdLastSetTime)"
                    Write-Verbose " - Days since pwdLastSet: $($DaysSincepwdLastSetTime)"

                    if ([string]::IsNullOrWhiteSpace($obj.LastlogonDate)) {
                        $DaysSinceLastLogon = $null
                    }
                    else {
                        $DaysSinceLastLogon = [math]::Round((-(New-TimeSpan -Start $date -End $obj.LastlogonDate)).TotalDays)
                    }
                    Write-Verbose " - Days since last logon: $($DaysSinceLastLogon)"

                    $time = $obj.LastLogonTimestamp
                    $LastLogonTime = [datetime]::FromFileTime("$time")
                    if ([string]::IsNullOrWhiteSpace($LastLogonTime)) {
                        $DaysSinceLogonTimestamp = $null
                    }
                    else {
                        $DaysSinceLogonTimestamp = [math]::Round((-(New-TimeSpan -Start $date -End $LastLogonTime)).TotalDays)
                    }
                    Write-Verbose " - LastLogonTime: $($LastLogonTime)"
                    Write-Verbose " - Days since LastLogonTime: $($DaysSinceLogonTimestamp)"
                }
            }

            if ($null -ne $obj.o[0]) {
                $org = $obj.o[0]
            }
            else {$org = $null}

            $DaysSinceChange = [math]::Round((-(New-TimeSpan -Start $date -End ($obj.whenChanged))).TotalDays)

            $DaysSinceCreation = [math]::Round((-(New-TimeSpan -Start $date -End ($obj.WhenCreated))).TotalDays)

            if (!([string]::IsNullOrWhiteSpace($manager))) {
                $ManagerInfo = Get-ADObject $manager -Properties Name,mail
                $ManagerName = ($ManagerInfo | Select-Object Name).Name
                $ManagerEmail = ($ManagerInfo | Select-Object mail).mail
            }


            #
            # Perform checks
            #
            Write-Verbose " - Performing Checks"
            $inactive = $false

            Write-Verbose " -- Inactive"
            if ($obj.ObjectType -eq "Org Box" -or $obj.ObjectType -match "Group") {
                Write-Verbose " --- Org Box or Group. Skipping"
            }
            else {
                # If logon times not empty
                if (((!([string]::IsNullOrWhiteSpace($LastLogonDate))) -and $LastLogonDate -lt $pastdate) -or ((!([string]::IsNullOrWhiteSpace($LastLogonTime))) -and $LastLogonTime -lt $pastdate)) {
                    Write-Verbose " --- IS inactive"
                    $inactive = $true

                    $DaysInactive = ($DaysSinceLastLogon,$DaysSinceLogonTimestamp | Measure-Object -Minimum).Minimum
                    if ($DaysInactive -ge 10000) {
                        $issues = "Inactive (never logged in)"
                        $DaysInactive = $DaysSinceCreation
                    }
                    else {$issues = "Inactive"}
                }
                else {# if logon times ARE empty
                    Write-Verbose " --- NOT inactive"
                    if (([string]::IsNullOrWhiteSpace($LastLogonDate)) -and ([string]::IsNullOrWhiteSpace($LastLogonTime))) {
                        $DaysInactive = "NA"
                        $inactive = $true
                        $issues = "Inactive (never logged in)"
                    }
                    else {
                        $inactive = $false
                        $DaysInactive = ($DaysSinceLastLogon,$DaysSinceLogonTimestamp | Measure-Object -Minimum).Minimum
                    }
                }
            }

            Write-Verbose " -- Smart card required"
            if (($obj.ObjectType -eq "Admin" -or $Obj.ObjectType -eq "User") -and $obj.SmartCardLogonRequired -eq $false) {
                if ([string]::IsNullOrWhiteSpace($issues)) {
                    $issues = "SmartCardLogonRequired not set"
                }
                else {$issues = $issues + ", SmartCardLogonRequired not set"}
            }


            Write-Verbose " -- Password checks"
            if ($obj.ObjectType -eq "Admin" -or $obj.ObjectType -eq "User" -or $obj.ObjectType -eq "Service Account" -or $obj.ObjectType -eq "Org Box") {
                if ($PasswordNeverExpires -eq $true) {
                    if ([string]::IsNullOrWhiteSpace($issues)) {
                        $issues = "PasswordNeverExpires set"
                    }
                    else {$issues = $issues + ", PasswordNeverExpires set"}
                }

                if ($PasswordNotRequired -eq $true) {
                    if ([string]::IsNullOrWhiteSpace($issues)) {
                        $issues = "PasswordNotRequired set"
                    }
                    else {$issues = $issues + ", PasswordNotRequired set"}
                }
            }
            if (((($obj.ObjectType -eq "Admin" -or $obj.ObjectType -eq "User") -and $SmartCardRequired -eq $false) -or $obj.ObjectType -eq "Service Account") -and $DaysSincePasswordLastSet -ge 60) {
                if ([string]::IsNullOrWhiteSpace($issues)) {$issues = "Password expired"}
                else {$issues = $issues + ", password expired"}
            }
            if ($obj.ObjectType -eq "Service Account" -and $DaysSincePasswordLastSet -lt 60 -and $DaysSincePasswordLastSet -ge 20) {
                if ([string]::IsNullOrWhiteSpace($issues)) {$issues = "Password expiring soon"}
                else {$issues = $issues + ", password expiring soon"}
            }
            if ($obj.ObjectType -eq "Computer" -and ([string]::IsNullOrWhiteSpace($pwdLastSetTime)) -and $DaysSinceCreation -gt 30) {
                if ([string]::IsNullOrWhiteSpace($issues)) {$issues = "Password blank (never connected to network)"}
                else {$issues = $issues + ", password blank (never connected to network)"}
            }

            Write-Verbose " -- Protected Object"
            if ($ProtectedObject -eq $true) {
                if (!($obj.MemberOf -match "Domain Admins" -or $obj.MemberOf -match "Domain Controller" -or $obj.MemberOf -match "Enterprise Admins" -or $obj.MemberOf -match "Protected Users" -or $obj.MemberOf -match "Schema Admins")) {
                    if ([string]::IsNullOrWhiteSpace($issues)) {$issues = "ProtectedObject"}
                    else {$issues = $issues + ", ProtectedObject"}
                }
            }

            Write-Verbose " -- Validation"
            $Validated = $false
            if ($env:userdnsdomain -match "area52" -and ($obj.ObjectType -eq "Admin" -or $obj.ObjectType -eq "Org Box" -or $obj.ObjectType -eq "Service Account")) {
                if ($validation) {Remove-Variable validation | Out-Null}
                if ($ValidationDate) {Remove-Variable ValidationDate | Out-Null}
                if ($ValidationDays) {Remove-Variable ValidationDays | Out-Null}

                if ([string]::IsNullOrWhiteSpace($obj.extensionAttribute7)) {
                    if ([string]::IsNullOrWhiteSpace($issues)) {
                        $issues = "Not validated"
                    }
                    else {
                        $issues = $issues + ", not validated"
                    }
                }
                else {
                    $Validated = $true
                    if ($obj.extensionAttribute7 -like "Acct Valid*") {
                        $validation = $obj.extensionAttribute7 -replace "Acct Validated ",""
                        $validation = $validation.Substring(0,8)
                        $ValidationDate = [datetime]::ParseExact($validation, "yyyyMMdd", $null)
                        $ValidationDays = [math]::Round((-(New-TimeSpan -Start $date -End $ValidationDate)).TotalDays)
                    }
                    else {
                        [string]$validation = $obj.extensionAttribute7
                        $validation = $validation.Substring(0,10)
                        $ValidationDate = [datetime]::ParseExact($validation, "yyyy-MM-dd", $null)
                        $ValidationDays = [math]::Round((-(New-TimeSpan -Start $date -End $ValidationDate)).TotalDays)
                    }

                    if ($ValidationDays -ge 335 -and $ValidationDays -lt 365) {
                        if ([string]::IsNullOrWhiteSpace($issues)) {
                            $issues = "Validation expiring soon"
                        }
                        else {
                            $issues = $issues + ", validation expiring soon"
                        }
                    }
                    elseif ($ValidationDays -ge 365) {
                        if ([string]::IsNullOrWhiteSpace($issues)) {
                            $issues = "Validation expired"
                        }
                        else {
                            $issues = $issues + ", validation expired"
                        }
                    }
                }
            }# validation

            Write-Verbose " -- Owner"
            if (($obj.ObjectType -eq "Group" -or $obj.ObjectType -eq "Org Box") -and ([string]::IsNullOrWhiteSpace($manager))) {
                if ([string]::IsNullOrWhiteSpace($issues)) {
                    $issues = "No manager set"
                }
                else {
                    $issues = $issues + ", no manager set"
                }
            }

            Write-Verbose " -- Service Account"
            if ($obj.ObjectType -eq "Service Account") {
                if ([string]::IsNullOrWhiteSpace($obj.extensionAttribute13)) {
                    if ([string]::IsNullOrWhiteSpace($issues)) {
                        $issues = "EA13 blank (POC field)"
                    }
                    else {
                        $issues = $issues + ", EA13 blank (POC field)"
                    }
                }
                if ([string]::IsNullOrWhiteSpace($obj.Description)) {
                    if ([string]::IsNullOrWhiteSpace($issues)) {
                        $issues = "Description blank"
                    }
                    else {
                        $issues = $issues + ", description blank"
                    }
                }
                if ([string]::IsNullOrWhiteSpace($obj.extensionAttribute3) -or $obj.extensionAttribute3 -notmatch "SVC") {
                    if ([string]::IsNullOrWhiteSpace($issues)) {
                        $issues = "extensionAttribute3 missing SVC exemption"
                    }
                    else {
                        $issues = $issues + ", extensionAttribute3 missing SVC exemption"
                    }
                }
                if ([string]::IsNullOrWhiteSpace($obj.l)) {
                    if ([string]::IsNullOrWhiteSpace($issues)) {
                        $issues = "l (City) missing"
                    }
                    else {
                        $issues = $issues + ", l (City) missing"
                    }
                }
                if ([string]::IsNullOrWhiteSpace($obj.msExchExtensionAttribute18)) {
                    if ($obj.WhenCreated -ge $crqcheckdate) {
                        if ([string]::IsNullOrWhiteSpace($issues)) {
                            $issues = "msExchExtensionAttribute18 missing authorizing CRQ number"
                        }
                        else {
                            $issues = $issues + ", msExchExtensionAttribute18 missing authorizing CRQ number"
                        }
                    }
                }
                if ($manager -notlike "*Organization*") {
                    if ([string]::IsNullOrWhiteSpace($issues)) {
                        $issues = "Owner/manager has to be an Org Box"
                    }
                    else {
                        $issues = $issues + ", owner/manager has to be an Org Box"
                    }
                }
                if ([string]::IsNullOrWhiteSpace($obj.Organization)) {
                    if ([string]::IsNullOrWhiteSpace($issues)) {
                        $issues = "Organization attribute empty"
                    }
                    else {
                        $issues = $issues + ", Organization attribute empty"
                    }
                }
                if ([string]::IsNullOrWhiteSpace($obj.physicalDeliveryOfficeName)) {
                    if ([string]::IsNullOrWhiteSpace($issues)) {
                        $issues = "Office (physicalDeliveryOfficeName) missing"
                    }
                    else {
                        $issues = $issues + ", Office (physicalDeliveryOfficeName) missing"
                    }
                }
                if ([string]::IsNullOrWhiteSpace($obj.telephoneNumber)) {
                    if ([string]::IsNullOrWhiteSpace($issues)) {
                        $issues = "telephoneNumber missing"
                    }
                    else {
                        $issues = $issues + ", telephoneNumber missing"
                    }
                }
            }

            Write-Verbose " -- Group"
            if ($obj.ObjectType -match "Group") {
                if ([string]::IsNullOrWhiteSpace($obj.Description)) {
                    if ([string]::IsNullOrWhiteSpace($issues)) {
                        $issues = "Description blank"
                    }
                    else {
                        $issues = $issues + ", description blank"
                    }
                }
                if ($members.Count -lt 1) {
                    if ([string]::IsNullOrWhiteSpace($issues)) {
                        $issues = "No members"
                    }
                    else {
                        $issues = $issues + ", no members"
                    }
                }

                if ($members.Count -gt 3) {
                    $members = "Membership list has 3+ users"
                }
            }

            $memberof = $obj.MemberOf
            if (($memberof).Count -gt 3) {
                $memberof = "MemberOf more than 3 groups"
            }

            if ([string]::IsNullOrWhiteSpace($issues)) {$compliant = $true}
            else {$compliant = $false}

            [PSCustomObject]@{
                Name                        = $obj.Name
                Compliant                   = $compliant
                Issues                      = $issues
                ObjectType                  = $obj.ObjectType
                Email                       = $email
                ManagerName                 = $ManagerName
                ManagerEmail                = $ManagerEmail
                Description                 = $obj.Description
                Enabled                     = $obj.Enabled
                o                           = $org
                Organization                = $obj.Organization
                ProtectedObject             = $ProtectedObject
                Inactive                    = $inactive
                DaysInactive                = if ($obj.ObjectType -notmatch "Group") {$DaysInactive} else {$null}
                LastlogonDate               = if ($obj.ObjectType -notmatch "Group") {$obj.LastlogonDate} else {$null}
                DaysSinceLastLogon          = $DaysSinceLastLogon
                LastLogonTime               = $LastLogonTime
                DaysSinceLogonTime          = $DaysSinceLastLogon
                SmartCardRequired           = $SmartCardRequired
                PasswordLastSet             = if ($obj.ObjectType -notmatch "Group") {$obj.PasswordLastSet} else {$null}
                DaysSincePasswordLastSet    = $DaysSincePasswordLastSet
                pwdLastSet                  = $pwdLastSetTime
                DaysSincepwdLastSetTime     = $DaysSincepwdLastSetTime
                PasswordNeverExpires        = if ($obj.ObjectType -notmatch "Group") {$obj.PasswordNeverExpires} else {$null}
                PasswordNotRequired         = if ($obj.ObjectType -notmatch "Group") {$obj.PasswordNotRequired} else {$null}
                Changed                     = $obj.whenChanged
                DaysSinceChange             = $DaysSinceChange
                Created                     = $obj.WhenCreated
                DaysSinceCreation           = $DaysSinceCreation
                Validated                   = $Validated
                ValidationDate              = $ValidationDate
                DaysSinceValidation         = $ValidationDays
                ExtensionAttribute3         = $obj.extensionAttribute3 -join ", "          # for checking smartcard exemption in the context of this script, your oganization may do something different
                ExtensionAttribute7         = $obj.extensionAttribute7 -join ", "          # for checking validation in the context of this script, your oganization may do something different
                ExtensionAttribute13        = $obj.extensionAttribute13 -join ", "         # for checking POC email address in the context of this script, your oganization may do something different
                ExtensionAttribute18        = $obj.msExchExtensionAttribute18 -join ", "   # for checking CRQ in the context of this script, your oganization may do something different
                CanonicalName               = $obj.CanonicalName
                distinguishedName           = $obj.distinguishedName
                MembersCount                = $members.Count
                GroupCategory               = $GroupCategory
                GroupScope                  = $GroupScope
                Members                     = $members -join ", "
                DisplayName                 = $obj.DisplayName
                EmployeeID                  = $obj.EmployeeID
                EmployeeType                = $obj.EmployeeType
                MemberOf                    = $memberof -join ", "
                Modified                    = $obj.Modified
                DaysSinceModified           = $DaysSinceModified
                ObjectClass                 = $obj.ObjectClass
                SamAccountName              = $obj.SamAccountName
            }# new object
        } # report foreach obj in objects
    }
    End {
        if ($SaveReport) {
            $Report | Export-Csv $ReportFolder\$dateformatted`_ADComplianceReport.csv -NoTypeInformation
        }
        else {$Report}
    }
}


Function Get-ComputerADSite {
<#
   .Parameter ComputerName
    Specifies the computer or computers
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 02/09/2018 00:11:18
    LASTEDIT: 02/09/2018 00:11:18
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipeline = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    Begin {
        $info = @()
    }
    Process {
        $info = foreach ($comp in $ComputerName) {
            $site = nltest /server:$comp /dsgetsite 2>$null
            if($LASTEXITCODE -eq 0){$st = $site[0]}
            else {$st = "NA"}
            [PSCustomObject]@{
                ComputerName = $comp
                Site = $st
            }#new object
        }
    }
    End {
        $info
    }
}


Function Get-DaysSinceLastLogon {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 02/01/2018 10:31:35
    LASTEDIT: 02/01/2018 10:31:35
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('User','SamAccountName','Computer','ComputerName','Username')]
        [string[]]$Name = "$env:USERNAME"
    )
    Begin {
        $sd = Get-Date
    }
    Process {
        foreach ($obj in $Name) {
            try {$record = Get-ADUser $obj -Properties LastLogonDate}
            catch {
                $nobj = $obj + "$"
                $record = Get-ADComputer $nobj -Properties LastLogonDate
            }
            $name = $record.Name
            $LLD = $record.LastLogonDate
            $sam = $record.SamAccountName
            try {
                $dsll = [math]::Round((-(New-TimeSpan -Start $sd -End $LLD)).TotalDays)
            }
            catch {
                $dsll = "NA"
            }

            [PSCustomObject]@{
                Name = $obj
                DaysSinceLastLogon = $dsll
                SamAccountName = $sam
            }#new object
        }
    }
    End {}
}


Function Get-FSMO {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 2022-09-01 22:47:51
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('fsmo')]
    Param (
        [Parameter()]
        [Switch]$netdom
    )
    if (!$netdom) {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            $RoleHolders = Get-ADDomainController -Filter * | Select-Object Name,OperationMasterRoles
            $RoleHolderInfo = foreach ($RoleHolder in $RoleHolders) {
                $Comp = $RoleHolder.Name
                $Roles = $RoleHolder.OperationMasterRoles
                $Roles = $Roles -join ", "
                [PSCustomObject]@{
                    ComputerName = $Comp
                    Roles = $Roles
                }#new object
            }
            $RoleHolderInfo
        }
        else {
            netdom /query FSMO
        }
    }
    else {
        netdom /query FSMO
    }
}


Function Get-LockedOutStatus {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:06:06
    LASTEDIT: 2022-09-01 23:01:39
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('User','SamAccountname')]
        [string[]]$Username = "$env:USERNAME"
    )
    Begin {
        $cktime = Get-Date -Format t
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            #ad module is installed
        }
        else {
            Write-Warning "Active Directory module is not installed and is required to run this command."
            break
        }
    }
    Process {
        foreach ($user in $Username) {
            $usrquery = Get-ADUser $User -properties LockedOut,lockoutTime
            $locked = $usrquery.LockedOut
            $locktime = $usrquery.lockoutTime
            if ($locked -eq $true) {
                [PSCustomObject]@{
                    User = $user
                    Status = "Locked"
                    Date = $locktime
                    CheckTime = $cktime
                }
            }#if
            else {
                [PSCustomObject]@{
                    User = $user
                    Status = "Not Locked"
                    Date = "--"
                    CheckTime = $cktime
                }
            }#else
        }#foreach
    }
    End {}
}


Function Get-NewADUser {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 02:34:40
    LASTEDIT: 2022-09-01 23:03:53
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [int32]$Days = 1
    )

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        $When = ((Get-Date).AddDays(-$Days)).Date
        Get-ADUser -Filter {whenCreated -ge $When} -Properties whenCreated | Select-Object Name,SamAccountName,whenCreated
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}


Function Get-NewADGroup {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 02:34:40
    LASTEDIT: 2022-09-01 23:05:07
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [int32]$Days = 1
    )

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        $When = ((Get-Date).AddDays(-$Days)).Date
        Get-ADGroup -Filter {whenCreated -ge $When} -Properties whenCreated | Select-Object Name,SamAccountName,whenCreated
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}


function Get-NonSmartCardRequiredUser {
    <#
    .SYNOPSIS
        Displays users in domain with SmartCardRequired attribute set to false.

    .DESCRIPTION
        Displays all users in the domain with SmartCardRequired attribute on account set to false.

    .PARAMETER ComputerName
        Specifies the name of one or more computers.

    .EXAMPLE
        C:\PS>Get-NonSmartCardRequiredUser
        Example of how to use this cmdlet

    .INPUTS
        None

    .OUTPUTS
        System.Array

    .COMPONENT
        WSTools

    .FUNCTIONALITY
        Active Directory, Smartcard, Smart Card, InTh, Insider Threat

    .NOTES
        Author: Skyler Hart
        Created: 2023-05-02 17:16:53
        Last Edit: 2023-05-02 17:16:53
        Requires:
            -Module ActiveDirectory

    .LINK
        https://wstools.dev
    #>
    [CmdletBinding()]
    Param (
        [AllowEmptyString()]
        [Alias('User')]
        [string]$Name
    )

    Begin {
        $ErrorActionPreference = "Stop"
        if ($null -eq (Get-Module -ListAvailable ActiveDir*).Path) {
            throw "Active Directory module not found. Active Directory module is required to run this function."
        }
    }
    Process {
        $users = Get-ADUser -Filter {SmartCardLogonRequired -eq $false} -Properties SmartCardLogonRequired,DisplayName,CanonicalName
    }
    End {
        if ($Name) {
            $users | Where-Object {$_ -match $Name}
        }
        else {$users}
    }
}


Function Get-PrivilegedGroup {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 03/05/2019 14:56:27
    LASTEDIT: 2022-09-04 00:41:10
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Switch]$GetParentGroups
    )
    $config = $Global:WSToolsConfig
    $agroups = $config.PrivGroups

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Write-Verbose "Getting groups listed in config file"
        $PrivGroupsCoded = foreach ($ag in $agroups) {
            Get-ADGroup $ag -Properties MemberOf | Add-Member -NotePropertyName Why -NotePropertyValue ParentInScript -Force -PassThru
        }
        $pgccount = $PrivGroupsCoded.Count
        Write-Verbose "Priv Groups in config: $pgccount"

        if ($GetParentGroups) {
            Write-Verbose "Getting Parent Groups"
            $ParentGroups = @()
            $groups = $PrivGroupsCoded.MemberOf | Select-Object -Unique
            $NewGroupsAdded = $true

            while ($NewGroupsAdded) {
                $NewGroupsAdded = $false
                $holdinglist = @()
                foreach ($group in $groups) {
                    Write-Verbose "Checking $group"
                    [array]$new_groups = Get-ADPrincipalGroupMembership $group | ForEach-Object {$_.distinguishedName}
                    if ($new_groups.Length -ge 1) {
                        $NewGroupsAdded = $true
                        foreach ($new in $new_groups) {
                            $holdinglist += $new
                        }
                    }
                    else {
                        $holdinglist += $group
                    }
                }
                [array]$groups = $holdinglist
                $ParentGroups += $groups | Where-Object {$_ -like "CN=*"} | Sort-Object | Select-Object -Unique
                if ($NewGroupsAdded) {
                    Write-Verbose "Starting re-check"
                }
            }

            $parentgroupscount = $ParentGroups.Count
            Write-Verbose "Parent groups: $parentgroupscount"

            $bgroups = $ParentGroups | Select-Object -Unique
            $PrivGroupsCoded = foreach ($group in $bgroups) {
                Write-Verbose "Getting AD info of parent group: $group"
                Get-ADGroup $group | Add-Member -NotePropertyName Why -NotePropertyValue Parent -Force -PassThru
            }
            $pgccount = $PrivGroupsCoded.Count
            Write-Verbose "Priv Groups after getting parent: $pgccount"
        }

        Write-Verbose "Getting sub groups"
        $subgroups = foreach ($group in $PrivGroupsCoded) {
            Get-ADGroupMember $group | Select-Object * | Where-Object {$_.objectClass -eq "group"} | Select-Object -ExpandProperty Name
        }
        $subgroups = $subgroups | Sort-Object | Select-Object -Unique
        $PrivSubGroups = @()
        $PrivSubGroups += foreach ($group in $subgroups) {
            Get-ADGroup $group | Select-Object -ExpandProperty distinguishedName
        }
        $NewGroupsAdded = $true
        while ($NewGroupsAdded) {
            $NewGroupsAdded = $false
            $holdinglist = @()
            foreach ($group in $subgroups) {
                Write-Verbose "Checking subgroup $group"
                [array]$new_groups = Get-ADGroupMember $group | Where-Object {$_.objectClass -eq "group"} | Select-Object -ExpandProperty Name
                if ($new_groups.Length -ge 1) {
                    $NewGroupsAdded = $true
                    foreach ($new in $new_groups) {
                        $holdinglist += $new
                    }
                }
                else {
                    $holdinglist += $group
                }
            }
            [array]$subgroups = $holdinglist
            $PrivSubGroups += $subgroups | Sort-Object | Select-Object -Unique
            if ($NewGroupsAdded) {
                Write-Verbose "Starting re-check"
            }
        }
        $PrivSubGroups = $PrivSubGroups | Sort-Object | Select-Object -Unique
        Write-Verbose "Getting AD info of each subgroup"
        $PrivGroupsSub = foreach ($group in $PrivSubGroups) {
            if ($PrivGroupsCoded -notmatch $group) {
                Write-Verbose " - Getting AD info of $group"
                Get-ADGroup $group | Add-Member -NotePropertyName Why -NotePropertyValue "Subgroup" -Force -PassThru
            }
        }
        $pgscount = $PrivGroupsSub.Count
        Write-Verbose "Sub Groups: $pgscount"

        Write-Verbose "Combining info"
        $AllGroups = @()
        $AllGroups += $PrivGroupsCoded
        $AllGroups += $PrivGroupsSub
        $AllGroups | Select-Object Name,Why,GroupScope,GroupCategory,DistinguishedName -Unique
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}


Function Get-ProtectedGroup {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/05/2018 17:24:35
    LASTEDIT: 2022-09-04 02:30:15
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
.LINK
    https://wstools.dev
#>
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        $groups = (Get-ADGroup -filter {admincount -eq "1"}).Name | Sort-Object
        $groups
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}


Function Get-ProtectedUser {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 02/05/2018 17:26:06
    LASTEDIT: 2022-09-04 02:32:23
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
.LINK
    https://wstools.dev
#>
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        $users = (Get-ADUser -filter {admincount -eq "1"}).Name | Sort-Object
        $users
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}


Function Get-ReplicationStatus {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 08/18/2017 20:48:21
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('replsum')]
    param()
    repadmin /replsum
}


Function Get-UserWithThumbnail {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/03/2014 14:18:42
    LASTEDIT: 2022-09-04 11:56:28
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
.LINK
    https://wstools.dev
#>
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Write-Output "Getting OU names . . ."
        $ous = (Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Select-Object DistinguishedName).DistinguishedName

        Write-Output "Getting Users . . ."
        $users = foreach ($ouname in $ous) {
            Get-ADUser -Filter * -Properties thumbnailPhoto -SearchBase "$ouname" -SearchScope OneLevel | Where-Object {!([string]::IsNullOrWhiteSpace($_.thumbnailPhoto))} | Select-Object Name,UserPrincipalName,thumbnailPhoto
        }

        $users | Select-Object Name,UserPrincipalName,thumbnailPhoto
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}


Function Open-ADDomainsAndTrusts {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:27:24
    LASTEDIT: 2022-09-04 12:04:10
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('trusts')]
    param()
    try {
        $ErrorActionPreference = "Stop"
        domain.msc
    }
    catch {
        Write-Output "Active Directory snapins are not installed/enabled."
    }
}


Function Open-ADSIEdit {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:21:51
    LASTEDIT: 2020-04-19 20:07:02
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('adsi')]
    param()
    try {
        $ErrorActionPreference = "Stop"
        adsiedit.msc
    }
    catch {
        try {
            Register-ADSIEdit
            Start-Sleep 1
            adsiedit.msc
        }
        catch {
            Write-Output "Active Directory snapins are not installed/enabled."
        }
    }
}


Function Open-ADSitesAndServices {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:29:08
    LASTEDIT: 2022-09-04 12:06:04
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    try {
        $ErrorActionPreference = "Stop"
        dssite.msc
    }
    catch {
        Write-Output "Active Directory snapins are not installed/enabled."
    }
}


Function Open-ADUsersAndComputers {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:28:17
    LASTEDIT: 2022-09-04 12:07:24
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('aduc','dsa')]
    param()
    try {
        $ErrorActionPreference = "Stop"
        dsa.msc
    }
    catch {
        Write-Output "Active Directory snapins are not installed/enabled."
    }
}


function Open-CMLibrary {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-10-18 22:49:11
    LASTEDIT: 2021-10-18 22:51:31
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Chrome,

        [Parameter(Mandatory=$false)]
        [Switch]$Edge,

        [Parameter(Mandatory=$false)]
        [Switch]$Firefox,

        [Parameter(Mandatory=$false)]
        [Switch]$InternetExplorer
    )

    $config = $Global:WSToolsConfig
    $URL = $config.CMLibrary

    if ($Chrome) {Start-Process "chrome.exe" $URL}
    elseif ($Edge) {Start-Process shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge $URL}
    elseif ($Firefox) {Start-Process "firefox.exe" $URL}
    elseif ($InternetExplorer) {Start-Process "iexplore.exe" $URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open($URL)
    }
}


Function Open-DHCPmgmt {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:25:18
    LASTEDIT: 2022-09-04 12:09:18
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('dhcp')]
    param()
    try {
        $ErrorActionPreference = "Stop"
        dhcpmgmt.msc
    }
    catch {
        Write-Output "Active Directory snapins are not installed/enabled."
    }
}


Function Open-DNSmgmt {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:26:23
    LASTEDIT: 2022-09-04 12:10:54
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('dns')]
    param()
    try {
        $ErrorActionPreference = "Stop"
        dnsmgmt.msc
    }
    catch {
        Write-Output "Active Directory snapins are not installed/enabled."
    }
}


function Open-EAC {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-10-18 22:55:39
    LASTEDIT: 2021-10-18 22:56:47
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Open-ECP','EAC','ECP')]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Chrome,

        [Parameter(Mandatory=$false)]
        [Switch]$Edge,

        [Parameter(Mandatory=$false)]
        [Switch]$Firefox,

        [Parameter(Mandatory=$false)]
        [Switch]$InternetExplorer
    )

    $config = $Global:WSToolsConfig
    $URL = $config.EAC

    if ($Chrome) {Start-Process "chrome.exe" $URL}
    elseif ($Edge) {Start-Process shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge $URL}
    elseif ($Firefox) {Start-Process "firefox.exe" $URL}
    elseif ($InternetExplorer) {Start-Process "iexplore.exe" $URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open($URL)
    }
}


Function Open-GroupPolicyMgmt {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:30:09
    LASTEDIT: 2022-09-04 12:12:07
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('gpo','gpmc','GroupPolicy')]
    param()
    try {
        $ErrorActionPreference = "Stop"
        gpmc.msc
    }
    catch {
        Write-Output "Active Directory snapins are not installed/enabled."
    }
}


Function Open-HyperVmgmt {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:32:48
    LASTEDIT: 2022-09-04 12:13:29
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('hyperv')]
    param()
    try {
        $ErrorActionPreference = "Stop"
        virtmgmt.msc
    }
    catch {
        Write-Output "Hyper-V management tools not installed/enabled."
    }
}


function Open-iLO {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/02/2018 12:00:33
    LASTEDIT: 2020-04-17 15:36:02
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('iLO')]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Chrome,

        [Parameter(Mandatory=$false)]
        [Switch]$Edge,

        [Parameter(Mandatory=$false)]
        [Switch]$Firefox,

        [Parameter(Mandatory=$false)]
        [Switch]$InternetExplorer
    )

    $config = $Global:WSToolsConfig
    $URL = $config.iLO

    if ($Chrome) {Start-Process "chrome.exe" $URL}
    elseif ($Edge) {Start-Process shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge $URL}
    elseif ($Firefox) {Start-Process "firefox.exe" $URL}
    elseif ($InternetExplorer) {Start-Process "iexplore.exe" $URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open($URL)
    }
}


Function Open-LAPS {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 21:57:51
    LASTEDIT: 2020-04-19 20:20:43
    KEYWORDS:
    REQUIRES:
        -Modules AdmPwd.PS
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('laps')]
    param()
    try {
        Start-Process 'C:\Program Files\LAPS\AdmPwd.UI' -ErrorAction Stop
    }
    catch [System.InvalidOperationException] {
        $err = $_.Exception.message.Trim()
        if ($err -match "cannot find the file") {
            Write-Error "LAPS admin console not installed"
        }
        else {
            Write-Error "Unknown error"
        }
    }
    catch {
        Get-Error -HowMany 1
    }
}


function Open-LexmarkManagementConsole {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2022-03-08 22:02:21
    LASTEDIT: 2022-03-08 22:02:21
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('lmc')]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Chrome,

        [Parameter(Mandatory=$false)]
        [Switch]$Edge,

        [Parameter(Mandatory=$false)]
        [Switch]$Firefox,

        [Parameter(Mandatory=$false)]
        [Switch]$InternetExplorer
    )

    $config = $Global:WSToolsConfig
    $URL = $config.LMC

    if ($Chrome) {Start-Process "chrome.exe" $URL}
    elseif ($Edge) {Start-Process shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge $URL}
    elseif ($Firefox) {Start-Process "firefox.exe" $URL}
    elseif ($InternetExplorer) {Start-Process "iexplore.exe" $URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open($URL)
    }
}


function Open-NetLogonLog {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-22 17:50:31
    Last Edit: 2021-06-22 17:50:31
    Keywords:
.LINK
    https://wstools.dev
#>
    $Continue = $false
    $file = "$env:windir\debug\netlogon.log"
    if (Test-Path "c:\Windows\ccm\CMTrace.exe") {
        $app = "c:\Windows\ccm\CMTrace.exe"
        $Continue = $true
    }
    elseif (Test-Path "C:\ProgramData\OSI\CMTrace.exe") {
        $app = "C:\ProgramData\OSI\CMTrace.exe"
        $Continue = $true
    }
    elseif (Test-Path "J:\Patches\CMTrace.exe") {
        $app = "J:\Patches\CMTrace.exe"
        $Continue = $true
    }
    else {
        Write-Error "Cannot find CMTrace.exe"
        $Continue = $false
    }

    if ($Continue) {
        foreach ($file in $FileName) {
            try {
                Start-Process $app -ArgumentList $file -ErrorAction Stop
            }
            catch {
                Write-Error "Could not find or did not have permission to open $file"
            }
        }
    }
}


function Open-NetworkDiagram {
<#
.NOTES
    Author: Skyler Hart
    Created: 2022-07-07 20:59:35
    Last Edit: 2022-07-07 20:59:35
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('NetDiagram','NetworkDiagram')]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Chrome,

        [Parameter(Mandatory=$false)]
        [Switch]$Edge,

        [Parameter(Mandatory=$false)]
        [Switch]$Firefox,

        [Parameter(Mandatory=$false)]
        [Switch]$InternetExplorer
    )

    $config = $Global:WSToolsConfig
    $dpath = $config.NetDiagram

    if ($dpath -like "http*") {
        if ($Chrome) {Start-Process "chrome.exe" $dpath}
        elseif ($Edge) {Start-Process shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge $dpath}
        elseif ($Firefox) {Start-Process "firefox.exe" $dpath}
        elseif ($InternetExplorer) {Start-Process "iexplore.exe" $dpath}
        else {
            #open in default browser
            (New-Object -com Shell.Application).Open($dpath)
        }
    }#is web address
    else {
        Invoke-Item $dpath
    }
}


function Open-OWA {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-10-18 22:54:07
    LASTEDIT: 2021-10-18 22:54:48
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('OWA')]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Chrome,

        [Parameter(Mandatory=$false)]
        [Switch]$Edge,

        [Parameter(Mandatory=$false)]
        [Switch]$Firefox,

        [Parameter(Mandatory=$false)]
        [Switch]$InternetExplorer
    )

    $config = $Global:WSToolsConfig
    $URL = $config.OWA

    if ($Chrome) {Start-Process "chrome.exe" $URL}
    elseif ($Edge) {Start-Process shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge $URL}
    elseif ($Firefox) {Start-Process "firefox.exe" $URL}
    elseif ($InternetExplorer) {Start-Process "iexplore.exe" $URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open($URL)
    }
}


function Open-PrintRelease {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2022-03-08 22:02:21
    LASTEDIT: 2022-03-08 22:02:21
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Chrome,

        [Parameter(Mandatory=$false)]
        [Switch]$Edge,

        [Parameter(Mandatory=$false)]
        [Switch]$Firefox,

        [Parameter(Mandatory=$false)]
        [Switch]$InternetExplorer
    )

    $config = $Global:WSToolsConfig
    $URL = $config.PrintRelease

    if ($Chrome) {Start-Process "chrome.exe" $URL}
    elseif ($Edge) {Start-Process shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge $URL}
    elseif ($Firefox) {Start-Process "firefox.exe" $URL}
    elseif ($InternetExplorer) {Start-Process "iexplore.exe" $URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open($URL)
    }
}


function Open-RackElevation {
<#
.NOTES
    Author: Skyler Hart
    Created: 2022-07-07 21:22:25
    Last Edit: 2022-07-07 21:22:25
    Other:
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('RackEl','RackElevation')]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Chrome,

        [Parameter(Mandatory=$false)]
        [Switch]$Edge,

        [Parameter(Mandatory=$false)]
        [Switch]$Firefox,

        [Parameter(Mandatory=$false)]
        [Switch]$InternetExplorer
    )

    $config = $Global:WSToolsConfig
    $dpath = $config.RackEl

    if ($dpath -like "http*") {
        if ($Chrome) {Start-Process "chrome.exe" $dpath}
        elseif ($Edge) {Start-Process shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge $dpath}
        elseif ($Firefox) {Start-Process "firefox.exe" $dpath}
        elseif ($InternetExplorer) {Start-Process "iexplore.exe" $dpath}
        else {
            #open in default browser
            (New-Object -com Shell.Application).Open($dpath)
        }
    }#is web address
    else {
        Invoke-Item $dpath
    }
}


function Open-SDN {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-10-18 22:38:19
    LASTEDIT: 2021-10-18 22:39:28
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Open-SDNMgmt','SDN','Open-Unifi','unifi')]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Chrome,

        [Parameter(Mandatory=$false)]
        [Switch]$Edge,

        [Parameter(Mandatory=$false)]
        [Switch]$Firefox,

        [Parameter(Mandatory=$false)]
        [Switch]$InternetExplorer
    )

    $config = $Global:WSToolsConfig
    $URL = $config.SDNMgmt

    if ($Chrome) {Start-Process "chrome.exe" $URL}
    elseif ($Edge) {Start-Process shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge $URL}
    elseif ($Firefox) {Start-Process "firefox.exe" $URL}
    elseif ($InternetExplorer) {Start-Process "iexplore.exe" $URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open($URL)
    }
}


function Open-SEIM {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-10-18 23:03:53
    LASTEDIT: 2021-10-18 23:04:54
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Open-SIEM','Open-ArcSight','Open-Splunk','Open-SysLog')]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Chrome,

        [Parameter(Mandatory=$false)]
        [Switch]$Edge,

        [Parameter(Mandatory=$false)]
        [Switch]$Firefox,

        [Parameter(Mandatory=$false)]
        [Switch]$InternetExplorer
    )

    $config = $Global:WSToolsConfig
    $URL = $config.SEIM

    if ($Chrome) {Start-Process "chrome.exe" $URL}
    elseif ($Edge) {Start-Process shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge $URL}
    elseif ($Firefox) {Start-Process "firefox.exe" $URL}
    elseif ($InternetExplorer) {Start-Process "iexplore.exe" $URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open($URL)
    }
}


Function Open-SharedFolders {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:14:08
    LASTEDIT: 08/19/2017 22:14:08
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Shares','Get-Shares')]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string]$ComputerName = "$env:COMPUTERNAME"
    )
    fsmgmt.msc /computer=\\$ComputerName
}


function Open-SharePoint {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-10-18 22:51:47
    LASTEDIT: 2021-10-18 22:52:18
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Chrome,

        [Parameter(Mandatory=$false)]
        [Switch]$Edge,

        [Parameter(Mandatory=$false)]
        [Switch]$Firefox,

        [Parameter(Mandatory=$false)]
        [Switch]$InternetExplorer
    )

    $config = $Global:WSToolsConfig
    $URL = $config.SharePoint

    if ($Chrome) {Start-Process "chrome.exe" $URL}
    elseif ($Edge) {Start-Process shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge $URL}
    elseif ($Firefox) {Start-Process "firefox.exe" $URL}
    elseif ($InternetExplorer) {Start-Process "iexplore.exe" $URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open($URL)
    }
}


Function Open-vCenter {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/18/2017 10:34:22
    LASTEDIT: 02/13/2018 11:05:06
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('vCenter')]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Chrome,

        [Parameter(Mandatory=$false)]
        [Switch]$Edge,

        [Parameter(Mandatory=$false)]
        [Switch]$Firefox,

        [Parameter(Mandatory=$false)]
        [Switch]$InternetExplorer
    )

    $config = $Global:WSToolsConfig
    $URL = $config.vCenter

    if ($Chrome) {Start-Process "chrome.exe" $URL}
    elseif ($Edge) {Start-Process shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge $URL}
    elseif ($Firefox) {Start-Process "firefox.exe" $URL}
    elseif ($InternetExplorer) {Start-Process "iexplore.exe" $URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open($URL)
    }
}


function Register-ADSIEdit {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-19 19:53:38
    Last Edit: 2022-09-04 12:18:51
    Keywords:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Initialize-ADSIEdit','Enable-ADSIEdit')]
    param()

    if (Test-Path $env:windir\System32\adsiedit.dll) {
        regsvr32.exe adsiedit.dll
    }
    else {
        Write-Warning "adsiedit.dll not found. Please ensure Active Directory tools are installed."
    }
}


Function Register-Schema {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/12/2018 20:10:54
    LASTEDIT: 2022-09-04 12:20:42
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    if (Test-Path $env:windir\System32\schmmgmt.dll) {
        regsvr32.exe schmmgmt.dll
    }
    else {
        Write-Warning "schmmgmt.dll not found. Please ensure Active Directory tools are installed."
    }
}


Function Restart-ActiveDirectory {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/08/2017 16:03:23
    LASTEDIT: 2022-09-04 12:22:27
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string]$DC = "$env:COMPUTERNAME",
        [Switch]$All
    )
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        if (!($All)) {
            Write-Information "Restarting Active Directory service on $DC"
            try {Restart-Service -inputobject $(Get-Service -ComputerName $DC -Name NTDS -ErrorAction Stop) -Force -ErrorAction Stop}
            catch {Throw "Unable to connect to $DC or failed to restart service."}
        }#if not all
        elseif ($All) {
            $AllDCs = (Get-ADForest).Domains | ForEach-Object {Get-ADDomainController -Filter * -Server $_}
            foreach ($Srv in $AllDCs) {
                $SrvName = $Srv.HostName
                Write-Output "Restarting Active Directory service on $SrvName"
                try {Restart-Service -inputobject $(Get-Service -ComputerName $SrvName -Name NTDS) -Force}
                catch {Throw "Unable to connect to $DC or failed to restart service."}
            }#foreach dc
        }#elseif
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}


Function Restart-DNS {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/08/2017 17:23:43
    LASTEDIT: 2022-09-04 12:35:59
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string]$DC = "$env:COMPUTERNAME",
        [Switch]$All
    )
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        if (!($All)) {
            Write-Output "Restarting DNS service on $DC"
            try {Restart-Service -inputobject $(Get-Service -ComputerName $DC -Name DNS) -Force}
            catch {Throw "Unable to connect to $DC or failed to restart service."}
        }#if not all
        elseif ($All) {
            $AllDCs = (Get-ADForest).Domains | ForEach-Object {Get-ADDomainController -Filter * -Server $_}
            foreach ($Srv in $AllDCs) {
                $SrvName = $Srv.HostName
                Write-Output "Restarting DNS service on $SrvName"
                try {Restart-Service -inputobject $(Get-Service -ComputerName $SrvName -Name DNS) -Force}
                catch {Throw "Unable to connect to $DC or failed to restart service."}
            }#foreach dc
        }#elseif
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}


Function Restart-KDC {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 02:45:00
    LASTEDIT: 2022-09-04 12:38:21
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string]$DC = "$env:COMPUTERNAME",
        [Switch]$All
    )
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        if (!($All)) {
            Write-Output "Restarting KDC service on $DC"
            try {Restart-Service -inputobject $(Get-Service -ComputerName $DC -Name kdc) -Force}
            catch {Throw "Unable to connect to $DC or failed to restart service."}
        }#if not all
        elseif ($All) {
            $AllDCs = (Get-ADForest).Domains | ForEach-Object {Get-ADDomainController -Filter * -Server $_}
            foreach ($Srv in $AllDCs) {
                $SrvName = $Srv.HostName
                Write-Output "Restarting KDC service on $SrvName"
                try {Restart-Service -inputobject $(Get-Service -ComputerName $SrvName -Name kdc) -Force}
                catch {Throw "Unable to connect to $DC or failed to restart service."}
            }#foreach dc
        }#elseif
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}


function Set-ADProfilePicture {
<#
.NOTES
    Author: Skyler Hart
    Created: 2017-08-18 20:47:20
    Last Edit: 2022-09-04 12:42:30
    Other:
    Requires:
        -Module ActiveDirectory
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [Alias('User','SamAccountname')]
        [string]$Username
    )

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $OpenFileDialog.initialDirectory = "C:\"
        $OpenFileDialog.filter = "JPG (*.jpg)| *.jpg"
        $OpenFileDialog.ShowDialog() | Out-Null
        $OpenFileDialog.filename
        $OpenFileDialog.ShowHelp = $true
        $ppath = $OpenFileDialog.FileName

        $item = Get-Item $ppath
        if ($item.Length -gt 102400) {Throw "Unable to set $Username's picture. Picture must be less than 100 KB. Also recommend max size of 96 x 96 pixels."}
        else {
            Import-Module activedirectory
            $photo1 = [byte[]](Get-Content $ppath -Encoding byte)
            Set-ADUser $UserName -Replace @{thumbnailPhoto=$photo1}
        }
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}

Export-ModuleMember -Alias * -Function *