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
        Specify the distinguishedName(s) of organizational units (OUs) to search for group objects that have users.

    .PARAMETER AdminSearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for admin objects.

    .PARAMETER AdminGroupSearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for group objects that have admins.

    .PARAMETER ComputerSearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for computer objects.

    .PARAMETER MSASearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for Managed Service Account objects.

    .PARAMETER OrganizationalSearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for org boxes or shared account objects.

    .PARAMETER ServerSearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for server objects.

    .PARAMETER ServiceAccountSearchBase
        Specify the distinguishedName(s) of organizational units (OUs) to search for Service Account objects.

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
        https://wanderingstag.github.io
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
