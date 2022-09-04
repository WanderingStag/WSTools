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
    Param (
        [Parameter()]
        [Switch]$netdom
    )
    if ([string]::IsNullOrWhiteSpace($netdom)) {
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
New-Alias -Name "FSMO" -Value Get-FSMO


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
    repadmin /replsum
}
New-Alias -Name "replsum" -Value Get-ReplicationStatus


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
    try {
        $ErrorActionPreference = "Stop"
        domain.msc
    }
    catch {
        Write-Output "Active Directory snapins are not installed/enabled."
    }
}
New-Alias -Name "trusts" -Value Open-ADDomainsAndTrusts


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
New-Alias -Name "adsi" -Value Open-ADSIEdit


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
    LASTEDIT: 08/19/2017 22:28:17
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    dsa.msc
}
New-Alias -Name "aduc" -Value Open-ADUsersAndComputers


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
    LASTEDIT: 08/19/2017 22:25:18
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    dhcpmgmt.msc
}
New-Alias -Name "dhcp" -Value Open-DHCPmgmt


Function Open-DNSmgmt {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:26:23
    LASTEDIT: 08/19/2017 22:26:23
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    dnsmgmt.msc
}
New-Alias -Name "dns" -Value Open-DNSmgmt


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
New-Alias -Name "Open-ECP" -Value Open-EAC
New-Alias -Name "EAC" -Value Open-EAC
New-Alias -Name "ECP" -Value Open-EAC


Function Open-GroupPolicyMgmt {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:30:09
    LASTEDIT: 08/19/2017 22:30:09
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    gpmc.msc
}
New-Alias -Name "gpo" -Value Open-GroupPolicyMgmt
New-Alias -Name "GroupPolicy" -Value Open-GroupPolicyMgmt


Function Open-HyperVmgmt {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:32:48
    LASTEDIT: 08/19/2017 22:32:48
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    virtmgmt.msc
}
New-Alias -Name "hyperv" -Value Open-HyperVmgmt


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
New-Alias -Name "iLO" -Value Open-iLO


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
New-Alias -Name "laps" -Value Open-LAPS


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
New-Alias -Name "Open-LMC" -Value Open-LexmarkManagementConsole


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
New-Alias -Name "netdiagram" -Value Open-NetworkDiagram
New-Alias -Name "networkdiagram" -Value Open-NetworkDiagram


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
New-Alias -Name "OWA" -Value Open-OWA


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
New-Alias -Name "rackel" -Value Open-RackElevation
New-Alias -Name "rackelevation" -Value Open-RackElevation


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
New-Alias -Name "Open-SDNMgmt" -Value Open-SDN
New-Alias -Name "SDN" -Value Open-SDN
New-Alias -Name "Open-Unifi" -Value Open-SDN
New-Alias -Name "unifi" -Value Open-SDN


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
New-Alias -Name "Open-SIEM" -Value Open-SEIM
New-Alias -Name "Open-ArcSight" -Value Open-SEIM
New-Alias -Name "Open-Splunk" -Value Open-SEIM


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
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string]$ComputerName = "$env:COMPUTERNAME"
    )
    fsmgmt.msc /computer=\\$ComputerName
}
New-Alias -Name "Shares" -Value Open-SharedFolders
New-Alias -Name "Get-Shares" -Value Open-SharedFolders


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
New-Alias -Name "vCenter" -Value Open-vCenter


function Register-ADSIEdit {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-19 19:53:38
    Last Edit: 2020-04-19 19:53:38
    Keywords:
.LINK
    https://wstools.dev
#>
    regsvr32.exe adsiedit.dll
}
New-Alias -Name "Initialize-ADSIEdit" -Value Register-ADSIEdit
New-Alias -Name "Enable-ADSIEdit" -Value Register-ADSIEdit


Function Register-Schema {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/12/2018 20:10:54
    LASTEDIT: 02/12/2018 20:10:54
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    regsvr32 schmmgmt.dll
}


Function Restart-ActiveDirectory {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/08/2017 16:03:23
    LASTEDIT: 09/08/2017 16:03:39
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


Function Restart-DNS {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/08/2017 17:23:43
    LASTEDIT: 09/08/2017 17:23:49
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


Function Restart-KDC {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 02:45:00
    LASTEDIT: 08/18/2017 20:46:32
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


function Set-ADProfilePicture {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:47:20
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [Alias('User','SamAccountname')]
        [string]$Username
    )

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

Export-ModuleMember -Alias * -Function *