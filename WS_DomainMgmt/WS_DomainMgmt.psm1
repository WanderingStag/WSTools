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
    LASTEDIT: 10/04/2018 20:20:39
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

    if ($null -ne $SearchBase) {
        get-adgroup -filter * -properties * -SearchBase $SearchBase | Where-Object {-Not
        ($_ | get-adgroupmember)} |
        Select-Object CN,GroupScope,GroupCategory,ManagedBy,SamAccountName,whenCreated,CanonicalName
    }
    else {
        get-adgroup -filter * -properties * | Where-Object {-Not
        ($_ | get-adgroupmember)} |
        Select-Object CN,GroupScope,GroupCategory,ManagedBy,SamAccountName,whenCreated,CanonicalName
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
    LASTEDIT: 10/04/2018 20:11:20
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

    if ($null -ne $SearchBase) {
        Get-ADUser -filter * -Properties * -SearchBase $SearchBase | Where-Object {$_.msExchHideFromAddressLists -eq "TRUE"} |
        Select-Object givenName,Surname,SamAccountname,EmailAddress,msExchHideFromAddressLists
    }
    else {
        Get-ADUser -filter * -Properties * | Where-Object {$_.msExchHideFromAddressLists -eq "TRUE"} |
        Select-Object givenName,Surname,SamAccountname,EmailAddress,msExchHideFromAddressLists
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
        foreach ($comp in $ComputerName) {
            $site = nltest /server:$comp /dsgetsite 2>$null
            if($LASTEXITCODE -eq 0){$st = $site[0]}
            else {$st = "NA"}
            $info += New-Object -TypeName PSObject -Property @{
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

            $info = New-Object -TypeName PSObject -Property @{
                Name = $obj
                DaysSinceLastLogon = $dsll
                SamAccountName = $sam
            }#new object

            $info | Select-Object Name,DaysSinceLastLogon,SamAccountName
        }
    }
    End {}
}


Function Get-FSMO {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 08/18/2017 20:48:14
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    netdom /query FSMO
}
New-Alias -Name "FSMO" -Value Get-FSMO


Function Get-LockedOutStatus {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:06:06
    LASTEDIT: 09/21/2017 13:06:06
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
    }
    Process {
        foreach ($user in $Username) {
            $usrquery = Get-ADUser $User -properties LockedOut,lockoutTime
            $locked = $usrquery.LockedOut
            $locktime = $usrquery.lockoutTime
            if ($locked -eq $true) {
                New-Object psobject -Property @{
                    User = $user
                    Status = "Locked"
                    Date = $locktime
                    CheckTime = $cktime
                }
            }#if
            else {
                New-Object psobject -Property @{
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
    LASTEDIT: 08/18/2017 20:59:08
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

    $When = ((Get-Date).AddDays(-$Days)).Date
    Get-ADUser -Filter {whenCreated -ge $When} -Properties whenCreated | Select-Object Name,SamAccountName,whenCreated
}


Function Get-NewADGroup {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 02:34:40
    LASTEDIT: 08/18/2017 20:59:52
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

    $When = ((Get-Date).AddDays(-$Days)).Date
    Get-ADGroup -Filter {whenCreated -ge $When} -Properties whenCreated | Select-Object Name,SamAccountName,whenCreated
}


Function Get-ProtectedGroup {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/05/2018 17:24:35
    LASTEDIT: 02/05/2018 17:24:35
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
.LINK
    https://wstools.dev
#>
    $groups = (Get-ADGroup -filter {admincount -eq "1"}).Name | Sort-Object
    $groups
}


Function Get-ProtectedUser {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 02/05/2018 17:26:06
    LASTEDIT: 02/05/2018 17:26:06
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
.LINK
    https://wstools.dev
#>
    $users = (Get-ADUser -filter {admincount -eq "1"}).Name | Sort-Object
    $users
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
    LASTEDIT: 2020-08-24 20:36:05
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
.LINK
    https://wstools.dev
#>
    Write-Output "Getting OU names . . ."
    $ous = (Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Select-Object DistinguishedName).DistinguishedName
    $number = $ous.Count
    $info = @()
    $users = @()

    $ounum = 0
    foreach ($ouname in $ous) {
        $ounum++
        Write-Output "Getting OU $ounum of $number"
        $people = (get-aduser -filter * -properties thumbnailPhoto -searchbase "$ouname" -SearchScope OneLevel | Where-Object {$null -ne $_.thumbnailPhoto} | Select-Object Name,UserPrincipalName,thumbnailPhoto)
        $users += $people
    }

    foreach ($user in $users) {
        $name = $user.Name
        $upn = $user.UserPrincipalName
        $info += New-Object -TypeName PSObject -Property @{
            User = $name
            UserPrincipalName = $upn
            HasThumbnail = $true
        }#new object
    }

    $info | Select-Object Name,UserPrincipalName,HasThumbnail
}


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


Function Open-ADDomainsAndTrusts {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:27:24
    LASTEDIT: 08/19/2017 22:27:24
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    domain.msc
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
            Write-Host "Active Directory snapins are not installed/enabled."
        }
    }
}
New-Alias -Name "adsi" -Value Open-ADSIEdit


Function Open-ADSitesAndServices {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:29:08
    LASTEDIT: 08/19/2017 22:29:08
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    dssite.msc
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
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Host','Name','Computer','CN')]
        [string]$ComputerName = "$env:COMPUTERNAME"
    )
    fsmgmt.msc /computer=\\$ComputerName
}
New-Alias -Name "Shares" -Value Open-SharedFolders
New-Alias -Name "Get-Shares" -Value Open-SharedFolders


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
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
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
            "Restarting Active Directory service on $SrvName"
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
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string]$DC = "$env:COMPUTERNAME",
        [Switch]$All
    )
    if (!($All)) {
        "Restarting DNS service on $DC"
        try {Restart-Service -inputobject $(Get-Service -ComputerName $DC -Name DNS) -Force}
        catch {Throw "Unable to connect to $DC or failed to restart service."}
    }#if not all
    elseif ($All) {
        $AllDCs = (Get-ADForest).Domains | ForEach-Object {Get-ADDomainController -Filter * -Server $_}
        foreach ($Srv in $AllDCs) {
            $SrvName = $Srv.HostName
            "Restarting DNS service on $SrvName"
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
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string]$DC = "$env:COMPUTERNAME",
        [Switch]$All
    )
    if (!($All)) {
        "Restarting KDC service on $DC"
        try {Restart-Service -inputobject $(Get-Service -ComputerName $DC -Name kdc) -Force}
        catch {Throw "Unable to connect to $DC or failed to restart service."}
    }#if not all
    elseif ($All) {
        $AllDCs = (Get-ADForest).Domains | ForEach-Object {Get-ADDomainController -Filter * -Server $_}
        foreach ($Srv in $AllDCs) {
            $SrvName = $Srv.HostName
            "Restarting KDC service on $SrvName"
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