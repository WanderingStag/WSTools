Function Copy-UserProfile {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/06/2020 19:39:42
    LASTEDIT: 04/06/2020 20:10:59
    KEYWORDS:
    REQUIRES:
        -Version 3.0
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = 'Enter user name. Ex: "1234567890A" without quotes',
            Mandatory=$true,
            Position=0
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('Username','SamAccountName')]
        [string]$User,

        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            Position=1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(HelpMessage = "Enter destination folder path as UNC unless a local path. Ex: E:\ESI\10-001 or \\COMP\e$\ESI\10-001",
            Mandatory=$false
        )]
        [Alias('Dest','DestinationFolder','DestFolder')]
        [string]$Destination = $null
    )
    Begin {
        if ($Destination -eq $null) {
            Write-Output "The destination folder selection window is open. It may be hidden behind windows."
            Add-Type -AssemblyName System.Windows.Forms
            $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
            $FolderBrowser.Description = "Select destination folder for user profile."
            $FolderBrowser.RootFolder = 'MyComputer'
            Set-WindowState MINIMIZE
            [void]$FolderBrowser.ShowDialog()
            Set-WindowState RESTORE
            $Destination = $FolderBrowser.SelectedPath
        }
        $df = $Destination + "\" + $User
    }
    Process {
        foreach ($comp in $ComputerName) {
            robocopy \\$comp\c$\Users\$user $df /mir /mt:3 /xj /r:3 /w:5 /njh /njs
        }
    }
    End {}
}


#Write help
#Add progress bar
function Find-UserProfile {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:58:21
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(Mandatory=$false, Position=1)]
        [Alias('User','SamAccountname')]
        [string[]]$Username = "$env:USERNAME"
    )

    $i = 0

    foreach ($Comp in $ComputerName) {
            #Progress Bar
            $length = $ComputerName.length
            $i++
            if ($length -gt "1") {
                $number = $ComputerName.length
                $amount = ($i / $number)
                $perc1 = $amount.ToString("P")
                Write-Progress -activity "Getting profile status on computers" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
            }#if length
        $compath = "\\" + $Comp + "\c$"
        if (Test-Connection $Comp -quiet) {
        try {
            New-PSDrive -Name ProfCk -PSProvider FileSystem -root "$compath" -ErrorAction Stop | Out-Null

            foreach ($User in $Username) {
                try {
                    $modtime = $null
                    $usrpath = "ProfCk:\Users\$User"
                    if (Test-Path -Path $usrpath) {
                        $modtime = Get-Item $usrpath | ForEach-Object {$_.LastWriteTime}
                        [PSCustomObject]@{
                            Name = $Comp
                            Status = "Online"
                            User = $User
                            Profile = "Yes"
                            ModifiedTime = $modtime
                        } | Select-Object Name,Status,User,Profile,ModifiedTime
                    }#if user profile exists on computer
                    else {
                        [PSCustomObject]@{
                            Name = $Comp
                            Status = "Online"
                            User = $User
                            Profile = "No"
                            ModifiedTime = $null
                        } | Select-Object Name,Status,User,Profile,ModifiedTime
                    }#else no profile
                }#try
                Catch [System.UnauthorizedAccessException] {
                    [PSCustomObject]@{
                        Name = $Comp
                        Status = "Access Denied"
                        User = $user
                        Profile = "Possible"
                        ModifiedTime = $null
                    } | Select-Object Name,Status,User,Profile,ModifiedTime
                }#catch access denied
            }#foreach user
            Remove-PSDrive -Name ProfCk -ErrorAction SilentlyContinue -Force | Out-Null
        }#try new psdrive
        Catch {
            [PSCustomObject]@{
                Name = $Comp
                Status = "Comm Error"
                User = $null
                Profile = $null
                ModifiedTime = $null
            } | Select-Object Name,Status,User,Profile,ModifiedTime
        }#catch new psdrive
        }#if online
        else {
            [PSCustomObject]@{
                Name = $Comp
                Status = "Offline"
                User = $null
                Profile = $null
                ModifiedTime = $null
            } | Select-Object Name,Status,User,Profile,ModifiedTime
        }
    }#foreach computer
}#find userprofile


#Need to add full c:\ drive search but exclude user profiles, windows, program files
#Find EFS encrypted folders
#Add check for additional drives, if there are then search those
function Find-UserProfileWithPSTSearch {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:58:26
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(Mandatory=$false, Position=1)]
        [Alias('User','SamAccountname')]
        [string[]]$Username = "$env:USERNAME"
    )

    $i = 0

    foreach ($Comp in $ComputerName) {
            #Progress Bar
            $length = $ComputerName.length
            $i++
            if ($length -gt "1") {
                $number = $ComputerName.length
                $amount = ($i / $number)
                $perc1 = $amount.ToString("P")
                Write-Progress -activity "Getting profile status on computers" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
            }#if length
        $compath = "\\" + $Comp + "\c$"
        try {
            New-PSDrive -Name ProfCk -PSProvider FileSystem -root "$compath" -ErrorAction Stop | Out-Null

            foreach ($User in $Username) {
                try {
                    $modtime = $null
                    $usrpath = "ProfCk:\Users\$User"
                    if (Test-Path -Path $usrpath -ErrorAction Stop) {
                        $modtime = Get-Item $usrpath | ForEach-Object {$_.LastWriteTime}

                        #Check for pst's
                        $pstck = (Get-ChildItem $usrpath -recurse -filter *.pst | Select-Object Name,LastWriteTime,LastAccessTime,Directory)
                        if ($null -ne $pstck) {
                            foreach ($pst in $pstck) {
                                $pstname = ($pst).Name
                                $pstlwt = ($pst).LastWriteTime
                                $pstlat = ($pst).LastAccessTime
                                $pstdir = ($pst).Directory.FullName

                                [PSCustomObject]@{
                                    Name = $Comp
                                    Status = "Online"
                                    User = $User
                                    Profile = "Yes"
                                    ProfileModifiedTime = $modtime
                                    PST = "Yes"
                                    PSTName = $pstname
                                    PSTLastWriteTime = $pstlwt
                                    PSTLastAccessTime = $pstlat
                                    PSTDirectory = $pstdir
                                } | Select-Object Name,Status,User,Profile,ProfileModifiedTime,PST,PSTName,PSTLastWriteTime,PSTLastAccessTime,PSTDirectory
                            }#foreach pst
                        }#if pstck not null
                        else {
                            [PSCustomObject]@{
                                Name = $Comp
                                Status = "Online"
                                User = $User
                                Profile = "Yes"
                                ProfileModifiedTime = $modtime
                                PST = "No"
                                PSTName = $null
                                PSTLastWriteTime = $null
                                PSTLastAccessTime = $null
                                PSTDirectory = $null
                            } | Select-Object Name,Status,User,Profile,ProfileModifiedTime,PST,PSTName,PSTLastWriteTime,PSTLastAccessTime,PSTDirectory
                        }#else pstck is null
                    }#if user profile exists on computer
                    else {
                        [PSCustomObject]@{
                            Name = $Comp
                            Status = "Online"
                            User = $User
                            Profile = "No"
                            ProfileModifiedTime = $null
                            PST = $null
                            PSTName = $null
                            PSTLastWriteTime = $null
                            PSTLastAccessTime = $null
                            PSTDirectory = $null
                        } | Select-Object Name,Status,User,Profile,ProfileModifiedTime,PST,PSTName,PSTLastWriteTime,PSTLastAccessTime,PSTDirectory
                    }#else no profile
                }#try
                Catch [System.UnauthorizedAccessException] {
                    [PSCustomObject]@{
                        Name = $Comp
                        Status = "Access Denied"
                        User = $user
                        Profile = "Possible"
                        ProfileModifiedTime = $null
                        PST = $null
                        PSTName = $null
                        PSTLastWriteTime = $null
                        PSTLastAccessTime = $null
                        PSTDirectory = $null
                    } | Select-Object Name,Status,User,Profile,ProfileModifiedTime,PST,PSTName,PSTLastWriteTime,PSTLastAccessTime,PSTDirectory
                }#catch access denied
            }#foreach user
            Remove-PSDrive -Name ProfCk -ErrorAction SilentlyContinue -Force | Out-Null
        }#try new psdrive
        Catch {
            [PSCustomObject]@{
                Name = $Comp
                Status = "Comm Error"
                User = $null
                Profile = $null
                ProfileModifiedTime = $null
                PST = $null
                PSTName = $null
                PSTLastWriteTime = $null
                PSTLastAccessTime = $null
                PSTDirectory = $null
            } | Select-Object Name,Status,User,Profile,ProfileModifiedTime,PST,PSTName,PSTLastWriteTime,PSTLastAccessTime,PSTDirectory
        }#catch new psdrive
    }#foreach computer
}#find userprofilewithpstsearch


function Export-MessagesToPST {
<#
   .Synopsis
    This function exports a users mailbox to a pst.
   .Description
    This function exports a users mailbox to a pst.
   .Example
    Export-MessagesToPST -TargetUserAlias joe.snuffy
    Exports joe.snuffy's mailbox to C:\Users\Desktop\joe.snuffy_mailboxyyyyMMddhhmm.pst where yyyyMMddhhmm is
    the date and time the mailbox was exported.
   .Example
    Export-MessagesToPST -TargetUserAlias joe.snuffy -ExportPath "c:\test"
    Exports joe.snuffy's mailbox to C:\test\joe.snuffy_mailboxyyyyMMddhhmm.pst where yyyyMMddhhmm is the date
    and time the mailbox was exported.
   .Parameter TargetUserAlias
    Mandatory parameter. Specify the users alias in Exchange or primary smtp address.
   .Parameter ExportPath
    By default saves to the logged on users desktop. You can specify where to save the pst to.
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 01/19/2014 01:20:00
    LASTEDIT: 2021-10-13 20:39:47
    KEYWORDS: Exchange, Mailbox, PST, export, InTh, Insider Threat
    REQUIRES:
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$TargetUserAlias,

        [Parameter(Mandatory=$false, Position=1)]
        [string]$ExportPath = ([System.Environment]::GetFolderPath("Desktop"))
    )

    $wmiq = Get-WmiObject win32_operatingsystem | Select-Object OSArchitecture
    if ($wmiq -like "*64-bit*") {
        [void][reflection.assembly]::LoadWithPartialName("System.Windows.Forms")
        $ErrorMsg = [System.Windows.Forms.MessageBox]::Show("Error: OS is 64-bit. Unable to Continue`n`nPrerequisites:`n1) Windows 32-bit OS`n2) Exchange 2007/2010/2013 32-bit Management Tools`n3) 32-bit Microsoft Office Suite with Microsoft Outlook`n4) Windows PowerShell v2 or newer","Error - Cannot Continue");
        $ErrorMsg
    }#if wmiq
    else {
        try {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.Admin -ErrorAction Stop}
        catch {Throw "Unable to add Microsoft.Exchange.Management.PowerShell.Admin snapin. Process cancelled."}

        Add-MailboxPermission -Identity "$TargetUserAlias" -User "$env:USERNAME" -AccessRights FullAccess -InheritanceType all -Confirm:$false
        new-item $ExportPath -type Directory -Force
        $LogDate = get-date -f yyyyMMddhhmm
        $FolderPath = $ExportPath + "\" + $TargetUserAlias + "_mailbox" + $LogDate + ".pst"
        Export-Mailbox -Identity "$TargetUserAlias" -PSTFolderPath $FolderPath -Confirm:$false
        Add-MailboxPermission -Identity "$TargetUserAlias" -User "$env:USERNAME" -Deny -AccessRights FullAccess -InheritanceType all -Confirm:$false
        Remove-MailboxPermission -Identity "$TargetUserAlias" -User "$env:USERNAME" -AccessRights FullAccess -InheritanceType all -Confirm:$false
    }#else
}#export messagestopst


function Get-ExchangeLastLoggedOnUser {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:58:33
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
 #Get-ADUser -Filter {EmailAddress -like "*"} -properties * | select EmailAddress | Export-Csv .\users.csv -NoTypeInformation
    $userfile = ".\users.csv"
    $users = "$userfile"

    foreach ($user in $users) {
        Get-MailboxStatistics -Identity $user.EmailAddress |
        Sort-Object DisplayName | Select-Object DisplayName,LastLoggedOnUserAccount,LastLogonTime,LastLogoffTime
    }
}#end get lastloggedonuser


#Change to WS script style
function Get-CurrentUser {
<#
.NOTES
    Author: Skyler Hart
    Created: 08/18/2017 20:58:42
    Last Edit: 2021-01-25 15:35:47
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName
    )

    Write-Output "`n Checking Users . . . "
    $i = 0

    $number = $ComputerName.length
    $ComputerName | Foreach-object {
    $Computer = $_
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting current user on computers. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length
    try
        {
            $processinfo = @(Get-WmiObject -class win32_process -ComputerName $Computer -EA "Stop")
                if ($processinfo) {
                    $processinfo | Foreach-Object {$_.GetOwner().User} |
                    Where-Object {$_ -ne "NETWORK SERVICE" -and $_ -ne "LOCAL SERVICE" -and $_ -ne "SYSTEM" -and $_ -ne "DWM-1" -and $_ -ne "UMFD-0" -and $_ -ne "UMFD-1 "} |
                    Sort-Object -Unique |
                    ForEach-Object {[PSCustomObject]@{Computer=$Computer;LoggedOn=$_} } |
                    Select-Object Computer,LoggedOn
                }#If
        }
    catch
        {
            "Cannot find any processes running on $computer" | Out-Host
        }
     }#Forech-object(ComputerName)
}#Get-CurrentUser


#Write help
function Get-LoggedOnUser {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:58:59
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Switch]$Lookup
     )

    foreach ($comp in $ComputerName) {
        if ($Lookup) {
            try {
                #$comp = "tvyxl-vpn119"
                $Hardware = get-wmiobject Win32_computerSystem -Computername $comp
                $username = $Hardware.Username
                $username2 = $username -creplace '^[^\\]*\\', ''
                $disp = (Get-ADUser $username2 -Properties DisplayName).DisplayName

                [PSCustomObject]@{
                    Computer = $Comp
                    Username = $Username
                    DisplayName = $disp
                } | Select-Object Computer,Username,DisplayName
            }#try
            catch {
                $Username = "Comm Error"
                [PSCustomObject]@{
                    Computer = $Comp
                    Username = $Username
                    DisplayName = $null
                } | Select-Object Computer,Username,DisplayName
            }#catch
        }#if need to lookup
        else {
            try {
                $Hardware = get-wmiobject Win32_computerSystem -Computername $comp
                $username = $Hardware.Username
                [PSCustomObject]@{
                    Computer = $Comp
                    Username = $Username
                } | Select-Object Computer,Username
            }#try
            catch {
                $Username = "Comm Error"
                [PSCustomObject]@{
                    Computer = $Comp
                    Username = $Username
                } | Select-Object Computer,Username
            }#catch
        }#else
    }#foreach comp
}


# Add check for currently logged on
# Add try catch
# Add progress bar
function Get-RecentUser {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 8/7/2017
    LASTEDIT: 2023-09-20 17:47:45
    KEYWORDS:
    REQUIRES:
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    Process {
        foreach ($Comp in $ComputerName) {

            if ($number -gt "1") {
                $i++
                $amount = ($i / $number)
                $perc1 = $amount.ToString("P")
                Write-Progress -activity "Getting recent users on computers. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
            }#if length

            #Gather events
            $eventlogSplat = @{
                'LogName' = 'Security'
                'ComputerName' = "$Comp"
                'FilterXPath' = '*[System[EventID=4624]] and (*[EventData[Data[@Name="LogonType"] = "2"]] or *[EventData[Data[@Name="LogonType"] = "3"]] or *[EventData[Data[@Name="LogonType"] = "7"]] or *[EventData[Data[@Name="LogonType"] = "10"]] or *[EventData[Data[@Name="LogonType"] = "11"]]) and (*[EventData[Data[@Name="TargetDomainName"] != "NT Authority"]] and *[EventData[Data[@Name="TargetDomainName"] != "Window Manager"]])'
                'MaxEvents' = 1000
            }
            $winevents = Get-WinEvent @eventlogSplat

            $events = foreach ($event in $winevents) {
                $event | Select-Object @{label='Time';expression={$_.TimeCreated}},
                    @{label='ComputerName';expression={$Comp}},
                    @{label='Username';expression={$_.Properties[5].Value}},
                    @{label='LogonType';expression={$_.Properties[8].Value}} |
                    Where-Object {$_.Username -notmatch "$Comp" -and $_.Username -notlike "UMFD-*"}
            }#foreach event in winevent

            #Filter by type of logon, username, and domain
            $events2 = $events | Select-Object Time,ComputerName,Username,LogonType | ForEach-Object {
                    if ($_.LogonType -eq 2) {$type2 = "Local"}#if 2
                    if ($_.LogonType -eq 3) {$type2 = "Remote"}#if 3
                    if ($_.LogonType -eq 7) {$type2 = "UnlockScreen"}#if 7
                    if ($_.LogonType -eq 10) {$type2 = "Remote"}#if 10
                    if ($_.LogonType -eq 11) {$type2 = "CachedLocal"}#if 11
                    [PSCustomObject]@{
                        When = $_.Time
                        Computer = $_.ComputerName
                        Type = $type2
                        User = $_.Username
                    }
                }

            #Get 2nd and 3rd most recent users
            #$users = $null
            Clear-Variable -Name notuser1,notuser2,user2,user3 -ErrorAction SilentlyContinue | Out-Null

            if ($null -ne $($events2).User) {$user1 = ($events2).User[0]}

            $events2 | ForEach-Object {
                if ($_.User -ne $user1) {[string[]]$notuser1 += $_.User}
            }#get unique users

            if ($null -ne $notuser1) {
                $user2 = $notuser1[0]
                foreach ($person in $notuser1) {
                    if ($null -ne $person) {
                        if ($person -ne $user2) {[string[]]$notuser2 += $person}
                        if ($null -ne $notuser2) {$user3 = $notuser2[0]}
                    }#if person not null
                }#previous user3
            }#if users not null

            #Get most recent logon event for each of the 3 users
            Clear-Variable -Name user1events,user2events,user3events -ErrorAction SilentlyContinue | Out-Null

            $user1events = $events2 | Where-Object {$_.User -eq $user1}
            $user2events = $events2 | Where-Object {$_.User -eq $user2}
            $user3events = $events2 | Where-Object {$_.User -eq $user3}

            if ($null -ne $user1events) {$user1events[0]}
            if ($null -ne $user2events) {$user2events[0]}
            if ($null -ne $user3events) {$user3events[0]}
        }#foreach computer
    }
}#get recent users


#Will show connected iPhones and other USB devices.
function Get-USBDevice {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 02:34:40
    LASTEDIT: 08/18/2017 21:00:23
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('usb')]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    foreach ($comp in $ComputerName) {
    Get-WmiObject Win32_USBControllerDevice -ComputerName $comp | ForEach-Object {[wmi]($_.Dependent)} | `
        Where-Object {$_.Name -notmatch "Composite Device" -and $_.Name -notmatch "Input Device" -and $_.Name -notmatch "Root Hub" `
        -and $_.Name -notmatch "Keyboard Device" -and $_.Name -notlike "HID-*"} | `
        Select-Object SystemName,Caption,DeviceID,Manufacturer,Name,Description | Sort-Object Caption
    }
}


#Write help
function Get-USBStorageDevice {
<#
.SYNOPSIS
    Shows USB storage devices that have connected to a computer.
.DESCRIPTION
    Shows USB storage devices that have connected to a local or remote computer. Limitations apply. Only shows devices that are listed in the registry. Sometimes, depending on the computer that is only the most recent device.
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.EXAMPLE
    C:\PS>Get-USBStorageDevice
    Example of how to use this cmdlet on a local computer.
.EXAMPLE
    C:\PS>Get-USBStorageDevice -ComputerName COMP1
    Shows the USB storage devices that have connected to the remote computer COMP1.
.NOTES
    Author: Skyler Hart
    Created: Sometime before 8/7/2017
    Last Edit: 2021-06-28 22:46:02
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    Begin {
        $dns = $env:USERDNSDOMAIN
        $ErrorActionPreference = "Stop"
        $Hive = "LocalMachine"
        $Key = "SYSTEM\CurrentControlSet\Enum\USBSTOR"
        $ComputerCount = 0
    }
    Process {
        foreach ($Comp in $ComputerName) {
            $Description,$DeviceID,$DT,$mac,$Manu,$Name,$sn = $null
            $USBSTORSubKeys1 = @()
            $ChildSubKeys = @()
            $ChildSubKeys1 = @()
            $ComputerCount++
            Write-Progress -Activity "Getting USB Storage Devices" -Status "Getting USB storage devices from $Comp" -PercentComplete (($ComputerCount/($ComputerName.Count)*100))

            <#
            ==================================
                       USB History
            ==================================
            #>
            try {
                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Hive,$Comp)
                $USBSTORKey = $Reg.OpenSubKey($Key)
                $USBSTORSubKeys1  = $USBSTORKey.GetSubKeyNames()
            }
            catch {
                $USBSTORSubKeys1 = $null
            }

            foreach ($SubKey1 in $USBSTORSubKeys1) {
                $ErrorActionPreference = "Continue"
                $Key2 = "SYSTEM\CurrentControlSet\Enum\USBSTOR\$SubKey1"
                $RegSubKey2 = $Reg.OpenSubKey($Key2)
                $SubkeyName2 = $RegSubKey2.GetSubKeyNames()
                $ChildSubkeys += "$Key2\$SubKeyName2"
                $RegSubKey2.Close()
            }#foreach subkey1

            foreach ($Child in $ChildSubKeys) {
                if ($Child -match " ") {
                    $BabySubKey = $null
                    $ChildSubKey1 = ($Child.Split(" "))[0]
                    $SplitChildSubKey1 - $ChildSubKey1.Split("\")

                    0..4 | ForEach-Object {[String]$BabySubKey += ($SplitChildSubkey1[$_]) + "\"}

                    $ChildSubKeys1 += $BabySubKey + ($Child.Split(" ")[-1])
                    $ChildSubKeys1 += $ChildSubKey1
                }#if
                else {
                    $ChildSubKeys1 += $Child
                }
                #$ChildSubKeys1.count
            }#foreach sub-child subkey

            foreach ($ChildSubKey1 in $ChildSubKeys1) {
                $USBKey = $Reg.OpenSubKey($ChildSubKey1)
                $USBDevice = $USBKey.GetValue('FriendlyName')

                if ($USBDevice) {
                    $USBDevices += [PSCustomObject]@{
                        USBDevice = $USBDevice
                        Computer  = $Comp
                        SerialNumber = ($ChildSubkey1.Split("\")[-1]).Split("&")[0]
                        Status = "Not connected"
                    }#new object
                }#if usbdevice
                $USBKey.Close()
            }#foreach child subkey
            $USBSTORKey.Close()

            <#
            ==================================
                       Active Devices
            ==================================
            #>
            $info = @()
            try {
                $usbinfo = $null
                $mac = $null
                $usbinfo = (Get-WmiObject -Class Win32_PnPEntity -Namespace "root\CIMV2" -ComputerName $Comp -ErrorAction Stop | Where-Object {$_.DeviceID -like "USBSTOR*" -and $_.DeviceID -notlike "*USBSTOR\CDROM&*"} | Select-Object Description,DeviceID,Manufacturer,Name)
                $mac = (Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $Comp -ErrorAction SilentlyContinue | Where-Object {$null -ne $_.DNSDomain} | Where-Object {$_.DNSDomainSuffixSearchOrder -match $dns}).MACAddress | Where-Object {$_ -ne $null}

                if ($mac.count -gt 1) {
                    $mac = $mac.ToString()
                }

                foreach ($usbinfo2 in $usbinfo) {
                    Clear-Variable Description,DeviceId,Manu,Name,sn -ErrorAction SilentlyContinue | Out-Null

                    #Create the object data
                    $Description = $usbinfo2.Description
                    $DeviceID = $usbinfo2.DeviceID
                    $Manu = $usbinfo2.Manufacturer
                    $Name = $usbinfo2.Name
                    $sn = $DeviceId
                    if ($sn -like "*&0" -or $sn -like "*&1") {
                        $sn = $sn.subString(0,$sn.length-2)
                        #for string and non string values: $text -replace ".{x}$"
                    }
                    $sn = $sn -creplace '(?s)^.*\\',''
                    $sn = $sn -creplace '(?s)^.*&&',''
                    #remove everything up to the first \: -creplace '^[^\\]*\\', ''
                    #remove everything to the last \: -creplace '(?s)^.*\\', ''
                    $sn = $sn -replace "____",""

                    if ($Description -match "Flash" -or $Name -match "Flash" -or $Name -match " FD ") {$DT = "Flash Drive"}
                    else {$DT = "External Hard Drive"}

                    $info += [PSCustomObject]@{
                        Computer = $comp
                        DeviceType = $DT
                        "Instance Path" = $DeviceID
                        "Display Name" = $Name
                        "MAC Address" = $mac
                        "Serial Number" = $sn
                        Status = "Connected"
                    }
                }#foreach storage device on the computer
                if ($null -eq $usbinfo) {
                    $DeviceID = "NO USB STORAGE DEVICE FOUND"
                    $info += [PSCustomObject]@{
                        Computer = $comp
                        DeviceType = $null
                        "Instance Path" = $DeviceID
                        "Display Name" = $null
                        "MAC Address" = $null
                        "Serial Number" = $null
                        Status = $null
                    }
                }
            }#try
            catch {
                $Description,$DeviceID,$DT,$mac,$Manu,$Name,$sn = $null
                $DeviceID = "Unable to connect"
                $info += [PSCustomObject]@{
                    Computer = $comp
                    DeviceType = $null
                    "Instance Path" = $DeviceID
                    "Display Name" = $null
                    "MAC Address" = $null
                    "Serial Number" = $null
                    Status = $null
                }
            }#catch

            <#
            ==================================
              Combine historical and active
            ==================================
            #>

            foreach ($USB in $USBDevices) {
                $name,$sn,$Status = $null

                $name = $USB.USBDevice
                $sn = $USB.SerialNumber
                $Status = $USB.Status
                $DT = $null
                $IP = $null
                $mac = $null

                if ($name -match "Flash" -or $name -match " FD ") {$DT = "Flash Drive"}
                else {$DT = "External Hard Drive"}

                foreach ($device in $info) {
                    $dsn,$IP,$mac = $null
                    $dsn = $device."Serial Number"
                    if ($dsn -eq $sn) {
                        $DT = $device.DeviceType
                        $IP = $device."Instance Path"
                        $mac = $device."MAC Address"
                        $Status = $device.Status
                    }
                }

                [PSCustomObject]@{
                    ComputerName = $Comp
                    DeviceType = $DT
                    "Instance Path" = $IP
                    "Display Name" = $name
                    "MAC Address" = $mac
                    "Serial Number" = $sn
                    Status = $Status
                } | Select-Object ComputerName,DeviceType,"Display Name","Instance Path","Serial Number","MAC Address",Status

            }#foreach usb device
        }#foreach comp
    }#process
    End {
        #
    }
}#end get-usbstoragedevice


function Get-UserLogonLogoffTime {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 21:00:47
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(Mandatory=$false, Position=1)]
        [Alias('Date','Time')]
        [string]$DaysBackToSearch = "1"
    )

    #Values for testing
    #$Comp = "$env:ComputerName"
    #$DaysBackToSearch = "1"

    #Event ID(s) to search for
    [int32[]]$ID = @(4624,4634)

    #Strings to search for
    $filecontent = "TaskDisplayName
MachineName
TimeCreated
Account Name:
Account Domain:
Logon Type:
Process Name:"

    #Setting initial values
    $i = 0
    $number = $ComputerName.length
    $stime = (Get-Date) - (New-TimeSpan -Day $DaysBackToSearch)


    #Search Each Computer
    foreach ($Comp in $ComputerName) {

        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting recent users on computers. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length


        #Other Variables
        $dnsdomain = "." + $env:USERDNSDOMAIN
        $csvcontent = "Task,When1,Computer1,AccountName,Domain2,LogonType1,Username1,Domain1,ProcessName1
            "


        #Create new files used during processing
        New-Item $env:Temp\searchlist.lst -ItemType File -Force -Value $filecontent | Out-Null
        New-Item $env:Temp\events.csv -ItemType File -Force -Value $csvcontent | Out-Null


        #Gather events
        $winevent = Get-WinEvent -ComputerName $Comp -FilterHashTable @{Logname='security'; ID= $ID; StartTime=$stime}


        foreach ($event in $winevent) {
            ($event | Select-Object TaskDisplayName,TimeCreated,MachineName,Message | Format-List * | findstr /G:"$env:TEMP\searchlist.lst") -replace "  ","" `
            -replace "TimeCreated : ","" -replace "MachineName : ","" -replace "Security ID:","" -replace "Account Name:","" `
            -replace "Account Domain:","" -replace "Logon ID:","" -replace "Logon Type:","" -replace "Security ID:","" `
            -replace "Account Name:","" -replace "Account Domain:","" -replace "Logon ID:","" -replace "Logon GUID:","" `
            -replace "Process Name:","" -replace "$dnsdomain","" -join "," -replace "TaskDisplayName : ","" | Out-File "$env:Temp\events.csv" -Append utf8
        }#foreach event in winevent


        #Process information on all events for the computer
        $events = Import-Csv "$env:Temp\events.csv"

        $notcomp = $comp + "$"
        $notcomp2 = "*$*"

        #Filter by type of logon, username, and domain
        $events | Where-Object {$_.LogonType1 -eq "2" -or $_.LogonType1 -eq "3" -or $_.LogonType1 -eq "7" -or $_.LogonType1 -eq "10" -or $_.LogonType1 -eq "11" `
            -and ($_.Domain1 -eq "$env:USERDOMAIN" -or $null -eq $_.Domain1) -and $_.Username1 -ne "$notcomp" -and $_.Username1 -notlike "$notcomp2"} |
            Select-Object Computer1,When1,Task,LogonType1,AccountName,Username1,ProcessName1 | ForEach-Object {
                $usrnm = $null
                if ($null -ne $_.Username1 -and $_.Username1 -ne "$notcomp" -and $_.Username1 -ne "$notcomp2") {$usrnm = $_.Username1}
                if ($null -eq $_.Username1  -and $_.AccountName -ne "$notcomp" -and $_.AccountName -ne "$notcomp2") {$usrnm = $_.AccountName}
                #if ($_.AccountName -ne "$notcomp" -or $_.AccountName -ne "$notcomp2") {$User = $_.AccountName}
                if ($_.LogonType1 -eq 2) {$type2 = "Local"}#if 2
                if ($_.LogonType1 -eq 3) {$type2 = "Remote"}#if 3
                if ($_.LogonType1 -eq 7) {$type2 = "UnlockScreen"}#if 7
                if ($_.LogonType1 -eq 11) {$type2 = "CachedLocal"}#if 11
                [PSCustomObject]@{
                    When = $_.When1
                    Computer = $_.Computer1
                    Task = $_.Task
                    Type = $type2
                    User = $usrnm
                    ProcessName = $_.ProcessName1
                } | Select-Object Computer,When,Task,Type,User,ProcessName
            } | Select-Object Computer,When,Task,Type,User | Export-Csv "$env:Temp\events2.csv" -Force -NoTypeInformation


        $events2 = Import-Csv "$env:Temp\events2.csv"
        ($events2) | Select-Object Computer,When,Task,Type,User


        Remove-Item "$env:TEMP\searchlist.lst" -Force
        Remove-Item "$env:Temp\events.csv" -Force
        Remove-Item "$env:Temp\events2.csv" -Force
    }#foreach computer
}


function Get-WSLocalGroup {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-02-28 19:52:59
    Last Edit: 2021-02-28 21:06:49
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200,

        [Parameter()]
        [string]$Output = $null

    )
    Begin {
        $config = $Global:WSToolsConfig
        $ScriptWD = $config.ScriptWD

        $ISS = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $ISS, $Host)
        $RunspacePool.Open()
        $Code = {
            [CmdletBinding()]
            Param (
                [Parameter(
                    Mandatory=$true,
                    Position=0
                )]
                [string]$comp,

                [Parameter(
                    Mandatory=$true,
                    Position=1
                )]
                [string]$Output
            )

            $info = @()
            try {
                $Role = (Get-WmiObject -ComputerName $comp -Class Win32_ComputerSystem -Property DomainRole -ErrorAction Stop).DomainRole
            }
            catch {
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    DatePulled = $Null
                    Description = $Null
                    Group = $Null
                    Members = $Null
                    Status = "Comm Error"
                }#new object
            }

            if ($Role -match "4|5") {
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    DatePulled = $Null
                    Description = $Null
                    Group = $Null
                    Members = $Null
                    Status = "Domain Controller - no local groups"
                }#new object
            }#if DC
            elseif ($Role -match "0|1|2|3") {
                $td = Get-Date
                $GI = ([ADSI]"WinNT://$comp").Children | Where-Object {$_.SchemaClassName -eq 'Group'}
                foreach ($group in $GI) {
                    $members = ($group.Invoke('Members') | ForEach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}) -join ", "
                    $info += [PSCustomObject]@{
                        ComputerName = $comp
                        DatePulled = $td
                        Description = $group.Description[0]
                        Group = $group.Name[0]
                        Members = $members
                        Status = "Connected"
                    }#new object
                }#foreach group on computer
            }#not DC

            if (Test-Path $Output) {
                $info | Select-Object ComputerName,Status,Group,Description,Members,DatePulled | Export-Csv $Output -NoTypeInformation -Append
            }
            else {
                $info | Select-Object ComputerName,Status,Group,Description,Members,DatePulled | Export-Csv $Output -NoTypeInformation
            }
        }#end code block
        $Jobs = @()
    }
    Process {
        if ([string]::IsNullOrWhiteSpace($Output)) {
            if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
            $Output = $ScriptWD + "\WS_LocalGroup.csv"
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($Output.ToString()) | out-null
            $PowershellThread.RunspacePool = $RunspacePool
            $Handle = $PowershellThread.BeginInvoke()
            $Job = "" | Select-Object Handle, Thread, object
            $Job.Handle = $Handle
            $Job.Thread = $PowershellThread
            $Job.Object = $Object.ToString()
            $Jobs += $Job
        }
    }
    End {
        $ResultTimer = Get-Date
        While (@($Jobs | Where-Object {$Null -ne $_.Handle}).count -gt 0)  {
            $Remaining = "$($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).object)"
            If ($Remaining.Length -gt 60){
                $Remaining = $Remaining.Substring(0,60) + "..."
            }
            Write-Progress `
                -Activity "Waiting for Jobs - $($MaxThreads - $($RunspacePool.GetAvailableRunspaces())) of $MaxThreads threads running" `
                -PercentComplete (($Jobs.count - $($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).count)) / $Jobs.Count * 100) `
                -Status "$(@($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False})).count) remaining - $remaining"
            ForEach ($Job in $($Jobs | Where-Object {$_.Handle.IsCompleted -eq $True})){
                $Job.Thread.EndInvoke($Job.Handle)
                $Job.Thread.Dispose()
                $Job.Thread = $Null
                $Job.Handle = $Null
                $ResultTimer = Get-Date
            }
            If (($(Get-Date) - $ResultTimer).totalseconds -gt $MaxResultTime){
                Write-Error "Child script appears to be frozen, try increasing MaxResultTime"
                Exit
            }
            Start-Sleep -Milliseconds $SleepTimer
        }
        $RunspacePool.Close() | Out-Null
        $RunspacePool.Dispose() | Out-Null
    }
}


function Get-WSLocalUser {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-02-27 22:05:08
    Last Edit: 2021-02-28 21:05:57
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200,

        [Parameter()]
        [string]$Output = $null

    )
    Begin {
        $config = $Global:WSToolsConfig
        $ScriptWD = $config.ScriptWD

        $ISS = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $ISS, $Host)
        $RunspacePool.Open()
        $Code = {
            [CmdletBinding()]
            Param (
                [Parameter(
                    Mandatory=$true,
                    Position=0
                )]
                [string]$comp,

                [Parameter(
                    Mandatory=$true,
                    Position=1
                )]
                [string]$Output
            )

            $info = @()
            try {
                $Role = (Get-WmiObject -ComputerName $comp -Class Win32_ComputerSystem -Property DomainRole -ErrorAction Stop).DomainRole
            }
            catch {
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    DatePulled = $Null
                    Description = $Null
                    Disabled = $Null
                    LastLogin = $Null
                    Locked = $Null
                    PasswordExpired = $Null
                    PasswordLastSet = $Null
                    PasswordLastSetDays = $Null
                    PasswordNeverExpires = $Null
                    PasswordNotChangable = $Null
                    PasswordNotRequired = $Null
                    Status = "Comm Error"
                    User = $Null
                }#new object
            }

            if ($Role -match "4|5") {
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    DatePulled = $Null
                    Description = $Null
                    Disabled = $Null
                    LastLogin = $Null
                    Locked = $Null
                    PasswordExpired = $Null
                    PasswordLastSet = $Null
                    PasswordLastSetDays = $Null
                    PasswordNeverExpires = $Null
                    PasswordNotChangable = $Null
                    PasswordNotRequired = $Null
                    Status = "Domain Controller - no local users"
                    User = $Null
                }#new object
            }#if DC
            elseif ($Role -match "0|1|2|3") {
                $UI = ([ADSI]"WinNT://$comp").Children | Where-Object {$_.SchemaClassName -eq 'User'}
                $td = Get-Date
                $info = foreach ($user in $UI) {
                    $uflags = $user.UserFlags[0]
                    $flags = New-Object System.Collections.ArrayList
                    switch ($uflags) {
                        ($uflags -BOR 0x0002) {[void]$flags.Add('Disabled')}
                        ($uflags -BOR 0x0010) {[void]$flags.Add('Locked')}
                        ($uflags -BOR 0x0020) {[void]$flags.Add('PwdNotReq')}
                        ($uflags -BOR 0x0040) {[void]$flags.Add('PwdNotChangable')}
                        ($uflags -BOR 0x10000) {[void]$flags.Add('NeverExp')}
                        ($uflags -BOR 0x800000) {[void]$flags.Add('PwdExp')}
                    }
                    $List = $flags -join ', '
                    [int32]$pa = 0
                    $pa = $user.PasswordAge[0]
                    $pls = ((Get-Date).AddSeconds(-($pa)))
                    $plsd = (New-TimeSpan -Start $pls -End (Get-Date)).Days

                    [PSCustomObject]@{
                        ComputerName = $comp
                        DatePulled  = $td
                        Description = $user.Description[0]
                        Disabled = if ($List -match "Disabled") {$true} else {$false}
                        LastLogin = (($user.LastLogin[0]).DateTime)
                        Locked = if ($List -match "Locked") {$true} else {$false}
                        PasswordExpired = if ($List -match "PwdExp") {$true} else {$false}
                        PasswordLastSet = $pls
                        PasswordLastSetDays = $plsd
                        PasswordNeverExpires = if ($List -match "NeverExp") {$true} else {$false}
                        PasswordNotChangable = if ($List -match "PwdNotChangable") {$true} else {$false}
                        PasswordNotRequired = if ($List -match "PwdNotReq") {$true} else {$false}
                        Status = "Connected"
                        User = $user.Name[0]
                    }#new object
                }#foreach user on computer
            }#not DC

            if (Test-Path $Output) {
                $info | Select-Object ComputerName,Status,User,Description,Disabled,LastLogin,Locked,PasswordExpired,PasswordLastSet,PasswordLastSetDays,PasswordNeverExpires,PasswordNotChangable,PasswordNotRequired,DatePulled | Export-Csv $Output -NoTypeInformation -Append
            }
            else {
                $info | Select-Object ComputerName,Status,User,Description,Disabled,LastLogin,Locked,PasswordExpired,PasswordLastSet,PasswordLastSetDays,PasswordNeverExpires,PasswordNotChangable,PasswordNotRequired,DatePulled | Export-Csv $Output -NoTypeInformation
            }
        }#end code block
        $Jobs = @()
    }
    Process {
        if ([string]::IsNullOrWhiteSpace($Output)) {
            if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
            $Output = $ScriptWD + "\WS_LocalUser.csv"
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($Output.ToString()) | out-null
            $PowershellThread.RunspacePool = $RunspacePool
            $Handle = $PowershellThread.BeginInvoke()
            $Job = "" | Select-Object Handle, Thread, object
            $Job.Handle = $Handle
            $Job.Thread = $PowershellThread
            $Job.Object = $Object.ToString()
            $Jobs += $Job
        }
    }
    End {
        $ResultTimer = Get-Date
        While (@($Jobs | Where-Object {$Null -ne $_.Handle}).count -gt 0)  {
            $Remaining = "$($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).object)"
            If ($Remaining.Length -gt 60){
                $Remaining = $Remaining.Substring(0,60) + "..."
            }
            Write-Progress `
                -Activity "Waiting for Jobs - $($MaxThreads - $($RunspacePool.GetAvailableRunspaces())) of $MaxThreads threads running" `
                -PercentComplete (($Jobs.count - $($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).count)) / $Jobs.Count * 100) `
                -Status "$(@($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False})).count) remaining - $remaining"
            ForEach ($Job in $($Jobs | Where-Object {$_.Handle.IsCompleted -eq $True})){
                $Job.Thread.EndInvoke($Job.Handle)
                $Job.Thread.Dispose()
                $Job.Thread = $Null
                $Job.Handle = $Null
                $ResultTimer = Get-Date
            }
            If (($(Get-Date) - $ResultTimer).totalseconds -gt $MaxResultTime){
                Write-Error "Child script appears to be frozen, try increasing MaxResultTime"
                Exit
            }
            Start-Sleep -Milliseconds $SleepTimer
        }
        $RunspacePool.Close() | Out-Null
        $RunspacePool.Dispose() | Out-Null
    }
}


Export-ModuleMember -Alias * -Function *