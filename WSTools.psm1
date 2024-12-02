function Add-UserJavaException {
    <#
    .SYNOPSIS
        Adds Java exception.

    .DESCRIPTION
        Will add a website entry to $env:USERPROFILE\AppData\LocalLow\Sun\Java\Deployment\security\exception.sites.

    .PARAMETER URI
        Specifies the URI of the website you want to add to the exception.sites file. Must be in the
        format https://wanderingstag.github.io.

    .EXAMPLE
        C:\PS>Add-UserJavaException https://wanderingstag.github.io
        Example of how to use this cmdlet

    .INPUTS
        System.String

    .OUTPUTS
        No output

    .COMPONENT
        WSTools

    .FUNCTIONALITY
        java, exception

    .NOTES
        Author: Skyler Hart
        Created: 2019-03-20 10:40:11
        Last Edit: 2021-12-20 00:15:00

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the address of the website.",
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('Site','URL','Address','Website')]
        [string]$URI
    )
    Add-Content -Path "$env:USERPROFILE\AppData\LocalLow\Sun\Java\Deployment\security\exception.sites" -Value "$URI"
}


function Clear-DirtyShutdown {
    <#
    .SYNOPSIS
        Clears dirty shutdown registry key.

    .DESCRIPTION
        Clears the registry key that prompts you to enter a reason the computer/server was shutdown, even after a
        clean shutdown.

    .PARAMETER ComputerName
        Specifies the name of one or more computers.

    .EXAMPLE
        C:\PS>Clear-DirtyShutdown
        Will clear a dirty shutdown that causes the shutdown tracker to appear.

    .EXAMPLE
        C:\PS>Clear-DirtyShutdown -ComputerName COMP1
        Will clear the dirty shutdown on COMP1. You must have admin rights on the remote computer.

    .INPUTS
        System.String

    .OUTPUTS
        No output

    .COMPONENT
        WSTools

    .FUNCTIONALITY
        registry, dirty shutdown, computer management, server

    .NOTES
        Author: Skyler Hart
        Created: 2020-05-08 17:54:09
        Last Edit: 2021-12-19 23:58:28
        Requires -RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $i = 0
    $number = $ComputerName.length
    foreach ($Comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Setting Dirty Shutdown Fix" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        $k = "DirtyShutdown"
        $v = 0
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $Comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability',$true)
        $SubKey.SetValue($k, $v, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}


function Clear-ImproperProfileCopy {
    <#
    .Synopsis
        Clears Application Data folder that was improperly copied which happens when copy and pasting a profile.

    .Description
        Copies nested Application Data folders to a higher level (by default to C:\f2) and deletes them.

    .Example
        Clear-ImproperProfileCopy -Source \\fileserver\example\user -Destination E:\f2
        Clears nested Application Data folders from \\fileserver\example\user. Uses E:\f2 as the folder for
        clearing.

    .Example
        Clear-ImproperProfileCopy E:\temp\Profile E:\f2
        Clears nested Application Data folders from E:\temp\Profile. Uses E:\f2 as the folder for clearing.

    .Parameter Source
        Specifies the folder that contains the Application Data folder causing issues.

    .Parameter Destination
        Specifies the folder that is used to copy the nested folders to and deletes them.

    .Notes
        AUTHOR: Skyler Hart
        CREATED: 06/11/2016 20:37:14
        LASTEDIT: 2020-04-15 21:54:21
        KEYWORDS: user, profile, app data, application data, cleanup, clear, improper

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Source,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$Destination
    )

    if (!($Destination)) {
        New-Item $Destination -ItemType Directory
        $cd = $true
    }
    else {
        $cd = $false
    }

    $folder1 = $Source + "\Application Data"
    $folder2 = $Destination + "\Application Data"
    $folder3 = $Source + "Application Data\Application Data\Application Data\Application Data"
    $folder4 = $Destination + "\Application Data\Application Data\Application Data\Application Data"

    $i = 0
    do {
        Move-Item -Path $folder3 -Destination $f2
        start-sleep 1
        Remove-Item -Path $folder1 -Recurse -Force
        Remove-Item -Path $folder2 -Recurse -Force
        Move-Item -Path $folder4 -Destination $f1
        start-sleep 1
        Remove-Item -Path $folder2 -Recurse -Force
        Remove-Item -Path $folder1 -Recurse -Force
        Start-Sleep 1
        $i++
        Write-Output "Completed Pass $i"
    }
    until (!(Test-Path $folder3))

    if ($cd) {
        Remove-Item -Path $Destination -Recurse -Force
    }
}


Function Clear-Space {
    <#
    .Synopsis
        Clears harddrive space

    .Description
        Clears harddrive space by clearing temp files and caches. Invoke method does not clear as many locations.       #DevSkim: ignore DS104456

    .Example
        Clear-Space
        Clears temp and cache data on the local computer

    .Example
        Clear-Space -ComputerName COMP1
        Clears temp and cache data on the computer COMP1

    .Example
        Clear-Space -ComputerName (gc c:\complist.txt)
        Clears temp and cache data on the computers listed in the file c:\complist.txt

    .Example
        Clear-Space -ComputerName (gc c:\complist.txt) -InvokeMethod
        Clears temp and cache data on the computers listed in the file c:\complist.txt using the Invoke-WMIMethod
        command.                                                                                                        #DevSkim: ignore DS104456

    .Parameter ComputerName
        Specifies the computer or computers to clear space on

    .Parameter InvokeMethod
        Specifies the computer or computers to clear space on using the Invoke-WMIMethod command                        #DevSkim: ignore DS104456

    .Notes
        AUTHOR: Skyler Hart
        CREATED: 05/19/2017 20:16:47
        LASTEDIT: 07/22/2019 14:21:15
        KEYWORDS: Delete, temp, patches, cache, prefetch, SCCM
        REMARKS: Needs to be ran as a user that has administrator rights

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter()]
        [Switch]$InvokeMethod
    )

    $path = (Get-Location).Path

    foreach ($Comp in $ComputerName) {
        #region PSDrive Method
        $psdpath = "\\$comp\c$"
        if (!($InvokeMethod)) {
            try {
                New-PSDrive -Name CS -PSProvider FileSystem -root "$psdpath" -ErrorAction Stop | Out-Null
                # Remove C:\Temp files
                if (Test-Path CS:\Temp) {
                    Set-Location "CS:\Temp"
                    if ((Get-Location).Path -eq "CS:\Temp") {
                        Write-Output "Removing items in C:\Temp on $Comp"
                        Remove-Item * -recurse -force
                    }
                }

                # Remove Windows Temp file
                if (Test-Path CS:\Windows\Temp) {
                    Set-Location "CS:\Windows\Temp"
                    if ((Get-Location).Path -eq "CS:\Windows\Temp") {
                        Write-Output "Removing items in C:\Windows\Temp on $Comp"
                        Remove-Item * -recurse -force
                    }
                }

                # Remove Prefetch files
                if (Test-Path CS:\Windows\Prefetch) {
                    Set-Location "CS:\Windows\Prefetch"
                    if ((Get-Location).Path -eq "CS:\Windows\Prefetch") {
                        Write-Output "Removing items in C:\Windows\Prefetch on $Comp"
                        Remove-Item * -recurse -force
                    }
                }

                # Remove temp files from user profiles
                if (Test-Path CS:\Users) {
                    Set-Location "CS:\Users"
                    if ((Get-Location).Path -eq "CS:\Users") {
                        Write-Output "Removing temp items in C:\Users on $Comp"
                        Remove-Item “.\*\Appdata\Local\Temp\*” -recurse -force
                    }
                }

                # Remove cached SCCM files
                if (Test-Path CS:\Windows\SysWOW64\ccm\cache) {
                    Set-Location "CS:\Windows\SysWOW64\ccm\cache"
                    if ((Get-Location).Path -eq "CS:\Windows\SysWOW64\ccm\cache") {
                        Write-Output "Removing items in C:\Windows\SysWOW64\ccm\cache on $Comp"
                        Remove-Item * -recurse -force
                    }
                }
                if (Test-Path CS:\Windows\System32\ccm\cache) {
                    Set-Location "CS:\Windows\System32\ccm\cache"
                    if ((Get-Location).Path -eq "CS:\Windows\System32\ccm\cache") {
                        Write-Output "Removing items in C:\Windows\System32\ccm\cache on $Comp"
                        Remove-Item * -recurse -force
                    }
                }
                if (Test-Path CS:\Windows\ccmcache) {
                    Set-Location "CS:\Windows\ccmcache"
                    if ((Get-Location).Path -eq "CS:\Windows\ccmcache") {
                        Write-Output "Removing items in CS:\Windows\ccmcache on $Comp"
                        Remove-Item * -recurse -force
                    }
                }

                # Remove Windows update cache
                if (Test-Path CS:\Windows\SoftwareDistribution\Download) {
                    Set-Location "CS:\Windows\SoftwareDistribution\Download"
                    if ((Get-Location).Path -eq "CS:\Windows\SoftwareDistribution\Download") {
                        Write-Output "Removing items in C:\Windows\SoftwareDistribution\Download on $Comp"
                        Remove-Item * -recurse -force
                    }
                }

                # Remove old patches. This is more of something local to where Skyler works. If you don't need it, remove it or comment it out.
                if (Test-Path CS:\Patches) {
                    Set-Location "CS:\Patches"
                    if ((Get-Location).Path -eq "CS:\Patches") {
                        Write-Output "Removing items in C:\Patches on $Comp"
                        $ts = Get-Date
                        $items = Get-ChildItem -Recurse
                        foreach ($item in $items) {
                            $length = $item.Length
                            $lastwrite = ($ts - $item.LastWriteTime).TotalDays
                            $fname = $item.FullName
                            if ($null -ne $length -and $lastwrite -gt "45") {
                                Remove-Item $fname -Force
                            }
                        }
                        (Get-ChildItem CS:\Patches -recurse | Where-Object {$_.PSIsContainer -eq $True}) | Where-Object {$_.GetFiles().Count -eq 0} | Remove-Item -Recurse -Force
                    }
                }
                Remove-PSDrive -Name CS -ErrorAction SilentlyContinue -Force | Out-Null
            }# try
            catch {
                Write-Output "Unable to connect to computer: $Comp" -ForegroundColor Red
            }
        }#if Invoke False
        #endregion PSDrive Method

        #region Invoke Method
        else {
            try {
                $wmiq = Get-WmiObject win32_operatingsystem -ComputerName $Comp -ErrorAction Stop | Select-Object OSArchitecture
                # Clear SCCM cache
                if ($wmiq -like "*64-bit*") {
                    $invoke = Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c del "C:\Windows\SysWOW64\ccm\cache\*.*" /f /q && FOR /D %p IN ("C:\Windows\SysWOW64\ccm\cache\*") DO rmdir "%p" /q' -ErrorAction SilentlyContinue #DevSkim: ignore DS104456
                    $id32 = $invoke.ProcessId
                    Write-Output "Waiting for deletion of files in C:\Windows\SysWOW64\ccm\cache to complete"
                    do {(Start-Sleep -Seconds 10)}
                    until ((Get-WMIobject -Class Win32_process -ComputerName $Comp) | Where-Object {$_.ProcessID -eq $id32})
                }# if 64bit
                else {
                    $invoke = Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c del "C:\Windows\System32\ccm\cache\*.*" /f /q && FOR /D %p IN ("C:\Windows\System32\ccm\cache\*") DO rmdir "%p" /q' -ErrorAction SilentlyContinue #DevSkim: ignore DS104456
                    $id32 = $invoke.ProcessId
                    Write-Output "Waiting for deletion of files in C:\Windows\System32\ccm\cache to complete"
                    do {(Start-Sleep -Seconds 10)}
                    until ((Get-WMIobject -Class Win32_process -ComputerName $Comp) | Where-Object {$_.ProcessID -eq $id32})
                }# else if 32bit
                $invoke = Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c del "C:\Windows\ccmcache\*.*" /f /q && FOR /D %p IN ("C:\Windows\ccmcache\*") DO rmdir "%p" /q' -ErrorAction SilentlyContinue #DevSkim: ignore DS104456
                $id32 = $invoke.ProcessId
                Write-Output "Waiting for deletion of files in C:\Windows\ccmcache to complete"
                do {(Start-Sleep -Seconds 10)}
                until ((Get-WMIobject -Class Win32_process -ComputerName $Comp) | Where-Object {$_.ProcessID -eq $id32})

                # Remove C:\Temp files
                $invoke = Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c del "C:\Temp\*.*" /f /q && FOR /D %p IN ("C:\Temp\*") DO rmdir "%p" /q' -ErrorAction SilentlyContinue #DevSkim: ignore DS104456
                $id32 = $invoke.ProcessId
                Write-Output "Waiting for deletion of files in C:\Temp to complete"
                do {(Start-Sleep -Seconds 10)}
                until ((Get-WMIobject -Class Win32_process -ComputerName $Comp) | Where-Object {$_.ProcessID -eq $id32})

                # Remove Windows Temp files
                $invoke = Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c del "C:\Windows\Temp\*.*" /f /q && FOR /D %p IN ("C:\Windows\Temp\*") DO rmdir "%p" /q' -ErrorAction SilentlyContinue #DevSkim: ignore DS104456
                $id32 = $invoke.ProcessId
                Write-Output "Waiting for deletion of files in C:\Windows\Temp to complete"
                do {(Start-Sleep -Seconds 10)}
                until ((Get-WMIobject -Class Win32_process -ComputerName $Comp) | Where-Object {$_.ProcessID -eq $id32})

                # Remove Prefetch files
                $invoke = Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c del "C:\Windows\Prefetch\*.*" /f /q && FOR /D %p IN ("C:\Windows\Prefetch\*") DO rmdir "%p" /q' -ErrorAction SilentlyContinue #DevSkim: ignore DS104456
                $id32 = $invoke.ProcessId
                Write-Output "Waiting for deletion of files in C:\Windows\Prefetch to complete"
                do {(Start-Sleep -Seconds 10)}
                until ((Get-WMIobject -Class Win32_process -ComputerName $Comp) | Where-Object {$_.ProcessID -eq $id32})

                # Remove Windows Update cache
                $invoke = Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c del "C:\Windows\SoftwareDistribution\Download\*.*" /f /q && FOR /D %p IN ("C:\Windows\SoftwareDistribution\Download\*") DO rmdir "%p" /q' -ErrorAction SilentlyContinue #DevSkim: ignore DS104456
                $id32 = $invoke.ProcessId
                Write-Output "Waiting for deletion of files in C:\Windows\SoftwareDistribution\Download to complete"
                do {(Start-Sleep -Seconds 10)}
                until ((Get-WMIobject -Class Win32_process -ComputerName $Comp) | Where-Object {$_.ProcessID -eq $id32})
            }
            catch {
                Write-Output "Unable to connect to computer: $Comp" -ForegroundColor Red
            }
        }# invoke method
        #endregion Invoke Method
    }# foreach computer
    Set-Location $path
}


function Connect-RDP {
    <#
    .SYNOPSIS
        Establishes a Remote Desktop Protocol (RDP) connection to a specified computer.

    .DESCRIPTION
        This function allows the user to connect to a remote computer via RDP. If a computer name is provided, it connects to that specific computer. If no computer name is provided, it will open the RDP client without specifying a target.

    .PARAMETER ComputerName
        Specifies the name of the computer to which you want to connect. This parameter is optional. If omitted, the RDP client will open without a specified target.

    .EXAMPLE
        Connect-RDP -ComputerName "Server01"
        Connects to the computer named "Server01" using RDP.

    .EXAMPLE
        Connect-RDP
        Opens the RDP client without specifying a target computer.

    .NOTES
        AUTHOR: Skyler Hart
        CREATED: 2017-08-18 20:48:07
        LASTEDIT: 2024-11-27 10:59:28

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [alias('rdp')]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string]$ComputerName
    )

    if (!([string]::IsNullOrWhiteSpace($ComputerName))) {
        mstsc /v:$ComputerName /admin
    }
    else {
        mstsc
    }
}


function ConvertFrom-BuildNumber {
    <#
    .SYNOPSIS
        Converts a Microsoft Build number to a version number.

    .DESCRIPTION
        Takes a build number for Windows 8/Server 2012 or newer and converts it to a version number and Operatiing System.

    .PARAMETER Build
        Specifies the number of the Microsoft Build.

    .EXAMPLE
        C:\PS>ConvertFrom-BuildNumber 20348
        Example of how to use this cmdlet. This example will return Windows Server 2022.

    .INPUTS
        System.Int32

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .COMPONENT
        WSTools

    .FUNCTIONALITY
        Microsoft, Build, Version, conversion

    .NOTES
        Author: Skyler Hart
        Created: 2023-09-22 12:04:10
        Last Edit: 2023-09-22 12:21:16
        Other:

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [Alias('ConvertFrom-MicrosoftBuildNumber')]
    param(
        [Parameter(
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [int32[]] $Build
    )

    Process {
        foreach ($BuildNumber in $Build) {
            if ($BuildNumber -eq 9200) {
                [PSCustomObject]@{
                    OS = "Windows 8 or Windows Server 2012"
                    Build = $BuildNumber
                    Version ="6.2"
                }
            }
            elseif ($BuildNumber -eq 9600) {
                [PSCustomObject]@{
                    OS = "Windows 8.1 or Windows Server 2012 R2"
                    Build = $BuildNumber
                    Version ="6.3"
                }
            }
            elseif ($BuildNumber -eq 14393) {
                [PSCustomObject]@{
                    OS = "Windows 10 or Windows Server 2016"
                    Build = $BuildNumber
                    Version ="1607"
                }
            }
            elseif ($BuildNumber -eq 15063) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="1703"
                }
            }
            elseif ($BuildNumber -eq 16299) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="1709"
                }
            }
            elseif ($BuildNumber -eq 17134) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="1803"
                }
            }
            elseif ($BuildNumber -eq 17763) {
                [PSCustomObject]@{
                    OS = "Windows 10 or Windows Server 2019"
                    Build = $BuildNumber
                    Version ="1809"
                }
            }
            elseif ($BuildNumber -eq 18362) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="1903"
                }
            }
            elseif ($BuildNumber -eq 18363) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="1909"
                }
            }
            elseif ($BuildNumber -eq 19041) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="2004"
                }
            }
            elseif ($BuildNumber -eq 19042) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="20H2 (2009)"
                }
            }
            elseif ($BuildNumber -eq 19043) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="21H1 (2103)"
                }
            }
            elseif ($BuildNumber -eq 19044) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="21H2 (2109)"
                }
            }
            elseif ($BuildNumber -eq 22000) {
                [PSCustomObject]@{
                    OS = "Windows 11"
                    Build = $BuildNumber
                    Version ="21H2 (2109)"
                }
            }
            elseif ($BuildNumber -eq 20348) {
                [PSCustomObject]@{
                    OS = "Windows Server 2022"
                    Build = $BuildNumber
                    Version ="21H2 (2109)"
                }
            }
            elseif ($BuildNumber -eq 19045) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="22H2 (2209)"
                }
            }
            elseif ($BuildNumber -eq 19046) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="23H2 (2309)"
                }
            }
            elseif ($BuildNumber -eq 22621) {
                [PSCustomObject]@{
                    OS = "Windows 11"
                    Build = $BuildNumber
                    Version ="22H2 (2209)"
                }
            }
            elseif ($BuildNumber -eq 22631) {
                [PSCustomObject]@{
                    OS = "Windows 11"
                    Build = $BuildNumber
                    Version ="23H2 (2309)"
                }
            }
            elseif ($BuildNumber -eq 26100) {
                [PSCustomObject]@{
                    OS = "Windows 11"
                    Build = $BuildNumber
                    Version ="24H2 (2409)"
                }
            }
        }
    }
}


function Copy-PowerShellJSON {
    <#
    .SYNOPSIS
        Enables PowerShell Snippets in Visual Studio Code.

    .DESCRIPTION
        Copies the powershell.json file from the WSTools module folder to %AppData%\Roaming\Code\User\snippets for
        the currently logged on user.

    .EXAMPLE
        C:\PS>Copy-PowerShellJSON
        Copies the powershell.json file from the WSTools module folder to %AppData%\Roaming\Code\User\snippets for
        the currently logged on user.

    .NOTES
        Author: Skyler Hart
        Created: 2020-04-13 22:44:11
        Last Edit: 2021-10-19 16:59:47
        Keywords: WSTools, Visual Studio Code, PowerShell, JSON, Preferences, snippets, code blocks

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [Alias('Update-PowerShellJSON','Set-PowerShellJSON')]
    param()

    if (!(Test-Path $env:APPDATA\Code\User)) {
        New-Item -Path $env:APPDATA\Code -ItemType Directory -Name User -Force
    }
    if (!(Test-Path $env:APPDATA\Code\User\snippets)) {
        New-Item -Path $env:APPDATA\Code\User -ItemType Directory -Name snippets -Force
    }
    Copy-Item -Path $PSScriptRoot\powershell.json -Destination $env:APPDATA\Code\User\snippets\powershell.json -Force
}


function Copy-UpdateHistory {
    <#
    .SYNOPSIS
        Copies the UpdateHistory.csv report to the UHPath config item path.

    .DESCRIPTION
        Copies the UpdateHistory.csv report created with Save-UpdateHistory to the UHPath config item path for the
        local computer or remote computers.

    .PARAMETER ComputerName
        Specifies the name of one or more computers.

    .EXAMPLE
        C:\PS>Copy-UpdateHistory
        Example of how to use this cmdlet to copy the UpdateHistory.csv file for the local computer to the UHPath
        location.

    .EXAMPLE
        C:\PS>Copy-UpdateHistory -ComputerName Server1
        Example of how to use this cmdlet to copy the UpdateHistory.csv file for the remote computer Server1 to the
        UHPath location.

    .INPUTS
        System.String

    .OUTPUTS
        System.String

    .COMPONENT
        WSTools

    .FUNCTIONALITY
        UpdateHistory, update history

    .NOTES
        Author: Skyler Hart
        Created: 2022-07-15 22:54:09
        Last Edit: 2022-07-15 22:54:09
        Other:
        Requires:
            -RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $uhpath = ($Global:WSToolsConfig).UHPath
    $i = 0
    $number = $ComputerName.length
    foreach ($Comp in $ComputerName) {
        # Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Copying Update Reports. Current computer: $Comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }# if length

        if ($Comp -eq $env:COMPUTERNAME) {
            if (Test-Path C:\ProgramData\WSTools\Reports\$Comp`_UpdateHistory.csv) {
                robocopy C:\ProgramData\WSTools\Reports $uhpath *_UpdateHistory.csv /r:3 /w:5 /njh /njs | Out-Null
            }
            else {
                Write-Error "Report not found. Please use Save-UpdateHistory to create a report."
            }
        }
        else {
            robocopy \\$Comp\c$\ProgramData\WSTools\Reports $uhpath *_UpdateHistory.csv /r:3 /w:5 /njh /njs | Out-Null
        }
    }
}


function Copy-VSCodeExtensions {
    <#
    .SYNOPSIS
        Copies Visual Studio Code extensions from a specified repository to the user's local VSCode extensions directory.

    .DESCRIPTION
        This function copies all VSCode extensions from a defined repository to the user's local extensions directory, maintaining mirror consistency using robocopy.

    .PARAMETER RepoPath
        Specifies the path to the repository that contains the VSCode extensions. This path should be pre-configured in the WSTools configuration.

    .EXAMPLE
        Copy-VSCodeExtensions
        Copies VSCode extensions from the configured repository to the user's local extensions directory.

    .NOTES
        AUTHOR: Skyler Hart
        CREATED: 2021-11-01 23:18:30
        LASTEDIT: 2024-11-27 13:00:00

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param ()

    $repo = ($Global:WSToolsConfig).VSCodeExtRepo
    $dst = "$env:USERPROFILE\.vscode\extensions"

    if (-not (Test-Path -Path $dst)) {
        New-Item -Path $dst -ItemType Directory -Force | Out-Null
    }

    robocopy $repo $dst /mir /mt:4 /r:4 /w:15 /njh /njs
}


unction Copy-VSCodeSettingsToProfile {
    <#
    .SYNOPSIS
        Copies Visual Studio Code settings to the user's profile.

    .DESCRIPTION
        This function copies Visual Studio Code settings from a configured repository path to the user's profile, ensuring the settings are up-to-date.

    .PARAMETER VSCodeSettingsPath
        Specifies the path to the Visual Studio Code settings file. This path should be pre-configured in the WSTools configuration.

    .EXAMPLE
        Copy-VSCodeSettingsToProfile
        Copies the VSCode settings from the configured repository path to the user's profile settings.

    .NOTES
        AUTHOR: Skyler Hart
        CREATED: 2021-11-01 22:14:14
        LASTEDIT: 2024-11-27 13:00:00

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param ()

    $vscs = ($Global:WSToolsConfig).VSCodeSettingsPath
    $userSettingsPath = "$env:APPDATA\Code\User\settings.json"

    if (-not (Test-Path -Path "$env:APPDATA\Code\User")) {
        New-Item -Path "$env:APPDATA\Code" -ItemType Directory -Name "User" -Force | Out-Null
    }

    $settingsContent = Get-Content -Path $vscs -Raw

    if (Test-Path -Path $userSettingsPath) {
        Set-Content -Path $userSettingsPath -Value $settingsContent -Force
    } else {
        Add-Content -Path $userSettingsPath -Value $settingsContent -Force
    }
}


function Disable-RDP {
    <#
    .SYNOPSIS
        Disables Remote Desktop Protocol (RDP) on the local computer.

    .DESCRIPTION
        This function disables RDP on the local computer by modifying the appropriate registry key to deny RDP connections.
        It requires administrative privileges to execute.

    .EXAMPLE
        Disable-RDP
        Disables RDP on the local computer.

    .NOTES
        AUTHOR: Skyler Hart
        CREATED: 2021-02-27 11:44:34
        LASTEDIT: 2024-11-27 13:00:00
        REQUIRES: RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param ()

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
    } else {
        throw "Must be run as administrator."
    }
}


function Disable-ServerManager {
    <#
    .SYNOPSIS
        Disables the Server Manager from launching automatically on the local computer.

    .DESCRIPTION
        This function disables the Server Manager from launching automatically on the local computer by disabling the related scheduled task.
        It requires administrative privileges to execute.

    .EXAMPLE
        Disable-ServerManager
        Disables the Server Manager from launching automatically on the local computer.

    .NOTES
        AUTHOR: Skyler Hart
        CREATED: 2020-05-08 23:18:39
        LASTEDIT: 2024-11-27 13:00:00
        REQUIRES: RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param ()

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Get-ScheduledTask -TaskName "ServerManager" | Disable-ScheduledTask
    } else {
        throw "Must be run as administrator."
    }
}


function Enable-RDP {
    <#
    .SYNOPSIS
        Enables Remote Desktop Protocol (RDP) on the local computer.

    .DESCRIPTION
        This function enables RDP on the local computer by modifying the appropriate registry key to allow RDP connections.
        It requires administrative privileges to execute.

    .EXAMPLE
        Enable-RDP
        Enables RDP on the local computer.

    .NOTES
        AUTHOR: Skyler Hart
        CREATED: 2020-05-08 23:21:17
        LASTEDIT: 2024-11-27 13:00:00
        REQUIRES: RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param ()

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
    } else {
        throw "Must be run as administrator."
    }
}

function Enable-ServerManager {
    <#
    .SYNOPSIS
        Enables the Server Manager to launch automatically on the local computer.

    .DESCRIPTION
        This function enables the Server Manager to launch automatically on the local computer by enabling the related scheduled task.
        It requires administrative privileges to execute.

    .EXAMPLE
        Enable-ServerManager
        Enables the Server Manager to launch automatically on the local computer.

    .NOTES
        AUTHOR: Skyler Hart
        CREATED: 2021-12-16 21:29:35
        LASTEDIT: 2024-11-27 13:00:00
        REQUIRES: RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param ()

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Get-ScheduledTask -TaskName "ServerManager" | Enable-ScheduledTask
    } else {
        throw "Must be run as administrator."
    }
}


function Format-IPList {
    <#
    .SYNOPSIS
        Takes a list of IP addresses and sorts them.

    .DESCRIPTION
        This function takes a list of IP addresses and sorts them in the appropriate order.

    .PARAMETER IPs
        Used to specify the IP addresses that you wish to sort.

    .EXAMPLE
        Format-IPList -IPs 127.0.0.5, 127.0.0.100, 10.0.1.5, 10.0.1.1, 10.0.1.100
        Sorts the given list of IP addresses in the correct order.

    .EXAMPLE
        Sort-IPs 127.0.0.5, 127.0.0.100, 10.0.1.5, 10.0.1.1, 10.0.1.100
        Uses the alias Sort-IPs to sort the list of IP addresses.

    .NOTES
        AUTHOR: Skyler Hart
        CREATED: 2023-10-11 10:58:24
        LASTEDIT: 2024-11-27 13:00:00

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [Alias('Sort-IPList','Sort-IPs')]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias('IPAddresses')]
        [System.Net.IPAddress[]]$IPs
    )

    Process {
        $IPs | Sort-Object {
            $_.GetAddressBytes() -as [System.Collections.IComparer]
        }
    }
}


function Get-BitLockerStatus {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2020-04-22 22:10:27
        Last Edit: 2020-04-22 22:10:27
        Keywords: BitLocker, Local, Remote, manage, manage-bde, bde
        Requires:
            -RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $overall = @()
    foreach ($Comp in $ComputerName) {
        $i = 0
        try {
            $ErrorActionPreference = "Stop"
            $bi = manage-bde.exe -ComputerName $Comp -status

            # Get Drives
            $drives = @()
            $d = $bi | Select-String -Pattern 'Volume '
            $drives += $d | ForEach-Object {
                $_.ToString().Trim().Substring(0,8) -replace "Volume ",""
            }# foreach drive

            # Get Size
            $size = @()
            $si = $bi | Select-String -Pattern 'Size'
            $size += $si | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach size

            # Get BitLocker Version
            $ver = @()
            $v = $bi | Select-String -Pattern 'BitLocker Version'
            $ver += $v | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach version

            # Get Status
            $status = @()
            $s = $bi | Select-String -Pattern 'Conversion Status'
            $status += $s | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach status

            # Get Percent Encrypted
            $per = @()
            $p = $bi | Select-String -Pattern 'Percentage Encrypt'
            $per += $p | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach percentage

            # Get Encryption Method
            $em = @()
            $e = $bi | Select-String -Pattern 'Encryption Method'
            $em += $e | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach encryption method

            # Get Protection Status
            $ps = @()
            $pi = $bi | Select-String -Pattern 'Protection Status'
            $ps += $pi | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach pro status

            # Get Lock Status
            $ls = @()
            $li = $bi | Select-String -Pattern 'Lock Status'
            $ls += $li | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach Lock Status

            # Get ID Field
            $id = @()
            $ii = $bi | Select-String -Pattern 'Identification Field'
            $id += $ii | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach ID

            # Get Key Protectors
            $key = @()
            $k = $bi | Select-String -Pattern 'Key Protect'
            $key += $k | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach
        }# try
        catch {
            Write-Output "Unable to connect to $Comp"
            $status = "Insuffiect permissions or unable to connect"
        }

        $num = $drives.Length
        do {
            $overall += [PSCustomObject]@{
                ComputerName = $Comp
                Drive = $drives[$i]
                Size = $size[$i]
                BitLockerVersion = $ver[$i]
                Status = $status[$i]
                PercentEncrypted = $per[$i]
                EncryptionMethod = $em[$i]
                ProtectionStatus = $ps[$i]
                LockStatus = $ls[$i]
                ID_Field = $id[$i]
                KeyProtectors = $key[$i]
            }
            $i++
        }#do
        while ($i -lt $num)
    }# foreach comp
    $overall | Select-Object ComputerName,Drive,Size,BitLockerVersion,Status,PercentEncrypted,EncryptionMethod,ProtectionStatus,LockStatus,ID_Field,KeyProtectors | Sort-Object ComputerName,Drive
}


function Get-CertificateInventory {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2021-11-18 22:44:53
        Last Edit: 2021-11-18 22:44:53
        Keywords:

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [Alias('Get-CertInv','Get-CertInfo')]
    param()

    $cpath = @('Cert:\LocalMachine\My','Cert:\LocalMachine\Remote Desktop')

    $os = (Get-WmiObject Win32_OperatingSystem).ProductType

    if ($os -eq 1) {$type = "Workstation"}
    elseif (($os -eq 2) -or ($os -eq 3)) {$type = "Server"}

    $certinfo = foreach ($cp in $cpath) {
        Get-ChildItem $cp | Select-Object *
    }

    $certs = foreach ($cert in $certinfo) {
        $cp = $cert.PSParentPath -replace "Microsoft.PowerShell.Security\\Certificate\:\:",""

        if (($cert.Subject) -eq ($cert.Issuer)) {$ss = $true}
        else {$ss = $false}

        $daystoexpire = (New-TimeSpan -Start (get-date) -End ($cert.NotAfter)).Days

        [PSCustomObject]@{
            ComputerName = ($env:computername)
            ProductType = $type
            Subject = ($cert.Subject)
            Issuer = ($cert.Issuer)
            Location = $cp
            SelfSigned = $ss
            ValidFrom = ($cert.NotBefore)
            ValidTo = ($cert.NotAfter)
            DaysToExpiration = $daystoexpire
            SerialNumber = ($cert.SerialNumber)
            Thumbprint = ($cert.Thumbprint)
        }# new object
    }
    $certs | Select-Object ComputerName,ProductType,Location,Subject,Issuer,SelfSigned,ValidFrom,ValidTo,DaysToExpiration,SerialNumber,Thumbprint | Sort-Object Subject
}


function Get-CommandList {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2021-08-06 23:09:24
        Last Edit: 2021-12-16 21:41:15

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Path','Output','OutputPath','Destination')]
        [string]$ExportPath,

        [switch]$All
    )

    if ($All) {
        $commands = Get-Command * | Select-Object HelpUri,ResolvedCommandName,Definition,Name,CommandType,ModuleName,RemotingCapability,Path,FileVersionInfo
    }
    else {$commands = Get-Command -All | Select-Object HelpUri,ResolvedCommandName,Definition,Name,CommandType,ModuleName,RemotingCapability,Path,FileVersionInfo}
    $commands = $commands | Select-Object HelpUri,ResolvedCommandName,Definition,Name,CommandType,ModuleName,RemotingCapability,Path,FileVersionInfo -Unique
    $slist = Import-Csv $PSScriptRoot\CommandListModules.csv

    $i = 0
    $number = $commands.length
    $info = @()
    $info = foreach ($c in $commands) {
        # Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Generating information for each command." -status "Command $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $commands.length)  * 100)
        }# if length

        $rn = $c.ResolvedCommandName
        if ($c.CommandType -eq "Alias") {
            if ([string]::IsNullOrWhiteSpace($c.ResolvedCommandName)) {
                $rn = $c.Definition
            }
            else {
                $rn = $c.ResolvedCommandName
            }
        }
        $mn = $c.ModuleName
        $sli = $slist | Where-Object {$_.Module -eq $mn}
        if ([string]::IsNullOrWhiteSpace($sli)) {
            [PSCustomObject]@{
                CommandType = ($c.CommandType)
                Name = ($c.Name)
                ResolvedName = $rn
                Path = ($c.Path)
                Description = ($c.FileVersionInfo.FileDescription)
                ModuleName = ($c.ModuleName)
                UsedByOrganization = $null
                RemotingCapability = ($c.RemotingCapability)
                UsedRemotely = $null
                Purpose = $null
                Reference = $null
                HelpUri = ($c.HelpUri)
            }# new object
        }
        else {
            [PSCustomObject]@{
                CommandType = ($c.CommandType)
                Name = ($c.Name)
                ResolvedName = $rn
                Path = ($c.Path)
                Description = ($c.FileVersionInfo.FileDescription)
                ModuleName = ($c.ModuleName)
                UsedByOrganization = ($sli.UsedByOrganization)
                RemotingCapability = ($c.RemotingCapability)
                UsedRemotely = ($sli.Remote)
                Purpose = ($sli.Purpose)
                Reference = ($sli.Reference)
                HelpUri = ($c.HelpUri)
            }# new object
        }
    }

    if ([string]::IsNullOrWhiteSpace($ExportPath)) {
        $info | Select-Object CommandType,Name,ResolvedName,Path,Description,ModuleName,UsedByOrganization,RemotingCapability,UsedRemotely,Purpose,Reference,HelpUri
    }
    else {
        $info | Select-Object CommandType,Name,ResolvedName,Path,Description,ModuleName,UsedByOrganization,RemotingCapability,UsedRemotely,Purpose,Reference,HelpUri | Export-Csv $ExportPath -NoTypeInformation -Force
    }
}


Function Get-ComputerHWInfo {
    <#
    .Synopsis
        Gets hardware information of local or remote computer(s).

    .Description
        Get Manufacturer, Model, Model Version, BIOS vendor, BIOS version, and release date of BIOS update on local
        or remote computer.

    .Example
        Get-ComputerHWInfo
        Get hardware information for local computer

    .Example
        Get-ComputerHWInfo COMP1
        Get hardware information for computer COMP1

    .Parameter ComputerName
        Used to specify the computer or computers to get hardware information for.

    .Notes
        AUTHOR: Skyler Hart
        CREATED: 3/15/2015 08:49:13
        LASTEDIT: 09/21/2017 13:03:30
        KEYWORDS: hardware, information, computer
        REQUIRES:
            -RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $keyname = 'HARDWARE\\DESCRIPTION\\System\\BIOS'
    foreach ($comp in $ComputerName) {
        $reg = $null
        $key = $null
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
        $key = $reg.OpenSubkey($keyname)
        $BRD = $key.GetValue('BIOSReleaseDate')
        $BV = $key.GetValue('BIOSVendor')
        $Bver = $key.GetValue('BIOSVersion')
        $SM = $key.GetValue('SystemManufacturer')
        $SPN = $key.GetValue('SystemProductName')
        $SV = $key.GetValue('SystemVersion')

        [PSCustomObject]@{
            ComputerName = $comp
            Manufacturer = $SM
            Model = $SPN
            ModelVersion = $SV
            BIOSVendor = $BV
            BIOSVersion = $Bver
            BIOSReleaseDate = $BRD
        }# new object
    }# foreach computer
}


Function Get-ComputerModel {
    <#
    .Parameter ComputerName
        Specifies the computer or computers

    .Notes
        AUTHOR: Skyler Hart
        CREATED: 2018-06-20 13:05:09
        LASTEDIT: 2020-08-31 21:40:19
        REQUIRES:
            -RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [Alias('Get-Model')]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )
    Process {
        foreach ($comp in $ComputerName) {
            try {
                $csi = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $comp -ErrorAction Stop

                switch ($csi.DomainRole) {
                    0 {$dr = "Standalone Workstation"}
                    1 {$dr = "Member Workstation"}
                    2 {$dr = "Standalone Server"}
                    3 {$dr = "Member Server"}
                    4 {$dr = "Domain Controller"}
                    5 {$dr = "Primary Domain Controller"}
                }

                if ($csi.Model -contains "Virtual") {$PorV = "Virtual"}
                else {$PorV = "Physical"}

                switch ($csi.PCSystemType) {
                    2 {$type = "Laptop/Tablet"}
                    default {$type = "Desktop"}
                }

                $manu = $csi.Manufacturer
                $model = $csi.Model

                [PSCustomObject]@{
                    ComputerName = $comp
                    DomainRole = $dr
                    Manufacturer = $manu
                    Model = $model
                    PorV = $PorV
                    Type = $type
                }
            }
            catch {
                $na = "NA"
                [PSCustomObject]@{
                    ComputerName = $comp
                    DomainRole = "Unable to connect"
                    Manufacturer = $na
                    Model = $na
                    PorV = $na
                    Type = $na
                }
            }
        }
    }
}


function Get-DayOfYear {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2021-05-20 20:48:46
        Last Edit: 2021-05-20 21:48:24
        Keywords: Day of year, Julian

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [Alias('Get-JulianDay','Get-JulianDate')]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [ValidateLength(1,10)]
        [Alias('Date')]
        [string]$Day = (Get-Date -Format "yyyy-MM-dd"),

        [Parameter(
            Mandatory=$false,
            Position=1
        )]
        [ValidateLength(4,4)]
        [string]$Year
    )

    $c = $Day.Length
    if ($c -le 3) {
        $nd = $Day - 1
        if ([string]::IsNullOrWhiteSpace($Year)) {
            [string]$Year = (Get-Date).Year
            $info = (Get-Date -Day 1 -Month 1 -Year $Year).AddDays($nd)
        }
        else {
            $info = (Get-Date -Day 1 -Month 1 -Year $Year).AddDays($nd)
        }
        $info
    }
    elseif ($c -eq 8) {
        $y = $Day.Substring(0,4)
        $m = $Day.Substring(4)
        $m = $m.Substring(0,2)
        $d = $Day.Substring(6)
        $info = (Get-Date -Year $y -Month $m -Day $d).DayOfYear
        $info
    }
    elseif ($c -eq 10) {
        $y = $Day.Substring(0,4)
        $m = $Day.Substring(5)
        $m = $m.Substring(0,2)
        $d = $Day.Substring(8)
        $info = (Get-Date -Year $y -Month $m -Day $d).DayOfYear
        $info
    }
    else {
        Write-Error "Not in the correct format. Format must be entered in the format x, xx, or xxx for a day of the year. Ex: 12. For a date, it must be entered in the format yyyyMMdd or yyyy-MM-dd. Ex: 2021-05-20" -Category SyntaxError
    }
}


Function Get-DefaultBrowserPath {
    <#
    .NOTES
        Author: Skyler Hart
        Created: Sometime before 2017-08-07
        Last Edit: 2020-08-20 15:09:53

    .LINK
        https://wanderingstag.github.io
    #>
    New-PSDrive -Name HKCR -PSProvider Registry -Root Hkey_Classes_Root | Out-Null
    $BrowserPath = ((Get-ItemProperty 'HKCR:\http\shell\open\command').'(default)').Split('"')[1]
    return $BrowserPath
    Remove-PSDrive -Name HKCR -Force -ErrorAction SilentlyContinue | Out-Null
}


function Get-DirectoryStat {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2020-08-09 10:07:49
        Last Edit: 2020-08-09 21:35:14

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the path of the folder you want stats on. Ex: C:\Temp or \\computername\c$\temp",
            Mandatory=$true,
            Position=0,
            ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('Dir','Folder','UNC')]
        [string[]]$DirectoryName
    )
    Begin {}
    Process {
        foreach ($Directory in $DirectoryName) {
            $stats = [PSCustomObject]@{
                Directory = $null
                FileCount = 0
                SizeBytes = [long]0
                SizeKB = 0
                SizeMB = 0
                SizeGB = 0
                Over100MB = 0
                Over1GB = 0
                Over5GB = 0
            }
            $stats.Directory = $Directory
            foreach ($d in [system.io.Directory]::EnumerateDirectories($Directory)) {
                foreach ($f in [system.io.Directory]::EnumerateFiles($d)) {
                    $length = (New-Object io.FileInfo $f).Length
                    $stats.FileCount++
                    $stats.SizeBytes += $length
                    if ($length -gt 104857600) {$stats.Over100MB++}
                    if ($length -gt 1073741824) {$stats.Over1GB++}
                    if ($length -gt 5368709120) {$stats.Over5GB++}
                    $stats.SizeKB += ("{0:N2}" -f ($length / 1KB))
                    $stats.SizeMB += ("{0:N2}" -f ($length / 1MB))
                    $stats.SizeGB += ("{0:N2}" -f ($length / 1GB))
                } #foreach file
            }#foreach subfolder get stats
            foreach ($f in [system.io.Directory]::EnumerateFiles($Directory)) {
                $length = (New-Object io.FileInfo $f).Length
                $stats.FileCount++
                $stats.SizeBytes += $length
                if ($length -gt 104857600) {$stats.Over100MB++}
                if ($length -gt 1073741824) {$stats.Over1GB++}
                if ($length -gt 5368709120) {$stats.Over5GB++}
                $stats.SizeKB += ("{0:N2}" -f ($length / 1KB))
                $stats.SizeMB += ("{0:N2}" -f ($length / 1MB))
                $stats.SizeGB += ("{0:N2}" -f ($length / 1GB))
            }#foreach file
            $stats | Select-Object Directory,FileCount,Over100MB,Over1GB,Over5GB,SizeBytes,SizeKB,SizeMB,SizeGB
        }#foreach directory in #directoryname
    }
    End {}
}


function Get-Drive {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2020-04-19 20:29:58
        Last Edit: 2020-04-19 20:29:58

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [Alias('drive')]
    param()
    Get-PSDrive -Name *
}


function Get-Error {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2020-04-18 16:42:46
        Last Edit: 2020-04-18 19:08:44

    .LINK
        https://wanderingstag.github.io
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Error')]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [int32]$HowMany
    )

    $Errors = $Global:Error

    if ([string]::IsNullOrWhiteSpace($HowMany)) {
        [int32]$HowMany = $Errors.Count
    }

    $n = $HowMany - 1
    $logs = $Errors[0..$n]

    foreach ($log in $logs) {
        $scriptn = $log.InvocationInfo.ScriptName
        $line = $log.InvocationInfo.ScriptLineNumber
        $char = $log.InvocationInfo.OffsetInline
        $command = $log.InvocationInfo.Line.Trim()
        $exc = $log.Exception.GetType().fullname
        $mes = $log.Exception.message.Trim()
        [PSCustomObject]@{
            Exception = "[$exc]"
            Message = $mes
            Script = $scriptn
            Command = $command
            Line = $line
            Character = $char
        }
    }
}


Function Get-ExpiredCertsComputer {
    <#
    .Notes
        AUTHOR: Skyler Hart
        CREATED: 10/04/2018 20:46:38
        LASTEDIT: 10/04/2018 21:08:31

    .LINK
        https://wanderingstag.github.io
    #>
    $cd = Get-Date
    $certs = Get-ChildItem -Path Cert:\LocalMachine -Recurse | Select-Object *

    $excerts = $null
    $excerts = @()

    foreach ($cer in $certs) {
        if ($null -ne $cer.NotAfter -and $cer.NotAfter -lt $cd) {
            $excerts += ($cer | Where-Object {$_.PSParentPath -notlike "*Root"} | Select-Object FriendlyName,SubjectName,NotBefore,NotAfter,SerialNumber,EnhancedKeyUsageList,DnsNameList,Issuer,Thumbprint,PSParentPath)
        }
    }
}


Function Get-ExpiredCertsUser {
    <#
    .Notes
        AUTHOR: Skyler Hart
        CREATED: 10/04/2018 21:08:39
        LASTEDIT: 10/04/2018 21:09:34

    .LINK
        https://wanderingstag.github.io
    #>
    $cd = Get-Date
    $certs = Get-ChildItem -Path Cert:\CurrentUser -Recurse | Select-Object *

    $excerts = $null
    $excerts = @()

    foreach ($cer in $certs) {
        if ($null -ne $cer.NotAfter -and $cer.NotAfter -lt $cd) {
            $excerts += ($cer | Where-Object {$_.PSParentPath -notlike "*Root"} | Select-Object FriendlyName,SubjectName,NotBefore,NotAfter,SerialNumber,EnhancedKeyUsageList,DnsNameList,Issuer,Thumbprint,PSParentPath)
        }
    }
}


Function Get-FeaturesOnDemand {
    <#
    .Notes
        AUTHOR: Skyler Hart
        CREATED: 09/25/2019 14:13:50
        LASTEDIT: 2020-08-31 21:44:37
        REQUIRES:
            Requires -RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {$Role = 'Admin'}
    else {$Role = 'User'}

    if ($Role -eq "Admin") {
        $info = (dism /online /get-capabilities | Where-Object {$_ -like "Capability Identity*" -or $_ -like "State*"})
        $idents = ($info | Where-Object {$_ -like "Capa*"}).Split(' : ') | Where-Object {$_ -ne "Capability" -and $_ -ne "Identity" -and $_ -ne $null -and $_ -ne ""}
        $state = $info | Where-Object {$_ -like "State*"}
        $state = $state -replace "State : "

        foreach ($ident in $idents) {
            $state2 = $state[$i]
            [PSCustomObject]@{
                CapabilityIdentity = $ident
                State = $state2
            }
        }
    }#if admin
    else {
        Write-Error "Not admin. Please run PowerShell as admin."
    }
}


Function Get-FileMetaData {
    <#
    .Synopsis
        This function gets file metadata and returns it as a custom PS Object.

    .Description
        This function gets file metadata using the Shell.Application object and
        returns a custom PSObject object that can be sorted, filtered or otherwise
        manipulated.

    .Example
        Get-FileMetaData -Path "e:\music"
        Gets file metadata for all files in the e:\music directory

    .Example
        Get-FileMetaData -Path (gci e:\music -Recurse -Directory).FullName
        This example uses the Get-ChildItem cmdlet to do a recursive lookup of
        all directories in the e:\music folder and then it goes through and gets
        all of the file metada for all the files in the directories and in the
        subdirectories.

    .Example
        Get-FileMetaData -Path "c:\fso","E:\music\Big Boi"
        Gets file metadata from files in both the c:\fso directory and the
        e:\music\big boi directory.

    .Example
        $meta = Get-FileMetaData -Path "E:\music"
        This example gets file metadata from all files in the root of the
        e:\music directory and stores the returned custom objects in a $meta
        variable for later processing and manipulation.

    .Parameter Path
        The path that is parsed for files

    .Notes
        NAME:  Get-FileMetaData
        AUTHOR: ed wilson, msft
        Edited By: Skyler Hart
        Original: 01/24/2014 14:08:24
        Last Edit: 2021-12-19 18:54:58
        KEYWORDS: Storage, Files, Metadata

    .Link
        https://devblogs.microsoft.com/scripting/
    #Requires -Version 2.0
    #>
    Param([string[]]$Path)
    foreach($sFolder in $Path) {
        $ItemInfo = Get-Item $sFolder | Select-Object *
        if ($ItemInfo.Mode -like "d-*") {
            $ItemType = "Directory"
            $FolderPath = $sFolder
        }
        else {
            $ItemType = "File"
            $FolderPath = $ItemInfo.DirectoryName
            $FileName = $ItemInfo.Name
        }
        $a = 0
        $objShell = New-Object -ComObject Shell.Application
        $objFolder = $objShell.namespace($FolderPath)
        $Metadata = foreach ($File in $objFolder.items()) {
            $FileMetaData = New-Object PSCustomObject
            for ($a ; $a  -le 266; $a++) {
                if($objFolder.getDetailsOf($File, $a)) {
                    $hash += @{$($objFolder.getDetailsOf($objFolder.items, $a)) = $($objFolder.getDetailsOf($File, $a))}
                    $FileMetaData | Add-Member $hash
                    $hash.clear()
                } #end if
            } #end for
            $a=0
            $FileMetaData
        } #end foreach $file
        if ($ItemType -eq "File") {
            $Metadata | Where-Object {$_.FileName -eq $FileName}
        }
        else {
            $Metadata
        }
    } #end foreach $sfolder
}


function Get-HomeDrive {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2020-11-03 15:02:09
        Last Edit: 2020-11-03 15:02:09

    .LINK
        https://wanderingstag.github.io
    #>
    $env:HOMESHARE
}


function Get-HWInfo {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2021-05-11 18:29:12
        Last Edit: 2021-05-11 23:48:31
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
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ErrorActionPreference = "Stop"
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $j = 0
        $number = $ComputerName.length
        foreach ($Comp in $ComputerName) {
            # Progress Bar
            if ($number -gt "1") {
                $j++
                $amount = ($j / $number)
                $perc1 = $amount.ToString("P")
                Write-Progress -activity "Getting hardware information" -status "Computer $j of $number. Percent complete:  $perc1" -PercentComplete (($j / $ComputerName.length)  * 100)
            }# if length

            if ((Test-Connection -BufferSize 32 -Count 1 -ComputerName $Comp -Quiet) -eq $true) {
                $status = "Online"

                # Get WMI Values
                try {
                    $csi = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Comp -ErrorAction Stop
                    $ldi = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $Comp -ErrorAction Stop | Where-Object {$_.DriveType -eq 3}
                    $nai = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $Comp -ErrorAction Stop
                    $osi = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Comp -ErrorAction Stop
                    $pmi = Get-WmiObject -Class Win32_PhysicalMemory -ComputerName $Comp -ErrorAction Stop
                    $pmai = Get-WmiObject -Class Win32_PhysicalMemoryArray -ComputerName $Comp -ErrorAction Stop
                    $pri = Get-WmiObject -Class Win32_Processor -ComputerName $Comp -ErrorAction Stop

                    # Get Computer System Information
                    $sn = (Get-WmiObject -Class Win32_BIOS -ComputerName $Comp -ErrorAction Stop | Select-Object SerialNumber).SerialNumber
                    switch ($csi.DomainRole) {
                        0 {$dr = "Standalone Workstation"}
                        1 {$dr = "Member Workstation"}
                        2 {$dr = "Standalone Server"}
                        3 {$dr = "Member Server"}
                        4 {$dr = "Domain Controller"}
                        5 {$dr = "Primary Domain Controller"}
                    }


                    if ($csi.Model -contains "Virtual") {$PorV = "Virtual"}
                    else {$PorV = "Physical"}

                    switch ($csi.PCSystemType) {
                        2 {$type = "Laptop/Tablet"}
                        4 {$type = "Server"}
                        5 {$type = "Server"}
                        7 {$type = "Server"}
                        default {$type = "Desktop"}
                    }

                    $manu = $csi.Manufacturer
                    $model = $csi.Model
                    $ProcCount = $csi.NumberofProcessors
                    $ProcCores = $csi.NumberofLogicalProcessors
                    $CoresPerProc = $ProcCores/$ProcCount

                    #Get Logical Disk Information
                    $l = 1
                    $LogicalDiskName = $null
                    $LogicalDiskSize = $null
                    $LogicalDiskFree = $null
                    $LogicalDiskUsed = $null
                    foreach ($ld in $ldi) {
                        if ($l -le 1) {
                            $LogicalDiskName = ($ld.Name)
                            $LogicalDiskSize = [string]([math]::round($ld.Size/1GB, 2)) + "GB"
                            $LogicalDiskFree = [string]([math]::round($ld.FreeSpace/1GB, 2)) + "GB"
                            $LogicalDiskUsed = [string]([math]::round(($ld.Size - $ld.FreeSpace)/1GB, 2)) + "GB"
                        }
                        else {
                            $LogicalDiskName += "`n"
                            $LogicalDiskName += ($ld.Name)
                            $LogicalDiskSize += "`n"
                            $LogicalDiskSize += [string]([math]::round($ld.Size/1GB, 2)) + "GB"
                            $LogicalDiskFree += "`n"
                            $LogicalDiskFree += [string]([math]::round($ld.FreeSpace/1GB, 2)) + "GB"
                            $LogicalDiskUsed += "`n"
                            $LogicalDiskUsed += [string]([math]::round(($ld.Size - $ld.FreeSpace)/1GB, 2)) + "GB"
                        }
                        $l++
                    }

                    # Get Network Adapter Configuration Information
                    $naie = $nai | Where-Object {$_.IPEnabled -eq $true -and $null -ne $_.IPAddress} | Select-Object Description,IPAddress,IPSubnet,MACAddress,DefaultIPGateway,DNSServerSearchOrder
                    $i = 1
                    $NetAdapterName = $null
                    $DNS = $null
                    $Gateway = $null
                    $IPAddress = $null
                    $Subnet = $null
                    $MACAddress = $null
                    foreach ($na in $naie) {
                        if ($i -le 1) {
                            $NetAdapterName = ($na.Description)
                            $DNS = ($na.DNSServerSearchOrder -join ", ")
                            $Gateway = ($na.DefaultIPGateway -join ", ")
                            $IPAddress = ($na.IPAddress -join ", ")
                            $Subnet = ($na.IPSubnet -join ", ")
                            $MACAddress = ($na.MACAddress)
                        }
                        else {
                            $NetAdapterName += "`n"
                            $NetAdapterName += ($na.Description)
                            $DNS += "`n"
                            $DNS += ($na.DNSServerSearchOrder -join ", ")
                            $Gateway += "`n"
                            $Gateway += ($na.DefaultIPGateway -join ", ")
                            $IPAddress += "`n"
                            $IPAddress += ($na.IPAddress -join ", ")
                            $Subnet += "`n"
                            $Subnet += ($na.IPSubnet -join ", ")
                            $MACAddress += "`n"
                            $MACAddress += ($na.MACAddress)
                        }
                        $i++
                    }# foreach network adapter

                    # Get Operating System Information
                    $OS = $osi.Caption -replace "Microsoft ",""
                    $Build = $osi.BuildNumber

                    if ($OS -like "Windows 10*" -or $OS -like "Windows 11*" -or $OS -match "2016" -or $OS -match "2019" -or $OS -match "2022") {
                        if ($Build -eq 14393) {
                            $OS = $OS + " v1607"
                        }
                        elseif ($Build -eq 15063) {
                            $OS = $OS + " v1703"
                        }
                        elseif ($Build -eq 16299) {
                            $OS = $OS + " v1709"
                        }
                        elseif ($Build -eq 17134) {
                            $OS = $OS + " v1803"
                        }
                        elseif ($Build -eq 17763) {
                            $OS = $OS + " v1809"
                        }
                        elseif ($Build -eq 18362) {
                            $OS = $OS + " v1903"
                        }
                        elseif ($Build -eq 18363) {
                            $OS = $OS + " v1909"
                        }
                        elseif ($Build -eq 19041) {
                            $OS = $OS + " v2004"
                        }
                        elseif ($Build -eq 19042) {
                            $OS = $OS + " v20H2"
                        }
                        elseif ($Build -eq 19043) {
                            $OS = $OS + " v21H1"
                        }
                        elseif ($Build -eq 19044 -or $Build -eq 22000 -or $Build -eq 20348) {# Win 10 Win 11 Srv 2022
                            $OS = $OS + " v21H2"
                        }
                        elseif ($Build -eq 19045 -or $Build -eq 22621) {# Win 10 Win 11
                            $OS = $OS + " v22H2"
                        }
                        elseif ($Build -eq 19046 -or $Build -eq 22631) {# Win 10 Win 11
                            $OS = $OS + " v23H2"
                        }
                        elseif ($Build -eq 26100) {#Win 11
                            $OS = $OS + " v24H2"
                        }
                    }# if os win 10, srv 2016, or srv 2019

                    # Get Processor Information
                    switch ($pri.Architecture) {
                        0 {$Architecture = "x86"}
                        1 {$Architecture = "MIPS"}
                        2 {$Architecture = "Alpha"}
                        3 {$Architecture = "PowerPC"}
                        6 {$Architecture = "Itanium"}
                        9 {$Architecture = "x64"}
                    }

                    $ProcManu = $pri.Manufacturer
                    $ProcName = $pri.Name

                    if ($ProcManu.Count -gt 1) {
                        $ProcManu = $ProcManu[0]
                        $ProcName = $ProcName[0]
                    }

                    # Get RAM Information
                    $iris = $pmi.Capacity
                    $ri = 0
                    foreach ($iri in $iris) {
                        $ri += $iri
                    }
                    $RAMCAP = [string]($ri/1GB) + "GB"
                    $RAMCount = $iris.count

                    $RAMSlots = $pmai.MemoryDevices
                    $MaxRAM = [string]($pmai.MaxCapacity/1MB) + "GB"
                }
                catch {
                    $Architecture = $null
                    $dr = $null
                    $manu = $null
                    $model = $null
                    $PorV = $null
                    $type = $null
                    $OS = $null
                    $Build = $null
                    $NetAdapterName = $null
                    $IPAddress = $null
                    $Subnet = $null
                    $MACAddress = $null
                    $sn = $null
                    $DNS = $null
                    $Gateway = $null
                    $ProcName = $null
                    $ProcManu = $null
                    $RAMCap = $null
                    $MaxRAM
                    $RAMCount = $null
                    $RAMSlots = $null
                    $LogicalDiskName = $null
                    $LogicalDiskSize = $null
                    $LogicalDiskFree = $null
                    $LogicalDiskUsed = $null
                    $ProcCount = $null
                    $ProcCores = $null
                    $CoresPerProc = $null
                }

                # Get BitLocker status
                try {
                    $bi = manage-bde.exe -ComputerName $Comp -status
                    $ps = @()
                    $pi = $bi | Select-String -Pattern 'Protection Status'
                    $ps += $pi | ForEach-Object {
                        $_.ToString().Trim().Substring(22)
                    }# foreach pro status
                    if ($ps[0] -eq "Protection On") {$bl = "Enabled"}
                    else {$bl = "Not Enabled"}
                }
                catch {
                    $bl = ""
                }

                [PSCustomObject]@{
                    ComputerName = $Comp
                    Status = $status
                    Manufacturer = $manu
                    Model = $model
                    BitLocker = $bl
                    DomainRole = $dr
                    PorV = $PorV
                    Type = $type
                    Architecture = $Architecture
                    SerialNumber = $sn
                    OperatingSystem = $OS
                    Build = $Build
                    NetAdapterName = $NetAdapterName
                    IPAddress = $IPAddress
                    Subnet = $Subnet
                    Gateway = $Gateway
                    DNS = $DNS
                    MACAddress = $MACAddress
                    ProcessorManufacturer = $ProcManu
                    ProcessorName = $ProcName
                    Processors = $ProcCount
                    CoresPerProcessor = $CoresPerProc
                    TotalCores = $ProcCores
                    InstalledRAM = $RAMCap
                    MaxRAM = $MaxRAM
                    RAMSlotsUsed = $RAMCount
                    TotalRAMSlots = $RAMSlots
                    LogicalDiskName = $LogicalDiskName
                    LogicalDiskSize = $LogicalDiskSize
                    LogicalDiskFree = $LogicalDiskFree
                    LogicalDiskUsed = $LogicalDiskUsed
                }# new object
            }# if online
            else {
                $status = "Offline"
                [PSCustomObject]@{
                    ComputerName = $Comp
                    Status = $status
                    Manufacturer = $null
                    Model = $null
                    BitLocker = $null
                    DomainRole = $null
                    PorV = $null
                    Type = $null
                    Architecture = $null
                    SerialNumber = $null
                    OperatingSystem = $null
                    Build = $null
                    NetAdapterName = $null
                    IPAddress = $null
                    Subnet = $null
                    Gateway = $null
                    DNS = $null
                    MACAddress = $null
                    ProcessorManufacturer = $null
                    ProcessorName = $null
                    Processors = $null
                    CoresPerProcessor = $null
                    TotalCores = $null
                    InstalledRAM = $null
                    MaxRAM = $null
                    RAMSlotsUsed = $null
                    TotalRAMSlots = $null
                    LogicalDiskName = $null
                    LogicalDiskSize = $null
                    LogicalDiskFree = $null
                    LogicalDiskUsed = $null
                }# new object
            }# if offline
        }# foreach computer
    }# if admin
    else {Write-Error "Not admin. Please run PowerShell as admin."}
}

function Get-HWPerformanceScore {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2022-06-04 22:43:29
        Last Edit: 2022-06-04 22:43:29
        Requires:
            -RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )
    Begin {
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
                [string]$comp
            )
            if ($comp -eq $env:COMPUTERNAME) {
                Get-CimInstance -ClassName Win32_WinSAT -ErrorAction Stop
            }
            else {
                Get-CimInstance -ClassName Win32_WinSAT -ComputerName $comp -ErrorAction Stop
            }
        }# end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
                -Activity "Getting hardware performance scores. Waiting for Jobs - $($MaxThreads - $($RunspacePool.GetAvailableRunspaces())) of $MaxThreads threads running" `
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


Function Get-IEVersion {
    <#
    .Notes
        AUTHOR: Skyler Hart
        CREATED: 09/21/2017 13:06:15
        LASTEDIT: 09/21/2017 13:06:15

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $keyname = 'SOFTWARE\\Microsoft\\Internet Explorer'
    foreach ($comp in $ComputerName) {
        $reg = $null
        $key = $null
        $value = $null
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
        $key = $reg.OpenSubkey($keyname)
        $value = $key.GetValue('Version')
        [PSCustomObject]@{
            ComputerName = $comp
            IEVersion = $value
        }# new object
    }# foreach computer
}


Function Get-InstalledProgram {
    <#
    .SYNOPSIS
        Displays installed programs on a computer.

    .DESCRIPTION
        Displays a list of installed programs on a local or remote computer by querying the registry.

    .PARAMETER ComputerName
        Specifies the name of one or more computers.

    .PARAMETER Property
        Will add additional properties to pull from the Uninstall key in the registry.

    .EXAMPLE
        C:\PS>Get-InstalledProgram
        Shows the installed programs on the local computer.

    .EXAMPLE
        C:\PS>Get-InstalledProgram -ComputerName COMPUTER1
        Shows the installed programs on the remote computer COMPUTER1.

    .EXAMPLE
        C:\PS>Get-InstalledProgram -ComputerName COMPUTER1,COMPUTER2
        Shows the installed programs on the remote computers COMPUTER1 and COMPUTER2.

    .EXAMPLE
        C:\PS>Get-InstalledProgram (gc C:\Temp\computers.txt)
        Shows the installed programs on the remote computers listed in the computers.txt file (each computer name on a new line.)

    .EXAMPLE
        C:\PS>Get-InstalledProgram COMPUTER1 -Property InstallSource
        Shows the installed programs on the remote computer COMPUTER1 and also shows the additional property InstallSource from the registry.

    .EXAMPLE
        C:\PS>Get-InstalledProgram COMPUTER1,COMPUTER2 -Property InstallSource,Comments
        Shows the installed programs on the remote computers COMPUTER1 and COMPUTER2. Also shows the additional properties InstallSource and Comments from the registry.

    .NOTES
        Author: Skyler Hart
        Created: Sometime prior to 2017-08
        Last Edit: 2020-08-19 23:03:32
        Keywords: Software, Programs, management

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Alias('Host','Name','DNSHostName','Computer')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Position=1)]
        [string[]]$Property
    )

    Begin {
        $RegistryLocation = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
                            'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'
        $HashProperty = @{}
        $SelectProperty = @('ComputerName','Installed','ProgramName','Version','Uninstall','Comment')
        if ($Property) {
            $SelectProperty += $Property
        }
    }#begin

    Process {
        foreach ($Computer in $ComputerName) {
            $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer)
            $installed = @()
            foreach ($CurrentReg in $RegistryLocation) {
                if ($RegBase) {
                    $CurrentRegKey = $RegBase.OpenSubKey($CurrentReg)
                    if ($CurrentRegKey) {
                        $CurrentRegKey.GetSubKeyNames() | ForEach-Object {
                            if ($Property) {
                                foreach ($CurrentProperty in $Property) {
                                    $HashProperty.$CurrentProperty = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue($CurrentProperty)
                                }
                            }
                            $HashProperty.ComputerName = $Computer
                            $HashProperty.ProgramName = ($DisplayName = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('DisplayName'))
                            $HashProperty.Version = ($DisplayVersion = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('DisplayVersion'))
                            $HashProperty.Installed = ($InstallDate = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('InstallDate'))
                            $HashProperty.Uninstall = ($UninstallString = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('UninstallString'))
                            $HashProperty.Comment = ($Comments = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('Comments'))
                            if ($DisplayName -and ($DisplayName -notmatch "Update for" -and $DisplayName -notmatch " Security Update for" -and $DisplayName -notmatch "Hotfix for" -and $DisplayName -notlike "Windows Setup Remediations*" `
                                -and $DisplayName -notlike "Outils de v*" -and $DisplayName -notlike "Intel(R) Processor*" -and $DisplayName -notlike "Intel(R) Chipset*" -and $DisplayName -notlike "herramientas de corr*" `
                                -and $DisplayName -notlike "Dell Touchpa*" -and $DisplayName -notmatch "Crystal Reports" -and $DisplayName -notmatch "Catalyst Control" -and $DisplayName -notlike "AMD *" -and $DisplayName -notlike "Microsoft * MUI*" `
                                -and $DisplayName -notlike "Microsoft Visual C* Redist*" -and $DisplayName -notlike "Vulkan Run Time Libraries*" -and $DisplayName -notlike "Microsoft Visual C* Minimum*" -and $DisplayName -notlike "Microsoft Visual C* Additional*")) {
                                $installed += [PSCustomObject]$HashProperty |
                                Select-Object -Property $SelectProperty
                            }
                            $DisplayVersion | Out-Null
                            $InstallDate | Out-Null
                            $UninstallString | Out-Null
                            $Comments | Out-Null
                        }#foreach object
                    }#if currentregkey
                }#if regbase
            }#foreach registry entry in registry location
            $installed | Select-Object $SelectProperty | Sort-Object ProgramName
        }#foreach computer
    }#process
}


function Get-IPrange {
    <#
    .SYNOPSIS
        Lists IPs within a range, subnet, or CIDR block.

    .DESCRIPTION
        Lists IPs within a range, subnet, or CIDR block.

    .PARAMETER CIDR
        Specifies what CIDR block notation you want to list IPs from.

    .PARAMETER End
        The ending IP in a range.

    .PARAMETER IP
        An IP from the subnet mask or CIDR block you want a range for.

    .PARAMETER Start
        Specifies a path to one or more locations.

    .PARAMETER Subnet
        The subnet mask you want a range for.

    .EXAMPLE
        C:\PS>Get-IPrange -ip 192.168.0.3 -subnet 255.255.255.192
        Will show all IPs within the 192.168.0.0 space with a subnet mask of 255.255.255.192 (CIDR 26.)

    .EXAMPLE
        C:\PS>Get-IPrange -PARAMETER
        Another example of how to use this cmdlet but with a parameter or switch.

    .NOTES
        Author: Skyler Hart
        Created: Sometime before 8/7/2017
        Last Edit: 2020-08-20 09:11:46

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('IPv4','Address','IPv4Address')]
        [string]$IP,

        [Parameter(
            Mandatory=$false
        )]
        [Alias('Notation','Block')]
        [string]$CIDR,

        [Parameter(
            Mandatory=$false
        )]
        [Alias('Mask')]
        [string]$Subnet,

        [Parameter(
            Mandatory=$false
        )]
        [string]$Start,

        [Parameter(
            Mandatory=$false
        )]
        [string]$End
    )


    if ($IP) {$ipaddr = [Net.IPAddress]::Parse($IP)}
    if ($CIDR) {$maskaddr = [Net.IPAddress]::Parse((Convert-INT64toIP -int ([convert]::ToInt64(("1"*$CIDR+"0"*(32-$CIDR)),2)))) }
    if ($Subnet) {$maskaddr = [Net.IPAddress]::Parse($Subnet)}
    if ($IP) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)}
    if ($IP) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))}

    if ($IP) {
        $startaddr = Convert-IPtoINT64 -IP $networkaddr.ipaddresstostring
        $endaddr = Convert-IPtoINT64 -IP $broadcastaddr.ipaddresstostring
    } else {
        $startaddr = Convert-IPtoINT64 -IP $start
        $endaddr = Convert-IPtoINT64 -IP $end
    }

    for ($i = $startaddr; $i -le $endaddr; $i++) {
        Convert-INT64toIP -int $i
    }
}


function Get-LinesOfCode {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2021-10-19 19:10:36
        Last Edit: 2021-10-19 19:10:36
        Keywords:
        Other: Excludes blank lines

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the path of the folder you want to count lines of PowerShell and JSON code for",
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    (Get-ChildItem -Path $Path -Recurse | Where-Object {$_.extension -in '.ps1','.psm1','.psd1','.json'} | select-string "^\s*$" -notMatch).Count
}


Function Get-LockedOutLocation {
    <#
    .SYNOPSIS
        This function will locate the computer that processed a failed user logon attempt which caused the user account to become locked out.

    .DESCRIPTION
        This function will locate the computer that processed a failed user logon attempt which caused the user account to become locked out.
        The locked out location is found by querying the PDC Emulator for locked out events (4740).
        The function will display the BadPasswordTime attribute on all of the domain controllers to add in further troubleshooting.

    .EXAMPLE
        PS C:\>Get-LockedOutLocation -Identity Joe.Davis
        This example will find the locked out location for Joe Davis.

    .NOTES
        This function is only compatible with an environment where the domain controller with the PDCe role to be running Windows Server 2008 SP2 and up.
        The script is also dependent the ActiveDirectory PowerShell module, which requires the AD Web services to be running on at least one domain controller.
        Author:Jason Walker
        Last Modified: 3/20/2013
    #>
    [CmdletBinding()]
    Param(
      [Parameter(Mandatory=$True)]
        [String]$Identity
    )

    Begin {
        $DCCounter = 0
        $LockedOutStats = @()
        Try {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        Catch {
           Write-Warning $_
           Break
        }
    }# end begin
    Process {
        # Get all domain controllers in domain
        $DomainControllers = Get-ADDomainController -Filter *
        $PDCEmulator = ($DomainControllers | Where-Object {$_.OperationMasterRoles -contains "PDCEmulator"})

        Write-Verbose "Finding the domain controllers in the domain"
        $LockedOutStats = Foreach ($DC in $DomainControllers) {
            $DCCounter++
            Write-Progress -Activity "Contacting DCs for lockout info" -Status "Querying $($DC.Hostname)" -PercentComplete (($DCCounter/$DomainControllers.Count) * 100)
            Try {
                $UserInfo = Get-ADUser -Identity $Identity  -Server $DC.Hostname -Properties AccountLockoutTime,LastBadPasswordAttempt,BadPwdCount,LockedOut -ErrorAction Stop
            }
            Catch {
                Write-Warning $_
                Continue
            }
            If($UserInfo.LastBadPasswordAttempt) {
                [PSCustomObject]@{
                        Name                   = $UserInfo.SamAccountName
                        SID                    = $UserInfo.SID.Value
                        LockedOut              = $UserInfo.LockedOut
                        BadPwdCount            = $UserInfo.BadPwdCount
                        BadPasswordTime        = $UserInfo.BadPasswordTime
                        DomainController       = $DC.Hostname
                        AccountLockoutTime     = $UserInfo.AccountLockoutTime
                        LastBadPasswordAttempt = ($UserInfo.LastBadPasswordAttempt).ToLocalTime()
                    }
            }# end if
        }# end foreach DCs
        $LockedOutStats | Format-Table -Property Name,LockedOut,DomainController,BadPwdCount,AccountLockoutTime,LastBadPasswordAttempt -AutoSize

        # Get User Info
        Try {
           Write-Verbose "Querying event log on $($PDCEmulator.HostName)"
            $LockedOutEvents = Get-WinEvent -ComputerName $PDCEmulator.HostName -FilterHashtable @{LogName='Security';Id=4740} -ErrorAction Stop | Sort-Object -Property TimeCreated -Descending
        }
        Catch {
           Write-Warning $_
            Continue
        }# end catch
        Foreach($Event in $LockedOutEvents) {
            If($Event | Where-Object {$_.Properties[2].value -match $UserInfo.SID.Value}) {
                $Event | Select-Object -Property @(
                    @{Label = 'User';               Expression = {$_.Properties[0].Value}}
                    @{Label = 'DomainController';   Expression = {$_.MachineName}}
                    @{Label = 'EventId';            Expression = {$_.Id}}
                    @{Label = 'LockedOutTimeStamp'; Expression = {$_.TimeCreated}}
                    @{Label = 'Message';            Expression = {$_.Message -split "`r" | Select-Object -First 1}}
                    @{Label = 'LockedOutLocation';  Expression = {$_.Properties[1].Value}}
                )
            }# end ifevent
        }# end foreach lockedout event
    }# end process
}


function Get-ModuleCommandCount {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-10-19 19:50:28
    Last Edit: 2021-10-19 19:50:28
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the name of the module. It must be one that is imported.",
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('Module')]
        [string]$Name,

        [switch]$Functions
    )

    if ($Functions) {(Get-Command -Module $Name -CommandType Function).Count}
    else {(Get-Command -Module $Name).Count}
}


function Get-ModuleList {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Get-ModuleList
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Get-ModuleList -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.NOTES
    Author: Skyler Hart
    Created: 2021-08-11 23:22:30
    Last Edit: 2021-08-11 23:41:15
    Keywords:
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [switch]$NotInCommandListModules
    )

    $modules = Get-Module -ListAvailable | Select-Object -Unique
    if ($NotInCommandListModules) {
        $nil = @()
        $clm = Import-Csv $PSScriptRoot\CommandListModules.csv
        $cm = $clm.Module
        foreach ($m in $modules) {
            $mn = $m.Name
            if ($cm -match $mn) {
                #do nothing
            }
            else {
                $nil += $mn
            }
        }

        $nil
    }
    else {
        $modules | Select-Object * | Sort-Object Name
    }
}


Function Get-MTU {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:06:23
    LASTEDIT: 2020-05-23 17:39:06
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    foreach ($comp in $ComputerName) {
        $netad = (Get-WmiObject Win32_NetworkAdapter -ComputerName $comp -Filter NetConnectionStatus=2  -ErrorAction Stop | Select-Object * | Where-Object {$null -ne $_.MACAddress -or $_.MACAddress -ne ""})
        $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$comp)
        $RegLoc = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'

        $RegKey = $RegBase.OpenSubKey($RegLoc)
        $ints = $RegKey.GetSubKeyNames()
        foreach ($int in $ints) {
            if ($netad -match $int) {
                #$HashProp = @()
                $RegLoc2 = $RegLoc + "\" + $int
                $RegKey2 = $RegBase.OpenSubKey($RegLoc2)
                $mtu = $null
                $mtu = $RegKey2.GetValue('MTU')
                if ([string]::IsNullOrWhiteSpace($mtu)) {
                    $mtu = "1500"
                }
                $domain = $RegKey2.GetValue('Domain')
                $dhcpaddr = $RegKey2.GetValue('DhcpIPAddress')
                $ipaddr = $RegKey2.GetValue('IPAddress')
                $ip = $null
                if ([string]::IsNullOrWhiteSpace($dhcpaddr)) {
                    $ip = $ipaddr[0]
                }
                else {
                    $ip = $dhcpaddr
                }

                if ([string]::IsNullOrWhiteSpace($ip) -or $ip -like "0*") {
                    #don't report
                }
                else {
                    $adprop = $netad | Where-Object {$_.GUID -eq $int}
                    [PSCustomObject]@{
                        ComputerName = $comp
                        Name = ($adprop.Name)
                        ConnectionID = ($adprop.NetConnectionID)
                        MTU = $mtu
                        Index = ($adprop.DeviceID)
                        IP = $ip
                        Domain = $domain
                    }#new object
                }
            }
        }
    }#foreach computer
}


# Working for the most part
# add search base filter so that you can search a specific OU or OUs
# Get-NICInfo (Get-Content .\computers.txt) | where {$_.DHCPEnabled -eq $false} | select Computer,DHCPEnabled,IPv4
# Get-ADComputer -Filter * | foreach {get-nicinfo $_.name | select Name,DHCPEnabled,IPv4} | Export-Csv .\nic.csv -NoTypeInformation
# Get-ADComputer -Filter * -SearchBase "OU=test,DC=testdomain,DC=com" | foreach {Get-NICInfo $_.name}
# Add check for autoipv6
# Put subnet check under IP check so can move autoipv6 subnet
Function Get-NICInfo {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:06:33
    LASTEDIT: 09/21/2017 13:06:33
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $i = 0
    $number = $ComputerName.length

    foreach ($Comp in $ComputerName) {
        Clear-Variable -Name ints,int,intname,mac,DHCPEnabled,DHCPServer,ipv6DHCPServer,dhsraddr,IPv4,ipv42,ipv6auto,IPv6,IPv62,`
            subnet,subnet2,ipv6subnet,ipv6subnet2,gateway,gateway2,ipv6gateway,ipv6gateway2,dns1,dns2,dns3,ipv6dns1,ipv6dns2,`
            ipv6dns3,ipv6auto,autosub -ErrorAction SilentlyContinue | Out-Null

        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting NIC info on computers. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        try {
            $wmio = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $Comp -ErrorAction Stop
            $wwhr = (($wmio) | Where-Object {$_.IPEnabled -eq $true -and $null -ne $_.IPAddress})
            $ints = ($wwhr | Select-Object -property *)

            if ($null -ne $ints) {
                foreach ($int in $ints) {
                    Clear-Variable -Name MAC,intname,DHCPEnabled,DHCPServer,dhsraddr,ipv6DHCPServer,IPv4,ipv42,ipv6auto,IPv6,`
                        IPv62,subnet,subnet2,ipv6subnet,ipv6subnet2,gateway,gateway2,ipv6gateway,ipv6gateway2,dns1,dns2,dns3,`
                        ipv6dns1,ipv6dns2,ipv6dns3,ipv6auto,autosub,ipv4addrs,ipv6addrs,ipv6addrauto,ipv4subnets,ipv6subnets,`
                        ipv4gateways,ipv6gateways,ipv4dhcpsrvs,ipv6dhcpsrvs,ipv4dnssrvs -ErrorAction SilentlyContinue | Out-Null

                    #Get interface Desscription
                    $intname = $int.Description

                    #Figure out if Static or DHCP
                    if ($int.DHCPEnabled -eq $False) {$DHCPEnabled = "False"}#if int static
                    else {$DHCPEnabled = "True"}#else int dhcp

                    #Get IP addresses
                    foreach ($ipaddr in $int.IPAddress) {
                        if ($ipaddr -match "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv4addrs += $ipaddr}#if ipv4addrs
                        if ($ipaddr -notmatch "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" -and $ipaddr -notlike "fe80*") {[string[]]$ipv6addrs += $ipaddr}#if ipv6addrs
                        if ($ipaddr -notmatch "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" -and $ipaddr -like "fe80*") {[string[]]$ipv6addrauto += $ipaddr}#if auto ipv6addr
                    }#foreach ipaddr
                    if ($null -ne $ipv4addrs) {
                        $IPv4 = $ipv4addrs[0]
                        $IPv42 = $ipv4addrs[1]}#if ipv4 not null
                    if (null -ne $$ipv6addrs) {
                        $IPv6 = $ipv6addrs[0]
                        $IPv62 = $ipv6addrs[1]}#if ipv6 not null
                    if ($null -ne $ipv6addrauto) {
                        $ipv6auto = $ipv6addrauto[0]}#if ipv6 auto not null

                    #Get subnet addresses
                    foreach ($subaddr in $int.IPSubnet) {
                        if ($subaddr -match "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv4subnets += $subaddr}#if ipv4addrs
                        if ($subaddr -match "[0-9]{1,2}" -and $subaddr -notmatch "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv6subnets += $subaddr}#if ipv6addrs
                    }#foreach subnet
                    if ($null -ne $ipv4subnets) {
                        $subnet = $ipv4subnets[0]
                        $subnet2 = $ipv4subnets[1]}#if ipv4 not null
                    if ($null -ne $ipv6subnets) {
                        if ($null -ne $ipv6addrauto) {
                            $autosub = $ipv6subnets[0]
                            $ipv6subnet = $ipv6subnets[1]
                            $ipv6subnet2 = $ipv6subnets[2]
                        }#if there is an auto assigned ipv6 address
                        else {
                            $ipv6subnet = $ipv6subnets[0]
                            $ipv6subnet2 = $ipv6subnets[1]
                        }#else there is no auto assigned IPv6 address
                    }#if ipv6 not null

                    #Get Gateway addresses
                    foreach ($gwaddr in $int.DefaultIPGateway) {
                        if ($gwaddr -match "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv4gateways += $gwaddr}#if ipv4addrs
                        if ($gwaddr -notmatch "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv6gateways += $gwaddr}#if ipv6addrs
                    }#foreach gateway
                    if ($null -ne $ipv4gateways) {
                        $gateway = $ipv4gateways[0]
                        $gateway2 = $ipv4gateways[1]}#if ipv4 not null
                    if ($null -ne $ipv6gateways) {
                        $ipv6gateway = $ipv6gateways[0]
                        $ipv6gateway2 = $ipv6gateways[1]}#if ipv6 not null

                    #Get DHCPServers
                    foreach ($dhsraddr in $int.DHCPServer) {
                        if ($dhsraddr -match "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv4dhcpsrvs += $dhsraddr}#if ipv4addrs
                        if ($dhsraddr -notmatch "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv6dhcpsrvs += $dhsraddr}#if ipv6addrs
                    }#foreach dhcp server
                    if ($null -ne $ipv4dhcpsrvs) {$DHCPServer = $ipv4dhcpsrvs[0]}#if ipv4 not null
                    if ($null -ne $ipv6dhcpsrvs) {$ipv6DHCPServer = $ipv6dhcpsrvs[0]}#if ipv6 not null

                    #Get MAC address
                    $MAC = $int.MACAddress

                    #Get DNS servers
                    foreach ($dnssraddr in $int.DNSServerSearchOrder) {
                        if ($dnssraddr -match "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv4dnssrvs += $dnssraddr}#if ipv4addrs
                        #if ($dnssraddr -notmatch "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv6dnssrvs += $dnssraddr}#if ipv6addrs
                    }#foreach dns server
                    $dns1 = $ipv4dnssrvs[0]
                    $dns2 = $ipv4dnssrvs[1]
                    $dns3 = $ipv4dnssrvs[2]
                    #$ipv6dns1 = $ipv6dnssrvs[0]
                    #$ipv6dns2 = $ipv6dnssrvs[1]
                    #$ipv6dns3 = $ipv6dnssrvs[2]

                    #Create Objects
                    [PSCustomObject]@{
                        Name = $Comp
                        Interface = $intname
                        MACAddress = $mac
                        DHCPEnabled = $DHCPEnabled
                        DHCPServer = $DHCPServer
                        IPv6DHCPServer = $ipv6DHCPServer
                        IPv4 = $IPv4
                        IPv4_2 = $ipv42
                        IPv6 = $IPv6
                        IPv6_2 = $IPv62
                        Subnet = $subnet
                        Subnet2 = $subnet2
                        IPv6Subnet = $ipv6subnet
                        IPv6Subnet2 = $ipv6subnet2
                        IPv4Gateway = $gateway
                        IPv4Gateway2 = $gateway2
                        IPv6Gateway = $ipv6gateway
                        IPv6Gateway2 = $ipv6gateway2
                        AutoIPv6 = $ipv6auto
                        AutoIPv6Subnet = $autosub
                        DNSServer1 = $dns1
                        DNSServer2 = $dns2
                        DNSServer3 = $dns3
                        #IPv6DNSServer1 = $ipv6dns1
                        #IPv6DNSServer2 = $ipv6dns2
                        #Pv6DNSServer3 = $ipv6dns3
                    }#new object
                }#foreach interface
            }#if ints not null
        }#try

        catch {
            [PSCustomObject]@{
                Name = $Comp
                Interface = "Comm Error"
                MACAddress = $mac
                DHCPEnabled = $DHCPEnabled
                DHCPServer = $DHCPServer
                IPv6DHCPServer = $ipv6DHCPServer
                IPv4 = $IPv4
                IPv4_2 = $ipv42
                IPv6 = $IPv6
                IPv6_2 = $IPv62
                Subnet = $subnet
                Subnet2 = $subnet2
                IPv6Subnet = $ipv6subnet
                IPv6Subnet2 = $ipv6subnet2
                IPv4Gateway = $gateway
                IPv4Gateway2 = $gateway2
                IPv6Gateway = $ipv6gateway
                IPv6Gateway2 = $ipv6gateway2
                AutoIPv6 = $ipv6auto
                AutoIPv6Subnet = $autosub
                DNSServer1 = $dns1
                DNSServer2 = $dns2
                DNSServer3 = $dns3
                #IPv6DNSServer1 = $ipv6dns1
                #IPv6DNSServer2 = $ipv6dns2
                #Pv6DNSServer3 = $ipv6dns3
            }#new object
        }#catch
    }#foreach computer
}


#referenced in Send-ToastNotification
function Get-NotificationApp {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-07-14 23:42:57
    Last Edit: 2021-07-16 01:57:31
    Keywords:
    Requires:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Get-ToastNotifierApp','Get-ToastNotificationApp')]
    param()

    $info = @()
    $HKCR = Get-PSDrive -Name HKCR -ErrorAction SilentlyContinue
    if (!($HKCR)) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root Hkey_Classes_Root -Scope Script | Out-Null
    }

    $AppRegPath = "HKCR:\AppUserModelId"
    $apps = Get-ChildItem $AppRegPath | Where-Object {$_.Name -notmatch "Andromeda_cw5n1h2txyewy!App" -and $_.Name -notmatch "Microsoft.Windows.Defender" -and `
        $_.Name -notlike "*Windows.Defender" -and $_.Name -notmatch "DeviceManagementTokenRenewalRequired" -and $_.Name -notmatch "Messaging.SystemAlertNotification" -and `
        $_.Name -notmatch "Windows.SystemToast.Suggested" -and $_.Name -notmatch "Windows.SystemToast.WindowsTip"
    }

    $info = foreach ($app in $apps) {
        $name = $app.Name -replace "HKEY_CLASSES_ROOT\\AppUserModelId\\",""
        $apppath = $AppRegPath + "\" + $name
        $dn = Get-ItemProperty -Path $apppath -Name DisplayName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue

        if ($name -eq 'Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge') {$dn = "Microsoft Edge"}
        elseif ($name -eq 'Microsoft.Office.OUTLOOK.EXE.15') {$dn = "Outlook"}
        #elseif ($name -eq "Microsoft.Office.OUTLOOK.EXE.16") {$dn = "Microsoft.Office.OUTLOOK.EXE.16"}
        elseif ($name -eq "Microsoft.Windows.ControlPanel") {$dn = "Control Panel"}
        elseif ($name -eq "Microsoft.Windows.Explorer") {$dn = "File Explorer"}
        elseif ($name -eq "Microsoft.Windows.InputSwitchToastHandler") {$dn = "Input Switch Notification"}
        elseif ($name -eq "Microsoft.Windows.LanguageComponentsInstaller") {$dn = "Language settings"}
        elseif ($name -eq "Microsoft.Windows.ParentalControls") {$dn = "Microsoft family features"}
        elseif ($name -eq "Windows.ActionCenter.QuietHours") {$dn = "Focus assist"}
        elseif ($name -eq "Windows.Defender.MpUxDlp") {$dn = "Data Loss Prevention"}
        elseif ($name -eq "Windows.Defender.SecurityCenter") {$dn = "Windows Security"}
        elseif ($name -eq "Windows.System.AppInitiatedDownload") {$dn = "Automatic file downloads"}
        elseif ($name -eq "Windows.System.Audio") {$dn = "Volume Warning"}
        elseif ($name -eq "Windows.System.Continuum") {$dn = "Tablet mode"}
        elseif ($name -eq "Windows.System.MiracastReceiver") {$dn = "Connect"}
        elseif ($name -eq "Windows.System.NearShareExperienceReceive") {$dn = "Nearby sharing"}
        elseif ($name -eq "Windows.System.ShareExperience") {$dn = "Nearby sharing"}
        elseif ($name -eq "Windows.SystemToast.AudioTroubleshooter") {$dn = "Audio"}
        elseif ($name -eq "Windows.SystemToast.AutoPlay") {$dn = "AutoPlay"}
        elseif ($name -eq "Windows.SystemToast.BackgroundAccess") {$dn = "Battery saver"}
        elseif ($name -eq "Windows.SystemToast.BackupReminder") {$dn = "Backup settings"}
        elseif ($name -eq "Windows.SystemToast.BdeUnlock") {$dn = "BitLocker Drive Encryption"}
        elseif ($name -eq "Windows.SystemToast.BitLockerPolicyRefresh") {$dn = "Device Encryption"}
        elseif ($name -eq "Windows.SystemToast.Bthprops") {$dn = "Add a device"}
        elseif ($name -eq "Windows.SystemToast.BthQuickPair") {$dn = "Bluetooth"}
        elseif ($name -eq "Windows.SystemToast.Calling") {$dn = "Incoming call"}
        elseif ($name -eq "Windows.SystemToast.Calling.SystemAlertNotification") {$dn = "Alert"}
        elseif ($name -eq "Windows.SystemToast.CloudExperienceHostLauncher") {$dn = "Device Setup"}
        elseif ($name -eq "Windows.SystemToast.CloudExperienceHostLauncherCustom") {$dn = "Device Setup"}
        elseif ($name -eq "Windows.SystemToast.Compat") {$dn = "Compatibility Assistant"}
        #elseif ($name -eq "Windows.SystemToast.DeviceConsent") {$dn = ""}
        elseif ($name -eq "Windows.SystemToast.DeviceEnrollmentActivity") {$dn = "Device Management Enrollment Service"}
        elseif ($name -eq "Windows.SystemToast.DeviceManagement") {$dn = "Work or School Account"}
        elseif ($name -eq "Windows.SystemToast.Devices") {$dn = "Devices"}
        elseif ($name -eq "Windows.SystemToast.DisplaySettings") {$dn = "Display Settings"}
        elseif ($name -eq "Windows.SystemToast.EnterpriseDataProtection") {$dn = "Windows Information Protection"}
        elseif ($name -eq "Windows.SystemToast.Explorer") {$dn = "File Explorer"}
        elseif ($name -eq "Windows.SystemToast.FodHelper") {$dn = "Optional Features"}
        elseif ($name -eq "Windows.SystemToast.HelloFace") {$dn = "Windows Hello"}
        elseif ($name -eq "Windows.SystemToast.LocationManager") {$dn = "Location"}
        elseif ($name -eq "Windows.SystemToast.LowDisk") {$dn = "Storage settings"}
        elseif ($name -eq "Windows.SystemToast.MobilityExperience") {$dn = "Continue from your phone"}
        elseif ($name -eq "Windows.SystemToast.NfpAppAcquire") {$dn = "System Notification"}
        elseif ($name -eq "Windows.SystemToast.NfpAppLaunch") {$dn = "Tap and start"}
        elseif ($name -eq "Windows.SystemToast.NfpDevicePairing") {$dn = "Tap and setup"}
        elseif ($name -eq "Windows.SystemToast.NfpReceiveContent") {$dn = "Tap and send"}
        elseif ($name -eq "Windows.SystemToast.Print.Notification") {$dn = "Print Notification"}
        elseif ($name -eq "Windows.SystemToast.RasToastNotifier") {$dn = "VPN"}
        elseif ($name -eq "Windows.SystemToast.SecurityAndMaintenance") {$dn = "Security and Maintenance"}
        elseif ($name -eq "Windows.SystemToast.SecurityCenter") {$dn = "Security and Maintenance"}
        elseif ($name -eq "Windows.SystemToast.SEManagement") {$dn = "Payment"}
        elseif ($name -eq "Windows.SystemToast.ServiceInitiatedHealing.Notification" ) {$dn = "Service Initiated Healing"}
        elseif ($name -eq "Windows.SystemToast.Share") {$dn = "Share"}
        elseif ($name -eq "Windows.SystemToast.SoftLanding") {$dn = "Tips"}
        elseif ($name -eq "Windows.SystemToast.SpeechServices") {$dn = "Microsoft Speech Recognition"}
        elseif ($name -eq "Windows.SystemToast.StorSvc") {$dn = "Storage settings"}
        elseif ($name -eq "Windows.SystemToast.Usb.Notification") {$dn = "USB"}
        elseif ($name -eq "Windows.SystemToast.WiFiNetworkManager") {$dn = "Wireless"}
        elseif ($name -eq "Windows.SystemToast.WindowsUpdate.Notification") {$dn = "Windows Update"}
        elseif ($name -eq "Windows.SystemToast.Winlogon") {$dn = "Windows logon reminder"}
        elseif ($name -eq "Windows.SystemToast.Wwansvc") {$dn = "Cellular"}
        elseif ([string]::IsNullOrWhiteSpace($dn)) {$dn = "unknown"}

        $zname = $dn + " (" + $name + ")"
        [PSCustomObject]@{
            Name = $name
            DisplayName = $dn
            zName = $zname
        }#new object
    }

    $info
    #Remove-PSDrive -Name HKCR -Force
}


Function Get-OperatingSystem {
<#
   .Synopsis
    Gets Operating System information
   .Description
    Gets Operating System information via WMI query (Default) or Registry query (Switch.) Determines whether the computer is 32-bit or 64-bit, the Operating System name, and the OS Build number.
   .Example
    Get-OperatingSystem
    Gets Operating System information for the local computer
   .Example
    Get-OperatingSystem -Registry
    Gets Operating System information for the local computer via Registry query instead os WMI query
   .Example
    Get-OperatingSystem -ComputerName SERVER1
    Gets Operating System information for computer SERVER1
   .Example
    Get-OperatingSystem -ComputerName (gc c:\complist.txt) -Registry
    Gets Operating System information for all computers listed in c:\complist.txt via Registry queries
   .Parameter ComputerName
    Specify computer or computer names to query
   .Parameter Registry
    Use Registry queries instead of WMI queries
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 06/06/2015 20:11:37
    LASTEDIT: 2021-11-26 17:02:59
    KEYWORDS: Operating System, OS
    REMARKS: For local computer it can be ran as user. For remote computers, it needs to be ran as a user who has administrative rights on the remote computer.
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(Mandatory=$false, Position=1)]
        [Switch]$Registry
    )

    #Set Values
    $keyname = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
    $64keyname = 'SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion'
    $i = 0

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {$Role = 'Admin'}
    else {$Role = 'User'}

    foreach ($Comp in $ComputerName){
        if ($Comp -ne $env:COMPUTERNAME) {
            if ($Role -eq "Admin") {$continue = $true}
            else {$continue = $false}
        }
        else {$continue = $true}

        if ($continue) {
        if ($Registry -eq $false) {
            #Progress Bar
            $length = $ComputerName.length
            $i++
            if ($length -gt "1") {
                $number = $ComputerName.length
                $amount = ($i / $number)
                $perc1 = $amount.ToString("P")
                Write-Progress -activity "Getting Operating System info on computers" -status "Checking $comp. Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
            }#if length

            try {
                $ErrorActionPreference = "Stop"
                $wmiq = Get-WmiObject Win32_OperatingSystem -ComputerName $Comp -ErrorAction Stop
                $OS = $wmiq.Caption -replace "Microsoft ",""
                $Bit = $wmiq.OSArchitecture
                $Build = $wmiq.BuildNumber

                if ($OS -like "Windows 10*" -or $OS -like "Windows 11*" -or $OS -match "2016" -or $OS -match "2019" -or $OS -match "2022") {
                    if ($Build -eq 14393) {
                        $OS = $OS + " v1607"
                    }
                    elseif ($Build -eq 15063) {
                        $OS = $OS + " v1703"
                    }
                    elseif ($Build -eq 16299) {
                        $OS = $OS + " v1709"
                    }
                    elseif ($Build -eq 17134) {
                        $OS = $OS + " v1803"
                    }
                    elseif ($Build -eq 17763) {
                        $OS = $OS + " v1809"
                    }
                    elseif ($Build -eq 18362) {
                        $OS = $OS + " v1903"
                    }
                    elseif ($Build -eq 18363) {
                        $OS = $OS + " v1909"
                    }
                    elseif ($Build -eq 19041) {
                        $OS = $OS + " v2004"
                    }
                    elseif ($Build -eq 19042) {
                        $OS = $OS + " v20H2"
                    }
                    elseif ($Build -eq 19043) {
                        $OS = $OS + " v21H1"
                    }
                    elseif ($Build -eq 19044 -or $Build -eq 22000 -or $Build -eq 20348) {#Win 10 Win 11 Server 2022
                        $OS = $OS + " v21H2"
                    }
                    elseif ($Build -eq 19045 -or $Build -eq 22621) {#Win 10 Win 11
                        $OS = $OS + " v22H2"
                    }
                    elseif ($Build -eq 19046 -or $Build -eq 22631) {#Win 10 Win 11
                        $OS = $OS + " v23H2"
                    }
                    elseif ($Build -eq 26100) {#Win 11
                        $OS = $OS + " v24H2"
                    }
                }#if os win 10, srv 2016, or srv 2019
            }#try
            catch {
                #Clear variables
                $reg = $null
                $key = $null
                $key2 = $null
                $value = $null
                $value2 = $null
                $build = $null
                $bit = $null
                $OS = $null

                try {
                    $ErrorActionPreference = "Stop"
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                    $key = $reg.OpenSubkey($keyname)
                    $value = $key.GetValue('ProductName')
                    $build = $key.GetValue('CurrentBuildNumber')

                    #64bit check
                    try {
                        $ErrorActionPreference = "Stop"
                        $key2 = $reg.OpenSubKey($64keyname)
                        $value2 = $key2.GetValue('CurrentVersion')
                    }
                    catch {$value2 = $null}
                    if ($null -eq $value2) {$Bit = "32-bit"}
                    else {$Bit = "64-bit"}

                    if ($value -like "Windows 10*" -or $OS -like "Windows 11*" -or $value -match "2016" -or $value -match "2019" -or $value -match "2022") {
                        if ($Build -eq 14393) {
                            $OS = $value + " v1607"
                        }
                        elseif ($Build -eq 15063) {
                            $OS = $value + " v1703"
                        }
                        elseif ($Build -eq 16299) {
                            $OS = $value + " v1709"
                        }
                        elseif ($Build -eq 17134) {
                            $OS = $value + " v1803"
                        }
                        elseif ($Build -eq 17763) {
                            $OS = $value + " v1809"
                        }
                        elseif ($Build -eq 18362) {
                            $OS = $value + " v1903"
                        }
                        elseif ($Build -eq 18363) {
                            $OS = $value + " v1909"
                        }
                        elseif ($Build -eq 19041) {
                            $OS = $OS + " v2004"
                        }
                        elseif ($Build -eq 19042) {
                            $OS = $OS + " v20H2"
                        }
                        elseif ($Build -eq 19043) {
                            $OS = $OS + " v21H1"
                        }
                        elseif ($Build -eq 19044 -or $Build -eq 22000 -or $Build -eq 20348) {
                            $OS = $OS + " v21H2"
                        }
                        elseif ($Build -eq 19045 -or $Build -eq 22621) {#Win 10 Win 11
                            $OS = $OS + " v22H2"
                        }
                        elseif ($Build -eq 19046 -or $Build -eq 22631) {#Win 10 Win 11
                            $OS = $OS + " v23H2"
                        }
                        elseif ($Build -eq 26100) {#Win 11
                            $OS = $OS + " v24H2"
                        }
                    }#if os win 10, srv 2016, or srv 2019
                    else {$OS = $value}
                }
                catch [System.UnauthorizedAccessException],[System.Management.Automation.MethodInvocationException] {
                    $err = $_.Exception.message.Trim()
                    if ($err -match "network path") {
                        $OS = "Could not connect"
                        $Bit = ""
                        $Build = ""
                    }
                    elseif ($err -match "access is not allowed" -or $err -match "Access is denied") {
                        $OS = "Insufficient Permissions"
                        $Bit = ""
                        $Build = ""
                    }
                    else {
                        $OS = "Error - unknown issue"
                        $Bit = ""
                        $Build = ""
                    }
                }
                catch {
                    $OS = "Could not connect"
                    $Bit = ""
                    $Build = ""
                }
            }#catch
            [PSCustomObject]@{
                ComputerName = $Comp
                OS = $OS
                Bit = $Bit
                Build = $Build
            }#new object
        }#ifnot registry
        else { #if registry
            #Clear variables
            $reg = $null
            $key = $null
            $key2 = $null
            $value = $null
            $value2 = $null
            $build = $null
            $bit = $null
            $OS = $null

            #Progress Bar
            $length = $ComputerName.length
            $i++
            if ($length -gt "1") {
                $number = $ComputerName.length
                $amount = ($i / $number)
                $perc1 = $amount.ToString("P")
                Write-Progress -activity "Getting Operating System info on computers" -status "Checking $comp. Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
            }#if length

            #Pull registry values
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
            $key = $reg.OpenSubkey($keyname)
            $value = $key.GetValue('ProductName')
            $build = $key.GetValue('CurrentBuildNumber')

            #64bit check
            try {
                $ErrorActionPreference = "Stop"
                $key2 = $reg.OpenSubKey($64keyname)
                $value2 = $key2.GetValue('CurrentVersion')
                if ($null -eq $value2) {$bit = "32-bit"}
                else {$bit = "64-bit"}
            }
            catch [System.UnauthorizedAccessException],[System.Management.Automation.MethodInvocationException] {
                $err = $_.Exception.message.Trim()
                if ($err -match "network path") {
                    $bit = "Could not connect"
                }
                elseif ($err -match "access is not allowed" -or $err -match "Access is denied") {
                    $bit = "Insufficient Permissions"
                }
                else {
                    $bit = "Could not connect"
                }
            }
            catch {
                $value2 = $null
                if ($null -eq $value2) {$bit = "32-bit"}
                else {$bit = "64-bit"}
            }

            if ($value -like "Windows 10*" -or $OS -like "Windows 11*" -or $value -match "2016" -or $value -match "2019" -or $value -match "2022") {
                if ($Build -eq 14393) {
                    $OS = $value + " v1607"
                }
                elseif ($Build -eq 15063) {
                    $OS = $value + " v1703"
                }
                elseif ($Build -eq 16299) {
                    $OS = $value + " v1709"
                }
                elseif ($Build -eq 17134) {
                    $OS = $value + " v1803"
                }
                elseif ($Build -eq 17763) {
                    $OS = $value + " v1809"
                }
                elseif ($Build -eq 18362) {
                    $OS = $value + " v1903"
                }
                elseif ($Build -eq 18363) {
                    $OS = $value + " v1909"
                }
                elseif ($Build -eq 19041) {
                    $OS = $value + " v2004"
                }
                elseif ($Build -eq 19042) {
                    $OS = $OS + " v20H2"
                }
                elseif ($Build -eq 19043) {
                    $OS = $OS + " v21H1"
                }
                elseif ($Build -eq 19044 -or $Build -eq 22000 -or $Build -eq 20348) {
                    $OS = $OS + " v21H2"
                }
                elseif ($Build -eq 19045 -or $Build -eq 22621) {#Win 10 Win 11
                    $OS = $OS + " v22H2"
                }
                elseif ($Build -eq 19046 -or $Build -eq 22631) {#Win 10 Win 11
                    $OS = $OS + " v23H2"
                }
                elseif ($Build -eq 26100) {#Win 11
                    $OS = $OS + " v24H2"
                }
            }#if os win 10, win 11, srv 2016, or srv 2019
            else {$OS = $value}

            #Create objects
            [PSCustomObject]@{
                ComputerName = $comp
                OS = $OS
                Bit = $bit
                Build = $build
            }#newobject
        }#elseif registry
    }#continue -eq $true
    else {
        [PSCustomObject]@{
            ComputerName = $comp
            OS = "Error: not running PowerShell as admin"
            Bit = $null
            Build = $null
        }#newobject
    }
    }#foreach comp
}


Function Get-ProcessorCapability {
<#
.NOTES
    Author: Skyler Hart
    Created: Sometime before 8/7/2017
    Last Edit: 2020-04-18 22:46:31
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    foreach ($comp in $ComputerName) {
        try {
            $ErrorActionPreference = "Stop"
            $strComputerName = $comp
            $strCpuArchitecture = $null
            $intCurrentAddressWidth = 0
            $intSupportableAddressWidth = 0

            $objWmi = Get-WmiObject -class "Win32_Processor" -namespace "root\cimV2" -computer $strComputerName -ErrorAction Stop

            $intCurrentAddressWidth = $objWmi.AddressWidth
            $intSupportableAddressWidth = $objWmi.DataWidth

            switch ($objWmi.Architecture) {
                0 {$strCpuArchitecture = "x86"}
                1 {$strCpuArchitecture = "MIPS"}
                2 {$strCpuArchitecture = "Alpha"}
                3 {$strCpuArchitecture = "PowerPC"}
                6 {$strCpuArchitecture = "Itanium"}
                9 {$strCpuArchitecture = "x64"}
            }

            if ($null -eq $intCurrentAddressWidth) {$curbit = $null}
            else {$curbit = "$intCurrentAddressWidth-bit"}

            if ($null -eq $intSupportableAddressWidth) {$capof = $null}
            else {$capof = "$intSupportableAddressWidth-bit"}
        }
        catch [System.UnauthorizedAccessException],[System.Management.Automation.MethodInvocationException] {
            $err = $_.Exception.message.Trim()
            if ($err -match "network path") {
                $strCpuArchitecture = "Could not connect"
                $curbit = $null
                $capof = $null
            }
            elseif ($err -match "access is not allowed" -or $err -match "Access is denied") {
                $strCpuArchitecture = "Insufficient Permissions"
                $curbit = $null
                $capof = $null
            }
            else {
                $strCpuArchitecture = "Error - unknown issue"
                $curbit = $null
                $capof = $null
            }
        }
        catch {
            $strCpuArchitecture = "Could not connect"
            $curbit = $null
            $capof = $null
        }
        [PSCustomObject]@{
            ComputerName = $comp
            CurrentBit = $curbit
            CapableOf = $capof
            Architecture = $strCpuArchitecture
        }
    }#foreach comp
}


Function Get-PSVersion {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/27/2019 12:35:00
    LASTEDIT: 02/27/2019 12:35:00
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Get-PowerShellVersion')]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter()]
        [string[]]$Ignore
    )

    $compinfo = $null
    $compinfo = @()

    $ignorelist = @('tvyx-fs-002p','tvyx-fs-004p','tvyx-cl-001p','tvyx-cl-001v','tvyx-cl-002p','tvyx-cl-002v','tvyx-dc-001v','tvyx-dc-002v','`$tvyx.siem','52TVYX-HBGP-001v','TVYX-VC-001P','tvyx-vmh-001','hqsipfile','tvyxw-lsms','hqceoepo','hqceofile','ceonetapp')
    foreach ($ig in $Ignore) {
        $ignorelist += $ig
    }

    $i = 0
    $number = $ComputerName.length
    $compinfo = foreach ($comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting installed PowerShell version on multiple computers" -status "Computer $i of $number. Currently checking: $comp. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        if ($ignorelist -notmatch $comp) {
            try {
                $info = Get-Item \\$comp\c$\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ErrorAction Stop
                $build = $info.VersionInfo.ProductVersion
                $filebuild = $info.VersionInfo.FileBuildPart
                $osinfo = Get-OperatingSystem $comp -ErrorAction Stop
                $os = $osinfo.OS

                if ($build -like "6.0*") {$ver = "1"}
                elseif ($build -like "6.1*") {$ver = "2"}
                elseif ($build -like "6.2*") {$ver = "3"}
                elseif ($build -like "6.3*") {$ver = "4"}
                elseif ($build -like "10.*") {
                    if ($filebuild -lt "14300") {$ver = "50"}
                    elseif ($filebuild -ge "14300") {$ver = "51"}
                }
                else {$ver = "Build $build"}

                if ($os -match "2008" -and $os -notmatch "2008 R2") {$maxver = "3"}
                elseif ($os -match "2008 R2") {$maxver = "51"}
                elseif ($os -match "2012 R2") {$maxver = "51"}
                elseif ($os -match "2016" -or $os -match "2019" -or $os -match "Windows 10" -or $os -match "Windows 11") {$maxver = "7"}

                if ($ver -lt $maxver) {$status = "Outdated"}
                elseif ($ver -ge $maxver) {$status = "Current"}
                else {$ver = "NA"}

                [PSCustomObject]@{
                    ComputerName = $comp
                    InstalledPowerShellVersion = $ver
                    Status = $status
                    HighestSupportedVersion = $maxver
                    OS = $os
                }#new object
            }
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    InstalledPowerShellVersion = "Unable to connect"
                    Status = "NA"
                    HighestSupportedVersion = "NA"
                    OS = "NA"
                }#new object
            }
        }
    }
    $compinfo
}


Function Get-SerialNumber {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 11/02/2018 12:11:03
    LASTEDIT: 11/02/2018 12:20:44
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Get-SN')]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $i = 0
    $number = $ComputerName.length
    foreach ($comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting Serial NUmber of computers" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length
        try {
            $sn = (Get-WmiObject win32_bios -ComputerName $comp | Select-Object SerialNumber).SerialNumber
            [PSCustomObject]@{
                ComputerName = $comp
                SerialNumber = $sn
            }#new object
        }
        catch {
            [PSCustomObject]@{
                ComputerName = $comp
                SerialNumber = "NA"
            }#new object
        }
    }
}


Function Get-ShutdownLog {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/28/2019 22:13:23
    LASTEDIT: 08/29/2019 00:17:09
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [Alias('Days')]
        [int32]$DaysBackToSearch = 30,

        [Parameter(Mandatory=$false)]
        [int32]$MostRecent = 10
    )

    #Event ID(s) to search for
    [int32[]]$ID = @(1074,6005,6006,6008)

    #Setting initial values
    $i = 0
    $number = $ComputerName.length
    $stime = (Get-Date) - (New-TimeSpan -Day $DaysBackToSearch)

    #Search Each Computer
    foreach ($comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting Setup log for computers. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        $winevents = Get-WinEvent -ComputerName $Comp -FilterHashTable @{Logname='system'; ID= $ID; StartTime=$stime} -ErrorAction Stop | Select-Object ProviderName,Message,Id,TimeCreated
        foreach ($winevent in $winevents) {
            $st = $null
            switch ($winevent.Id) {
                6005 {
                    $st = "Startup completed"
                    $type = "Startup"
                }
                6006 {
                    $st = "Shutdown completed"
                    $type = "Shutdown"
                }
                6008 {
                    $st = "Unexpected shutdown"
                    $type = "Shutdown"
                }
            }#switch

            $eid = $winevent.Id
            $mess = $winevent.Message
            $time = $winevent.TimeCreated

            if ($eid -eq 6005 -or $eid -eq 6006 -or $eid -eq 6008) {
                $user = $null
                $program = $null
                $reason = $null
            }
            else {
                $program = $mess.Substring(0, $mess.IndexOf('(')) -replace "The process ",""
                $program = $program.trim()
                $us1 = $mess.Split('')
                $us2 = $null
                $us2 = $us1 | Where-Object {$_ -Like "$env:userdomain\*"}
                $us3 = $null
                $us3 = $us1 | Where-Object {$_ -Like "AUTHORITY\*"}
                if ($null -ne $us2) {
                    $user = $us2
                }
                else {
                    $user = "NT " + $us3
                }
                $tx1 = ($mess.Substring(0, $mess.IndexOf(': '))).length + 2
                $tx2 = $mess.Substring($tx1)
                $reason = ($tx2 -split '["\n\r"|"\r\n"|\n|\r]' | Where-Object {$_ -notlike "Reason code*" -and $_ -notlike "Shutdown Type*" -and $_ -notlike "Comment*"})[0]

                $re = $mess.Substring(65,40)
                if ($re -match "restart") {
                    $st = "Reboot initiated"
                    $type = "Restart"
                }
                else {
                    $st = "Shutdown"
                    $type = "Shutdown initiated"
                }
            }

            [PSCustomObject]@{
                ComputerName = $comp
                Time = $time
                Status = $st
                Type = $type
                Program = $program
                User = $user
                Reason = $reason
            }#new object
        }#foreach event found
    }#foreach computer
}


Function Get-UpTime {
<#
.NOTES
    Author: Skyler Hart
    Created: 2017-08-18 20:42:41
    Last Edit: 2020-07-07 15:29:12
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    foreach ($Comp in $ComputerName) {
        try {
            $wmiq = Get-WmiObject Win32_OperatingSystem -ComputerName $Comp -erroraction stop
            $bootup = [Management.ManagementDateTimeConverter]::ToDateTime($wmiq.LastBootUpTime)
            $ts = New-TimeSpan $bootup
            $tot = [string]([math]::Round($ts.totalhours,2)) + " h"
            [PSCustomObject]@{
                ComputerName = $Comp
                LastBoot = $bootup
                Total = $tot
                Days = ($ts.Days)
                Hours = ($ts.Hours)
                Minutes = ($ts.Minutes)
                Seconds = ($ts.Seconds)
            }#newobject
        }#try
        catch {
            $bootup = "Failed: Could not connect to computer"
            [PSCustomObject]@{
                ComputerName = $Comp
                LastBoot = $bootup
                Total = ""
                Days = ""
                Hours = ""
                Minutes = ""
                Seconds = ""
            }#newobject
        }#catch
    }#foreach comp
}


function Get-UpdateHistory {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-05-23 20:44:28
    Last Edit: 2023-03-12 22:08:43
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('DaysBackToSearch')]
        [int32]$Days = "7"
    )

    $stime = (Get-Date) - (New-TimeSpan -Day $Days)
    $session = New-Object -ComObject 'Microsoft.Update.Session'
    $ec = ($session.CreateUpdateSearcher()).GetTotalHistoryCount()
    $history = ($session.QueryHistory("",0,$ec) | Select-Object ResultCode,Date,Title,Description,ClientApplicationID,Categories,SupportUrl)
    $ef = $history | Where-Object {$_.Date -gt $stime}

    $wsusupdates = foreach ($e in $ef | Where-Object {$null -ne ($e.Title) -or ($e.Title) -ne ""}) {
        switch ($e.ResultCode) {
            0 {$Result = "Not Started"}
            1 {$Result = "Restart Required"}
            2 {$Result = "Succeeded"}
            3 {$Result = "Succeeded With Errors"}
            4 {$Result = "Failed"}
            5 {$Result = "Aborted"}
            Default {$Result = ($e.ResultCode)}
        }#switch

        $Cat = $e.Categories | Select-Object -First 1 -ExpandProperty Name

        [PSCustomObject]@{
            ComputerName = $env:computername
            Date = ($e.Date)
            Result = $Result
            KB = (([regex]::match($e.Title,'KB(\d+)')).Value)
            Title = ($e.Title)
            Category = $Cat
            ClientApplicationID = ($e.ClientApplicationID)
            Description = ($e.Description)
            SupportUrl = ($e.SupportUrl)
        }
    }#foreach event in history

    $WSUSkbs = $wsusupdates | Where-Object {$_.Result -eq "Succeeded"} | Select-Object -ExpandProperty KB -Unique

    $setuplogevents = Get-WinEvent -FilterHashtable @{logname = 'setup'} | Where-Object {($_.Id -eq 2 -or $_.Id -eq 3) -and $_.TimeCreated -gt $stime}
    $manualupdates = foreach ($update in $setuplogevents) {
        $updatekb = ($update.Message | Select-String -Pattern 'KB(\d+)' -AllMatches) | Select-Object -ExpandProperty Matches

        if ($updatekb -in $WSUSkbs) {
            #do nothing
        }
        else {
            if ($update.Id -eq 2) {$status = "Succeeded"}
            else {$status = "Failed"}

            [PSCustomObject]@{
                ComputerName = $env:computername
                Date = $update.TimeCreated
                Result = $status
                KB = $updatekb
                Title = $null
                Category = $null
                ClientApplicationID = "Manual or Remote Script"
                Description = $null
                SupportUrl = $null
            }#new object
        }
    }

    $allupdates = @()
    $allupdates += $wsusupdates
    $allupdates += $manualupdates

    $allupdates | Sort-Object Date -Descending

<#
    This remote piece requires a firewall change in order to get it to work...
    New-NetFirewallRule -DisplayName "RPC Dynamic Ports" -Enabled:True -Profile:Domain -Direction:Inbound -Action:Allow -Protocol "TCP" -Program "%systemroot%\system32\dllhost.exe"

    The error that it gets is:
    Exception calling "CreateInstance" with "1" argument(s): "Retrieving the COM class factory for remote component with
    CLSID {4CB43D7F-7EEE-4906-8698-60DA1C38F2FE} from machine SN1001 failed due to the following error: 800706ba SN1001."

    foreach ($comp in $ComputerName) {
        $session = [Activator]::CreateInstance([type]::GetTypeFromProgID('Microsoft.Update.Session',$comp))
        $ec = ($session.CreateUpdateSearcher()).GetTotalHistoryCount()
        $history = ($session.QueryHistory("",0,$ec) | Select-Object ResultCode,Date,Title,Description,ClientApplicationID,Categories,SupportUrl)
        $ef = $history | Where-Object {$_.Date -gt $stime}

        foreach ($e in $ef | Where-Object {$null -ne ($e.Title) -or ($e.Title) -ne ""}) {
            switch ($e.ResultCode) {
                0 {$Result = "Not Started"}
                1 {$Result = "Restart Required"}
                2 {$Result = "Succeeded"}
                3 {$Result = "Succeeded With Errors"}
                4 {$Result = "Failed"}
                5 {$Result = "Aborted"}
                Default {$Result = ($e.ResultCode)}
            }#switch

            $Cat = $e.Categories | Select-Object -First 1 -ExpandProperty Name

            $obj = [PSCustomObject]@{
                ComputerName = $comp
                Date = ($e.Date)
                Result = $Result
                KB = (([regex]::match($e.Title,'KB(\d+)')).Value)
                Title = ($e.Title)
                Category = $Cat
                ClientApplicationID = ($e.ClientApplicationID)
                Description = ($e.Description)
                SupportUrl = ($e.SupportUrl)
            }

            $obj
        }#foreach event in history
    }#foreach comp
#>
}


function Get-User {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-20 19:51:03
    Last Edit: 2020-04-20 23:14:32
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
        [ValidateNotNullorEmpty()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(
            Mandatory=$false,
            Position=1
        )]
        [Alias('Username')]
        [string]$User
    )

    foreach ($Comp in $ComputerName) {
        try {
            #Connect to computer and get information on user/users
            if ($null -ne $User) {
                $ui = Get-WmiObject -Class Win32_UserAccount -filter "LocalAccount='True'" -ComputerName $comp -ErrorAction Stop | Select-Object Name,Description,Disabled,Lockout,PasswordChangeable,PasswordExpires,PasswordRequired | Where-Object {$_.Name -match $User}
            }#if user not null
            else {
                $ui = Get-WmiObject -Class Win32_UserAccount -filter "LocalAccount='True'" -ComputerName $comp -ErrorAction Stop | Select-Object Name,Description,Disabled,Lockout,PasswordChangeable,PasswordExpires,PasswordRequired
            }

            ForEach ($u in $ui) {
                [PSCustomObject]@{
                    Computer = $Comp
                    User = $u.Name
                    Description = $u.Description
                    Disabled = $u.Disabled
                    Locked = $u.Lockout
                    PasswordChangeable = $u.PasswordChangeable
                    PasswordExpires = $u.PasswordExpires
                    PasswordRequired = $u.PasswordRequired
                }
            }#foreach u
        }#try
        catch {
            [PSCustomObject]@{
                Computer = $Comp
                User = $null
                Description = $null
                Disabled = $null
                Locked = $null
                PasswordChangeable = $null
                PasswordExpires = $null
                PasswordRequired = $null
            }
        }#catch
    }#foreach comp
}


function Get-UserGroup {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-11-03 11:14:26
    Last Edit: 2020-11-03 11:14:26
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $groups = $id.Groups | foreach-object {$_.Translate([Security.Principal.NTAccount])}
    $groups | Select-Object Value -ExpandProperty Value
}


#Look up "root\WMI" or "root\CCM" using Get-ComputerWMINamespaces
Function Get-WMIClass {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:05:10
    LASTEDIT: 09/21/2017 13:05:10
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string]$ComputerName = "$env:COMPUTERNAME"
    )

    Get-WmiObject -Namespace root\WMI -ComputerName $ComputerName -List
}


Function Get-WMINameSpace {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:05:21
    LASTEDIT: 09/21/2017 13:05:21
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string]$ComputerName = "$env:COMPUTERNAME",

        [string]$Namespace = "root"
    )

    Get-WmiObject -Namespace $Namespace -Class "__Namespace" -ComputerName $ComputerName | Select-Object Name
}


function Get-WindowsSetupLog {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 03/18/2019 15:43:03
    LASTEDIT: 08/28/2019 22:06:44
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Get-UpdateStatus','Get-UpdateLog')]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [Alias('Days')]
        [int32]$DaysBackToSearch = 180,

        [Parameter(Mandatory=$false)]
        [int32]$MostRecent = 6
    )

    #Event ID(s) to search for
    [int32[]]$ID = @(1,2,3,4)

    #Setting initial values
    $i = 0
    $number = $ComputerName.length
    $stime = (Get-Date) - (New-TimeSpan -Day $DaysBackToSearch)
    $info = @()

    #Search Each Computer
    foreach ($Comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting Setup log for computers. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        try {
            #Gather events
            $winevents = Get-WinEvent -ComputerName $Comp -FilterHashTable @{Logname='setup'; ID= $ID; StartTime=$stime} -ErrorAction Stop | Select-Object ProviderName,Message,Id,TimeCreated

            $info += foreach ($winevent in $winevents) {
                if ($winevent.ProviderName -eq "Microsoft-Windows-Servicing" -or ($winevent.ProviderName -eq "Microsoft-Windows-WUSA" -and $winevent.Id -eq "3")) {
                    switch ($winevent.Id) {
                        1 {$st = "Initiating Update"}
                        2 {$st = "Installed"}
                        3 {$st = "Error"}
                        4 {$st = "Reboot Required"}
                    }

                    $eid = $winevent.Id
                    $mess = $winevent.Message
                    $time = $winevent.TimeCreated

                    if ($eid -eq 3) {
                        $update = "NA"
                    }
                    else {
                        $update = $mess -replace "Package ","" -replace " was successfully*","" -replace "A reboot is necessary before package ","" -replace " can be changed to the Installed state.","" `
                            -replace " changed to the Installed state.","" -replace "A reboot is necessary before ","" -replace "Initiating changes for ","" -replace ". Current State is Absent. Target state is Installed. Client id: WindowsUpdateAgent.","" `
                            -replace ". Current state is Superseded. Target state is Absent. Client id: DISM Manager Provider.","" -replace ". Current state is Absent. Target state is Installed. Client id: DISM Manager Provider.","" `
                            -replace ". Current state is Superseded. Target state is Installed. Client id: DISM Manager Provider.","" -replace ". Current state is Installed. Target state is Installed. Client id: DISM Manager Provider.","" `
                            -replace ". Current state is Superseded. Target state is Absent. Client id: CbsTask.","" -replace ". Current state is Installed. Target state is Absent. Client id: DISM Manager Provider.","" `
                            -replace ". Current state is Installed. Target state is Absent. Client id: CbsTask.","" -replace ". Current state is Staged. Target state is Absent. Client id: CbsTask.","" `
                            -replace ". Current state is Absent. Target state is Installed. Client id: UpdateAgentLCU.",""
                    }

                    [PSCustomObject]@{
                        ComputerName = $comp
                        Update = $update
                        Status = $st
                        Message = $mess
                        Time = $time
                    }#new object
                }#if servicing provider or error
            }#foreach event
        }
        catch {
            $info += [PSCustomObject]@{
                ComputerName = $comp
                Update = "NA"
                Status = ""
                Message = ""
                Time = ""
            }#new object
        }

        $info | Select-Object ComputerName,Update,Status,Time,Message -First $MostRecent
    }#foreach computer
}


function Get-ZuluTime {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-10 22:28:39
    Last Edit: 2021-06-10 22:28:39
.LINK
    https://wanderingstag.github.io
#>
    (Get-Date).ToUniversalTime()
}


Function Import-DRAModule {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/17/2019 13:47:31
    LASTEDIT: 2020-08-20 14:42:59
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    $config = $Global:WSToolsConfig
    $ip = $config.DRAInstallLocation
    $if = $config.DRAInstallFile

    if (Test-Path $ip) {
        Import-Module $ip
    }
    else {
        Write-Output "DRA module not found. Please install it from $if"
    }
}


Function Import-MOF {
<#
.PARAMETER Path
    Specifies the path to the mof file intended to import.
.EXAMPLE
    C:\PS>Import-MOF C:\Example\windows10.mof
    Example of how to use this cmdlet.
.EXAMPLE
    C:\PS>New-WMIFilter 'C:\setup\GPOs\WMIs\Google Chrome\Google Chrome.mof'
    Example of how to use this cmdlet.
.EXAMPLE
    C:\PS>Import-MOF -Path C:\Example\virtualservers.mof
    Another example of how to use this cmdlet but with a parameter or switch.
.NOTES
    Author: Skyler Hart
    Created: 10/27/2017 15:54:18
    Last Edit: 2020-05-08 20:30:19
    Keywords:
    Requires:
        -Module ActiveDirectory
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Import-WMIFilter')]
    Param (
        [Parameter(
            HelpMessage = "Enter the path of the .mof file you want to import. Ex: C:\Example\examplewmi.mof",
            Mandatory=$true,
            Position=0
        )]
        [Alias('mof','Name','File')]
        [string]$Path
    )

    $auth = 'Author = ' + '"' + $env:username + '@' + $env:USERDNSDOMAIN + '"'
    $dom = 'Domain = ' + '"' + $env:USERDNSDOMAIN + '"'
    $content = Get-Content $Path
    $content2 = $content -replace 'Author = \"(.*)\"',"$auth" -replace "",""
    $content2 = $content2 -replace 'Domain = \"(.*)\"',"$dom"
    $content2 > $Path
    mofcomp -N:root\Policy $Path
}


Function Join-File {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 04/30/2019 14:52:40
    LASTEDIT: 04/30/2019 17:17:50
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
    [Alias('Merge-File')]
    Param (
        [Parameter(HelpMessage = "Enter the path of the folder with the part files you want to join.",
            Mandatory=$true,
            Position=0
        )]
        [Alias('Source','InputLocation','SourceFolder')]
        [string]$Path,

        [Parameter(HelpMessage = "Enter the path where you want the joined file placed.",
            Mandatory=$false,
            Position=1
        )]
        [Alias('OutputLocation','Output','DestinationPath','Destination')]
        [string]$DestinationFolder
    )

    $og = (Get-Location).Path
    $objs = Get-ChildItem $Path | Where-Object {$_.Name -like "*_Part*"}

    $myobjs = foreach ($obj in $objs) {
        $ext = $obj.Extension
        $name = $obj.Name
        $num = $name -replace "[\s\S]*.*(_Part)","" -replace $ext,""
        $fn = $obj.FullName
        $dp = $obj.Directory.FullName

        [PSCustomObject]@{
            FullName = $fn
            Name = $name
            Extension = $ext
            Num = [int]$num
            Directory = $dp
        }#new object
    }

    $sobj = $myobjs | Sort-Object Num | Select-Object FullName,Name,Extension,Directory

    $fo = $sobj[0]
    $fon = $fo.Name
    $fon = $fon -replace "_Part01",""
    $fd = $fo.Directory
    if ($DestinationFolder -eq "") {
        $fop = $fd + "\" + $fon
        Set-Location $fd
    }
    else {
        $fop = $DestinationFolder + "\" + $fon
        if (!(Test-Path $DestinationFolder)) {
         New-Item -Path $DestinationFolder -ItemType Directory
        }
        Set-Location $DestinationFolder
    }

    $WriteObj = New-Object System.IO.BinaryWriter([System.IO.File]::Create($fop))

    if ($host.Version.Major -ge 3) {
        $sobj.FullName | ForEach-Object {
            Write-Output "Appending $_ to $fop"
            $ReadObj = New-Object System.IO.BinaryReader([System.IO.File]::Open($_, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read))

            $WriteObj.BaseStream.Position = $WriteObj.BaseStream.Length
            $ReadObj.BaseStream.CopyTo($WriteObj.BaseStream)
            $WriteObj.BaseStream.Flush()

            $ReadObj.Close()
        }
    }
    else {
        [Byte[]]$Buffer = New-Object Byte[] 100MB

        $sobj.FullName | ForEach-Object {
            Write-Output "Appending $_ to $fop"
            $ReadObj = New-Object System.IO.BinaryReader([System.IO.File]::Open($_, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read))

            while ($ReadObj.BaseStream.Position -lt $ReadObj.BaseStream.Length) {
                $ReadBytes = $ReadObj.Read($Buffer, 0, $Buffer.Length)
                $WriteObj.Write($Buffer, 0, $ReadBytes)
            }

            $ReadObj.Close()
        }
    }

    $WriteObj.Close()
    Set-Location $og
}


function Mount-HomeDrive {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-11-03 14:58:38
    Last Edit: 2020-11-03 14:58:38
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Add-HomeDrive')]
    param()
    net use $env:HOMEDRIVE $env:HOMESHARE /persistent:yes
}


#get more open commands here: https://sysadminstricks.com/tricks/most-useful-microsoft-management-console-snap-in-control-files-msc-files.html
function Open-AdminTools {
<#
   .Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:48:27
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
    [Alias('tools','admintools','admin')]
    param()
    control.exe admintools
}


function Open-BitLocker {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 21:56:03
    LASTEDIT: 08/19/2017 21:56:03
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
    [Alias('BitLocker')]
    param()
    control.exe /name Microsoft.BitLockerDriveEncryption
}


function Open-CertificatesComputer {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:22:46
    LASTEDIT: 08/19/2017 22:22:46
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    certlm.msc
}


function Open-CertificatesUser {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:22:46
    LASTEDIT: 08/19/2017 22:22:46
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    certmgr.msc
}


function Open-CMTrace {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-10-19 15:07:45
    Last Edit: 2021-10-19 15:15:48
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Open-CCMTrace','CMTrace','CCMTrace')]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [Alias('File','FileName','Name','Source')]
        [string]$Path
    )

    $lcm = "C:\Windows\CCM\CMTrace.exe"
    $ncm = ($Global:WSToolsConfig).CMTrace

    if ([string]::IsNullOrWhiteSpace($Path)) {
        if (Test-Path $lcm) {Start-Process $lcm}
        else {Start-Process $ncm}
    }
    else {
        if (Test-Path $lcm) {Start-Process $lcm -ArgumentList $Path}
        else {Start-Process $ncm -ArgumentList $Path}
    }
}


function Open-ComputerManagement {
<#
   .Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:48:35
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
        [string]$ComputerName = "$env:COMPUTERNAME"
    )
    compmgmt.msc /computer:\\$ComputerName
}


function Open-DeviceManager {
<#
   .Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:48:43
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
        [string]$ComputerName = "$env:COMPUTERNAME"
    )
    devmgmt.msc /computer:\\$ComputerName
}


function Open-DevicesAndPrinters {
<#
   .Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:48:52
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    control.exe printers
}


function Open-DiscDrive {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-05-08 23:26:34
    Last Edit: 2020-05-08 23:26:34
    Keywords:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Eject-Disc')]
    param()
    $sh = New-Object -ComObject "Shell.Application"
    $sh.Namespace(17).Items() | Where-Object {$_.Type -eq "CD Drive"} | ForEach-Object {$_.InvokeVerb("Eject")}
}


function Open-DiskManagement {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:19:32
    LASTEDIT: 08/19/2017 22:19:32
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
        [string]$ComputerName = "$env:COMPUTERNAME"
    )
    diskmgmt.msc /computer:\\$ComputerName
}


function Open-EventViewer {
<#
   .Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:48:35
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
    [Alias('events')]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )
    eventvwr.msc /computer:\\$ComputerName
}


Function Open-FirewallLog {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 09/11/2017 14:50:51
    LASTEDIT: 09/11/2017 14:50:51
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
        [Parameter()]
        [Switch]$Domain,

        [Parameter()]
        [Switch]$Private,

        [Parameter()]
        [Switch]$Public
    )

    if ($Private -eq $true) {notepad %systemroot%\system32\logfiles\firewall\domainfirewall.log}
    elseif ($Public -eq $true) {notepad %systemroot%\system32\logfiles\firewall\privatefirewall.log}
    elseif ($Domain -eq $true -or ($Private -eq $false -and $Public -eq $false)) {notepad %systemroot%\system32\logfiles\firewall\publicfirewall.log}
}


Function Open-HomeAssistant {
    <#
       .Notes
        AUTHOR: Skyler Hart
        CREATED: 2022-03-08 21:51:19
        LASTEDIT: 2022-03-08 21:51:19
        KEYWORDS:
        REQUIRES:
.LINK
    https://wanderingstag.github.io
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
    $URL = $config.HomeAssistant

    if ($Chrome) {Start-Process "chrome.exe" $URL}
    elseif ($Edge) {Start-Process Microsoft-Edge:$URL}
    elseif ($Firefox) {Start-Process "firefox.exe" $URL}
    elseif ($InternetExplorer) {Start-Process "iexplore.exe" $URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open($URL)
    }
}


function Open-HomeDrive {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-11-03 15:03:52
    Last Edit: 2020-11-03 15:03:52
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    explorer.exe $env:HOMESHARE
}


function Open-LocalGPeditor {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:31:01
    LASTEDIT: 08/19/2017 22:31:01
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
    [Alias('Open-LocalPolicyEditor','LocalPolicy')]
    param()
    gpedit.msc
}


Function Open-NetworkConnections {
<#
   .Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:49:17
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
    [Alias('network','connections')]
    param()
    control.exe ncpa.cpl
}


function Open-ProgramsAndFeatures {
<#
   .Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:49:23
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
    [Alias('programs')]
    param()
    Start-Process appwiz.cpl
}


Function Open-Remedy {
    <#
       .Notes
        AUTHOR: Skyler Hart
        CREATED: 10/03/2017 10:52:44
        LASTEDIT: 2020-04-17 15:47:44
        KEYWORDS:
        REQUIRES:
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Remedy','EITSM','Open-EITSM')]
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
    $URL = $config.Remedy

    if ($Chrome) {Start-Process "chrome.exe" $URL}
    elseif ($Edge) {Start-Process Microsoft-Edge:$URL}
    elseif ($Firefox) {Start-Process "firefox.exe" $URL}
    elseif ($InternetExplorer) {Start-Process "iexplore.exe" $URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open($URL)
    }
}


Function Open-Services {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:14:08
    LASTEDIT: 08/19/2017 22:14:08
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
    [Alias('services')]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string]$ComputerName = "$env:COMPUTERNAME"
    )
    services.msc /computer=\\$ComputerName
}


Function Open-SystemProperties {
<#
   .Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:49:29
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    control.exe sysdm.cpl
}


function Open-VisualStudioCodeSettings {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-05-18 21:18:59
    Last Edit: 2021-05-18 21:27:47
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does."
    )]
    [CmdletBinding()]
    [Alias('Open-VSCCodeSettings')]
    param()

    $vssettings = "$env:APPDATA\Code\User\settings.json"
    if ($host.Name -match "Visual Studio Code") {
        code $vssettings
    }
    else {
        powershell_ise $vssettings
    }
}


function Register-NotificationApp {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-11-03 21:36:05
    Last Edit: 2020-11-03 21:36:05
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the short name of the application.",
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$AppID,

        [Parameter(
            HelpMessage = "Enter the display name of the application.",
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$AppDisplayName,

        [Parameter(
            Mandatory=$false
        )]
        [int]$ShowInSettings = 0
    )

    $HKCR = Get-PSDrive -Name HKCR -ErrorAction SilentlyContinue
    if (!($HKCR)) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root Hkey_Classes_Root -Scope Script
    }

    $AppRegPath = "HKCR:\AppUserModelId"
    $RegPath = "$AppRegPath\$AppID"
    if (!(Test-Path $RegPath)) {
        $null = New-Item -Path $AppRegPath -Name $AppID -Force
    }

    $DisplayName = Get-ItemProperty -Path $RegPath -Name DisplayName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
    if ($DisplayName -ne $AppDisplayName) {
        $null = New-ItemProperty -Path $RegPath -Name DisplayName -Value $AppDisplayName -PropertyType String -Force
    }

    $ShowInSettingsValue = Get-ItemProperty -Path $RegPath -Name ShowInSettings -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ShowInSettings -ErrorAction SilentlyContinue
    if ($ShowInSettingsValue -ne $ShowInSettings) {
        $null = New-ItemProperty -Path $RegPath -Name ShowInSettings -Value $ShowInSettings -PropertyType DWORD -Force
    }
    Remove-PSDrive -Name HKCR -Force
}


function Restart-AxwayTrayApp {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Restart-AxwayTrayApp
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Restart-AxwayTrayApp -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.NOTES
    Author: Skyler Hart
    Created: 2021-06-16 23:25:56
    Last Edit: 2021-06-16 23:25:56
    Keywords:
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    Get-Process | Where-Object {$_.Name -match "dvtray"} | Stop-Process -Force | Out-Null
    & 'C:\Program Files\Tumbleweed\Desktop Validator\DVTrayApp.exe'
}


function Remove-OldPowerShellModule {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-08-31 23:58:29
    Last Edit: 2021-08-31 23:58:29
    Keywords:
    Other:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 250,

        [Parameter()]
        $MaxResultTime = 14400
    )
    Begin {
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
                [string]$comp
            )
            Import-Module WSTools
            $ops = ($Global:WSToolsConfig).OldPSModule

            foreach ($o in $ops) {
                $p = "\\$comp\c$\Program Files\WindowsPowerShell\Modules\" + $o
                if (Test-Path $p) {
                    Remove-Item -Path $p -Recurse -Force
                }
            }
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


function Repair-DuplicateSusClientID {
<#
.SYNOPSIS
    Removes SusClientID registry key on the local or remote computer.
.DESCRIPTION
    When creating a computer from a template (virtual disc) the SusClientID isn't changed and will result in WSUS only having one object for all the computers created. This function clears the SusClientID from the registry on the local or remote computer(s) so when syncing with WSUS a new SusClientID will be created. The first initial sync with WSUS typically fails. It may take several minutes for the computer to sync appropriately with WSUS.
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.EXAMPLE
    C:\PS>Repair-DuplicateSusClientID
    Example of how to use this cmdlet to fix a duplicate SusClientID on the local computer.
.EXAMPLE
    C:\PS>Repair-DuplicateSusClientID -ComputerName Server1
    Another example of how to use this cmdlet but with the ComputerName parameter. In this example, Server1 is a remote computer.
.INPUTS
    System.String
.OUTPUTS
    System.String
.COMPONENT
    WSTools
.FUNCTIONALITY
    WSUS, fix, repair, SusClientID
.NOTES
    Author: Skyler Hart
    Created: 2022-07-15 21:05:27
    Last Edit: 2022-07-15 21:05:27
    Other:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    if ($ComputerName -eq $env:COMPUTERNAME) {
        Write-Output "$(Get-Date) - ${ComputerName}: Stoppping Services"
        Get-Service -Name BITS | Stop-Service
        Get-Service -Name wuauserv | Stop-Service
        Write-Output "$(Get-Date) - ${ComputerName}: Removing registry keys"
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "AccountDomainSid" -Force | Out-Null
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "PingID" -Force | Out-Null
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientId" -Force | Out-Null
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientIdValidation" -Force | Out-Null
        Write-Output "$(Get-Date) - ${ComputerName}: Removing SoftwareDistribution folder"
        Remove-Item -Path C:\Windows\SoftwareDistribution -Force | Out-Null
        Write-Output "$(Get-Date) - ${ComputerName}: Starting Services"
        Get-Service -Name BITS | Start-Service
        Get-Service -Name wuauserv | Start-Service
        Write-Output "$(Get-Date) - ${ComputerName}: Reauthorizing client"
        Start-Process -FilePath "C:\Windows\System32\wuauclt.exe" -ArgumentList "/resetauthorization /detectnow" -Wait
        Start-Sleep -Seconds 10
        Write-Output "$(Get-Date) - ${ComputerName}: Starting detection"
        (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
    }
    else{
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {#DevSkim: ignore DS104456
            $comp = $env:COMPUTERNAME
            Write-Output "$(Get-Date) - ${comp}: Stoppping Services"
            Get-Service -Name BITS | Stop-Service
            Get-Service -Name wuauserv | Stop-Service
            Write-Output "$(Get-Date) - ${comp}: Removing registry keys"
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "AccountDomainSid" -Force | Out-Null
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "PingID" -Force | Out-Null
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientId" -Force | Out-Null
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientIdValidation" -Force | Out-Null
            Write-Output "$(Get-Date) - ${comp}: Removing SoftwareDistribution folder"
            Remove-Item -Path C:\Windows\SoftwareDistribution -Force | Out-Null
            Write-Output "$(Get-Date) - ${comp}: Starting Services"
            Get-Service -Name BITS | Start-Service
            Get-Service -Name wuauserv | Start-Service
            Write-Output "$(Get-Date) - ${comp}: Reauthorizing client"
            Start-Process -FilePath "C:\Windows\System32\wuauclt.exe" -ArgumentList "/resetauthorization /detectnow" -Wait
            Start-Sleep -Seconds 10
            Write-Output "$(Get-Date) - ${comp}: Starting detection"
            (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
        } -ThrottleLimit 5
    }
}


function Save-MaintenanceReport {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-06-16 14:39:04
    Last Edit: 2023-03-22 08:26:11
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
	[CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [int32]$Days = ((Get-Date -Format yyyyMMdd) - ((Get-Date -Format yyyyMMdd).Substring(0,6) + "01"))
    )

    $UHPath = ($Global:WSToolsConfig).UHPath
    $dt = get-date -Format yyyyMMdd
    $sp = $UHPath + "\" + $dt + "_MaintenanceReport.csv"
    $stime = (Get-Date) - (New-TimeSpan -Day $Days)
    $info = Get-ChildItem $UHPath | Where-Object {$_.LastWriteTime -gt $stime -and $_.Name -notlike "*MaintenanceReport.csv"} | Select-Object FullName -ExpandProperty FullName
    $finfo = Import-Csv ($info)
    $finfo | Select-Object Date,ComputerName,KB,Result,Title,Description,Category,ClientApplicationID,SupportUrl | Where-Object {$_.Date -gt $stime} | Sort-Object Date,ComputerName -Descending | Export-Csv $sp -NoTypeInformation
}


function Save-HelpToFile {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-12-17 23:05:01
    Last Edit: 2021-12-17 23:05:01
    Keywords:
    Other:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter()]
        [Alias('Path','Folder','Destination')]
        [string]$DestinationPath
    )

    if ([string]::IsNullOrWhiteSpace($Source)) {
        $DestinationPath = ($Global:WSToolsConfig).HelpFolder
    }

    if (Test-Path $DestinationPath) {
        Save-Help -DestinationPath $DestinationPath -Module * -Force
    }
    else {
        Write-Error 'Destination folder "$DestinationPath" not found.'
    }
}


function Save-UpdateHistory {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-06-15 13:03:22
    Last Edit: 2023-03-22 08:26:33
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [int32]$ThrottleLimit = 5
    )

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {#DevSkim: ignore DS104456
        [int32]$Days = ((Get-Date -Format yyyyMMdd) - ((Get-Date -Format yyyyMMdd).Substring(0,6) + "01") + 1)
        $fn = $env:computername + "_UpdateHistory.csv"
        $lf = $env:ProgramData + "\WSTools\Reports"
        $lp = $lf + "\" + $fn

        $stime = (Get-Date) - (New-TimeSpan -Day $Days)
        $session = New-Object -ComObject 'Microsoft.Update.Session'
        $ec = ($session.CreateUpdateSearcher()).GetTotalHistoryCount()
        $history = ($session.QueryHistory("",0,$ec) |
            Select-Object ResultCode,Date,Title,Description,ClientApplicationID,Categories,SupportUrl)
        $ef = $history | Where-Object {$_.Date -gt $stime -and !([string]::IsNullOrWhiteSpace($_.Title))}

        $wsusupdates = foreach ($e in $ef) {
            switch ($e.ResultCode) {
                0 {$Result = "Not Started"}
                1 {$Result = "Restart Required"}
                2 {$Result = "Succeeded"}
                3 {$Result = "Succeeded With Errors"}
                4 {$Result = "Failed"}
                5 {$Result = "Aborted"}
                Default {$Result = ($e.ResultCode)}
            }#switch

            $Cat = $e.Categories | Select-Object -First 1 -ExpandProperty Name

            [PSCustomObject]@{
                ComputerName = $env:computername
                Date = ($e.Date)
                Result = $Result
                KB = (([regex]::match($e.Title,'KB(\d+)')).Value)
                Title = ($e.Title)
                Category = $Cat
                ClientApplicationID = ($e.ClientApplicationID)
                Description = ($e.Description)
                SupportUrl = ($e.SupportUrl)
            }
        }#foreach event in history

        $WSUSkbs = $wsusupdates | Where-Object {$_.Result -eq "Succeeded"} | Select-Object -ExpandProperty KB -Unique

        $setuplogevents = Get-WinEvent -FilterHashtable @{logname = 'setup'} | Where-Object {($_.Id -eq 2 -or $_.Id -eq 3) -and $_.TimeCreated -gt $stime}
        $manualupdates = foreach ($update in $setuplogevents) {
            $updatekb = ($update.Message | Select-String -Pattern 'KB(\d+)' -AllMatches) | Select-Object -ExpandProperty Matches

            if ($updatekb -in $WSUSkbs) {
                #do nothing
            }
            else {
                if ($update.Id -eq 2) {$status = "Succeeded"}
                else {$status = "Failed"}

                [PSCustomObject]@{
                    ComputerName = $env:computername
                    Date = $update.TimeCreated
                    Result = $status
                    KB = $updatekb
                    Title = $null
                    Category = $null
                    ClientApplicationID = "Manual or Remote Script"
                    Description = $null
                    SupportUrl = $null
                }#new object
            }
        }

        $allupdates = @()
        $allupdates += $wsusupdates
        $allupdates += $manualupdates

        if (Test-Path $env:ProgramData\WSTools) {
            #do nothing
        }
        else {
            New-Item -Path $env:ProgramData -Name WSTools -ItemType Directory
        }

        if (Test-Path $lf) {
            #do nothing
        }
        else {
            New-Item -Path $env:ProgramData\WSTools -Name Reports -ItemType Directory
        }

        $allupdates | Sort-Object Date -Descending | Export-Csv $lp -Force
    } -ThrottleLimit $ThrottleLimit
}


function Set-AxwayConfig {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-16 22:10:29
    Last Edit: 2021-06-16 23:22:15
    Keywords:
    Other:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Import-AxwayConfig')]
    param(
        [Parameter(
            #HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName,

        [Parameter(
            HelpMessage = "Enter the path for the configuration file to import.",
            Mandatory=$true,
            Position=1
        )]
        [ValidateNotNullOrEmpty()]
        [string]$ConfigFile
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Start-Process "$env:ProgramFiles\Tumbleweed\Desktop Validator\dvconfig.exe" -ArgumentList "-command write -file $ConfigFile"
        }
        else {Write-Error "Must be ran as administrator."}
    }
    else {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $i = 0
            $number = $ComputerName.length
            foreach ($Comp in $ComputerName) {
                #Progress Bar
                if ($number -gt "1") {
                    $i++
                    $amount = ($i / $number)
                    $perc1 = $amount.ToString("P")
                    Write-Progress -activity "Setting Axway config" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
                }#if length

                try {
                    Invoke-Command -ComputerName $Comp -ScriptBlock {Start-Process "$env:ProgramFiles\Tumbleweed\Desktop Validator\dvconfig.exe" -ArgumentList "-command write -file $ConfigFile"} -ErrorAction Stop #DevSkim: ignore DS104456
                    #$install = Invoke-WMIMethod -Class Win32_Process -ComputerName $Comp -Name Create -ArgumentList 'cmd /c "c:\Program Files\Tumbleweed\Desktop Validator\dvconfig.exe" -command write -file $ConfigFile' -ErrorAction Stop #DevSkim: ignore DS104456
                    $info = [PSCustomObject]@{
                        ComputerName = $Comp
                        Status = "Axway config imported"
                    }#new object
                }
                catch {
                    $info = [PSCustomObject]@{
                        ComputerName = $Comp
                        Status = "Unable to import Axway config"
                    }#new object
                }
                $info
            }#foreach computer
        }#if admin
        else {Write-Error "Must be ran as admin when running against remote computers"}#not admin
    }#else not local
}


function Set-ChromeDeveloperTools {
<#
.SYNOPSIS
    Will enable or disable Chrome Developer tools.
.DESCRIPTION
    Sets the registry entry HKLM:\SOFTWARE\Policies\Google\Chrome\DeveloperToolsDisabled to 1 (Disabled) or 0 (Enabled)
.PARAMETER Disable
    Will Disable Chrome Developer Tools.
.EXAMPLE
    C:\PS>Set-ChromeDeveloperTools
    Example of how to use this cmdlet to enable Chrome Developer Tools.
.EXAMPLE
    C:\PS>Set-ChromeDeveloperTools -Disable
    Example of how to use this cmdlet to disable Chrome Developer Tools.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    Chrome, Developer Tools
.NOTES
    Author: Skyler Hart
    Created: 2022-09-20 19:53:22
    Last Edit: 2022-09-20 19:53:22
    Other:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Developer Tools is the actual name of the setting so keeping it consistent."
    )]
    [CmdletBinding()]
    [Alias('Set-DeveloperTools')]
    param(
        [Parameter()]
        [switch]$Disable
    )

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        if ($Disable) {
            try {
                Get-ItemPropertyValue -Path HKLM:\SOFTWARE\Policies\Google\Chrome -Name DeveloperToolsDisabled -ErrorAction Stop

                #modify entry
                Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome -Name DeveloperToolsDisabled -Value 1
            }
            catch {
                #Create entry
                New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome -Name DeveloperToolsDisabled -Value 1
            }
        }
        else {
            try {
                Get-ItemPropertyValue -Path HKLM:\SOFTWARE\Policies\Google\Chrome -Name DeveloperToolsDisabled -ErrorAction Stop
                Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome -Name DeveloperToolsDisabled -Value 0
            }
            catch {
                Write-Output "Chrome Developer Tools already enabled."
            }
        }
    }
    else {
        Write-Warning "Function must be ran as administrator."
    }
}


Function Set-Explorer {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 02/08/2018 21:26:47
    LASTEDIT: 02/08/2018 21:26:47
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
        [Switch]$ThisPC,
        [Switch]$QuickAccess
    )

    if ($ThisPC) {Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1 -Force}
    elseif ($QuickAccess) {Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 2 -Force}
    else {Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1 -Force}
}


Function Set-JavaException {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-11-09 22:51:15
    LASTEDIT: 2021-11-09 23:32:06
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Add-JavaException')]
    Param (
        [Parameter(
            Mandatory=$false
        )]
        [Alias('URI','Address')]
        [string]$URL,

        [Parameter(
            Mandatory = $false
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200,

        [switch]$FromShare
    )

    Begin {
        if ($FromShare) {$Share = "FromShareTrue"}
        else {$Share = ""}
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
                [string]$URL,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$FromShare
            )

            if ($comp -eq $env:COMPUTERNAME) {
                $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
                if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                    if ($FromShare -eq "FromShareTrue") {
                        Import-Module WSTools
                        $jes = ($Global:WSToolsConfig).JException
                        try {$Path = Get-ChildItem "$env:ProgramFiles\Java" -ErrorAction Stop | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                        catch {$Path = Get-ChildItem "${env:ProgramFiles(x86)}\Java" | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                        $lib = [environment]::ExpandEnvironmentVariables("%PROGRAMFILES%\Java\$Path\lib")
                        $lib32 = [environment]::ExpandEnvironmentVariables("%PROGRAMFILES(x86)%\Java\$Path\lib")

                        if (Test-Path $lib) {
                            Copy-Item -Path $jes\exception.sites -Destination $lib -Force
                        }

                        if (Test-Path $lib32) {
                            Copy-Item -Path $jes\exception.sites -Destination $lib32 -Force
                        }
                    }
                    else {
                        try {$Path = Get-ChildItem "$env:ProgramFiles\Java" -ErrorAction Stop | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                        catch {$Path = Get-ChildItem "${env:ProgramFiles(x86)}\Java" | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                        $lib = [environment]::ExpandEnvironmentVariables("%PROGRAMFILES%\Java\$Path\lib")
                        $lib32 = [environment]::ExpandEnvironmentVariables("%PROGRAMFILES(x86)%\Java\$Path\lib")

                        if (Test-Path $lib) {
                            Add-Content -Path $lib\exception.sites -Value $URL -Force
                        }

                        if (Test-Path $lib32) {
                            Add-Content -Path $lib32\exception.sites -Value $URL -Force
                        }
                    }
                }
                else {Write-Error "Must be ran as administrator"}
            }#if local comp
            else {
                if ($FromShare -eq "FromShareTrue") {
                    Import-Module WSTools
                    $jes = ($Global:WSToolsConfig).JException
                    try {$Path = Get-ChildItem "\\$comp\c$\Program Files\Java" -ErrorAction Stop | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                    catch {$Path = Get-ChildItem "\\$comp\c$\Program Files (x86)\Java" | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                    $lib = "\\" + $comp + "\c$\Program Files\Java\" + $Path + "\lib"
                    $lib32 = "\\" + $comp + "\c$\Program Files (x86)\Java\" + $Path + "\lib"
                    #$je = Get-Content $jes\exception.sites

                    if (Test-Path $lib) {
                        Robocopy.exe $jes $lib exception.sites
                        #if (Test-Path $lib\exception.sites) {
                        #    Set-Content -Path $lib\exception.sites -Value $je -Force
                        #}
                        #else {
                        #    Add-Content -Path $lib\exception.sites -Value $je -Force
                        #}
                    }

                    if (Test-Path $lib32) {
                        Robocopy.exe $jes $lib32 exception.sites
                        #if (Test-Path $lib32\exception.sites) {
                        #    Set-Content -Path $lib32\exception.sites -Value $je -Force
                        #}
                        #else {
                        #    Add-Content -Path $lib32\exception.sites -Value $je -Force
                        #}
                    }
                }
                else {
                    try {$Path = Get-ChildItem "\\$comp\c$\Program Files\Java" -ErrorAction Stop | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                    catch {$Path = Get-ChildItem "\\$comp\c$\Program Files (x86)\Java" | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                    $lib = "\\" + $comp + "\c$\Program Files\Java\" + $Path + "\lib"
                    $lib32 = "\\" + $comp + "\c$\Program Files (x86)\Java\" + $Path + "\lib"

                    if (Test-Path $lib) {
                        Add-Content -Path $lib\exception.sites -Value $URL -Force
                    }

                    if (Test-Path $lib32) {
                        Add-Content -Path $lib32\exception.sites -Value $URL -Force
                    }
                }
            }#if remote comp
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($URL.ToString()) | out-null
            $PowershellThread.AddArgument($Share.ToString()) | out-null
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


function Set-LAPSshortcut {
<#
.PARAMETER Path
    Specifies whether to save to the Public Desktop or the logged on users desktop.
.EXAMPLE
    C:\PS>Set-LAPSshortcut PublicDesktop
    Shows how to setup the LAPS shortcut on the Public Desktop.
.EXAMPLE
    C:\PS>Set-LAPSshortcut UserDesktop
    Shows how to setup the LAPS shortcut on the logged on users desktop.
.EXAMPLE
    C:\PS>Set-LAPSshortcut -Path PublicDesktop
    Shows how to setup the LAPS shortcut on the Public Desktop.
.EXAMPLE
    C:\PS>Set-LAPSshortcut -Path UserDesktop
    Shows how to setup the LAPS shortcut on the logged on users desktop.
.NOTES
    Author: Skyler Hart
    Created: 2020-05-08 22:34:49
    Last Edit: 2021-10-13 20:48:50
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter either PublicDesktop or UserDesktop. PublicDesktop requires admin rights.",
            Mandatory=$true,
            Position=0
        )]
        [ValidateSet('PublicDesktop','UserDesktop')]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if ($Path -eq "PublicDesktop") {
        $sp = "C:\Users\Public\Desktop\LAPS.lnk"
    }
    elseif ($Path -eq "UserDesktop") {
        $sp = ([System.Environment]::GetFolderPath("Desktop")) + "\LAPS.lnk"
    }
    $AppLocation = "C:\Program Files\LAPS\AdmPwd.UI.exe"
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$sp")
    $Shortcut.TargetPath = $AppLocation
    $Shortcut.IconLocation = "C:\Program Files\LAPS\AdmPwd.UI.exe,0"
    $Shortcut.Description ="LAPS Admin Console"
    $Shortcut.WorkingDirectory ="C:\Program Files\LAPS"
    $Shortcut.Save()
}


function Set-MTU {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-05-12 20:56:13
    Last Edit: 2020-05-12 20:56:13
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
	[CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [int32]$Size = 1500
    )
    Set-NetIPInterface -AddressFamily IPv4 -NlMtuBytes $Size
}


function Set-NetworkConnectionsShortcut {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-05-08 23:01:21
    Last Edit: 2021-10-13 20:55:00
    Keywords:
    Requires:
        -RunAsAdministrator if placing in Public Desktop.
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter either PublicDesktop or UserDesktop. PublicDesktop requires admin rights.",
            Mandatory=$true,
            Position=0
        )]
        [ValidateSet('PublicDesktop','UserDesktop')]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if ($Path -eq "PublicDesktop") {
        $sp = "C:\Users\Public\Desktop\Network Connections.lnk"
    }
    elseif ($Path -eq "UserDesktop") {
        $sp = ([System.Environment]::GetFolderPath("Desktop")) + "\Network Connections.lnk"
    }
    $AppLocation = "explorer.exe"
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$sp")
    $Shortcut.TargetPath = $AppLocation
    $Shortcut.Arguments = "shell:::{992CFFA0-F557-101A-88EC-00DD010CCC48}"
    $Shortcut.IconLocation = "$env:systemroot\system32\netshell.dll,0"
    $Shortcut.Description = "Network Connection Properties"
    $Shortcut.WorkingDirectory = "C:\Windows\System32"
    $Shortcut.Save()
}


function Set-Preferences {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-18 13:00:47
    Last Edit: 2021-10-12 11:23:19
    Keywords:
    Requires:
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    $config = $Global:WSToolsConfig
    $explorer = $config.Explorer
    $store = $config.StoreLookup
    $hidden = $config.HiddenFiles
    $exten = $config.FileExtensions
    $sctext = $config.ShortcutText

    if ($explorer -eq $true) {
        try {
            Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1 -Force -ErrorAction Stop
        }
        catch {
            New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name Advanced -Force -ErrorAction Stop
            New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -PropertyType DWord -Value 1 -Force -ErrorAction Stop
        }
    }
    else {
        try {
            Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 2 -Force -ErrorAction Stop
        }
        catch {
            New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name Advanced -Force -ErrorAction Stop
            New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -PropertyType DWord -Value 2 -Force -ErrorAction Stop
        }
    }

    if ($store -eq $false) {
        try {
            Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Type DWord -Value 1 -Force -ErrorAction Stop
        }
        catch {
            New-Item -Path HKCU:\Software\Policies\Microsoft\Windows -Name Explorer -Force -ErrorAction SilentlyContinue
            New-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        try {
            Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Type DWord -Value 0 -Force -ErrorAction Stop
        }
        catch {
            New-Item -Path HKCU:\Software\Policies\Microsoft\Windows -Name Explorer -Force -ErrorAction Stop
            New-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -PropertyType DWord -Value 0 -Force -ErrorAction Stop
        }
    }

    if ($hidden -eq $true) {
        try {
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
        }
        catch {
            New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        try {
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -Type DWord -Value 2 -Force -ErrorAction SilentlyContinue
        }
        catch {
            New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -PropertyType DWord -Value 2 -Force -ErrorAction SilentlyContinue
        }
    }

    if ($exten -eq $true) {
        try {
            Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
        }
        catch {
            New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        try {
            Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
        }
        catch {
            New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
        }
    }

    if ($sctext -eq $false) {
        try {
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name Link -Value ([byte[]](00,00,00,00)) -Force -ErrorAction SilentlyContinue
        }
        catch {
            New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name Link -PropertyType Binary -Value ([byte[]](00,00,00,00)) -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        try {
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name Link -Value ([byte[]](17,00,00,00)) -Force -ErrorAction SilentlyContinue
        }
        catch {
            New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name Link -PropertyType Binary -Value ([byte[]](17,00,00,00)) -Force -ErrorAction SilentlyContinue
        }
    }

    try {
        Set-PSReadLineOption -PredictionSource $predictionsource -ErrorAction Stop
    }
    catch {
        Set-PSReadLineOption -PredictionSource History -ErrorAction SilentlyContinue
    }
    Write-Output "Some settings will not apply until after you log off and then log back on."
}


#need to look into using Restart-Computer
function Set-Reboot {
<#
.NOTES
    Author: Skyler Hart
    Created: Sometime before 2017-08-18
    Last Edit: 2021-06-10 21:13:11
    Keywords:
    Requires:
        -RunAsAdministrator for remote computers
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [ValidateLength(4,4)]
        [string]$Time = (($Global:WSToolsConfig).RebootTime),

        [Parameter()]
        [switch]$Abort
    )

    $hr = $Time.Substring(0,2)
    $mm = $Time.Substring(2)
    $d = 0

    #Having the time calculation here will provide a rolling reboot. The more computers you have the longer the reboot period will be.
    #Ex: If you have 200 computers and you specify a 0100 start time, it could last until 0130. It all depends on how long the script takes to run.
    #Move the code below to the specified place if you don't want a rolling reboot.
    $info = Get-Date
    if (($info.Hour) -gt $hr) {
        $d = 1
    }
    elseif (($info.Hour) -eq $hr) {
        if (($info.Minute) -ge $mm) {
            $d = 1
        }
    }

    if ($d -eq 0) {
        $tt1 = ([decimal]::round(((Get-Date).Date.AddHours($hr).AddMinutes($mm) - (Get-Date)).TotalSeconds))
    }
    else {
        $tt1 = ([decimal]::round(((Get-Date).AddDays($d).Date.AddHours($hr).AddMinutes($mm) - (Get-Date)).TotalSeconds))
    }
    #Move the code above to the specified place if you don't want a rolling reboot.

    foreach ($Comp in $ComputerName) {
        if ($Abort) {shutdown -a -m \\$Comp}
        else {
            #Move the code above to here if you don't want a rolling reboot
            try {
                shutdown -r -m \\$Comp -t $tt1
            }
            catch {
                Throw "Could not schedule rebooot on $Comp"
            }
        }#else
    }
}


function Set-RemoteDesktopCert {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-11-18 22:53:02
    Last Edit: 2021-11-18 22:53:02
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Set-RDPCert')]
    param(
        [Parameter(
            HelpMessage = "Enter the thumbprint of the certificate.",
            Mandatory=$true
        )]
        [Alias('Cert')]
        [string]$Thumbprint
    )

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $tsgs = Get-WmiObject -Class Win32_TSGeneralSetting -Namespace root\cimV2\terminalservices -Filter "TerminalName='RDP-tcp'"
        Set-WmiInstance -Path $tsgs.__path -argument @{SSLCertificateSHA1Hash="$Thumbprint"} #DevSkim: ignore DS126858
    }
    else {Write-Error "Must be ran as administrator."}
}


function Set-ServerConfig {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-10-24 20:09:27
    Last Edit: 2020-10-24 20:09:27
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    $sc = $Global:WSToolsConfig

    $netadapter = Get-NetAdapter
    foreach ($na in $netadapter) {
        $ia = $na.Name

        #DHCP
        if ($sc.SCDHCP -eq $true) {
            $na | Set-NetIPInterface -Dhcp Enabled
        }
        else {
            $na | Set-NetIPInterface -Dhcp Disabled
        }

        #IPv6
        if ($sc.SCIPv6 -eq $true) {
            Enable-NetAdapterBinding -InterfaceAlias $ia -ComponentID ms_tcpip6
        }
        else {
            Disable-NetAdapterBinding -InterfaceAlias $ia -ComponentID ms_tcpip6
        }

        #Link-Layer Topology Discovery Responder
        if ($sc.SCllrspndr -eq $true) {
            Enable-NetAdapterBinding -InterfaceAlias $ia -ComponentID ms_rspndr
        }
        else {
            Disable-NetAdapterBinding -InterfaceAlias $ia -ComponentID ms_rspndr
        }

        #Link-Layer Topology Discovery Mapper I/O
        if ($sc.SClltdio -eq $true) {
            Enable-NetAdapterBinding -InterfaceAlias $ia -ComponentID ms_lltdio
        }
        else {
            Disable-NetAdapterBinding -InterfaceAlias $ia -ComponentID ms_lltdio
        }

        #Offloading
        if ($sc.SCOffload -eq $true) {
            Set-NetAdapterAdvancedProperty -Name $ia -DisplayName "*Offloa*" -DisplayValue "Enabled"
        }
        else {
            Set-NetAdapterAdvancedProperty -Name $ia -DisplayName "*Offloa*" -DisplayValue "Disabled"
        }
    }#foreach network adapter

    #NetBIOS
    $NICS = Get-WmiObject Win32_NetworkAdapterConfiguration
    $nb = $sc.SCNetBios
    foreach ($NIC in $NICS) {
        $NIC.settcpipnetbios($nb)
    }

    #RDP
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value ($sc.SCRDP)

    #Server Manager
    if ($sc.SCServerMgr -eq $true) {
        Get-ScheduledTask -TaskName ServerManager | Enable-ScheduledTask
    }
    else {
        Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask
    }

    #WINS
    $wdns = $sc.SCWDNS
    $lmh = $sc.SCLMHost
    $nicClass = Get-WmiObject -list Win32_NetworkAdapterConfiguration
    $nicClass.enablewins($wdns,$lmh)
}


Function Set-ShortcutText {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-18 20:44:39
    Last Edit: 2020-04-18 20:44:39
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Switch]$Yes,
        [Switch]$No
    )

    if ($Yes) {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name Link -Value ([byte[]](00,00,00,00)) -Force}
    elseif ($No) {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name Link -Value ([byte[]](17,00,00,00)) -Force}
    else {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name NoUseStoreOpenWith -Value ([byte[]](00,00,00,00)) -Force}
}


function Set-Shutdown {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-10 21:26:41
    Last Edit: 2021-06-10 21:36:56
    Keywords:
    Requires:
        -RunAsAdministrator for remote computers
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [ValidateLength(4,4)]
        [string]$Time = (($Global:WSToolsConfig).ShutdownTime),

        [Parameter()]
        [switch]$Abort
    )

    $hr = $Time.Substring(0,2)
    $mm = $Time.Substring(2)
    $d = 0

    #Having the time calculation here will provide a rolling shutdown. The more computers you have the longer the shutdown period will be.
    #Ex: If you have 200 computers and you specify a 0100 start time, it could last until 0130. It all depends on how long the script takes to run.
    #Move the code below to the specified place if you don't want a rolling shutdown.
    $info = Get-Date
    if (($info.Hour) -gt $hr) {
        $d = 1
    }
    elseif (($info.Hour) -eq $hr) {
        if (($info.Minute) -ge $mm) {
            $d = 1
        }
    }

    if ($d -eq 0) {
        $tt1 = ([decimal]::round(((Get-Date).Date.AddHours($hr).AddMinutes($mm) - (Get-Date)).TotalSeconds))
    }
    else {
        $tt1 = ([decimal]::round(((Get-Date).AddDays($d).Date.AddHours($hr).AddMinutes($mm) - (Get-Date)).TotalSeconds))
    }
    #Move the code above to the specified place if you don't want a rolling shutdown.

    foreach ($Comp in $ComputerName) {
        if ($Abort) {shutdown -a -m \\$Comp}
        else {
            #
            # Move the code above to here if you don't want a rolling shutdown
            #
            try {
                shutdown -s -m \\$Comp -t $tt1
            }
            catch {
                Throw "Could not schedule shutdown on $Comp"
            }
        }#else
    }
}


Function Set-SpeakerVolume {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 08/18/2017 20:47:06
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Volume')]
    Param (
        [switch]$min,
        [switch]$max,
        [int32]$volume = "10",
        [switch]$mute
    )

    $volume = ($volume/2)
    $wshShell = new-object -com wscript.shell

    If ($min) {1..50 | ForEach-Object {$wshShell.SendKeys([char]174)}}
    ElseIf ($max) {1..50 | ForEach-Object {$wshShell.SendKeys([char]175)}}
    elseif ($mute) {$wshShell.SendKeys([char]173)}#turns sound on or off dependent on what it was before
    elseif ($volume) {1..50 | ForEach-Object {$wshShell.SendKeys([char]174)};1..$Volume | ForEach-Object {$wshShell.SendKeys([char]175)}}
}


Function Set-StoreLookup {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 02/08/2018 21:44:31
    LASTEDIT: 02/08/2018 21:44:31
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
        [Switch]$Yes,
        [Switch]$No
    )

    if ($Yes) {Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Type DWord -Value 0 -Force}
    elseif ($No) {Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Type DWord -Value 1 -Force}
    else {Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Type DWord -Value 1 -Force}
}


function Set-WindowState {
    # source: https://gist.github.com/jakeballard/11240204
    param(
        [Parameter()]
        [ValidateSet('FORCEMINIMIZE','HIDE','MAXIMIZE','MINIMIZE','RESTORE',
                    'SHOW','SHOWDEFAULT','SHOWMAXIMIZED','SHOWMINIMIZED',
                    'SHOWMINNOACTIVE','SHOWNA','SHOWNOACTIVATE','SHOWNORMAL')]
        $Style = 'SHOW',

        [Parameter()]
        $MainWindowHandle = (Get-Process -id $pid).MainWindowHandle
    )
    $WindowStates = @{
        'FORCEMINIMIZE'   = 11
        'HIDE'            = 0
        'MAXIMIZE'        = 3
        'MINIMIZE'        = 6
        'RESTORE'         = 9
        'SHOW'            = 5
        'SHOWDEFAULT'     = 10
        'SHOWMAXIMIZED'   = 3
        'SHOWMINIMIZED'   = 2
        'SHOWMINNOACTIVE' = 7
        'SHOWNA'          = 8
        'SHOWNOACTIVATE'  = 4
        'SHOWNORMAL'      = 1
    }

    $Win32ShowWindowAsync = Add-Type -memberDefinition @"
    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@ -name "Win32ShowWindowAsync" -namespace Win32Functions -passThru

    $Win32ShowWindowAsync::ShowWindowAsync($MainWindowHandle, $WindowStates[$Style]) | Out-Null
    Write-Verbose ("Set Window Style '{1} on '{0}'" -f $MainWindowHandle, $Style)
}


Function Show-BalloonTip {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 08/18/2017 20:47:33
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('tip')]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Text,

        [Parameter(Mandatory=$true)]
        [string]$Title,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Info','Error','Warning')]
        [string]$Icon = 'Info',

        [Parameter(Mandatory=$false)]
        [int32]$Timeout = 30000
    )

    Add-Type -AssemblyName System.Windows.Forms
    If ($null -eq $PopUp)  {$PopUp = New-Object System.Windows.Forms.NotifyIcon}
    $Path = Get-Process -Id $PID | Select-Object -ExpandProperty Path
    $PopUp.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($Path)
    $PopUp.BalloonTipIcon = $Icon
    $PopUp.BalloonTipText = $Text
    $PopUp.BalloonTipTitle = $Title
    $PopUp.Visible = $true
    $PopUp.ShowBalloonTip($Timeout)
}


function Show-FederalHoliday {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-20 17:20:14
    Last Edit: 2023-02-01 21:24:05
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Get-FederalHoliday')]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$Name,

        [Parameter(Mandatory=$false)]
        [int32]$Year,

        [Parameter(Mandatory=$false)]
        [switch]$AllYears
    )

    $holidays = ($Global:WSToolsConfig).Holidays
    $fyear = $holidays.Year | Select-Object -First 1
    $lyear = $holidays.Year | Select-Object -Last 1
    $cyear = (Get-Date).Year

    Write-Verbose "Year is set to: $Year"

    if ([string]::IsNullOrWhiteSpace($Year) -or $Year -eq 0) {
        Write-Verbose "Year is null, empty, or set to 0. Setting year to $cyear"
        $Year = $cyear
    }
    else {
        Write-Verbose "Year is populated."
        if ($Year -ge $fyear -and $Year -le $lyear) {
            #do nothing
        }
        else {
            $obj = "Year $Year is not between $fyear and $lyear."
            Write-Error "Year entered is not valid. See details below for valid years." -TargetObject $obj -ErrorAction Stop
        }
    }

    if ([string]::IsNullOrWhiteSpace($Name)) {
        if ($AllYears) {
            $holidays | Select-Object Name,Year,Date,DayOfWeek | Sort-Object Date
        }
        else {
            $holidays | Where-Object {$_.Year -eq $Year} | Select-Object Name,Date,DayOfWeek | Sort-Object Date
        }
    }#if no name specified
    else {
        foreach ($hol in $Name) {
            if ($AllYears) {
                $holidays | Where-Object {$_.Name -match $hol} | Select-Object Name,Year,Date,DayOfWeek
            }#if all years
            else {
                $holidays | Where-Object {$_.Year -eq $Year -and $_.Name -match $hol} | Select-Object Name,Date,DayOfWeek
            }#if specific year
        }#for each name entered
    }#if a name is specified
}


Function Show-FileExtensions {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 02/08/2018 21:41:37
    LASTEDIT: 02/08/2018 21:41:37
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does."
    )]
    [CmdletBinding()]
    Param (
        [Switch]$Yes,
        [Switch]$No
    )

    if ($Yes) {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Type DWord -Value 0 -Force}
    elseif ($No) {Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Type DWord -Value 1 -Force}
    else {Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Type DWord -Value 0 -Force}
}


Function Show-HiddenFiles {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 02/08/2018 21:40:23
    LASTEDIT: 02/08/2018 21:40:23
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does."
    )]
    [CmdletBinding()]
    Param (
        [Switch]$Yes,
        [Switch]$No
    )

    if ($Yes) {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -Type DWord -Value 1 -Force}
    elseif ($No) {Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -Type DWord -Value 2 -Force}
    else {Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -Type DWord -Value 1 -Force}
}


Function Show-MessageBox {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 08/18/2017 20:47:49
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
#info: https://msdn.microsoft.com/en-us/library/x83z1d9f(v=vs.84).aspx
    [CmdletBinding()]
    [Alias('message')]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Text,

        [Parameter(Mandatory=$true)]
        [string]$Title,

        [Parameter(Mandatory=$false)]
        [int32]$Timeout = 10
    )

    $wshell = New-Object -ComObject Wscript.Shell
    $wshell.Popup($Text,$Timeout,$Title,0x0 + 0x40)

#First option:
#0x0 Show OK button.
#0x1 Show OK and Cancel buttons.
#0x2 Show Abort, Retry, and Ignore buttons.
#0x3 Show Yes, No, and Cancel buttons.
#0x4 Show Yes and No buttons.
#0x5 Show Retry and Cancel buttons.
#0x6 Show Cancel, Try Again, and Continue buttons.

#Second Option
#0x10 Show "Stop Mark" icon.
#0x20 Show "Question Mark" icon.
#0x30 Show "Exclamation Mark" icon.
#0x40 Show "Information Mark" icon.

#Return values
#-1 The user did not click a button before nSecondsToWait seconds elapsed.
#1 OK button
#2 Cancel button
#3 Abort button
#4 Retry button
#5 Ignore button
#6 Yes button
#7 No button
#10 Try Again button
#11 Continue button
}


Function Split-File {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 04/30/2019 13:18:22
    LASTEDIT: 2021-12-17 21:13:05
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter the path of the file you want to split.",
            Mandatory=$true,
            Position=0
        )]
        [Alias('Source','InputLocation','SourceFile')]
        [string]$Path,

        [Parameter(HelpMessage = "Enter the path of where you want the part files placed.",
            Mandatory=$false,
            Position=1
        )]
        [Alias('OutputLocation','Output','DestinationPath','Destination')]
        [string]$DestinationFolder,

        [Parameter(HelpMessage = "Enter the size you want the part files to be. Can be bytes or you can specify a size. Ex: 100MB",
            Mandatory=$false,
            Position=2
        )]
        [Alias('Size','Newsize')]
        [int]$PartFileSize = 10MB
    )

    $FilePath = [IO.Path]::GetDirectoryName($Path)
    if (([string]::IsNullOrWhiteSpace($DestinationFolder)) -and $FilePath -ne "") {$FilePath = $FilePath + "\"}
    elseif ($null -ne $DestinationFolder -and $DestinationFolder -ne "") {
        $FilePath = $DestinationFolder + "\"
    }
    $FileName = [IO.Path]::GetFileNameWithoutExtension($Path)
    $Extension = [IO.Path]::GetExtension($Path)
    $Part = "_Part"

    if (!(Test-Path $FilePath)) {
        New-Item -Path $FilePath -ItemType Directory
    }

    $ReadObj = New-Object System.IO.BinaryReader([System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read))
	[Byte[]]$Buffer = New-Object Byte[] $PartFileSize
	[int]$BytesRead = 0

    $N = 1
    Write-Output "Saving part files to $FilePath"
    while (($BytesRead = $ReadObj.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
        $NewName = "{0}{1}{2}{3,2:00}{4}" -f ($FilePath,$FileName,$Part,$N,$Extension)
        $WriteObj = New-Object System.IO.BinaryWriter([System.IO.File]::Create($NewName))
        $WriteObj.Write($Buffer, 0, $BytesRead)
        $WriteObj.Close()
        $N++
    }
    $ReadObj.Close()
}


function Start-AxwayTrayApp {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Start-AxwayTrayApp
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Start-AxwayTrayApp -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.NOTES
    Author: Skyler Hart
    Created: 2021-06-16 23:27:38
    Last Edit: 2021-06-16 23:27:38
    Keywords:
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    & 'C:\Program Files\Tumbleweed\Desktop Validator\DVTrayApp.exe'
}


function Start-WSToolsGUI {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-10-30 00:55:48
    Last Edit: 2021-10-30 00:55:48
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('wsgui','wstgui','Start-WSToolsTrayApp')]
    param()
    Start-Process powershell.exe -ArgumentList "`$host.ui.RawUI.WindowTitle = 'WSTools Taskbar App'; & '$PSScriptRoot\WSTools_SystemTrayApp.ps1'"
}


function Stop-AppService {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-19 23:06:20
    Last Edit: 2021-10-12 16:00:59
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    $AppNames = ($Global:WSToolsConfig).AppNames
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $services = Get-Service | Where-Object {$_.Status -eq "Running"}
        foreach ($app in $AppNames) {
            $services | Where-Object {$_.DisplayName -match $app -or $_.Name -match $app} | Stop-Service -Force
        }
    }
    else {
        Write-Output "Must run PowerShell as admin to run Stop-AppService."
    }
    Write-Output "Completed stopping application services."
}


function Stop-AxwayTrayApp {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Stop-AxwayTrayApp
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Stop-AxwayTrayApp -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.NOTES
    Author: Skyler Hart
    Created: 2021-06-16 23:28:20
    Last Edit: 2021-06-16 23:28:20
    Keywords:
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    Get-Process | Where-Object {$_.Name -match "dvtray"} | Stop-Process -Force
}


function Stop-Database {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-10-24 19:01:26
    Last Edit: 2023-02-07 22:33:18
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Stop-Oracle','Stop-SQL','Stop-MongoDB')]
    param()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Get-Service -Name * | Where-Object {$_.DisplayName -match "Oracle" -or $_.DisplayName -match "SQL" -or $_.DisplayName -match "MongoDB"} | Stop-Service -Force
    }
    else {
        Write-Output "Must run PowerShell as admin to run Stop-Database."
    }
}


function Stop-Exchange {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-10-24 11:00:45
    Last Edit: 2020-10-24 11:00:45
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Get-Service -Name * | Where-Object {$_.DisplayName -match "Exchange"} | Stop-Service -Force
    }
    else {
        Write-Output "Must run PowerShell as admin to run Stop-Exchange."
    }
}


function Sync-InTune {
<#
.SYNOPSIS
    Will sync device with InTune/MEM.
.DESCRIPTION
    Will initiate the sync process with InTune/Microsoft EndPoint Manager to receive new policies and report information.
.EXAMPLE
    C:\PS>Sync-InTune
    Example of how to use this cmdlet.
.COMPONENT
    WSTools
.FUNCTIONALITY
    InTune, Microsoft Endpoint Manager, MEM
.NOTES
    Author: Skyler Hart
    Created: 2022-09-25 01:38:28
    Last Edit: 2022-09-25 01:38:28
    Other:
    Requires:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Sync-MEM')]
    param()

    try {
        Get-ScheduledTask -TaskName PushLaunch -ErrorAction Stop | Start-ScheduledTask
    }
    catch {
        Write-Warning "Device is not InTune/Microsoft Endpoint Manager (MEM) managed."
    }
}


Function Test-EmailRelay {
    <#
       .Notes
        AUTHOR: Skyler Hart
        CREATED: 08/18/2017 20:40:04
        LASTEDIT: 2021-10-12 22:09:30
        KEYWORDS: E-mail, email, relay, smtp
        REMARKS: On secure networks, port 25 has to be open
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Test-SMTPRelay','Test-MailRelay')]
    Param (
        [Parameter(
            Mandatory=$true,
            Position=0,
            HelpMessage="Enter e-mail address of recipient")]
        [string]$Recipient
    )

    $config = $Global:WSToolsConfig
    $from = $config.Sender
    $smtpserver = $config.SMTPServer
    $port = $config.SMTPPort

    $date = Get-Date
    $subject = "Test from $env:COMPUTERNAME $date"

    send-mailmessage -To $Recipient -From $from -Subject $subject -Body "Testing relay of SMTP messages.`nFrom: $from `nTo: $Recipient `n`nPlease delete this message." -smtpserver $smtpserver -Port $port
}


Function Test-Online {
<#
   .Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:47:56

    TODO: Add functionality to convert ip to computername and vice versa. Enter ip range 192.168.0.0/26
    and have it convert it. Or 192.168.0.0-255 and check all computers. Write help. Add aliases and fix pipeline.

    .LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $i = 0
    $number = $ComputerName.length
    foreach ($comp in $ComputerName){
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Testing whether computers are online or offline. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length
        try {
            $testcon = Test-Connection -ComputerName $comp -Count 3 -ErrorAction Stop
            if ($testcon) {
                $status = "Online"
            }#if test
            else {
                $status = "Offline"
            }#else
        }#try
        catch [System.Net.NetworkInformation.PingException] {
            $status = "Comm error"
        }#catch
        catch [System.Management.Automation.InvocationInfo] {
            $status = "Comm error"
        }
        catch {
            $status = "Comm error"
        }
        [PSCustomObject]@{
            Name = $comp
            Status = $status
        }#newobject
    }#foreach computer
}


Function Test-RegistryValue {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 02/08/2018 22:32:46
    LASTEDIT: 02/08/2018 22:32:46
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
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]$Path,

        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]$Value
    )

    try {
        Get-ItemPropertyValue -Path $Path -Name $Value -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}


function Test-ResponseTime {
<#
.SYNOPSIS
    Finds the response time of a remote computer.
.DESCRIPTION
    Will find average, minimum, and maximum response times (from four pings) of a remote computer, which defaults to the computers logon server if an address is not specified.

.PARAMETER RemoteAddress
    Specifies the name of one or more remote computers.
.PARAMETER ThrottleLimit
    Allows you to specify the most remote computers that will be tested at a time, defaults to 5.
.EXAMPLE
    C:\PS>Test-ResponseTime
    Example of how to use this cmdlet.
.EXAMPLE
    C:\PS>Test-ResponseTime www.wanderingstag.com
    Shows how to test the response time to the website www.wanderingstag.com.
.EXAMPLE
    C:\PS>Test-ResponseTime COMP1,www.wanderingstag.com
    Shows how to test the response time to the computer COMP1 and the website www.wanderingstag.com.
.EXAMPLE
    C:\PS>Test-MTU COMP1,COMP2,COMP3,www.wanderingstag.com -ThrottleLimit 2
    Shows how to test the response times to multiple computers, the test will be performed against two of the computers at a time.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    Response time, ping, network, connectivity, troubleshooting
.NOTES
    Author: Skyler Hart
    Created: 2023-02-01 22:51:01
    Last Edit: 2023-02-01 22:51:01
    Other:
    Requires:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param (
        [Parameter()]
        [Alias('Host','Name','Computer','ComputerName','TestAddress')]
        [string[]] $RemoteAddress,

        [int32] $ThrottleLimit = 5
    )

    if ([string]::IsNullOrWhiteSpace($RemoteAddress)) {
        Write-Verbose "Test Address not specified. Setting to logon server."
        $RemoteAddress = ($env:LOGONSERVER).Replace('\\','') + "." + $env:USERDNSDOMAIN
    }
    Write-Verbose "RemoteAddress: $RemoteAddress"

    Write-Verbose "Testing connections"
    $responses = Test-Connection -ComputerName $RemoteAddress -ThrottleLimit $ThrottleLimit
    Write-Verbose "Responses: $responses"

    $testaddresses = $responses | Select-Object -ExpandProperty Address -Unique

    if (($testaddresses.Count) -le 1) {
        $j = $responses | Where-Object {$_.Address -eq $testaddresses[0]}
        $measuredinfo = $responses.ResponseTime | Measure-Object -Average -Maximum -Minimum
        [PSCustomObject]@{
            ComputerName = ($responses[0].PSComputerName)
            TestAddress = ($responses[0].Address)
            ResponseTime = ($measuredinfo | Select-Object -ExpandProperty Average)
            Minimum = ($measuredinfo | Select-Object -ExpandProperty Minimum)
            Maximum = ($measuredinfo | Select-Object -ExpandProperty Maximum)
        }#new object
    }
    else {
        for ($i = 0; $i -lt $testaddresses.Length; $i++) {
            $j = $responses | Where-Object {$_.Address -eq $testaddresses[$i]}
            $measuredinfo = $j.ResponseTime | Measure-Object -Average -Maximum -Minimum
            [PSCustomObject]@{
                ComputerName = ($j[0].PSComputerName)
                TestAddress = $testaddresses[$i]
                ResponseTime = ($measuredinfo | Select-Object -ExpandProperty Average)
                Minimum = ($measuredinfo | Select-Object -ExpandProperty Minimum)
                Maximum = ($measuredinfo | Select-Object -ExpandProperty Maximum)
            }#new object
        }
    }
}


function Update-BrokenInheritance {
<#
.SYNOPSIS
    Finds and fixes users with broken inheritance.
.DESCRIPTION
    Will search Active Directory for users that do not have permissions inheritance enabled and then fix the inheritance.
.PARAMETER Identity
    Specify a user to fix the inheritance on. Can use sAMAccountName or distinguishedName. If no user is specified it will find all users with broken inheritance.
.PARAMETER SearchBase
    Specify the OU to search using the distinguishedName of the OU. If not specified it searches the whole domain.
.EXAMPLE
    C:\PS>Update-BrokenInheritance -Identity "CN=Joe Snuffy,CN=Users,DC=wstools,DC=dev"
    Will fix the broken inheritance on the user Joe Snuffy.
.EXAMPLE
    C:\PS>Update-BrokenInheritance -SearchBase "CN=Users,DC=wstools,DC=dev"
    Will fix the broken inheritance on all users in the Users OU.
.INPUTS
    System.String
.OUTPUTS
    System.String
.COMPONENT
    WSTools
.FUNCTIONALITY
    Permissions, Inheritance, Active Directory
.NOTES
    Author: Skyler Hart
    Created: Sometime before 2017-08-07
    Last Edit: 2022-09-05 23:40:29
    Other:
    Requires:
        -Module ActiveDirectory
.LINK
    https://wanderingstag.github.io
#>
    Param (
        [Parameter(
            HelpMessage="Enter the distinguishedName of the OU that you want to search",
            Mandatory=$false
        )]
    	[string]$SearchBase = (Get-ADDomain).DistinguishedName,

        [Parameter(
            HelpMessage="Enter User ID (sAMAccountName or distinguishedName)",
            Mandatory=$false
        )]
		[string]$Identity
	)

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        #Start Directory Searcher
        If (!($Identity)) {
	        $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$SearchBase","(&(objectcategory=user)(objectclass=user))")
    	}
        Else {
            Write-Output "Searching for User $($Identity)"
    	    If ($Identity -like "CN=*") {
                $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Identity")
	        }
            Else {
                $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$SearchBase","(&(objectcategory=user)(objectclass=user)(samaccountname=$($Identity)))")
	        }
        }

        #Find All Matching Users
        $Users = $DirectorySearcher.FindAll()

        Foreach ($obj in $users) {
            #Set 'objBefore' to the current object so we can track any changes
            $objBefore = $obj.GetDirectoryEntry()

            #Check to see if user has Inheritance Disabled; $True is inheritance disabled, $False is inheritance enabled
            If ($objBefore.psBase.ObjectSecurity.AreAccessRulesProtected -eq $True) {
                Write-Output "User: $($objBefore.sAMAccountName) Inheritance is disabled: $($objBefore.psBase.ObjectSecurity.AreAccessRulesProtected) ; adminSDHolder: $($objBefore.Properties.AdminCount)"
                $objBeforeACL = $($objBefore.psBase.ObjectSecurity.AreAccessRulesProtected)

                #Fix inheritance
                Write-Output "Updating $($objBefore.sAMAccountName)."
                $objBefore.psbase.ObjectSecurity.SetAccessRuleProtection($false,$true)
                $objBefore.psbase.CommitChanges()

                #Set 'objAfter' so we can see the updated change
                $objAfter = $obj.GetDirectoryEntry()
                $objAfterACL = $($objAfter.psBase.ObjectSecurity.AreAccessRulesProtected)
            }
            Else {
                #User has inheritance enabled, so do nothing
            }
        }
    }#if ad module exists
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}


function Update-HelpFromFile {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-12-17 22:54:13
    Last Edit: 2021-12-17 22:54:13
    Keywords:
    Other:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter()]
        [Alias('Path','Folder','Source')]
        [string]$SourcePath
    )

    if ([string]::IsNullOrWhiteSpace($Source)) {
        $SourcePath = ($Global:WSToolsConfig).HelpFolder
    }
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {Update-Help -SourcePath $SourcePath -Module * -Force}
    else {Write-Error "Must be ran as administrator."}
}


function Update-ModulesFromLocalRepo {
<#
.NOTES
    Author: Skyler Hart
    Created: 2022-06-29 21:51:12
    Last Edit: 2022-06-29 21:51:12
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )
    Begin {
        $config = $Global:WSToolsConfig
        $repo = $config.LocalPSRepo

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
                [string]$repo
            )
            $rmodules = Get-ChildItem $repo | Where-Object {$_.Attributes -eq "Directory"} | Select-Object Name,FullName
            if ($comp -eq $env:COMPUTERNAME) {
                $lmodules = Get-ChildItem $env:ProgramFiles\WindowsPowerShell\Modules | Where-Object {$_.Attributes -eq "Directory"} | Select-Object Name,FullName
            }#if local
            else {
                $lmodules = Get-ChildItem "\\$comp\c$\Program Files\WindowsPowerShell\Modules" | Where-Object {$_.Attributes -eq "Directory"} | Select-Object Name,FullName
            }#if remote

            foreach ($mod in $lmodules) {
                $modname = $mod.Name
                $modpath = $mod.FullName

                $rpath = $rmodules | Where-Object {$_.Name -eq $modname} | Select-Object -ExpandProperty FullName

                if ([string]::IsNullOrWhiteSpace($rpath)) {
                    #do nothing
                }
                else {
                    Write-Output "$(Get-Date) - ${comp}: Updating $modname"
                    robocopy $rpath $modpath /mir /mt:4 /njh /njs /r:3 /w:10 | Out-Null
                }
            }
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Copying PowerShell modules" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($repo.ToString()) | out-null
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


function Update-VisioStencils {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-05-18 20:56:13
    Last Edit: 2021-10-13 20:33:20
    Keywords: Visio, Stencils
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does."
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Copy-VisioStencils','Get-VisioStencils')]
    param()

    $vspath = ($Global:WSToolsConfig).Stencils
    $rpath = [System.Environment]::GetFolderPath("MyDocuments") + "\My Shapes"

    if (Test-Path $rpath) {
        $confirmation = Read-Host "Are you sure you want to overwrite the files in $rpath with files in $vspath`? `nPress y for yes and then press enter. To cancel enter any other value then press enter."
        if ($confirmation -eq 'y') {
            robocopy $vspath $rpath /mir /mt:4 /r:3 /w:15 /njh /njs
        }
    }
    else {
        robocopy $vspath $rpath /mir /mt:4 /r:3 /w:15 /njh /njs
    }
}


#####################################
#                                   #
#             WSTools               #
#                                   #
#####################################
Function Get-WSToolsAlias {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 01/31/2018 23:42:55
    LASTEDIT: 01/31/2018 23:42:55
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('WSToolsAliases')]
    param()
    Get-Alias | Where-Object {$_.Source -eq "WSTools"}
}


Function Get-WSToolsCommand {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 01/31/2018 23:52:54
    LASTEDIT: 01/31/2018 23:52:54
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('WSToolsCommands')]
    param()
    $commands = (Get-Module WSTools | Select-Object ExportedCommands).ExportedCommands
    $commands.Values | Select-Object CommandType,Name,Source
}


function Get-WSToolsConfig {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-05-23 12:27:36
    Last Edit: 2020-08-20 11:18:58
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Import-WSToolsConfig','WSToolsConfig')]
    param()
    $Global:WSToolsConfig
}


Function Get-WSToolsVersion {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/09/2018 00:23:25
    LASTEDIT: 02/14/2018 11:05:37
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('WSToolsVersion')]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Remote,

        [Parameter(Mandatory=$false)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName
    )

    if ($Remote) {
        foreach ($comp in $ComputerName) {
            $path = "\\$comp\c$\Program Files\WindowsPowerShell\Modules\WSTools\WSTools.psd1"
            try {
                $info = Test-ModuleManifest $path
                $ver = $info.Version
            }
            catch {
                $ver = "NA"
            }

            try {
                $info2 = Get-Item $path
                $i2 = $info2.LastWriteTime
            }
            catch {
                $i2 = "NA"
            }

            $version = [PSCustomObject]@{
                ComputerName = $comp
                WSToolsVersion = $ver
                Date = $i2
                Path = $path
            }#new object
            $version | Select-Object ComputerName,WSToolsVersion,Date,Path
        }
    }
    else {
        $path = "$PSScriptRoot\WSTools.psd1"
        try {
            $info = Test-ModuleManifest $path
            $ver = $info.Version
        }
        catch {
            $ver = "NA"
        }

        try {
            $info2 = Get-Item $path
            $i2 = $info2.LastWriteTime
        }
        catch {
            $i2 = "NA"
        }
        $cn = $env:COMPUTERNAME

        $version = [PSCustomObject]@{
            ComputerName = $cn
            WSToolsVersion = $ver
            Date = $i2
            Path = $path
        }#new object
        $version | Select-Object ComputerName,WSToolsVersion,Date,Path
    }
}


Function Install-WSTools {
<#
.SYNOPSIS
    Installs/copies the WSTools PowerShell module to a remote computer.
.DESCRIPTION
    Copies the WSTools module from the location specified in the WSTools config file (config.ps1) for UpdatePath to the C:\Program Files\WindowsPowerShell\Modules\WSTools folder on the remote computer.
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.EXAMPLE
    C:\PS>Install-WSTools COMPNAME
    How to install the WSTools PowerShell module on the remote computer COMPNAME.
.EXAMPLE
    C:\PS>Install-WSTools -ComputerName COMPNAME1,COMPNAME2
    How to install the WSTools PowerShell module on the remote computers COMPNAME1 and COMPNAME2.
.NOTES
    Author: Skyler Hart
    Created: 2018-06-13 14:17:09
    Last Edit: 2022-02-19 22:56:29
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "WSTools is the proper name for the module."
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Copy-WSTools','Push-WSTools')]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','common name')]
        [string[]] $ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )
    Begin {
        $config = $Global:WSToolsConfig
        $app = $config.UpdatePath
        $appname = "WSTools"

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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname
            )
            try {
                robocopy $app "\\$comp\c$\Program Files\WindowsPowerShell\Modules\$appname" /mir /mt:4 /r:3 /w:15 /njh /njs
            }
            catch {
                #
            }
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
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
                -Activity "Copying $appname module to computers. Waiting for Jobs - $($MaxThreads - $($RunspacePool.GetAvailableRunspaces())) of $MaxThreads threads running" `
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


function Set-WSToolsConfig {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-17 15:00:06
    Last Edit: 2020-04-17 15:00:06
.LINK
    https://wanderingstag.github.io
#>
    PowerShell_Ise "$PSScriptRoot\config.ps1"
}


Function Update-WSTools {
<#
   .Synopsis
    This updates the WSTools module
   .Description
    Updates the WSTools module in various locations
   .Example
    Update-WSTools
    Will update the WSTools module
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 14:48:46
    LASTEDIT: 10/17/2019 23:14:22
    KEYWORDS: PowerShell, module, WSTools, personal
    REMARKS:
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "WSTools is the proper name for the module."
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    $config = $Global:WSToolsConfig
    $UPath = $config.UpdatePath
    $UComp = $config.UpdateComp
    $APaths = $config.AdditionalUpdatePaths

    if ($null -ne $UComp -and $env:COMPUTERNAME -eq $UComp) {
        Robocopy.exe $env:ProgramFiles\WindowsPowerShell\Modules\WSTools $UPath /mir /mt:4 /r:3 /w:5 /njh /njs
        if ($null -ne $APaths -or $APaths -eq "") {
            ForEach ($apath in $APaths) {
                Write-Output "Updating $apath"
                Robocopy.exe $env:ProgramFiles\WindowsPowerShell\Modules\WSTools $apath /mir /mt:4 /r:3 /w:5 /njh /njs
            }
        }
    }
    else {
        robocopy $UPath $env:ProgramFiles\WindowsPowerShell\Modules\WSTools /mir /mt:4 /njs /njh /r:3 /w:15
    }
}


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
        CREATED: 2014-01-18 11:50:00
        LASTEDIT: 2022-09-01 21:59:13
        KEYWORDS: Groups, empty groups, group management
        REQUIRES:
            ActiveDirectory

    .LINK
        https://wanderingstag.github.io
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
        CREATED: 2014-01-18 02:50:00
        LASTEDIT: 2022-09-01 22:30:56
        KEYWORDS: Hidden Users, User, Exchange, GAL, Global Address List
        REQUIRES:
            ActiveDirectory

    .LINK
        https://wanderingstag.github.io
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
}


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
        CREATED: 2014-01-19 01:45:00
        LASTEDIT: 08/15/2018 22:47:26
        KEYWORDS: SID

    .LINK
        https://wanderingstag.github.io
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
}


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
        https://wanderingstag.github.io
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
        https://wanderingstag.github.io
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
        https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
        https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    elseif ($Edge) {Start-Process Microsoft-Edge:$URL}
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    elseif ($Edge) {Start-Process Microsoft-Edge:$URL}
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    elseif ($Edge) {Start-Process Microsoft-Edge:$URL}
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    elseif ($Edge) {Start-Process Microsoft-Edge:$URL}
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
        elseif ($Edge) {Start-Process Microsoft-Edge:$dpath}
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
    https://wanderingstag.github.io
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
    elseif ($Edge) {Start-Process Microsoft-Edge:$URL}
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
    https://wanderingstag.github.io
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
    elseif ($Edge) {Start-Process Microsoft-Edge:$URL}
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
    https://wanderingstag.github.io
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
        elseif ($Edge) {Start-Process Microsoft-Edge:$dpath}
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
    https://wanderingstag.github.io
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
    elseif ($Edge) {Start-Process Microsoft-Edge:$URL}
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
    https://wanderingstag.github.io
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
    elseif ($Edge) {Start-Process Microsoft-Edge:$URL}
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    elseif ($Edge) {Start-Process Microsoft-Edge:$URL}
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
    https://wanderingstag.github.io
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
    elseif ($Edge) {Start-Process Microsoft-Edge:$URL}
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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
    https://wanderingstag.github.io
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


function Test-MTU {
<#
.SYNOPSIS
    Finds the MTU size for packets to a remote computer.
.DESCRIPTION
    Will find the point where packets don't fragment (MTU) to a remote source, which defaults to the computers logon server if an address isn't specified.
.PARAMETER RemoteAddress
    Specifies the name or IP of one or more remote computers.
.PARAMETER BufferSizeMax
    Allows you to specify the highest MTU to test.
.EXAMPLE
    C:\PS>Test-MTU
    Example of how to use this cmdlet.
.EXAMPLE
    C:\PS>Test-MTU www.wanderingstag.com
    Shows how to test the MTU to the website www.wanderingstag.com.
.EXAMPLE
    C:\PS>Test-MTU COMP1,www.wanderingstag.com
    Shows how to test the MTU to the computer COMP1 and the website www.wanderingstag.com.
.EXAMPLE
    C:\PS>Test-MTU COMP1 1272
    Shows how to test the MTU to the computer COMP1, the max buffer size (MTU) will start at 1272.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    Maximum Transmission Unit, MTU, network, connectivity, troubleshooting
.NOTES
    Author: Skyler Hart
    Created: 2022-11-22 21:27:58
    Last Edit: 2022-11-22 23:06:11
    Other:
    Requires:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [Alias('Host', 'Name', 'Computer', 'ComputerName', 'TestAddress')]
        [string[]]$RemoteAddress,

        #Set BufferSizeMax to the largest MTU you want to test (1500 normally or up to 9000 if using Jumbo Frames)
        [Parameter(Mandatory=$false)]
        [int]$BufferSizeMax = 1500
    )

    if ([string]::IsNullOrWhiteSpace($RemoteAddress)) {
        Write-Verbose "Test Address not specified. Setting to logon server."
        $RemoteAddress = ($env:LOGONSERVER).Replace('\\','') + "." + $env:USERDNSDOMAIN
    }
    Write-Verbose "RemoteAddress: $TestAddress"
    Write-Verbose "BufferSizeMax: $BufferSizeMax"

    foreach ($TestAddress in $RemoteAddress) {
        $LastMinBuffer=$BufferSizeMin
        $LastMaxBuffer=$BufferSizeMax
        $MaxFound=$false
        $GoodMTU = @()
        $BadMTU = @()

        #Calculate first MTU test, halfway between zero and BufferSizeMax
        [int]$BufferSize = ($BufferSizeMax - 0) / 2
        while ($MaxFound -eq $false){
            try{
                $Response = ping $TestAddress -n 1 -f -l $BufferSize
                #if MTU is too big, ping will return: Packet needs to be fragmented but DF set.
                if ($Response -like "*fragmented*") {throw}
                if ($LastMinBuffer -eq $BufferSize) {
                    #test values have converged onto the highest working MTU, stop here and report value
                    $MaxFound = $true
                    break
                }
                else {
                    #it worked at this size, make buffer bigger
                    Write-Verbose "Found good MTU: $BufferSize"
                    $GoodMTU += $BufferSize
                    $LastMinBuffer = $BufferSize
                    $BufferSize = $BufferSize + (($LastMaxBuffer - $LastMinBuffer) / 2)
                }
            }
            catch {
                #it didn't work at this size, make buffer smaller
                Write-Verbose "Found bad MTU: $BufferSize"
                $BadMTU += $BufferSize
                $LastMaxBuffer = $BufferSize
                #if we're getting close, just subtract 1
                if(($LastMaxBuffer - $LastMinBuffer) -le 3){
                    $BufferSize = $BufferSize - 1
                } else {
                    $BufferSize = $LastMinBuffer + (($LastMaxBuffer - $LastMinBuffer) / 2)
                }
            }
        }

        Write-Verbose "Good MTUs: $GoodMTU"
        Write-Verbose "Bad MTUs: $BadMTU"
        Write-Verbose "Recommended MTU: $BufferSize"

        if ($BufferSize -le 1472) {
            $BufferSize = $BufferSize+28
        }

        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            GoodMTUs = $GoodMTU -join ","
            BadMTUs = $BadMTU -join ","
            MTUwithBuffer = $BufferSize
            TestAddress = $TestAddress
        }#new object
    }
}


function Test-NetworkSpeed {
<#
.SYNOPSIS
    Test network file transfer speeds, upload and download.
.DESCRIPTION
    Will test the file transfer speed of a generated file and provide you with the speed in Mbps (Megabit) and MBps (Megabyte) for uploads and downloads to a SMB file share.
.PARAMETER FileSize
    Specifies the file size of the file to be generated and transferred. Enter in the format xxKB, xxMB, or xxGB.
.PARAMETER LocalPath
    Specifies the path to the local folder where a file will be generated and where a file will be copied to.
.PARAMETER RemotePath
    Specifies the path to the remote folder where a file will be generated and where a file will be copied to.
.EXAMPLE
    C:\PS>Test-NetworkSpeed
    Example of how to use this cmdlet using the configured values in the WSTools config.ps1 file.
.EXAMPLE
    C:\PS>Test-NetworkSpeed -FileSize 500KB
    Another example of how to use this cmdlet but with the FileSize parameter. This example will generate 500 Kilobyte files to transfer.
.EXAMPLE
    C:\PS>Test-NetworkSpeed -FileSize 100MB
    Another example of how to use this cmdlet but with the FileSize parameter. This example will generate 100 Megabyte files to transfer.
.EXAMPLE
    C:\PS>Test-NetworkSpeed -FileSize 1GB
    Another example of how to use this cmdlet but with the FileSize parameter. This example will generate 1 Gigabyte files to transfer.
.EXAMPLE
    C:\PS>Test-NetworkSpeed -LocalPath C:\Transfer
    Another example of how to use this cmdlet but with the local path parameter.
.EXAMPLE
    C:\PS>Test-NetworkSpeed -LocalPath D:\Temp -RemotePath \\server1.wstools.dev\Transfer
    Another example of how to use this cmdlet but with the local and remote path parameters.
.INPUTS
    System.String, System.Int64
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    Network, troubleshooting, speedtest, test
.NOTES
    Author: Skyler Hart
    Created: 2022-06-24 18:21:40
    Last Edit: 2022-06-24 18:21:40
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [string]$LocalPath,

        [Parameter(
            Mandatory=$false
        )]
        [string]$RemotePath,

        [Parameter(
            Mandatory=$false
        )]
        [int64]$FileSize
    )

    Begin {
        Write-Verbose "$(Get-Date): Start Network Speed Test"
        $config = $Global:WSToolsConfig
        $filename = (Get-Date -Format yyyyMMddHHmmssms) + "_testfile"

        if ([string]::IsNullOrWhiteSpace($FileSize)) {
            $FileSize = $config.NSFileSize
        }
        Write-Verbose "$(Get-Date): File size is: $FileSize"

        if ([string]::IsNullOrWhiteSpace($LocalPath)) {
            $LocalPath = $config.NSLocal
            $LocalFile = $LocalPath + "\" + $filename + "_upload.dat"
        }
        else {
            $LocalFile = $LocalPath + "\" + $filename + "_upload.dat"
        }
        Write-Verbose "$(Get-Date): LocalPath is: $LocalPath"
        Write-Verbose "$(Get-Date): LocalFile is: $LocalFile"

        if ([string]::IsNullOrWhiteSpace($RemotePath)) {
            $RemotePath = $config.NSRemote
            $RemoteFile = $RemotePath + "\" + $filename + "_download.dat"
        }
        else {
            $RemoteFile = $RemotePath + "\" + $filename + "_download.dat"
        }

        $LocalDownFile = $LocalPath + "\" + $filename + "_download.dat"
        $RemoteUpFile = $RemotePath + "\" + $filename + "_upload.dat"

        Write-Verbose "$(Get-Date): RemotePath is: $RemotePath"
        Write-Verbose "$(Get-Date): RemoteFile is: $RemoteFile"

        try {
            Write-Verbose "$(Get-Date): Create local file"
            $writelocalfile = new-object System.IO.FileStream $LocalFile, Create, ReadWrite
            $writelocalfile.SetLength($FileSize)
            $writelocalfile.Close()

            $UpSize = Get-Item $LocalFile | Measure-Object -Property Length -Sum | Select-Object -ExpandProperty Sum
        }
        catch {
            Write-Warning "Unable to create local file at $LocalFile"
            Write-Warning "Error: $($Error[0])"
            break
        }

        try {
            Write-Verbose "$(Get-Date): Create remote file"
            $writeremotefile = new-object System.IO.FileStream $RemoteFile, Create, ReadWrite
            $writeremotefile.SetLength($FileSize)
            $writeremotefile.Close()

            $DownSize = Get-Item $RemoteFile | Measure-Object -Property Length -Sum | Select-Object -ExpandProperty Sum
        }
        catch {
            Write-Warning "Unable to create remote file at $RemoteFile"
            Write-Warning "Error: $($Error[0])"
            break
        }
    }
    Process {
        Write-Verbose "$(Get-Date): Beginning Upload Test"
        try {
            $UploadTest = Measure-Command {
                Copy-Item $LocalFile $RemotePath -ErrorAction Stop
            }
            $UStatus = "Complete"
        }
        catch {
            Write-Warning "Error during upload test: $($Error[0])"
            $UStatus = "Error"
            $UpMbps = 0
            $UploadTest = New-TimeSpan -Days 0
        }
        $UploadSeconds = $UploadTest.TotalSeconds
        Write-Verbose "$(Get-Date): File upload took: $UploadSeconds"

        Write-Verbose "$(Get-Date): Beginning Download Test"
        try {
            $DownloadTest = Measure-Command {
                Copy-Item $RemoteFile $LocalPath -ErrorAction Stop
            }
            $DStatus = "Complete"
        }
        catch {
            Write-Warning "Error during download test: $($Error[0])"
            $DStatus = "Error"
            $DownMbps = 0
            $DownloadTest = New-TimeSpan -Days 0
        }
        $DownloadSeconds = $DownloadTest.TotalSeconds
        Write-Verbose "$(Get-Date): File upload took: $DownloadSeconds"

        Write-Verbose "$(Get-Date): Removing generated files."
        Remove-Item $LocalFile -Force -ErrorAction SilentlyContinue
        Remove-Item $RemoteFile -Force -ErrorAction SilentlyContinue
        Remove-Item $LocalDownFile -Force -ErrorAction SilentlyContinue
        Remove-Item $RemoteUpFile -Force -ErrorAction SilentlyContinue

        Write-Verbose "$(Get-Date): Calculating speeds"
        $UpMbps = [Math]::Round((($UpSize * 8) / $UploadSeconds) / 1048576,2)
        $UpMB = [Math]::Round((($UpSize) / $UploadSeconds) / 1024 / 1024,2)
        $DownMbps = [Math]::Round((($DownSize * 8) / $DownloadSeconds) / 1048576,2)
        $DownMB = [Math]::Round((($DownSize) / $DownloadSeconds) / 1024 / 1024,2)

        Write-Verbose "$(Get-Date): Generating results"
        [PSCustomObject]@{
            FileSizeMB = ([Math]::Round($UpSize/1024/1024,2))
            DownloadStatus = $DStatus
            DownloadSeconds = $DownloadSeconds
            DownMbps = $DownMbps
            DownMBperSecond = $DownMB
            UploadStatus = $UStatus
            UploadSeconds = $UploadSeconds
            UpMbps = $UpMbps
            UpMBperSecond = $UpMB
        }#new object
    }
}


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
}



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
}

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
}


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


Function Add-DateTime {
<#
   .Synopsis
    This function adds the date and time at current insertion point.
   .Example
    Add-DateTime
    Adds date and time at current insertion point in a PowerShell ISE window.
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 19:51:23
    LASTEDIT: 10/26/2017 09:48:00
    KEYWORDS: Scripting Techniques, Windows PowerShell ISE
.LINK
    https://wanderingstag.github.io
#Requires -Version 2.0
#>
    $timeText = @"
$(Get-Date)
"@
    $psise.CurrentFile.Editor.InsertText($timeText)
}


Function Add-DomainCheck {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 06/13/2018 14:42:45
    LASTEDIT: 10/04/2018 21:16:04
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>

    $domainText = @"
    if (`$env:USERDNSDOMAIN -match "skynet") {

    }#if skynet

    elseif (`$env:USERDNSDOMAIN -match "area") {

    }#if area

    elseif (`$env:USERDNSDOMAIN -like "*.ogn.*") {

    }#if tic

    elseif (`$env:USERDNSDOMAIN -eq "lab.local") {

    }#if virtual lab

    elseif (`$env:USERDNSDOMAIN -match ".smil.") {

    }#secure
"@
    $psise.CurrentFile.Editor.InsertText($domainText)
}


Function Add-Function {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/18/2017 13:58:17
    LASTEDIT: 12/20/2019 22:18:43
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
        [Parameter(Mandatory=$false)]
        [Switch]$Browsers,

        [Parameter(Mandatory=$false)]
        [Switch]$Object,

        [Parameter(Mandatory=$false)]
        [Switch]$User
    )

if ($Browsers) {
    $browserHelp = @"

   .Parameter Chrome
    Opens the website in Google Chrome
   .Parameter Edge
    Opens the website in Microsoft Edge
   .Parameter Firefox
    Opens the website in Mozilla Firefox
   .Parameter InternetExplorer
    Opens the website in Microsoft Internet Explorer
"@
    $browserText1 = @"
,

        [Parameter(Mandatory=`$false)]
        [Switch]`$Chrome,

        [Parameter(Mandatory=`$false)]
        [Switch]`$Edge,

        [Parameter(Mandatory=`$false)]
        [Switch]`$Firefox,

        [Parameter(Mandatory=`$false)]
        [Switch]`$InternetExplorer
"@

    $browserText2 = @"
    `$URL = "https://......."
    if (`$Chrome) {Start-Process "chrome.exe" `$URL}
    elseif (`$Edge) {Start-Process Microsoft-Edge:`$URL}
    elseif (`$Firefox) {Start-Process "firefox.exe" `$URL}
    elseif (`$InternetExplorer) {Start-Process "iexplore.exe" `$URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open(`$URL)
    }
"@
}
else {
    $browserText1 = ""
    $browserText2 = ""
}

if ($Object) {
    $objectText = @"
    [PSCustomObject]@{
        ComputerName = `$comp
    }#new object
"@
}
else {$objectText = ""}

if ($User) {
    $userHelp = @"

   .Parameter Username
    Specifies the user or users
"@
    $userText1 = @"
,

        [Parameter(Mandatory=`$false, Position=1, ValueFromPipeline=`$true, ValueFromPipelineByPropertyName=`$true)]
        [Alias('User','SamAccountname')]
        [ValidateNotNullOrEmpty()]
        [string[]]`$Username = "`$env:USERNAME"
"@
    $userText2 = @"

    foreach (`$user in `$UserName) {

    }
"@
}
else {
    $userHelp = ""
    $userText1 = ""
    $userText2 = ""
}


    $functionText = @"
Function {
<#
   .Synopsis
    This does that
   .Description
    This does that
   .Example
    Example-
    Example- accomplishes
   .Parameter ComputerName
    Specifies the computer or computers$userHelp$browserHelp
   .Notes
    AUTHOR:
    CREATED: $(Get-Date)
    LASTEDIT: $(Get-Date)
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
   .Link
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=`$false,
            Position=0,
            ValueFromPipeline = `$true,
            ValueFromPipelineByPropertyName = `$true
        )]
        [ValidateSet('Info','Error','Warning')]
        [ValidateNotNullOrEmpty()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]`$ComputerName = "`$env:COMPUTERNAME"$userText1$browserText1
    )

    foreach (`$comp in `$ComputerName) {

    }
$userText2
$browserText2
$objectText
}
"@

    $psise.CurrentFile.Editor.InsertText($functionText)
}


Function Add-Help {
<#
   .Synopsis
    This function adds help at current insertion point.
   .Example
    Add-Help
    Adds comment based help at current insertion point in a PowerShell ISE window.
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 09/07/2010 17:32:34
    LASTEDIT: 10/04/2018 20:26:05
    KEYWORDS: Scripting Techniques, Windows PowerShell ISE, Help
    REQUIRES:
        #Requires -Version 2.0
.LINK
    https://wanderingstag.github.io
#>
    $helpText = @"
<#
   .Synopsis
    This does that
   .Description
    This does that
   .Example
    Example-
    Example- accomplishes
   .Parameter PARAMETER
    The parameter does this
   .Notes
    AUTHOR:
    CREATED: $(Get-Date)
    LASTEDIT: $(Get-Date)
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
   .Link
    https://wanderingstag.github.io
#>
"@
    $psise.CurrentFile.Editor.InsertText($helpText)
}


Function Add-InternetBrowsersBlock {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/18/2017 12:58:28
    LASTEDIT: 10/18/2017 12:58:28
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    $browserblockText = @"
    if (`$Chrome) {Start-Process "chrome.exe" `$URL}
    elseif (`$Edge) {Start-Process Microsoft-Edge:`$URL}
    elseif (`$Firefox) {Start-Process "firefox.exe" `$URL}
    elseif (`$InternetExplorer) {Start-Process "iexplore.exe" `$URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open(`$URL)
    }
"@
    $psise.CurrentFile.Editor.InsertText($browserblockText)
}


Function Add-ParamBlock {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/27/2017 15:14:53
    LASTEDIT: 12/20/2019 22:15:51
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    $paramblockText = @"
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=`$false,
            Position=0,
            ValueFromPipeline = `$true,
            ValueFromPipelineByPropertyName = `$true
        )]
        [ValidateSet('Info','Error','Warning')]
        [ValidateNotNullOrEmpty()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]`$ComputerName = "`$env:COMPUTERNAME",

        [Parameter()]
        [Switch]`$Switch
    )
"@
    $psise.CurrentFile.Editor.InsertText($paramblockText)
}


Function Add-ParamInternetBrowser {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/18/2017 12:55:22
    LASTEDIT: 10/18/2017 14:37:37
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    $paramIBText = @"
        [Parameter(Mandatory=`$false)]
        [Switch]`$Chrome,

        [Parameter(Mandatory=`$false)]
        [Switch]`$Edge,

        [Parameter(Mandatory=`$false)]
        [Switch]`$Firefox,

        [Parameter(Mandatory=`$false)]
        [Switch]`$InternetExplorer
"@
    $psise.CurrentFile.Editor.InsertText($paramIBText)
}


Function Add-ParamSwitchWithOption {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/23/2017 17:20:36
    LASTEDIT: 12/20/2019 22:14:54
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>

    $switchText = @"
,

        [Parameter(Mandatory=`$false)]
        [ValidateSet('Info','Error','Warning')]
        [ValidateNotNullOrEmpty()]
        [Alias('Host','Name','Computer','CN')]
        [string]`$Icon = 'Info'
"@
    $psise.CurrentFile.Editor.InsertText($switchText)
}


Function Add-ProgressBar {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 10:53:40
    LASTEDIT: 04/23/2018 10:53:40
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    $objectText = @"
`$i = 0
`$number = `$ComputerName.length

#Progress Bar
if (`$number -gt "1") {
    `$i++
    `$amount = (`$i / `$number)
    `$perc1 = `$amount.ToString("P")
    `Write-Progress -activity "Currently doing..." -status "Computer `$i of `$number. Percent complete:  `$perc1" -PercentComplete ((`$i / `$ComputerName.length)  * 100)
}#if length
"@
    $psise.CurrentFile.Editor.InsertText($objectText)
}


Function Add-PSObject {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/27/2017 17:13:32
    LASTEDIT: 12/21/2019 23:35:03
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Switch]$CustomObject
    )

    if ($CustomObject) {
        $objectText = @"
`$object = [ordered]@{
    'Property1'        = `$null
    'LongPropertyEx'   = `$null
}#pscustom object
[pscustomobject]`$object
#or
[pscustomobject]@{Property1=`$null;LongPropertyEx=`$null}
"@
    }#if custom object
    else {
        $objectText = @"
[PSCustomObject]@{
    ComputerName = `$comp
}#new object
"@
    }#else
    $psise.CurrentFile.Editor.InsertText($objectText)
}


Function Add-Switch {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 07/31/2019 22:17:04
    LASTEDIT: 07/31/2019 22:17:04
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    $objectText = @"
switch (`$variable) {
    value {`$variable2 = "something"}

    {'value1','value2' -contains `$_} {`$variable2 = "something"}

    {`$anothervariable -match `$variable} {`$variable2 = "something"}
}
"@
    $psise.CurrentFile.Editor.InsertText($objectText)
}


function Convert-AppIconToBase64 {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Convert-AppIconToBase64
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Convert-AppIconToBase64 -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.NOTES
    Author: Skyler Hart
    Created: 2020-11-10 18:57:12
    Last Edit: 2020-11-10 18:57:12
    Keywords:
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the path of the file to extract the icon from. Ex: C:\Temp\app.exe",
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.IO
    $Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($Path)
    $stream = New-Object System.IO.MemoryStream
    $Icon.Save($stream)
    $Bytes = $stream.ToArray()
    $stream.Flush()
    $stream.Dispose()
    $b64 = [convert]::ToBase64String($Bytes)
    $b64
}


function Convert-DatesToDays {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-03 08:54:49
    Last Edit: 2021-06-03 09:23:27
    Keywords: date, converter
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [ValidateLength(8,10)]
        [Alias('Day1')]
        [string]$Date1 = (Get-Date -Format "yyyy-MM-dd"),

        [Parameter(
            Mandatory=$false,
            Position=1
        )]
        [ValidateLength(8,10)]
        [Alias('Day2')]
        [string]$Date2 = (Get-Date -Format "yyyy-MM-dd")
    )

    $c1 = $Date1.Length
    if ($c1 -eq 8) {
        $y = $Date1.Substring(0,4)
        $m = $Date1.Substring(4)
        $m = $m.Substring(0,2)
        $d = $Date1.Substring(6)
        $start = (Get-Date -Year $y -Month $m -Day $d)
    }
    elseif ($c1 -eq 10) {
        $y = $Date1.Substring(0,4)
        $m = $Date1.Substring(5)
        $m = $m.Substring(0,2)
        $d = $Date1.Substring(8)
        $start = (Get-Date -Year $y -Month $m -Day $d)
    }

    $c2 = $Date2.Length
    if ($c2 -eq 8) {
        $y = $Date2.Substring(0,4)
        $m = $Date2.Substring(4)
        $m = $m.Substring(0,2)
        $d = $Date2.Substring(6)
        $end = (Get-Date -Year $y -Month $m -Day $d)
    }
    elseif ($c2 -eq 10) {
        $y = $Date2.Substring(0,4)
        $m = $Date2.Substring(5)
        $m = $m.Substring(0,2)
        $d = $Date2.Substring(8)
        $end = (Get-Date -Year $y -Month $m -Day $d)
    }

    $ts = New-TimeSpan -Start $start -End $end
    $ts.Days
}


function Convert-DaysToWorkDay {
<#
.EXAMPLE
    C:\PS>Convert-DaysToWorkDay 1
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Convert-DaysToWorkDay -1
    Another example of how to use this cmdlet.
.NOTES
    Author: Skyler Hart
    Created: 2021-03-04 18:54:31
    Last Edit: 2021-06-20 17:13:33
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the amount of days you want to convert. Must an a positive or negative integer (Ex: 1 or -1).",
            Mandatory=$true,
            Position=0
        )]
        [int32]$Days,

        [Parameter(
            HelpMessage = "Must be in the format yyyy-MM-dd.",
            Mandatory=$false,
            Position=1
        )]
        [datetime]$StartDay = (Get-Date).Date
    )

    $holidays = ($Global:WSToolsConfig).Holidays.Date

    if ($Days -lt 0) {
        $sub = "sub"
    }
    elseif ($Days -gt 0) {
        $sub = "add"
    }
    else {$sub = "zero"}

    if ($sub -eq "sub") {
        $i = -1
        do {
            $StartDay = $StartDay.AddDays(-1)

            if ($holidays -contains $StartDay) {
                $StartDay = $StartDay.AddDays(-1)
            }

            if ($StartDay.DayOfWeek -match "Sunday") {
                $StartDay = $StartDay.AddDays(-1)
            }

            if ($StartDay.DayOfWeek -match "Saturday") {
                $StartDay = $StartDay.AddDays(-1)
            }

            if ($holidays -contains $StartDay) {
                $StartDay = $StartDay.AddDays(-1)
            }

            $i--
        } until ($i -lt $Days)

        if ($holidays -contains $StartDay) {
            $StartDay = $StartDay.AddDays(-1)
        }

        if ($StartDay.DayOfWeek -match "Sunday") {
            $StartDay = $StartDay.AddDays(-1)
        }

        if ($StartDay.DayOfWeek -match "Saturday") {
            $StartDay = $StartDay.AddDays(-1)
        }

        if ($holidays -contains $StartDay) {
            $StartDay = $StartDay.AddDays(-1)
        }
        $StartDay
    }
    elseif ($sub -eq "add") {
        $i = 1
        do {
            $StartDay = $StartDay.AddDays(1)

            if ($holidays -contains $StartDay) {
                $StartDay = $StartDay.AddDays(1)
            }

            if ($StartDay.DayOfWeek -match "Saturday") {
                $StartDay = $StartDay.AddDays(1)
            }

            if ($StartDay.DayOfWeek -match "Sunday") {
                $StartDay = $StartDay.AddDays(1)
            }

            if ($holidays -contains $StartDay) {
                $StartDay = $StartDay.AddDays(1)
            }

            $i++
        } until ($i -gt $Days)

        if ($holidays -contains $StartDay) {
            $StartDay = $StartDay.AddDays(1)
        }

        if ($StartDay.DayOfWeek -match "Saturday") {
            $StartDay = $StartDay.AddDays(1)
        }

        if ($StartDay.DayOfWeek -match "Sunday") {
            $StartDay = $StartDay.AddDays(1)
        }

        if ($holidays -contains $StartDay) {
            $StartDay = $StartDay.AddDays(1)
        }
        $StartDay
    }
    else {$StartDay}
}


function Convert-ImageToBase64 {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-11-03 22:22:19
    Last Edit: 2020-11-03 22:22:19
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Convert-ICOtoBase64')]
    param(
        [Parameter(
            HelpMessage = "Enter the path of the image you want to convert. Ex: D:\temp\image.jpg",
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$ImagePath
    )

    $b64 = [convert]::ToBase64String((get-content $ImagePath -encoding byte))
    $b64
}


function Convert-IPtoINT64 () {
    param ($IP)
    $octets = $IP.split(".")
    return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3])
}

function Convert-INT64toIP() {
    param ([int64]$int)
    return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring())
}


Function Import-XML {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/25/2017 17:03:54
    LASTEDIT: 10/25/2017 17:03:54
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Path
    )

    [xml]$XmlFile = Get-Content -Path $Path
    $XmlFile
}


function Convert-Uint16ToString {
<#
.SYNOPSIS
    Converts uin16 arrays to a readable string.
.DESCRIPTION
    Take the members from a uint16 array and converts it to a user friendly string.
.PARAMETER Members
    Takes the array members for a uint16 array.
.EXAMPLE
    C:\PS>Convert-Uint16ToString $uint16array
    Converts the uint16 array in the $uint16array variable.
.EXAMPLE
    C:\PS>Convert-Uint16ToString ((Get-CimInstance WmiMonitorID -Namespace root/WMI)[0] | Select-Object -ExpandProperty SerialNumberID)
    Converts the SerialNumberID of the first monitor to a readable format.
.INPUTS
    System.uint16
.OUTPUTS
    System.String
.COMPONENT
    WSTools
.FUNCTIONALITY
    converter, uint16
.NOTES
    Author: Skyler Hart
    Created: 2023-02-11 01:02:00
    Last Edit: 2023-02-11 01:02:00
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter()]
        [uint16[]]$Members
    )

    Process {
        -join [char[]] ($Members)
    }
}



Function Get-Accelerator {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 12/21/2019 23:28:57
    LASTEDIT: 12/21/2019 23:28:57
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Get-TypeAccelerators','accelerators')]
    param()

    [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get | Sort-Object Key
}


Function Get-FilePath {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:05:42
    LASTEDIT: 09/21/2017 13:05:42
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = "C:\"
    $OpenFileDialog.filter = "All files (*.*)| *.*"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
    $OpenFileDialog.ShowHelp = $true
}


Function Get-FolderPath {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:05:51
    LASTEDIT: 09/21/2017 13:05:51
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    Write-Output "The folder selection window is open. It may be hidden behind windows."
    Add-Type -AssemblyName System.Windows.Forms
    $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    #$FolderBrowser.Description = "Select Folder"
    #$FolderBrowser.ShowNewFolderButton = $false
    #$FolderBrowser.RootFolder = 'MyComputer'
    #to see special folders:  [Enum]::GetNames([System.Environment+SpecialFolder])
    #special folders can be used in the RootFolder section
    #Set-WindowState MINIMIZE
    [void]$FolderBrowser.ShowDialog()
    #Set-WindowState RESTORE
    $FolderBrowser.SelectedPath
}


Function Get-FunctionsInModule {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/21/2017 13:06:27
    LASTEDIT: 08/21/2017 13:06:27
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Module
    )

    $mod = (Get-Module $Module -ListAvailable).ExportedCommands
    $mod.Values.Name | Sort-Object
}


function Get-PowerShellVariable {
<#
.SYNOPSIS
    Will show env: and PowerShell variable active in session.
.DESCRIPTION
    Gets environment variables and the active PowerShell variables in the current session and shows their values.
.PARAMETER Name
    To filter for a specific variable.
.EXAMPLE
    C:\PS>Get-PowerShellVariable
    Example of how to use this cmdlet.
.EXAMPLE
    C:\PS>Get-PowerShellVariable -Name ErrorActionPreference
    Will show what the value is for $ErrorActionPreference.
.EXAMPLE
    C:\PS>Get-PowerShellVariable -Name ErrorActionPreference,OneDriveConsumer
    Will show what the value is for $ErrorActionPreference and $env:OneDriveConsumer.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    variable, environment, system
.NOTES
    Author: Skyler Hart
    Created: 2022-09-22 23:29:51
    Last Edit: 2022-09-22 23:29:51
    Other:
    Requires:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$Name
    )

    $variables = Get-ChildItem Env: | Add-Member -MemberType NoteProperty -Name "VariableType" -Value "`$env:" -PassThru
    $variables += Get-Variable | Add-Member -MemberType NoteProperty -Name "VariableType" -Value "PowerShell" -PassThru

    if (!([string]::IsNullOrWhiteSpace($Name))) {
        $filtered = foreach ($obj in $Name) {
            $variables | Where-Object {$_.Name -match $obj} | Select-Object VariableType,Name,Value
        }
    }
    else {
        $filtered = $variables | Select-Object VariableType,Name,Value
    }

    $filtered | Select-Object | Sort-Object Name
}


Function Get-Role {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/20/2017 16:30:43
    LASTEDIT: 10/20/2017 16:30:43
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {$Role = "Admin"}
    else {$Role = "Non-Admin"}
    $Role
}


Function Set-AutoLoadPreference {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/01/2018 10:23:26
    LASTEDIT: 02/01/2018 10:23:26
    KEYWORDS:
    REQUIRES:
        -Version 2.0 only doesn't apply to Version 3.0 or newer
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [ValidateSet("All","None")]
        $mode = "All"
    )
    $PSModuleAutoloadingPreference = $mode
}


Function Set-Profile {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 21:07:03
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Edit-Profile','Profile')]
    param()

    #If profile already exists, open for editing
    if (Test-Path $profile) {
        start-process "$env:windir\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe" $profile
    }
    #If it doesn't exist, create it and put default stuff into it
    else {
        $filecontent = '##############################################################
# This file contains the commands to run upon startup of     #
# PowerShell or PowerShell ISE. Dependent on whether you     #
# used the command "Set-Profile" in PowerShell or            #
# PowerShell ISE.                                            #
#                                                            #
# To add additional commands to run at startup just type     #
# them below then save this file. To edit this file in the   #
# future, use the command "Set-Profile"                      #
##############################################################



'

        New-Item $profile -ItemType File -Force -Value $filecontent | Out-Null
        start-sleep 1
        start-process "$env:windir\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe" $profile
    }
}


Function Set-Title {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:47:14
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('title')]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$titleText
    )
    $Host.UI.RawUI.WindowTitle = $titleText
}


function Start-CommandMultiThreaded {
<#
.SYNOPSIS
    Takes a single command and multithreads it.
.DESCRIPTION
    Will multithread any command/cmdlet/function you specify.
.PARAMETER Command
    Where you specify the command you want to multithread.
.PARAMETER Objects
    The arguments that are provided to the command. Generally used for specifying the name of one or more computers. However, it can be used for specifying other arguments such as a list of users.
.PARAMETER MaxThreads
    The maximum threads to run. Can cause resource issues.
.PARAMETER MaxTime
    The amount of seconds to run the script after last job (object) is started.
.PARAMETER SleepTimer
    The amount of milliseconds between each time the script checks the status of jobs. For high resource utilization on the system or if the script is going to take longer to run, this should be increased.
.PARAMETER AddParameter
    Allows specifying additional parameters beyond what is used in Objects. Need to format in a hash table. Ex:
    @{"ParameterName" = "Value"}
    or
    @{"ParameterName" = "Value";"AnotherParameter" = "AnotherValue"}
.PARAMETER AddSwitch
    Allows specifying additional switches to add to the command you run. Need to format in a single string or an array of strings. Ex:
    "TotalCount"
    or
    @("TotalCount","All")
.EXAMPLE
    C:\PS>Start-CommandMultiThreaded Clear-Space (gc c:\Scripts\comps.txt)
    Will run the Clear-Space command against nine of the computers in the comps.txt file at a time. This is because the -MaxThreads parameter isn't set so it runs at the default of 9 objects at a time.
.EXAMPLE
    C:\PS>gc c:\Scripts\comps.txt | Start-CommandMultiThreaded Clear-Space
    Will run the Clear-Space command against nine of the computers in the comps.txt file at a time. This is because the -MaxThreads parameter isn't set so it runs at the default of 9 objects at a time.
.EXAMPLE
    C:\PS>Start-CommandMultiThreaded -Command Get-Service -Objects (gc c:\Scripts\comps.txt) -AddParameter @{"Name" = "wuauserv"} -AddSwitch @('RequiredServices','DependentServices')
    Will get the service "wuauserv" and it's dependent/required services from the computers listed in comps.txt.
.EXAMPLE
    C:\PS>Start-CommandMultiThreaded -Command Set-AxwayConfig -Objects COMP1,COMP2 -AddParameter @{"ConfigFile" = "C:\PKI\MyOrgsAxwayConfig.txt"}
    Will set the Axway config file on both the computer COMP1 and COMP2 at the same time using C:\PKI\MyOrgsAxwayConfig.txt on those computers as the file to import.
.INPUTS
    System.Management.Automation.PSObject.System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    Multithread, multitask
.NOTES
    Author: Skyler Hart
    Created: Sometime before 2017-08-07
    Last Edit: 2022-09-05 22:19:49
    Other:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [string]$Command,

        [Parameter(
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string[]]$Objects,

        [Parameter()]
        [int32]$MaxThreads = 9,

        [Parameter()]
        [int32]$MaxTime = 300,

        [Parameter()]
        [int32]$SleepTimer = 500,

        [Parameter()]
        [HashTable]$AddParameter,

        [Parameter()]
        [Array]$AddSwitch
    )

    Begin {
        $ISS = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads, $ISS, $Host)
        $RunspacePool.Open()
        If ($(Get-Command | Select-Object Name) -match $Command) {
            $Code = $Null
        }
        Else {
            $Code = [ScriptBlock]::Create($(Get-Content $Command))
        }
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Loading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $Objects){
            If ([string]::IsNullOrWhiteSpace($Code)) {
                $PowershellThread = [PowerShell]::Create().AddCommand($Command)
            }
            Else {
                $PowershellThread = [PowerShell]::Create().AddScript($Code)
            }

            $PowershellThread.AddArgument($Object.ToString()) | Out-Null
            ForEach ($Key in $AddParameter.Keys) {
                $PowershellThread.AddParameter($Key, $AddParameter.$key) | Out-Null
            }
            ForEach ($Switch in $AddSwitch) {
                $Switch
                $PowershellThread.AddParameter($Switch) | Out-Null
            }
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
            $Remaining = "$($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).object)"
            If ($Remaining.Length -gt 60) {
                $Remaining = $Remaining.Substring(0,60) + "..."
            }
            Write-Progress -Activity "Waiting for Jobs To Finish - $($MaxThreads - $($RunspacePool.GetAvailableRunspaces())) of $MaxThreads threads running" `
                -PercentComplete (($Jobs.count - $($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).count)) / $Jobs.Count * 100) `
                -Status "$(@($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False})).count) remaining - $remaining"
            ForEach ($Job in $($Jobs | Where-Object {$_.Handle.IsCompleted -eq $True})) {
                $Job.Thread.EndInvoke($Job.Handle)
                $Job.Thread.Dispose()
                $Job.Thread = $Null
                $Job.Handle = $Null
                $ResultTimer = Get-Date
            }
            If (($(Get-Date) - $ResultTimer).totalseconds -gt $MaxTime) {
                Write-Error "Script appears to be frozen, try increasing MaxResultTime"
                Exit
            }
            Start-Sleep -Milliseconds $SleepTimer
        }
        $RunspacePool.Close() | Out-Null
        $RunspacePool.Dispose() | Out-Null
    }
}


Function Start-PowerShell {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/24/2017 14:41:52
    LASTEDIT: 10/24/2017 16:41:21
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Open-PowerShell')]
    Param (
        [Parameter(Mandatory=$false)]
        [switch]$Console,

        [Parameter(Mandatory=$false)]
        [switch]$ISE,

        [Parameter(Mandatory=$false)]
        [switch]$VSC,

        [Parameter(Mandatory=$false)]
        [switch]$RunAs
    )


    if ($true -notin $Console,$ISE,$VSC) {
        if ($Host.Name -eq 'ConsoleHost') {
            if ($RunAs) {Start-Process "$env:windir\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe" -Verb RunAs}
            else {Start-Process "$env:windir\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe"}
        }
        else {
            if ($RunAs) {Start-Process powershell.exe -Verb RunAs}
            else {Start-Process powershell.exe}
        }
    }
    else {
        if ($Console) {
            if ($RunAs) {Start-Process powershell.exe -Verb RunAs}
            else {Start-Process powershell.exe}
        }
        elseif ($ISE) {
            if ($RunAs) {Start-Process "$env:windir\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe"}
            else {Start-Process "$env:windir\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe"}
        }
        elseif ($VSC) {
            if ($RunAs) {Start-Process "$env:programfiles\Microsoft VS Code\Code.exe"}
            else {Start-Process "$env:programfiles\Microsoft VS Code\Code.exe"}
        }
    }
}


#needs Get-NotificationApp
function Send-ToastNotification {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Send-ToastNotification
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Send-ToastNotification -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.NOTES
    Author: Skyler Hart
    Created: 2020-11-08 14:57:29
    Last Edit: 2021-07-16 23:08:42
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the message to send.",
            Mandatory=$true,
            Position=0
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(
            HelpMessage = "Enter the name of the sender.",
            Mandatory=$false,
            Position=1
        )]
        [string]$Sender = " ",

        [Parameter(
            Mandatory=$false,
            Position=2
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName,

        [Parameter(
            Mandatory=$false
        )]
        [string]$Title,

        [Parameter(Mandatory=$false)]
        [ValidateSet('ms-winsoundevent:Notification.Default',
        'ms-winsoundevent:Notification.IM',
        'ms-winsoundevent:Notification.Mail',
        'ms-winsoundevent:Notification.Reminder',
        'ms-winsoundevent:Notification.SMS',
        'ms-winsoundevent:Notification.Looping.Alarm',
        'ms-winsoundevent:Notification.Looping.Alarm2',
        'ms-winsoundevent:Notification.Looping.Alarm3',
        'ms-winsoundevent:Notification.Looping.Alarm4',
        'ms-winsoundevent:Notification.Looping.Alarm5',
        'ms-winsoundevent:Notification.Looping.Alarm6',
        'ms-winsoundevent:Notification.Looping.Alarm7',
        'ms-winsoundevent:Notification.Looping.Alarm8',
        'ms-winsoundevent:Notification.Looping.Alarm9',
        'ms-winsoundevent:Notification.Looping.Alarm10',
        'ms-winsoundevent:Notification.Looping.Call',
        'ms-winsoundevent:Notification.Looping.Call2',
        'ms-winsoundevent:Notification.Looping.Call3',
        'ms-winsoundevent:Notification.Looping.Call4',
        'ms-winsoundevent:Notification.Looping.Call5',
        'ms-winsoundevent:Notification.Looping.Call6',
        'ms-winsoundevent:Notification.Looping.Call7',
        'ms-winsoundevent:Notification.Looping.Call8',
        'ms-winsoundevent:Notification.Looping.Call9',
        'ms-winsoundevent:Notification.Looping.Call10',
        'Silent')]
        [string]$AudioSource = 'ms-winsoundevent:Notification.Looping.Alarm3',

        [Parameter()]
        [switch]$ShortDuration,

        [Parameter()]
        [switch]$RequireDismiss #overrides ShortDuration
    )
    DynamicParam {
        # Set the dynamic parameters' name. You probably want to change this.
        $ParameterName = 'Notifier'

        # Create the dictionary
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]

        # Create and set the parameters' attributes. You may also want to change these.
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $false
        $ParameterAttribute.Position = 3

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet. You definitely want to change this. This part populates your set.
        $arrSet = ((Get-NotificationApp).Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($arrSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        return $RuntimeParameterDictionary
    }
    Begin {
        $Notifier = $PsBoundParameters[$ParameterName]
        if ([string]::IsNullOrWhiteSpace($Notifier)) {$Notifier = "Windows.SystemToast.NfpAppAcquire"}
        if ([string]::IsNullOrWhiteSpace($Title)) {
            $ttext = $null
        }
        else {
            $ttext = "<text>$Title</text>"
        }

        if ($AudioSource -eq 'Silent') {
            $atext = '<audio silent="true"/>'
        }
        else {
            $atext = '<audio src="' + $AudioSource + '"/>'
        }
        if ($RequireDismiss) {
            $scenario = '<toast scenario="reminder">'
            $actions = @"
        <actions>
            <action arguments="dismiss" content="Dismiss" activationType="system"/>
        </actions>
"@
        }
        else {
            if ($ShortDuration) {$dur = "short"}
            else {$dur = "long"}
            $scenario = '<toast duration="' + $dur + '">'
            $actions = $null
        }

        [xml]$ToastTemplate = @"
            $scenario
                <visual>
                <binding template="ToastGeneric">
                    <text>$Sender</text>
                    $ttext
                    <group>
                        <subgroup>
                            <text hint-style="subtitle" hint-wrap="true">$Message</text>
                        </subgroup>
                    </group>
                </binding>
                </visual>
                $actions
                $atext
            </toast>
"@

        [scriptblock]$ToastScript = {
            Param($ToastTemplate)
            #Load required assemblies
            [void][Windows.UI.Notifications.ToastNotification,Windows.UI.Notifications,ContentType=WindowsRuntime]
            [void][Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom,ContentType=WindowsRuntime]

            #Format XML
            $FinalXML = [Windows.Data.Xml.Dom.XmlDocument]::new()
            $FinalXML.LoadXml($ToastTemplate.OuterXml)

            #Create the Toast
            $Toast = [Windows.UI.Notifications.ToastNotification]::new($FinalXML)

            #Show the Toast message
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($Notifier).show($Toast)
        }
    }
    Process {
        if (![string]::IsNullOrEmpty($ComputerName)) {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock $ToastScript -ArgumentList $ToastTemplate #DevSkim: ignore DS104456
        }
        else {Invoke-Command -ScriptBlock $ToastScript -ArgumentList $ToastTemplate} #DevSkim: ignore DS104456
    }
    End {
        #done
    }
}


Function Test-DynamicParameterSwitchCheck {
<#
.SYNOPSIS
    Non-functional. For reference.
.DESCRIPTION
    Shows how to create a function with dynamic parameters (Add and Modify) that only appear if the username parameter is populated and the Enable switch is added.
.COMPONENT
    WSTools
.FUNCTIONALITY
    Example, Reference
.NOTES
    Author: Skyler Hart
    Created: 2022-09-11 01:28:57
    Last Edit: 2022-09-11 01:41:04
    Other:
.LINK
    https://wanderingstag.github.io
#>
    Param (
        [Parameter(Mandatory = $false)]
        [Alias('EDIPI','DisplayName')]
        [string[]]$UserName,

        [Parameter(Mandatory = $false)]
        [switch]$Enable

    )
    DynamicParam {
        if (![string]::IsNullOrWhiteSpace($Username) -and $Enable -eq $true) {
            #Parameter
            $parameterAttribute = [System.Management.Automation.ParameterAttribute]@{
                ParameterSetName = "AddingMembers"
                Mandatory = $false
            }

            $attributeCollection = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
            $attributeCollection.Add($parameterAttribute)

            $dynParam1 = [System.Management.Automation.RuntimeDefinedParameter]::new(
                'Add', [switch], $attributeCollection
            )

            $paramDictionary = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
            $paramDictionary.Add('Add', $dynParam1)

            #Parameter2
            $parameterAttribute2 = [System.Management.Automation.ParameterAttribute]@{
                ParameterSetName = "ModifyingMembers"
                Mandatory = $false
            }

            $attributeCollection2 = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
            $attributeCollection2.Add($parameterAttribute2)

            $dynParam2 = [System.Management.Automation.RuntimeDefinedParameter]::new(
                'Modify', [switch], $attributeCollection2
            )

            $paramDictionary.Add('Modify', $dynParam2)
            return $paramDictionary
        }
    }#dynamic
    Process {
        $PSBoundParameters['Add'].IsPresent
    }
}


Function Clear-Patches {
<#
.SYNOPSIS
    Clears the C:\Patches folder.
.DESCRIPTION
    Removes items in the C:\Patches folder on the local or remote computer.
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Recursive
    Removes all files and folders in the Patches folder on the specified computer.
.PARAMETER Old
    Removes files in the root of the C:\Patches folder (except Install.ps1) that are older than 28 days.
.EXAMPLE
    C:\PS>Clear-Patches
    Clears C:\Patches folder on the local computer (but not the inidividual program folders.)
.EXAMPLE
    C:\PS>Clear-Patches -ComputerName COMP1
    Clears C:\Patches folder on the computer COMP1.
.EXAMPLE
    C:\PS>Clear-Patches -ComputerName (gc c:\complist.txt) -Recursive
    Clears all files and folders in C:\Patches on the computers listed in the file c:\complist.txt.
.EXAMPLE
    C:\PS>Clear-Patches -ComputerName (gc c:\complist.txt) -Old
    Clears files in the root of C:\Patches that are older than 28 days on the computers listed in the file c:\complist.txt.
.NOTES
    Author: Skyler Hart
    Created: 2020-08-18 09:58:51
    Last Edit: 2020-08-18 09:58:51
    Keywords: Delete, temp, patches
    Other: Needs to be ran as a user that has administrator rights
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does and is what the folder name is called."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [switch]$Recursive,

        [Parameter()]
        [switch]$Old,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        $ISS = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $ISS, $Host)
        $RunspacePool.Open()

        if ($Recursive) {
            $Code = {
                [CmdletBinding()]
                Param (
                    [Parameter(
                        Mandatory=$true,
                        Position=0
                    )]
                    [string]$comp
                )

                $psdpath = "\\$comp\c$"
                $dn = $comp + "CS"
                $patches = $dn + ":\Patches"
                try {
                    New-PSDrive -Name $dn -PSProvider FileSystem -root "$psdpath" -ErrorAction Stop | Out-Null
                    if (Test-Path $patches) {
                        Set-Location $patches -ErrorAction Stop
                        if ((Get-Location).Path -eq $patches) {
                            Remove-Item * -Recurse -force -ErrorAction SilentlyContinue
                        }
                        $info = [PSCustomObject]@{
                            ComputerName = $Comp
                            Status = "Cleared"
                        }#new object
                    }
                    else {
                        $info = [PSCustomObject]@{
                            ComputerName = $Comp
                            Status = "No patches folder"
                        }#new object
                    }
                    Remove-PSDrive -Name $dn -ErrorAction SilentlyContinue -Force | Out-Null
                }#try
                catch {
                    $info = [PSCustomObject]@{
                        ComputerName = $Comp
                        Status = "Unable to clear"
                    }#new object
                }#catch

                $info
            }#end code block
        }#if recursive
        elseif ($Old) {
            $Code = {
                [CmdletBinding()]
                Param (
                    [Parameter(
                        Mandatory=$true,
                        Position=0
                    )]
                    [string]$comp
                )

                $psdpath = "\\$comp\c$"
                $dn = $comp + "CS"
                $patches = $dn + ":\Patches"
                try {
                    New-PSDrive -Name $dn -PSProvider FileSystem -root "$psdpath" -ErrorAction Stop | Out-Null
                    if (Test-Path $patches) {
                        Set-Location $patches -ErrorAction Stop
                        $op = Get-ChildItem $patches | Where-Object {$_.Attributes -ne "Directory" -and $_.Name -notmatch "Install.ps1" -and $_.LastWriteTime -lt ((Get-Date).AddDays(-28))} | Select-Object FullName -ExpandProperty FullName

                        foreach ($p in $op) {
                            Remove-Item -Path $p -Force -ErrorAction SilentlyContinue
                        }
                        $info = [PSCustomObject]@{
                            ComputerName = $Comp
                            Status = "Cleared"
                        }#new object
                    }
                    else {
                        $info = [PSCustomObject]@{
                            ComputerName = $Comp
                            Status = "No patches folder"
                        }#new object
                    }
                    Remove-PSDrive -Name $dn -ErrorAction SilentlyContinue -Force | Out-Null
                }#try
                catch {
                    $info = [PSCustomObject]@{
                        ComputerName = $Comp
                        Status = "Unable to clear"
                    }#new object
                }#catch

                $info
            }#end code block
        }#elseif Old
        else {
            $Code = {
                [CmdletBinding()]
                Param (
                    [Parameter(
                        Mandatory=$true,
                        Position=0
                    )]
                    [string]$comp
                )

                $psdpath = "\\$comp\c$"
                $dn = $comp + "CS"
                $patches = $dn + ":\Patches"
                try {
                    New-PSDrive -Name $dn -PSProvider FileSystem -root "$psdpath" -ErrorAction Stop | Out-Null
                    if (Test-Path $patches) {
                        Set-Location $patches -ErrorAction Stop
                        if ((Get-Location).Path -eq $patches) {
                            Remove-Item .\*.* -force -ErrorAction SilentlyContinue
                            Remove-Item .\cab\* -Recurse -Force -ErrorAction SilentlyContinue
                        }
                        $info = [PSCustomObject]@{
                            ComputerName = $Comp
                            Status = "Cleared"
                        }#new object
                    }
                    else {
                        $info = [PSCustomObject]@{
                            ComputerName = $Comp
                            Status = "No patches folder"
                        }#new object
                    }
                    Remove-PSDrive -Name $dn -ErrorAction SilentlyContinue -Force | Out-Null
                }#try
                catch {
                    $info = [PSCustomObject]@{
                        ComputerName = $Comp
                        Status = "Unable to clear"
                    }#new object
                }#catch
                $info
            }#end code block
        }#else not recursive or old
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null

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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Copy-SQLServerManagementStudio {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-07-24 21:03:23
    LASTEDIT: 2021-07-24 21:03:23
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
[Alias('Copy-SSMS')]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.SSMS
    $appname = "SSMS"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-SplunkForwarder {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-07-21 23:37:25
    LASTEDIT: 2021-07-21 23:43:29
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.SplunkUF
    $appname = "SplunkForwarder"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Tanium {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 11/08/2019 14:21:26
    LASTEDIT: 11/08/2019 14:21:26
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.Tanium
    $appname = "Tanium"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Teams {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 12/04/2019 17:43:21
    LASTEDIT: 12/04/2019 17:45:37
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Teams is the name of the application."
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.Teams
    $appname = "Teams"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-VisualStudioCode {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-06-15 21:43:12
    LASTEDIT: 2021-11-18 22:31:01
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
[Alias('Copy-VSCode')]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.VSCode
    $appname = "VSCode"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:2 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-VMwareTools {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-07-21 23:47:48
    LASTEDIT: 2021-07-21 23:49:09
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.VMwareTools
    $appname = "VMwareTools"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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



Function Copy-VLC {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 07/23/2019 20:44:10
    LASTEDIT: 07/23/2019 20:46:11
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.VLC
    $appname = "VLC"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Wireshark {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 07/23/2019 20:53:52
    LASTEDIT: 07/23/2019 20:56:26
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.Wireshark
    $appname = "Wireshark"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" *.exe /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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



Function Install-Edge {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-05-25 22:50:45
    Last Edit: 2022-09-04 22:08:12
    Other:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter]
        [switch]$Vanilla
    )

    $config = $Global:WSToolsConfig
    if ($Vanilla) {
        $app = $config.EdgeVanilla
    }
    else {
        $app = $config.Edge
    }

    $b = 0
    $n = $ComputerName.Count
    foreach ($comp in $ComputerName) {
        if ($n -gt 1) {
            $b++
            $p = ($b / $n)
            $p1 = $p.ToString("P")
            Write-Progress -Id 1 -activity "Copying Edge to computer and then initiating install" -status "Computer $b of $n. Percent complete:  $p1" -PercentComplete (($b / $n)  * 100)
        }

        try {
            if ($Vanilla) {
                if ($host.Name -notmatch "ServerRemoteHost") {
                    robocopy $app \\$comp\c$\Patches\EdgeVanilla /mir /mt:2 /r:3 /w:15 /njh /njs
                }
                $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList "cmd /c msiexec.exe /i c:\Patches\EdgeVanilla\MicrosoftEdgeEnterpriseX64.msi /qn /norestart" -ErrorAction Stop #DevSkim: ignore DS104456
            }
            else {
                if ($host.Name -notmatch "ServerRemoteHost") {
                    robocopy $app \\$comp\c$\Patches\Edge /mir /mt:2 /r:3 /w:15 /njh /njs
                }
                $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList "cmd /c c:\Patches\Edge\Deploy-application.exe -DeployMode 'NonInteractive'" -ErrorAction Stop #DevSkim: ignore DS104456
            }

            $end = Get-Date
            $info = New-Object -TypeName PSObject -Property @{
                ComputerName = $comp
                Status = "Install Initialized"
                Time = $end
            }#new object
        }
        catch {
            $end = Get-Date
            $info = New-Object -TypeName PSObject -Property @{
                ComputerName = $comp
                Status = "Unable to install"
                Time = $end
            }#new object
        }
        $info
    }
    Write-Host "Please wait at least five minutes before installing another program" -ForegroundColor Yellow
}


Function Install-GitSCM {
<#
   .Parameter ComputerName
    Specifies the computer or computers
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2022-09-04 21:50:21
    LASTEDIT: 2022-09-04 21:53:03
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $app = $config.Git

    $b = 0
    $n = $ComputerName.Count
    foreach ($comp in $ComputerName) {
        if ($n -gt 1) {
            $b++
            $p = ($b / $n)
            $p1 = $p.ToString("P")
            Write-Progress -Id 1 -activity "Copying Git SCM to computer and then initiating install" -status "Computer $b of $n. Percent complete:  $p1" -PercentComplete (($b / $n)  * 100)
        }

        try {
            if ($host.Name -notmatch "ServerRemoteHost") {
                robocopy $app \\$comp\c$\Patches\GitSCM /mir /mt:2 /r:3 /w:15 /njh /njs
            }
            $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList "cmd /c c:\Patches\GitSCM\Git-64-bit.exe /SP- /VERYSILENT /SUPPRESSMSGBOXES /NOCANCEL /NORESTART /CLOSEAPPLICATIONS /NORESTARTAPPLICATIONS /TYPE=full" -ErrorAction Stop #DevSkim: ignore DS104456
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Install Initialized"
                Time = $end
            }#pscustomobject
        }
        catch {
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Unable to install"
                Time = $end
            }#pscustomobject
        }
        $info
    }
}


Function Install-MECM {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-10-12 11:49:19
    LASTEDIT: 2021-10-12 11:55:08
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Install-SCCM')]
    Param (
        [Parameter()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $app = $config.MECM

    $b = 0
    $n = $ComputerName.Count
    foreach ($comp in $ComputerName) {
        if ($n -gt 1) {
            $b++
            $p = ($b / $n)
            $p1 = $p.ToString("P")
            Write-Progress -Id 1 -activity "Copying MECM to computer and then initiating install" -status "Computer $b of $n. Percent complete:  $p1" -PercentComplete (($b / $n)  * 100)
        }

        try {
            if ($host.Name -notmatch "ServerRemoteHost") {
                robocopy $app \\$comp\c$\Patches\MECM ccmsetup.exe /r:3 /w:15 /njh /njs
            }
            $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList "cmd /c c:\Patches\MECM\ccmsetup.exe" -ErrorAction Stop #DevSkim: ignore DS104456
            $install | Out-Null
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Install Initialized"
                Time = $end
            }#new object
        }
        catch {
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Unable to install"
                Time = $end
            }#new object
        }
        $info
    }
    Write-Output "The MECM install can take over an install to fully complete. Please wait a minimum of 30 minutes before rebooting or installing another program."
}


Function Install-OneDrive {
<#
   .Parameter ComputerName
    Specifies the computer or computers
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2022-09-04 22:24:27
    LASTEDIT: 2022-09-04 22:24:27
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $app = $config.OneDrive

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $b = 0
        $n = $ComputerName.Count
        foreach ($comp in $ComputerName) {
            if ($n -gt 1) {
                $b++
                $p = ($b / $n)
                $p1 = $p.ToString("P")
                Write-Progress -Id 1 -activity "Copying OneDrive to computer and then initiating install" -status "Computer $b of $n. Percent complete:  $p1" -PercentComplete (($b / $n)  * 100)
            }

            try {
                if ($host.Name -notmatch "ServerRemoteHost") {
                    robocopy $app \\$comp\c$\Patches\OneDrive /mir /mt:2 /r:3 /w:15 /njh /njs
                }
                $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList "cmd /c c:\Patches\OneDrive\OneDriveSetup.exe /silent /allusers" -ErrorAction Stop #DevSkim: ignore DS104456
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Status = "Install Initialized"
                    Time = $end
                }#pscustomobject
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Status = "Unable to install"
                    Time = $end
                }#pscustomobject
            }
            $info
        }
    }
    else {
        if ($ComputerName -eq $env:COMPUTERNAME) {
            robocopy $app \\$comp\c$\Patches\OneDrive /mir /mt:2 /r:3 /w:15 /njh /njs
            Start-Process -FilePath "C:\Patches\OneDrive\OneDriveSetup.exe" -ArgumentList "/Silent"
        }
        else {
            Write-Warning "Must be ran as admin to install on remote computers."
        }
    }
}


Function Install-Patches {
<#
.SYNOPSIS
    Will install patches in the local patches folder.
.DESCRIPTION
    Installes patches in the LocalPatches config setting path (default is C:\Patches.)
.PARAMETER ComputerName
    Specifies the name of one or more computers to install patches on.
.EXAMPLE
    C:\PS>Install-Patches
    Will install patches in the LocalPatches config setting path (default is C:\Patches.)
.EXAMPLE
    C:\PS>Install-Patches -ComputerName COMP1,COMP2
    Will install patches in the LocalPatches config setting path (default is C:\Patches) on COMP1 and COMP2.
.NOTES
    Author: Skyler Hart
    Created: 2017-03-25 08:30:23
    Last Edit: 2021-08-12 00:36:14
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does."
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Install-Updates')]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $Patches = $config.LocalPatches

    $fp = $PSScriptRoot.Substring(0,($PSScriptRoot.Length-15)) + "\InstallRemote.ps1"

    if ($ComputerName -eq $env:COMPUTERNAME) {
        Copy-Item -Path $fp -Destination $Patches
        & "$Patches\InstallRemote.ps1"
    }
    else {
        Invoke-Command -ComputerName $ComputerName -FilePath $fp -ErrorAction Stop  #DevSkim: ignore DS104456
    }
}#install patches


Function Install-SQLServerManagementStudio {
<#
   .Parameter ComputerName
    Specifies the computer or computers
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-07-24 21:25:32
    LASTEDIT: 2021-07-24 21:25:32
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Install-SSMS')]
    Param (
        [Parameter()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $app = $config.SSMS

    $b = 0
    $n = $ComputerName.Count
    foreach ($comp in $ComputerName) {
        if ($n -gt 1) {
            $b++
            $p = ($b / $n)
            $p1 = $p.ToString("P")
            Write-Progress -Id 1 -activity "Copying SSMS to computer and then initiating install" -status "Computer $b of $n. Percent complete:  $p1" -PercentComplete (($b / $n)  * 100)
        }

        try {
            if ($host.Name -notmatch "ServerRemoteHost") {
                robocopy $app \\$comp\c$\Patches\SSMS SSMS-Setup*.exe /r:3 /w:15 /njh /njs
            }
            $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c c:\Patches\SSMS\SSMS-Setup-ENU.exe /Quiet SSMSInstallRoot="C:\Program Files (x86)\Microsoft SQL Server Management Studio 18" DoNotInstallAzureDataStudio=1' -ErrorAction Stop #DevSkim: ignore DS104456
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Install Initialized"
                Time = $end
            }#new object
        }
        catch {
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Unable to install"
                Time = $end
            }#new object
        }
        $info
    }
}


Function Install-VisualStudioCode {
<#
   .Parameter ComputerName
    Specifies the computer or computers
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-06-15 21:56:38
    LASTEDIT: 2021-11-18 22:32:44
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Install-VSCode')]
    Param (
        [Parameter()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $app = $config.VSCode

    $b = 0
    $n = $ComputerName.Count
    foreach ($comp in $ComputerName) {
        if ($n -gt 1) {
            $b++
            $p = ($b / $n)
            $p1 = $p.ToString("P")
            Write-Progress -Id 1 -activity "Copying Visual Studio Code to computer and then initiating install" -status "Computer $b of $n. Percent complete:  $p1" -PercentComplete (($b / $n)  * 100)
        }

        try {
            if ($host.Name -notmatch "ServerRemoteHost") {
                robocopy $app \\$comp\c$\Patches\VSCode /mir /mt:2 /r:3 /w:15 /njh /njs
            }
            $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList "cmd /c c:\Patches\VSCode\VSCodeSetup-x64.exe /SP- /VERYSILENT /SUPPRESSMSGBOXES /NOCANCEL /NORESTART /CLOSEAPPLICATIONS /NORESTARTAPPLICATIONS /TYPE=full" -ErrorAction Stop #DevSkim: ignore DS104456
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Install Initialized"
                Time = $end
            }#new object
        }
        catch {
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Unable to install"
                Time = $end
            }#new object
        }
        $info
    }
}


Function Install-VMwareTools {
<#
.SYNOPSIS
    Will install VMware tools on one or more computers.
.DESCRIPTION
    Installes VMware Tools from the C:\Patches\VMware directory. Uses config file to determine network path to copy to the local computer first. On remote computers, install file will need to already exist (use Copy-VMwareTools).
.PARAMETER ComputerName
    Specifies the name of one or more computers to install VMware Tools on.
.EXAMPLE
    C:\PS>Install-VMwareTools
    Will install VMware Tools from setup file in C:\Patches\VMwareTools.
.EXAMPLE
    C:\PS>Install-VMwareTools -ComputerName COMP1,COMP2
    Will install VMware Tools from setup file in C:\Patches\VMwareTools on COMP1 and COMP2.
.NOTES
    Author: Skyler Hart
    Created: 2022-12-16 22:04:04
    Last Edit: 2022-12-16 22:04:04
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does."
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $vmtsource = $config.VMwareTools

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        if ($ComputerName -eq $env:COMPUTERNAME) {
            if ($host.Name -notmatch "ServerRemoteHost") {
                Copy-Item -Path $vmtsource -Destination "C:\Patches\VMwareTools"
            }
            Start-Process C:\Patches\VMwareTools\vmware-tools.exe -ArgumentList "/S /v ""/qn REBOOT=R ADDLOCAL=ALL""" -Wait; $rn = (Get-Date).ToUniversalTime().ToString("yyyyMMdd HH:mm:ss UTC"); $string = $rn + " - " + $env:COMPUTERNAME + ":"; Write-Output "$string VMware tools install initiated."
        }
        else {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {#DevSkim: ignore DS104456
                Start-Process C:\Patches\VMwareTools\vmware-tools.exe -ArgumentList "/S /v ""/qn REBOOT=R ADDLOCAL=ALL""" -Wait; $rn = (Get-Date).ToUniversalTime().ToString("yyyyMMdd HH:mm:ss UTC"); $string = $rn + " - " + $env:COMPUTERNAME + ":"; Write-Output "$string VMware tools install initiated."
            } -ErrorAction SilentlyContinue
        }
    }
    else {
        Write-Error "Must be ran as admin."
    }
}


#regionUninstall
###########################################################################
###########################################################################
##                                                                       ##
##                              Uninstall                                ##
##                                                                       ##
###########################################################################
###########################################################################


Function Uninstall-7Zip {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 07/22/2019 20:52:09
    LASTEDIT: 07/22/2019 20:53:01
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )

            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='7-Zip%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "7-Zip"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "7-Zip"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-90Meter {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/29/2019 13:33:05
    LASTEDIT: 08/29/2019 13:33:05
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )

            try {
                $uninstall =  Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList "cmd /c c:\windows\system32\msiexec.exe /uninstall {54C965FF-E457-4993-A083-61B9A6AEFEC1} /quiet /norestart" -ErrorAction Stop #DevSkim: ignore DS104456
                $uninstall
                Start-Sleep -Seconds 20
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE '90Meter%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "90Meter"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "90Meter"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process{
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.RunspacePool = $RunspacePool
            $Handle = $PowershellThread.BeginInvoke()
            $Job = "" | Select-Object Handle, Thread, object
            $Job.Handle = $Handle
            $Job.Thread = $PowershellThread
            $Job.Object = $Object.ToString()
            $Jobs += $Job
        }
    }
    End{
        $ResultTimer = Get-Date
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-ActivClient {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2022-12-19 23:13:27
    LASTEDIT: 2022-12-19 23:13:27
    KEYWORDS:
    REQUIRES:
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%ActivClient%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "ActivClient"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "ActivClient"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process{
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.RunspacePool = $RunspacePool
            $Handle = $PowershellThread.BeginInvoke()
            $Job = "" | Select-Object Handle, Thread, object
            $Job.Handle = $Handle
            $Job.Thread = $PowershellThread
            $Job.Object = $Object.ToString()
            $Jobs += $Job
        }
    }
    End{
        $ResultTimer = Get-Date
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-AdobeAir {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:08:38
    LASTEDIT: 07/22/2019 20:23:33
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
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Adobe Air%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Air"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Air"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process{
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.RunspacePool = $RunspacePool
            $Handle = $PowershellThread.BeginInvoke()
            $Job = "" | Select-Object Handle, Thread, object
            $Job.Handle = $Handle
            $Job.Thread = $PowershellThread
            $Job.Object = $Object.ToString()
            $Jobs += $Job
        }
    }
    End{
        $ResultTimer = Get-Date
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-AdobeExperienceManager {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 12:37:42
    Last Edit: 2021-01-25 12:37:42
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Uninstall-AEM','Uninstall-AdobeAEM','Uninstall-Designer','Uninstall-Forms')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Adobe Experienc%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Designe%' AND Vendor LIKE 'Adobe%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Experience Manager (AEM)"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Experience Manager (AEM)"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process{
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.RunspacePool = $RunspacePool
            $Handle = $PowershellThread.BeginInvoke()
            $Job = "" | Select-Object Handle, Thread, object
            $Job.Handle = $Handle
            $Job.Thread = $PowershellThread
            $Job.Object = $Object.ToString()
            $Jobs += $Job
        }
    }
    End{
        $ResultTimer = Get-Date
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-AdobeFlash {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:08:42
    LASTEDIT: 07/22/2019 20:26:17
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
    [Alias('Uninstall-Flash')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Adobe Flash%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Flash"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Flash"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-AdobePro {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:08:49
    LASTEDIT: 07/22/2019 20:29:01
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
    [Alias('Uninstall-AdobeAcrobat','Uninstall-Acrobat')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Adobe Acrobat%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Acrobat Pro"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Acrobat Pro"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-AdobeLiveCycleFormsDesigner {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2022-08-25 20:48:03
    LASTEDIT: 2022-08-25 20:48:03
    KEYWORDS:
    REQUIRES:
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Adobe LiveCycle%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe LiveCycle Forms Designer"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe LiveCycle Forms Designer"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-AdobeReader {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:08:53
    LASTEDIT: 07/22/2019 20:31:36
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
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Adobe Reader%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Reader"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Reader"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-AdobeShockwave {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:08:57
    LASTEDIT: 07/22/2019 20:34:05
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
    [Alias('Uninstall-Shockwave')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Adobe Shockwave%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Shockwave"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Shockwave"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-Axway {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2022-08-25 20:52:32
    LASTEDIT: 2022-08-25 20:52:32
    KEYWORDS:
    REQUIRES:
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Axwa%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Axway"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Axway"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-CiscoAnyConnect {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 13:44:09
    Last Edit: 2021-01-25 13:44:09
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Uninstall-AnyConnect')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Cisco AnyConnect%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Cisco AnyConnect"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Cisco AnyConnect"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-DamewareMiniRemoteControl {
<#
.NOTES
    Author: Skyler Hart
    Created: 2022-04-19 11:19:52
    Last Edit: 2022-04-19 11:19:52
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Dameware Mini Remote%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Dameware Mini Remote Control"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Dameware Mini Remote Control"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-F5BigIPEdgeClient {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 13:55:11
    Last Edit: 2021-01-25 13:55:11
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Uninstall-BigIPEdgeClient')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'BIG-IP Edge%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "F5 BIG-IP Edge Client"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "F5 BIG-IP Edge Client"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-GoogleChrome {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 07/22/2019 15:29:24
    LASTEDIT: 07/22/2019 20:36:24
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
    [Alias('Uninstall-Chrome')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Chrome%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Google Chrome"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Google Chrome"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-HPInsightAgent {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:09:07
    LASTEDIT: 07/22/2019 20:41:20
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
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'HP Insight%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "HP Insight Agent"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "HP Insight Agent"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-HPVersionControlAgent {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:09:12
    LASTEDIT: 07/22/2019 20:42:42
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
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'HP Version%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "HP Version Control Agent"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "HP Version Control Agent"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-IBMForms {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:09:25
    LASTEDIT: 07/22/2019 20:47:05
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does and is the name of the application."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name like 'IBM Forms%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "IBM Forms"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "IBM Forms"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-McAfeeVSE {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:09:30
    LASTEDIT: 07/22/2019 20:49:03
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
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='McAfee VirusScan%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "McAfee VirusScan"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "McAfee VirusScan"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-MicrosoftInfoPath {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 13:10:44
    Last Edit: 2021-01-25 13:10:44
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does and is the name of the application."
    )]
    [CmdletBinding()]
    [Alias('Uninstall-InfoPath')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name like '%InfoPath%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "InfoPath"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "InfoPath"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-MozillaFirefox {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 07/22/2019 20:19:10
    LASTEDIT: 11/26/2019 14:25:58
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
    [Alias('Uninstall-Firefox')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files\Mozilla Firefox\uninstall\helper.exe" -ms' -ErrorAction SilentlyContinue | Out-Null
                Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files (x86)\Mozilla Firefox\uninstall\helper.exe" -ms' -ErrorAction SilentlyContinue | Out-Null
                Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files\Mozilla Maintenance Service\uninstall.exe" /S' -ErrorAction SilentlyContinue | Out-Null
                Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files (x86)\Mozilla Maintenance Service\uninstall.exe" /S' -ErrorAction SilentlyContinue | Out-Null
                Start-Sleep -Seconds 30
                Get-WmiObject -Class Win32_Product -Filter "Name like '%Firefox%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Mozilla Firefox"
                    Status = "Removal Initialized"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Mozilla Firefox"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-MozillaMaintenanceService {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/01/2019 16:36:26
    LASTEDIT: 08/01/2019 16:36:26
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
    [Alias('Uninstall-FirefoxMaintenanceService')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files\Mozilla Maintenance Service\uninstall.exe" /S' -ErrorAction SilentlyContinue | Out-Null
                Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files (x86)\Mozilla Maintenance Service\uninstall.exe" /S' -ErrorAction Stop | Out-Null
                Start-Sleep -Seconds 30
                Get-WmiObject -Class Win32_Product -Filter "Name like '%Firefox%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Mozilla Maintenance Service"
                    Status = "Removal Initialized"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Mozilla Maintenance Service"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-OracleJava {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:09:20
    LASTEDIT: 07/22/2019 20:44:41
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
    [Alias('Uninstall-Java')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name like 'Java%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Java"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Java"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-TransVerse {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 14:42:32
    Last Edit: 2022-08-26 20:59:03
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )

            if ($comp -eq $env:COMPUTERNAME) {
                & ${env:ProgramFiles(x86)}\Transverse\unins000.exe /SILENT
                Start-Sleep -Seconds 10
                Get-WmiObject -Class Win32_Product -Filter "Name like '%TransVerse%'" -ErrorAction Stop | Remove-WmiObject -ErrorAction SilentlyContinue
            }
            else {
                Invoke-Command -ComputerName $comp -ScriptBlock {& ${env:ProgramFiles(x86)}\Transverse\unins000.exe /SILENT}
                try {
                    Get-WmiObject -Class Win32_Product -Filter "Name like '%TransVerse%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                    [PSCustomObject]@{
                        ComputerName = $comp
                        Program = "TransVerse"
                        Status = "Removed"
                    }#new object
                }#try
                catch {
                    [PSCustomObject]@{
                        ComputerName = $comp
                        Program = "TransVerse"
                        Status = "Failed"
                    }#new object
                }#catch
            }#if not local
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-VLC {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 07/22/2019 20:55:21
    LASTEDIT: 07/22/2019 20:56:10
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
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='VLC%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "VLC"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "VLC"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-Wireshark {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 15:04:23
    Last Edit: 2021-01-25 15:04:23
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='Wireshar%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Wireshark"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Wireshark"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-WinRAR {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 18:16:01
    Last Edit: 2021-01-25 18:16:01
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='WinRA%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "WinRAR"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "WinRAR"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-WinSCP {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 07/22/2019 20:54:29
    LASTEDIT: 07/22/2019 20:54:42
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
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='WinSCP%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "WinSCP"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "WinSCP"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-WinZip {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 18:12:40
    Last Edit: 2021-01-25 18:12:40
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='WinZi%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "WinZip"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "WinZip"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-Zoom {
<#
.NOTES
    Author: Skyler Hart
    Created: 2022-03-22 20:57:00
    Last Edit: 2022-03-22 20:57:00
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='Zoom%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Zoom"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Zoom"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


#endregionUninstall

###########################################################################
###########################################################################
##                                                                       ##
##                                Other                                  ##
##                                                                       ##
###########################################################################
###########################################################################


Function Disable-3DES {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 14:40:00
    LASTEDIT: 04/23/2018 14:40:00
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
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $Valuedata = 0

    foreach ($comp in $ComputerName) {
        #.
        #. Ciphers
        #.

        #Disable Triple DES #############remove trailing /168 for everything 2008R2/7 and newer
        $wmiq = Get-WmiObject Win32_OperatingSystem -ComputerName $Comp -ErrorAction Stop
        $os = $wmiq.Caption
        if ($os -match "Windows 7" -or $os -match "Windows Server 2008 R2" -or $os -match "2012" -or $os -match "2016") {
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168') #DevSkim: ignore DS106863
            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168',$true) #DevSkim: ignore DS106863
            $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        }
        else {
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168') #DevSkim: ignore DS106863
            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168',$true) #DevSkim: ignore DS106863
            $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        }
    }
}#function disable 3des


Function Enable-3DES {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 14:41:22
    LASTEDIT: 04/23/2018 14:41:22
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
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $Valuedata = 1

    foreach ($comp in $ComputerName) {
        #.
        #. Ciphers
        #.

        #Enable Triple DES #############remove trailing /168 for everything 2008R2/7 and newer
        $wmiq = Get-WmiObject Win32_OperatingSystem -ComputerName $Comp -ErrorAction Stop
        $os = $wmiq.Caption
        if ($os -match "Windows 7" -or $os -match "Windows Server 2008 R2" -or $os -match "2012" -or $os -match "2016") {
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168') #DevSkim: ignore DS106863
            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168',$true) #DevSkim: ignore DS106863
            $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        }
        else {
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168') #DevSkim: ignore DS106863
            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168',$true) #DevSkim: ignore DS106863
            $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        }
    }
}#function enable 3des


Function Disable-DiffieHellman {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 16:38:23
    LASTEDIT: 04/23/2018 16:38:23
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
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $Valuedata = 0

    foreach ($comp in $ComputerName) {
        #.
        #. Ciphers
        #.

        #Disable Diffie-Hellman
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}#function disable diffie-hellman


Function Enable-DiffieHellman {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 16:38:31
    LASTEDIT: 04/23/2018 16:38:31
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
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $Valuedata = 1

    foreach ($comp in $ComputerName) {
        #.
        #. Ciphers
        #.

        #Disable Diffie-Hellman
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}#function enable diffie-hellman


Function Disable-RC4 {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 15:00:09
    LASTEDIT: 04/23/2018 15:00:09
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
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $Valuedata = 0

    foreach ($comp in $ComputerName) {
        #.
        #. Ciphers
        #.

        #Disable RC4
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128')
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128')
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128')
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}#function disable rc4


Function Enable-RC4 {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 15:00:19
    LASTEDIT: 04/23/2018 15:00:19
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
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $Valuedata = 1

    foreach ($comp in $ComputerName) {
        #.
        #. Ciphers
        #.

        #Enable RC4
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128')
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128')
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128')
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}#function enable rc4


function Disable-TLS1.0 { #DevSkim: ignore DS169125,DS440000
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-04-22 11:49:33
    Last Edit: 2021-07-14 23:13:18
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
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $ValueName2 = "DisabledByDefault"
    $ValueData = 0
    $ValueData1 = 1

    foreach ($Comp in $ComputerName) {
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client',$true)
        $SubKey.SetValue($ValueName, $ValueData1, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($ValueName2, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $SubKey2 = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server',$true)
        $SubKey2.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey2.SetValue($ValueName2, $ValueData1, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}


function Enable-TLS1.0 { #DevSkim: ignore DS169125,DS440000
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-04-22 12:03:16
    Last Edit: 2021-07-14 23:14:51
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
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $ValueName2 = "DisabledByDefault"
    $Valuedata = 0
    $Valuedata2 = 1

    foreach ($Comp in $ComputerName) {
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client',$true)
        $SubKey.SetValue($ValueName, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($ValueName2, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $SubKey2 = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server',$true)
        $SubKey2.SetValue($ValueName, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey2.SetValue($ValueName2, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}


function Disable-TLS1.1 { #DevSkim: ignore DS169125,DS440000
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-04-22 19:16:08
    Last Edit: 2021-04-22 19:16:08
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
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $ValueName2 = "DisabledByDefault"
    $Valuedata = 0
    $Valuedata2 = 1

    foreach ($Comp in $ComputerName) {
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($ValueName2, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $SubKey2 = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server',$true)
        $SubKey2.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}


function Enable-TLS1.1 { #DevSkim: ignore DS169125,DS440000
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-04-22 19:16:48
    Last Edit: 2021-04-22 19:16:48
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
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $ValueName2 = "DisabledByDefault"
    $Valuedata = 0
    $Valuedata2 = 1

    foreach ($Comp in $ComputerName) {
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client',$true)
        $SubKey.SetValue($ValueName, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($ValueName2, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $SubKey2 = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server',$true)
        $SubKey2.SetValue($ValueName, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}


function Disable-TLS1.2 { #DevSkim: ignore DS169125,DS440000
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-04-22 19:18:49
    Last Edit: 2021-04-22 19:18:49
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
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $ValueName2 = "DisabledByDefault"
    $Valuedata = 0
    $Valuedata2 = 1

    foreach ($Comp in $ComputerName) {
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($ValueName2, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $SubKey2 = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server',$true)
        $SubKey2.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}


function Enable-TLS1.2 { #DevSkim: ignore DS169125,DS440000
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-04-22 19:19:26
    Last Edit: 2021-04-22 19:19:26
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
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $ValueName2 = "DisabledByDefault"
    $Valuedata = 0
    $Valuedata2 = 1

    foreach ($Comp in $ComputerName) {
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client',$true)
        $SubKey.SetValue($ValueName, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($ValueName2, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $SubKey2 = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server',$true)
        $SubKey2.SetValue($ValueName, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}


function Get-HttpHeaderSetting {
<#
.SYNOPSIS
    Gets the Http Header setting on the current machine.
.DESCRIPTION
    Displays the name and value of Http Header settings on the local computer. Blank entries means the value is not created.
.EXAMPLE
    C:\PS>Get-HttpHeaderSetting
    Example of how to use this cmdlet. Will show Http Header settings on the computer. Will output something similar to this:
    Name       Disabled FullPath
    ----       -------- --------
    Parameters        1 HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    HTTP Header, registry, remediation
.NOTES
    Author: Skyler Hart
    Created: 2022-11-30 23:43:58
    Last Edit: 2022-11-30 23:43:58
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param()

    $schannel = @()
    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\HTTP) {
        $schannel += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\HTTP -Recurse | ForEach-Object {Get-ItemProperty Registry::$_}
    }

    $schannel = $schannel | Select-Object PSPath,Disabled

    $formattedschannel = foreach ($obj in $schannel) {
        $shortpath = $obj.PSPath -replace "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\",""
        $fullpath = $obj.PSPath -replace "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE","HKLM:"
        if ($shortpath -eq "Parameters") {
            [PSCustomObject]@{
                Name = $shortpath
                Disabled = $obj.Disabled
                FullPath = $fullpath
            }#new object
        }
    }
    $formattedschannel
}


function Get-SCHANNELSetting {
<#
.SYNOPSIS
    Gets the SCHANNEL settings on the current machine.
.DESCRIPTION
    Displays the name and value of SCHANNEL settings on the local computer. Blank entries means the value is not created.
.PARAMETER Name
    Used to specify the name of a SCHANNEL setting to display. Uses matching.
.EXAMPLE
    C:\PS>Get-SCHANNELSetting
    Example of how to use this cmdlet. Will show all SCHANNEL settings on the computer. Will output something similar to this:
    Name                                 DisabledByDefault    Enabled FullPath
    ----                                 -----------------    ------- --------
    Ciphers\DES 56/56                                               0 HKLM:\SYSTEM\CurrentControlSet\Control\SecurityPro...
    Ciphers\NULL                                                    0 HKLM:\SYSTEM\CurrentControlSet\Control\SecurityPro.
.EXAMPLE
    C:\PS>Get-SCHANNELSetting -Name Ciphers
    Will show all the Ciphers configured in the SCHANNEL registry settings.
.EXAMPLE
    C:\PS>Get-SCHANNELSetting -Name "TLS 1.0"
    Will show all the TLS 1.0 SCHANNEL registry settings configured on the computer.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    SCHANNEL, registry, remediation
.NOTES
    Author: Skyler Hart
    Created: 2022-09-05 00:24:25
    Last Edit: 2022-09-05 00:56:53
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [Alias('Path')]
        [string]$Name
    )

    $schannel = @()
    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers) {
        $schannel += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers -Recurse | ForEach-Object {Get-ItemProperty Registry::$_}
    }

    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites) {
        $schannel += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites -Recurse | ForEach-Object {Get-ItemProperty Registry::$_}
    }

    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes) {
        $schannel += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes -Recurse | ForEach-Object {Get-ItemProperty Registry::$_}
    }

    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms) {
        $schannel += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms -Recurse | ForEach-Object {Get-ItemProperty Registry::$_}
    }

    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols) {
        $schannel += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols -Recurse | ForEach-Object {Get-ItemProperty Registry::$_}
    }

    $schannel = $schannel | Select-Object PSPath,DisabledByDefault,Enabled

    $formattedschannel = foreach ($obj in $schannel) {
        $shortpath = $obj.PSPath -replace "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\",""
        $fullpath = $obj.PSPath -replace "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE","HKLM:"
        [PSCustomObject]@{
            Name = $shortpath
            DisabledByDefault = $obj.DisabledByDefault
            Enabled = $obj.Enabled
            FullPath = $fullpath
        }#new object
    }

    if (!([string]::IsNullOrWhiteSpace($Name))) {
        $formattedschannel = $formattedschannel | Where-Object {$_.Name -match $Name}
    }
    $formattedschannel
}


function Initialize-GPUpdate {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-16 21:41:53
    Last Edit: 2021-06-16 21:41:53
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        gpupdate.exe /force
    }
    else {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $i = 0
            $number = $ComputerName.length
            foreach ($Comp in $ComputerName) {
                #Progress Bar
                if ($number -gt "1") {
                    $i++
                    $amount = ($i / $number)
                    $perc1 = $amount.ToString("P")
                    Write-Progress -activity "Forcing a GPUpdate" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
                }#if length

                try {
                    $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $Comp -Name Create -ArgumentList "cmd /c gpupdate /force" -ErrorAction Stop #DevSkim: ignore DS104456
                    $info = [PSCustomObject]@{
                        ComputerName = $Comp
                        Status = "GPUpdate Initialized"
                    }#new object
                }
                catch {
                    $info = [PSCustomObject]@{
                        ComputerName = $Comp
                        Status = "Unable to initialize GPUpdate"
                    }#new object
                }
                $info
            }#foreach computer
        }#if admin
        else {Write-Error "Must be ran as admin when running against remote computers"}#not admin
    }#else not local
}


Function Set-FeatureSettingsOverride {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 03/26/2019 21:30:15
    LASTEDIT: 2021-04-22 12:51:51
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
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $RES = @()
    $infos = @()
    $infos += @{
        Value = 'FeatureSettingsOverride'
        Data = 72
    }
    $infos += @{
        Value = 'FeatureSettingsOverrideMask'
        Data = 3
    }


    foreach ($info in $infos) {
        $RES += [PSCustomObject]$info
    }


    $i = 0
    $number = $ComputerName.length
    foreach ($comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Setting remediation values" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        foreach ($RE in $RES) {
            $ValueName = $RE.Value
            $ValueData = $RE.Data
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management')
            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',$true)
            $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        }
    }#foreach computer
}


Function Set-FirefoxAutoUpdate {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-06-20 01:01:26
    LASTEDIT: 2021-06-20 01:08:02
    KEYWORDS:
    REQUIRES:
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter()]
        [Switch]$Enable
    )

    $v1 = 'DisableAppUpdate'
    if ($Enable) {$d = 0}
    else {$d = 1}

    $i = 0
    $number = $ComputerName.length

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        foreach ($comp in $ComputerName) {
            #Progress Bar
            if ($number -gt "1") {
                $i++
                $amount = ($i / $number)
                $perc1 = $amount.ToString("P")
                Write-Progress -activity "Setting Firefox Auto Update value" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
            }#if length

            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Policies\Mozilla\Firefox')
            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Mozilla\Firefox',$true)
            $SubKey.SetValue($v1, $d, [Microsoft.Win32.RegistryValueKind]::DWORD)
        }#foreach computer
    }#if admin
    else {Write-Error "Set-FirefoxAutoUpdate must be ran as administrator"}
}


function Set-MS15124 {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 12/21/2017 12:43:44
    LASTEDIT: 12/21/2017 12:48:58
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
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "iexplore.exe"
    $Valuedata = 1

    foreach ($comp in $ComputerName) {
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING')
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}#function set-ms15-124


function Set-HiveNightmareFix {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-10-19 11:25:39
    Last Edit: 2021-10-19 11:25:39
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        icacls $env:windir\system32\config\*.* /inheritance:e
        vssadmin.exe delete shadows /all
    }
    else {Write-Error "Must be ran as admin"}
}


function Set-PrintNightmareFix {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-07-14 20:47:02
    Last Edit: 2021-10-19 10:39:03
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
        [ValidateNotNullOrEmpty()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [switch]$DisableSpooler
    )

    $v1 = 'NoWarningNoElevationOnInstall'
    $v2 = 'UpdatePromptSettings'
    $v3 = 'RestrictDriverInstallationToAdministrators'
    $d0 = 0
    $d1 = 1

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        foreach ($Comp in $ComputerName) {
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint')
            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',$true)
            $SubKey.SetValue($v1, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',$true)
            $SubKey.SetValue($v2, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',$true)
            $SubKey.SetValue($v3, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

            if ($Comp -eq $env:COMPUTERNAME) {
                if ($DisableSpooler) {
                    Stop-Service -Name Spooler -Force | Out-Null
                    Set-Service -Name Spooler -StartupType Disabled
                }
            }
        }#foreach computer
    }
    else {Write-Error "Must be ran as administrator"}
}


Function Set-RemediationValues {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/08/2018 22:10:17
    LASTEDIT: 2023-11-17 16:58:54
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $v1 = 'iexplore.exe'
    $v2 = 'SchUseStrongCrypto'
    $v3 = 'Enabled'
    $v4 = 'DisabledByDefault'
    $v5 = 'FeatureSettingsOverride'
    $v6 = 'FeatureSettingsOverrideMask'
    $v7 = 'SMB1'

    #PrintNightmare
    $v8 = 'NoWarningNoElevationOnInstall'
    $v9 = 'UpdatePromptSettings'
    $v10 = 'RestrictDriverInstallationToAdministrators'

    # EnableCertPadding
    $CertPadding = 'EnableCertPaddingCheck'

    $d0 = 0
    $d1 = 1
    $d3 = 3
    $d72 = 72 #change to 8264 for systems without hyper-threading
    #value for enabling SCHANNEL things
    #4294967295

    $i = 0
    $number = $ComputerName.length
    foreach ($comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Setting remediation values" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        #regionInternetExplorer
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING',$true)
        $SubKey.SetValue($v1, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING',$true)
        $SubKey.SetValue($v1, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX',$true)
        $SubKey.SetValue($v1, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX',$true)
        $SubKey.SetValue($v1, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionNETFramework
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\.NETFramework\v2.0.50727')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\.NETFramework\v2.0.50727',$true)
        $SubKey.SetValue($v2, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727',$true)
        $SubKey.SetValue($v2, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\.NETFramework\v4.0.30319')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\.NETFramework\v4.0.30319',$true)
        $SubKey.SetValue($v2, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319',$true)
        $SubKey.SetValue($v2, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionSCHANNELProtocols
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols')

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client',$true)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client',$true)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client',$true)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client',$true)
        $SubKey.SetValue($v3, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client',$true)
        $SubKey.SetValue($v4, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client',$true)
        $SubKey.SetValue($v3, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client',$true)
        $SubKey.SetValue($v4, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server',$true)
        $SubKey.SetValue($v3, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client',$true)
        $SubKey.SetValue($v3, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client',$true)
        $SubKey.SetValue($v4, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionSCHANNELCiphers
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/56')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/56',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168')  #DevSkim: ignore DS106863
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168',$true) #DevSkim: ignore DS106863
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56')  #DevSkim: ignore DS106863
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56',$true) #DevSkim: ignore DS106863
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionSCHANNELHashes
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA',$true)
        #$SubKey.SetValue($v3, 4294967295, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #Known Microsoft bug causes this to error out

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5')  #DevSkim: ignore DS126858
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5',$true) #DevSkim: ignore DS126858
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionSCHANNELKeyExchangeAlgorithms
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS',$true)
        #$SubKey.SetValue($v3, 4294967295, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #Known Microsoft bug causes this to error out

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #For local computer, properly set SHA and PKCS
        if ($comp -eq $env:COMPUTERNAME) {
            $filepath = $PSScriptRoot.Substring(0,($PSScriptRoot.Length-15)) + "\SHAandPKCS.reg"
            reg import $filepath
        }

        #regionSessionManager
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',$true)
        $SubKey.SetValue($v5, $d72, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',$true)
        $SubKey.SetValue($v6, $d3, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionSMB
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',$true)
        $SubKey.SetValue($v7, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        if ($comp -eq $env:COMPUTERNAME) {
            $os = (Get-OperatingSystem).OS
            if ($os -match "2008" -or $os -match "Windows 7") {
                #Disable SMB1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 –Force
                sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
                sc.exe config mrxsmb10 start= disabled
                Start-Sleep 3

                #Enable SMB2
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 1 –Force
                sc.exe config lanmanworkstation depend= bowser/mrxsmb10/mrxsmb20/nsi
                sc.exe config mrxsmb20 start= auto
            }
            else {
                #Disable SMB1
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
                Start-Sleep 3

                #Enable SMB2
                Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
            }
        }
        #endregion

        # PrintNightmare
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',$true)
        $SubKey.SetValue($v8, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',$true)
        $SubKey.SetValue($v9, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',$true)
        $SubKey.SetValue($v10, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        # Enable Cert Padding Check
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\Cryptography\Wintrust\Config')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\Cryptography\Wintrust\Config',$true)
        $SubKey.SetValue($CertPadding, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config',$true)
        $SubKey.SetValue($CertPadding, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        # Network Level Authentication
        Set-NLA -ComputerName $comp
    }#foreach computer
}


#need to finish https://support.microsoft.com/en-us/help/2696547/how-to-detect-enable-and-disable-smbv1-smbv2-and-smbv3-in-windows-and
Function Set-SMBv1 {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 01/31/2018 09:32:17
    LASTEDIT: 02/09/2018 00:47:46
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Switch]$On
    )

    #Determine OS
    $os = (Get-OperatingSystem).OS

    if ($On) {
        if ($os -match "2008" -or $os -match "7") {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 1 –Force
        }
        else {
            Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
        }
    }
    else {
        if ($os -match "2008" -or $os -match "7") {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 –Force
        }
        else {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
        }
    }
}


Function Set-SMBv1Fix {
<#
   .Synopsis
    Enables SMB v1.
   .Description
    Turns SMBv1 on. While this fix action turns SMBv1 on, group policy can turn SMBv1 off, which is counted on.
   .Example
    Set-SMBv1Fix COMP1
    Sets the fix action on COMP1. After the fix action is applied, COMP1 will need to be rebooted.
   .Example
    Set-SMBv1Fix
    Sets the fix action on the local computer. After the fix action is applied, the local computer will need to be rebooted.
   .Parameter ComputerName
    Specifies the computer or computers
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 12/18/2018 09:36:43
    LASTEDIT: 12/18/2018 10:25:19
    KEYWORDS: fix action, fix, SMB, SMBv1
    REQUIRES:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "SMB1"
    $Valuedata = 1
    $i = 0
    $number = $ComputerName.length

    foreach ($comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Setting SMBv1 registry fix" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        Invoke-Command -ComputerName $comp -ScriptBlock {Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart} #DevSkim: ignore DS104456

        #([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters') #DevSkim: ignore DS106863
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',$true) #DevSkim: ignore DS106863
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}


function Get-NetworkLevelAuthentication {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-18 15:28:10
    Last Edit: 2020-04-18 15:28:10
    Keywords: Network, NLA, Network Level Authentication, RDP, Remote Desktop
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Get-NLA')]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    foreach ($Comp in $ComputerName) {
        try {
            $ErrorActionPreference = "Stop"
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Comp)
            $key = $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp")
            [Bool]$ua = $key.GetValue('UserAuthentication')

            [PSCustomObject]@{
                ComputerName = $Comp
                UserAuthentication = $ua
            }#new object
        }
        catch [System.Management.Automation.MethodInvocationException] {
            $err = $_.Exception.message.Trim()
            if ($err -match "network path") {
                $ua = "Could not connect"
            }
            elseif ($err -match "access is not allowed") {
                $ua = "Insufficient permissions"
            }
            else {
                $ua = "Unknown error"
            }
            [PSCustomObject]@{
                ComputerName = $Comp
                UserAuthentication = $ua
            }#new object
        }
        catch {
            [PSCustomObject]@{
                ComputerName = $Comp
                UserAuthentication = "Unknown error"
            }#new object
        }
    }
}


function Set-NetworkLevelAuthentication {
<#
.PARAMETER Disable
    Specifies to disable Network Level Authentication. Without this NLA will be enabled.
.EXAMPLE
    C:\PS>Set-NetworkLevelAuthentication
    Will enable network level authentication on the local computer.
.EXAMPLE
    C:\PS>Set-NetworkLevelAuthentication -Disable
    Will disable network level authentication on the local computer.
.EXAMPLE
    C:\PS>Set-NetworkLevelAuthentication -ComputerName COMP1
    Will enable network level authentication on the computer COMP1.
.NOTES
    Author: Skyler Hart
    Created: 2020-04-18 16:01:02
    Last Edit: 2020-04-18 16:01:02
    Keywords: Network, NLA, Network Level Authentication, RDP, Remote Desktop
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Set-NLA')]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(
            Mandatory=$false
        )]
        [Switch]$Disable
    )

    foreach ($Comp in $ComputerName) {
        try {
            $ErrorActionPreference = "Stop"
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Comp)
            $key = $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",$true)
            if ($Disable) {
                $key.SetValue('UserAuthentication', 0, [Microsoft.Win32.RegistryValueKind]::DWORD)
            }
            else {
                $key.SetValue('UserAuthentication', 1, [Microsoft.Win32.RegistryValueKind]::DWORD)
            }
        }
        catch [System.Management.Automation.MethodInvocationException] {
            $err = $_.Exception.message.Trim()
            if ($err -match "network path") {
                $ua = "Could not connect"
            }
            elseif ($err -match "access is not allowed") {
                $ua = "Insufficient permissions"
            }
            else {
                $ua = "Unknown error"
            }
            [PSCustomObject]@{
                ComputerName = $Comp
                UserAuthentication = $ua
            }#new object
        }
    }
}


###########################################################################
###########################################################################
##                                                                       ##
##                              MECM/SCCM                                ##
##                                                                       ##
###########################################################################
###########################################################################

function Get-SCCMInstallStatus {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Get-SCCMInstallStatus
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Get-SCCMInstallStatus -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    The functionality (keywords) that best describes this cmdlet
.NOTES
    Author: Skyler Hart
    Created: 2023-03-29 23:01:59
    Last Edit: 2023-03-29 23:01:59
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias()]
    param(
        [Parameter(
            #HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false#,
            #Position=0,
            #ValueFromPipeline = $true
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateCount(min,max)]
        [ValidateLength(min,max)]
        [ValidateSet('Info','Error','Warning','One','Two','Three')]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $status = Invoke-Command -ComputerName $ComputerName -ScriptBlock {#DevSkim: ignore DS104456
        try {
            $CCMUpdate = get-wmiobject -query "SELECT * FROM CCM_SoftwareUpdate" -namespace "ROOT\ccm\ClientSDK" -ErrorAction stop
            if (@($CCMUpdate | Where-Object {$_.EvaluationState -eq 2 -or $_.EvaluationState -eq 3 -or $_.EvaluationState -eq 4 -or $_.EvaluationState -eq 5 -or $_.EvaluationState -eq 6 -or $_.EvaluationState -eq 7 -or $_.EvaluationState -eq 11 }).length -ne 0) {
                [pscustomobject]@{Computer = $env:computername; UpdateStatus = "3 - In Progress"}
            } elseif(@($CCMUpdate | Where-Object {$_.EvaluationState -eq 13}).length -ne 0) {
                [pscustomobject]@{Computer = $env:computername; UpdateStatus = "4 - Update Failed"}
            } elseif(@($CCMUpdate | Where-Object { $_.EvaluationState -eq 8 -or $_.EvaluationState -eq 9 -or $_.EvaluationState -eq 10 }).length -ne 0) {
                [pscustomobject]@{Computer = $env:computername; UpdateStatus = "2 - Requires Reboot"}
            } elseif(@($CCMUpdate | Where-Object { $_.EvaluationState -eq 0 -or $_.EvaluationState -eq 1}).length -ne 0) {
                [pscustomobject]@{Computer = $env:computername; UpdateStatus = "0 - Updates Available"}
            } else {
                [pscustomobject]@{Computer = $env:computername; UpdateStatus = "1 - Completed"}
            }
        } catch {
            [pscustomobject]@{Computer = $env:computername; UpdateStatus = "5 - Error Reading Update History"}
        }
    } -ErrorAction SilentlyContinue
    ForEach ($server in $servers) {
        if ($status.computer -notcontains $server) {
            $status += [pscustomobject]@{Computer = $server;UpdateStatus = "6 - Remote Connection Failure"}
        }
    }
    $status | Select-Object Computer,UpdateStatus | Sort-Object -Property UpdateStatus,Computer
}


function Get-SCCMPendingUpdate {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Get-SCCMPendingUpdate
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Get-SCCMPendingUpdate -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    The functionality (keywords) that best describes this cmdlet
.NOTES
    Author: Skyler Hart
    Created: 2023-03-29 22:31:19
    Last Edit: 2023-03-29 22:31:19
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias()]
    param(
        [Parameter(
            #HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false#,
            #Position=0,
            #ValueFromPipeline = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    Process {
        foreach ($Comp in $ComputerName) {
            if ($Comp -eq $env:COMPUTERNAME) {
                $Updates = (Get-WmiObject -Query "SELECT * FROM CCM_SoftwareUpdate" -namespace "ROOT\ccm\ClientSDK")
                foreach ($Update in $Updates) {
                    [PSCustomObject]@{
                        ComputerName = $Update.PSComputerName
                        Update = $Update.Name
                    }#new object
                }
            }
            else {
                Invoke-Command -ComputerName $Comp -ScriptBlock {#DevSkim: ignore DS104456
                    $Updates = (Get-WmiObject -Query "SELECT * FROM CCM_SoftwareUpdate" -namespace "ROOT\ccm\ClientSDK")
                    foreach ($Update in $Updates) {
                        [PSCustomObject]@{
                            ComputerName = $Update.PSComputerName
                            Update = $Update.Name
                        }#new object
                    }
                }
            }#not local
        }
    }
}

function Install-SCCMUpdate {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Install-SCCMUpdate
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Install-SCCMUpdate -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    The functionality (keywords) that best describes this cmdlet
.NOTES
    Author: Skyler Hart
    Created: 2023-03-29 22:42:28
    Last Edit: 2023-03-29 22:42:28
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias()]
    param(
        [Parameter(
            #HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false#,
            #Position=0,
            #ValueFromPipeline = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    Begin {}
    Process {
        foreach ($Comp in $ComputerName) {
            if ($Comp -eq $env:COMPUTERNAME) {
                ([wmiclass]'ROOT\ccm\ClientSDK:CCM_SoftwareUpdatesManager').InstallUpdates([System.Management.ManagementObject[]] (get-wmiobject -query 'SELECT * FROM CCM_SoftwareUpdate' -namespace 'ROOT\ccm\ClientSDK'))
            }
            else {
                Invoke-Command -ComputerName $Comp -ScriptBlock {#DevSkim: ignore DS104456
                    ([wmiclass]'ROOT\ccm\ClientSDK:CCM_SoftwareUpdatesManager').InstallUpdates([System.Management.ManagementObject[]] (get-wmiobject -query 'SELECT * FROM CCM_SoftwareUpdate' -namespace 'ROOT\ccm\ClientSDK'))
                }
            }#not local
        }
    }
    End {}
}

function Open-CMTrace {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-22 17:29:32
    Last Edit: 2021-06-22 17:29:32
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    if (Test-Path "c:\Windows\ccm\CMTrace.exe") {
        Start-Process "c:\Windows\ccm\CMTrace.exe"
    }
    elseif (Test-Path "C:\ProgramData\OSI\CMTrace.exe") {
        Start-Process "C:\ProgramData\OSI\CMTrace.exe"
    }
    elseif (Test-Path "J:\Patches\CMTrace.exe") {
        Start-Process "J:\Patches\CMTrace.exe"
    }
    else {
        Write-Error "Cannot find CMTrace.exe"
    }
}

function Open-ConfigurationManager {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 2020-09-28 09:31:24
    KEYWORDS:
    REQUIRES:
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('configmgr')]
    param()
    if (Test-Path "C:\Windows\CCM\SMSCFGRC.cpl") {Start-Process C:\Windows\CCM\SMSCFGRC.cpl}
    elseif (Test-Path "C:\Windows\SysWOW64\CCM\SMSCFGRC.cpl") {Start-Process C:\Windows\SysWOW64\CCM\SMSCFGRC.cpl}
    elseif (Test-Path "C:\Windows\System32\CCM\SMSCFGRC.cpl") {Start-Process C:\Windows\System32\CCM\SMSCFGRC.cpl}
    else {Throw "Configuration Manager not found"}
}


function Open-FileWithCMTrace {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-22 17:35:23
    Last Edit: 2021-06-22 17:35:23
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Open-Log')]
    param(
        [Parameter(
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('File','Path')]
        [string[]]$FileName
    )
    $Continue = $false
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
            Start-Process $app -ArgumentList $file
        }
    }
}


function Open-RunAdvertisedPrograms {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 21:10:15
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
    [Alias('rap')]
    param()
    if (Test-Path "C:\Windows\SysWOW64\CCM\SMSRAP.cpl") {Start-Process C:\Windows\SysWOW64\CCM\SMSRAP.cpl}
    elseif (Test-Path "C:\Windows\System32\CCM\SMSRAP.cpl") {Start-Process C:\Windows\System32\CCM\SMSRAP.cpl}
    else {Throw "Run Advertised Programs not found"}
}


function Open-SoftwareCenter {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-09-28 09:36:19
    Last Edit: 2020-09-28 09:36:19
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('SoftwareCenter','SCCM','MECM')]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [ValidateSet('AvailableSoftware','Updates','OSD','InstallationStatus','Compliance','Options')]
        [ValidateNotNullOrEmpty()]
        [Alias('Tab')]
        [string]$Page = "AvailableSoftware"
    )

    Start-Process softwarecenter:Page=$Page
}


function Open-SCCMLogsFolder {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 2020-09-28 09:25:48
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator on remote computers
.LINK
    https://wanderingstag.github.io
#>
<#--
CAS.log
Provides information about the process of downloading software updates to the local cache and cache management.

CIAgent.log
Provides information about processing configuration items, including software updates.

LocationServices.log
Provides information about the location of the WSUS server when a scan is initiated on the client.

PatchDownloader.log
Provides information about the process for downloading software updates from the update source to the download destination on the site server.

Note
On 64-bit operating systems and on 32-bit operating systems without Configuration Manager 2007 installed, PatchDownloader.log is created in the server logs directory. On 32-bit operating systems, if the Configuration Manager 2007 client is installed, and on the synchronization host computer for the Inventory Tool for Microsoft Updates, PatchDownloader.log is created in the client logs directory.

PolicyAgent.log
Provides information about the process for downloading, compiling, and deleting policies on client computers.

PolicyEvaluator
Provides information about the process for evaluating policies on client computers, including policies from software updates.

RebootCoordinator.log
Provides information about the process for coordinating system restarts on client computers after software update installations.

ScanAgent.log
Provides information about the scan requests for software updates, what tool is requested for the scan, the WSUS location, and so on.

ScanWrapper
Provides information about the prerequisite checks and the scan process initialization for the Inventory Tool for Microsoft Updates on Systems Management Server (SMS) 2003 clients.

SdmAgent.log
Provides information about the process for verifying and decompressing packages that contain configuration item information for software updates.

ServiceWindowManager.log
Provides information about the process for evaluating configured maintenance windows.

smscliUI.log
Provides information about the Configuration Manager Control Panel user interactions, such as initiating an Software Updates Scan Cycle from the Configuration Manager Properties dialog box, opening the Program Download Monitor, and so on.

SmsWusHandler
Provides information about the scan process for the Inventory Tool for Microsoft Updates on SMS 2003 client computers.

StateMessage.log
Provides information about when software updates state messages are created and sent to the management point.

UpdatesDeployment.log
Provides information about the deployment on the client, including software update activation, evaluation, and enforcement. Verbose logging shows additional information about the interaction with the client user interface.

UpdatesHandler.log
Provides information about software update compliance scanning, and the download and installation of software updates on the client.

UpdatesStore.log
Provides information about the compliance status for the software updates that were assessed during the compliance scan cycle.

WUAHandler.log
Provides information about when the Windows Update Agent on the client searches for software updates.

WUSSyncXML.log
Provides information about the Inventory Tool for Microsoft Updates synchronization process.
This log is only on the client computer configured as the synchronization host for the Inventory Tool for Microsoft Updates.
--#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    foreach ($comp in $ComputerName) {
        if (Test-Path \\$comp\c$\Windows\CCM\Logs) {
            explorer \\$comp\c$\Windows\CCM\Logs
        }
        else {
            try {
                $wmiq = Get-WmiObject win32_operatingsystem -ComputerName $comp -ErrorAction Stop | Select-Object OSArchitecture
                if ($wmiq -like "*64-bit*") {
                    explorer \\$comp\c$\Windows\SysWOW64\CCM\Logs
                }
                else {
                    explorer \\$comp\c$\Windows\System32\CCM\Logs
                }
            }#try
            catch {
                Throw "Unable to connect to $comp"
            }
        }
    }#foreach computer
}


function Open-WindowsUpdateLog {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 05/03/2016 20:06:39
    LASTEDIT: 08/07/2018 15:53:00
    KEYWORDS:
    REQUIRES:
.LINK
    https://wanderingstag.github.io
#>
<#--
Found on the Configuration Manager Client computer, by default, in %windir%.

WindowsUpdate.log
Provides information about when the Windows Update Agent connects to the WSUS server and retrieves the
software updates for compliance assessment and whether there are updates to the agent components.
--#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Continues querying system(s)."
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","Cancels the command."
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

    $title = "Alert!"
    $message = "This command doesn't work on Windows 10 or newer computers. Do you want to continue running it?"
    $result = $host.ui.PromptForChoice($title, $message, $options, 1)
    switch ($result) {
        0 {
            Write-Output "Yes"
        }
        1 {
            Write-Output "No"
        }
    }

    if ($result -eq 0) {
        foreach ($comp in $ComputerName) {
            try {
                notepad \\$comp\c$\Windows\WindowsUpdate.log
            }
            catch {
                Throw "Unable to connect to $comp"
            }
        }
    }#if yes then continue
    else {
        #do nothing
    }
}


Function Restore-WindowsUpdate {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-12-03 19:41:37
    LASTEDIT: 2021-12-03 19:41:37
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {dism.exe /Online /Cleanup-image /Restorehealth}
    else {Write-Error "Must be ran as admin"}
}


function Start-SCCMUpdateScan {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Start-SCCMUpdateScan
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Start-SCCMUpdateScan -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    The functionality (keywords) that best describes this cmdlet
.NOTES
    Author: Skyler Hart
    Created: 2023-03-29 21:50:02
    Last Edit: 2023-03-29 21:50:02
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias()]
    param(
        [Parameter(
            #HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false#,
            #Position=0,
            #ValueFromPipeline = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    Process {
        foreach ($Comp in $ComputerName) {
            if ($Comp -eq $env:COMPUTERNAME) {
                Get-WmiObject -Query "SELECT * FROM CCM_UpdateStatus" -Namespace "root\ccm\SoftwareUpdates\UpdatesStore" | ForEach-Object {
                    if($_.ScanTime -gt $ScanTime) { $ScanTime = $_.ScanTime }
                }; $LastScan = ([System.Management.ManagementDateTimeConverter]::ToDateTime($ScanTime)); $LastScan;
	            if(((get-date) - $LastScan).minutes -ge 10) {
		            [void]([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000113}');
		            ([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000108}'); "Update scan and evaluation"
	            }
            }
            else {
                Invoke-Command -ComputerName $Comp -ScriptBlock {#DevSkim: ignore DS104456
                    Get-WmiObject -Query "SELECT * FROM CCM_UpdateStatus" -Namespace "root\ccm\SoftwareUpdates\UpdatesStore" | ForEach-Object {
                        if($_.ScanTime -gt $ScanTime) { $ScanTime = $_.ScanTime }
                    }; $LastScan = ([System.Management.ManagementDateTimeConverter]::ToDateTime($ScanTime)); $LastScan;
                    if(((get-date) - $LastScan).minutes -ge 10) {
                        [void]([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000113}');
                        ([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000108}'); "Update scan and evaluation"
                    }
                }
            }#not local
        }#foreach comp
    }
}

###########################################################################
###########################################################################
##                                                                       ##
##                                 HBSS                                  ##
##                                                                       ##
###########################################################################
###########################################################################
Function Get-ENSStatus {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/10/2019 21:57:28
    LASTEDIT: 09/25/2019 14:43:59
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
    [Alias('ENS','Get-ENSInfo','ESS','Get-ESSInfo')]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    #Set variables needed for overall script
    $i = 0
    $number = $ComputerName.length
    [int32]$version = $PSVersionTable.PSVersion.Major
    $hname = $host.Name
    $64na = 'SOFTWARE\\WOW6432Node\\Network Associates\\ePolicy Orchestrator\\Agent'
    $64ens = 'SOFTWARE\\WOW6432Node\\Network Associates\\TVD\\Shared Components\\Framework'
    $32ens = 'SOFTWARE\\Network Associates\\TVD\\Shared Components\\Framework'
    $d = $env:USERDNSDOMAIN
    $dn = $d.Split('.') | Select-Object -Last 1

    #For each computer, check ENS
    foreach ($comp in $ComputerName) {
        #Set variables required per computer
        Clear-Variable -Name value2,reg,key,key2,datold,daysdatold,daysold,ensversion,epolist,epoinfo,ePOServers,ePOServerList,lasc,lascd,luc,lucd,name -ErrorAction SilentlyContinue | Out-Null

        $continue = $false
        $ensinstalled = $false

        #Progress Bar... Computers checked
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting ENS status. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#progress bar

        #Make sure running at least PowerShell v3
        if ($version -gt 2 -or $hname -like "ServerRemote*") {

            #try 64 if fails then try 32-bit and if that fails then mark as unable to connect
            try {
                $ErrorActionPreference = "Stop"
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                $key = $reg.OpenSubKey($64na)
                try {
                    $key2 = $reg.OpenSubKey($64ens)
                    $ensinstalled = $true
                }
                catch {
                    $ensinstalled = $false
                }

                $epolist = $key.GetValue('ePOServerList')

                if ($ensinstalled -eq $true) {
                    [string]$luc = $key2.GetValue('LastUpdateCheck')
                    [string]$lasc = $key2.GetValue('LastASCI')
                    $ensversion = $key2.GetValue('Version')

                    if ([string]::IsNullOrWhiteSpace($epolist)) {
                        $ensinstalled = "Partial - not functional"
                    }

                    $continue = $true
                }
            }
            catch {
                try {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                    $key = $reg.OpenSubKey($32ens)
                    $value2 = $key.GetValue('CurrentVersion')
                    $value2 | Out-Null
                    $continue = $true
                }
                catch {
                    $value2 = $null
                    $continue = $false
                }
            }

            if ($continue) {
                $epoinfo = $epolist.Split('|')
                $epoinfo = $epoinfo.Split(';')
                $ePOServers = $epoinfo | Where-Object {$_ -match $dn}
                foreach ($ePOServer in $ePOServers) {
                    $name = $null
                    $name = $ePOServer.Substring(0, $ePOServer.IndexOf('.'))
                    if ([string]::IsNullOrWhiteSpace($ePOServerList)) {
                        $ePOServerList = $name
                    }
                    else {
                        $ePOServerList = $ePOServerList + ", " + $name
                    }
                }
                $ePOServerList = $ePOServerList.Trim()

                $lucd = [datetime]::ParseExact($luc, 'yyyyMMddHHmmss', $null)
                $lascd = [datetime]::ParseExact($lasc, 'yyyyMMddHHmmss', $null)

                #Perform check to see if DAT is out of date
                if ($lucd -eq $null) {
                    [string]$ldfj = "20000101"
                    $lucd = [datetime]::ParseExact($ldfj, 'yyyyMMdd', $null)
                }
                #$today = get-date
                #$daysold = $today - $lucd
                #if ($daysold -gt $datdaysold) {$datout = "Yes"}
                #else {$datout = "No"}
                #$daysdatold = $daysold.Days
            }

            #Create the object data
            [PSCustomObject]@{
                ComputerName = $comp
                FrameworkInstalled = $ensinstalled
                FrameworkVersion = $ensversion
                ePOServerList = $ePOServerList
                LastServerComms = $lascd
                LastSecurityUpdateCheck = $lucd

            }
        }#if host version gt 2
        else {
            Write-Output "  PowerShell must be at least version 3. Current version:  $version"
        }#else host version
    }#foreach computer
}#get ensstatus


# Working. To Do:
# Get-HBSSStatus (Get-Content .\computers.txt) | Format-Table -AutoSize
# Get-HBSSStatus (Get-Content .\computers.txt) | Export-Csv .\hbssstatus.csv -NoTypeInformation
function Get-HBSSStatus {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:11:01
    LASTEDIT: 09/25/2019 14:42:42
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
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    #Set variables needed for overall script
    $i = 0
    $number = $ComputerName.length
    $64keyname = 'SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion'
    $64hbsskey = 'SOFTWARE\\Wow6432Node\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\VIRUSCAN8800'
    $64hipskey = 'SOFTWARE\\Wow6432Node\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\HOSTIPS_8000'
    $64epokey = 'SOFTWARE\\Wow6432Node\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\EPOAGENT3000'
    $32hbsskey = 'SOFTWARE\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\VIRUSCAN8800'
    $32hipskey = 'SOFTWARE\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\HOSTIPS_8000'
    $32epokey = 'SOFTWARE\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\EPOAGENT3000'
    $version = $host.Version.Major
    $hname = $host.Name
    $datdaysold = "4" #specific number of days old the DAT can be
    $EngineVersion = "5900*" #has to be a generic version such as 5700* or 5800*
    $PatchesInstalled = "12" #specific number of patches that should be installed
    $AntiVirusVersion = "8.8*" #has to be a generic version such as 8.8* or 8.9* or even 9.1*
    $HBSSFrameworkVersion = "5.6.1.308" #specific framework version that is required

    $64enskey = 'SOFTWARE\WOW6432Node\Network Associates\TVD\Shared Components\Framework'

    #For each computer, check HBSS
    foreach ($comp in $ComputerName) {
        #Set variables required per computer
        Clear-Variable value2,reg,reg2,reg3,key,key2,key3,datdateval,DATVersionval,DATVersion,engversionval,hotfixverval,versval,hipsverval,frameworkverval,outdated,engoutdated,hfoutdated,avoutdated,fwoutdated,ePOServers | Out-Null

        #Progress Bar... Computers checked
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting HBSS status. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#progress bar

        #Make sure running at least PowerShell v3
        if ($version -gt "2" -or $hname -like "ServerRemote*") {
            #64-bit test
            try {
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                $key = $reg.OpenSubKey($64keyname)
                $value2 = $key.GetValue('CurrentVersion')
            }
            catch {$value2 = $null}

#region 64-bit tasks
            if ($null -ne $value2) {
                #Get HBSS values (not ENS)
                try {
                    $reg2 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                    $key2 = $reg2.OpenSubkey($64hbsskey)
                    $datdateval = $key2.GetValue('DatDate')
                    $DATVersionval = $key2.GetValue('DATVersion')
                    $engversionval = $key2.GetValue('EngineVersion')
                    $hotfixverval = $key2.GetValue('HotFixVersions')
                    $versval = $key2.GetValue('Version')

                    #Check registry for HIPS values
                    try {
                        $reg3 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                        $key3 = $reg3.OpenSubkey($64hipskey)
                        $hipsverval = $key3.GetValue('Version')
                    }
                    catch {
                        $hipsverval = "Not Installed"
                    }

                    #Check registry for HBSS Framework values
                    try {
                        $reg4 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                        $key4 = $reg4.OpenSubkey($64epokey)
                        $frameworkverval = $key4.GetValue('Version')
                        $type = "HBSS"
                        $type | Out-Null
                    }
                    catch {
                        $frameworkverval = "Not Installed"
                        $type = $null
                    }
                }
                catch {
                    $datdateval = $null
                    $DATVersionval = $null
                    $engversionval = $null
                    $hotfixverval = $null
                    $versval = $null
                    $type = $null
                }
                #Get ENS values
            }#if 64-bit
#endregion 64bit tasks


#region 32-bit tasks
            if ($null -eq $value2) {
                #See if HBSS has been installed
                #if (Test-Path "$psdpath\Program Files\Common Files\McAfee\Engine\OldEngine\config.dat") {$hbssstatus = "Yes"}
                #else {$hbssstatus = "No"}


                #Check registry for Virus Scan values
                try {
                    $reg2 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                    $key2 = $reg2.OpenSubkey($32hbsskey)
                    $datdateval = $key2.GetValue('DatDate')
                    $DATVersionval = $key2.GetValue('DATVersion')
                    $engversionval = $key2.GetValue('EngineVersion')
                    $hotfixverval = $key2.GetValue('HotFixVersions')
                    $versval = $key2.GetValue('Version')
                }
                catch {
                    $datdateval = $null
                    $DATVersionval = $null
                    $engversionval = $null
                    $hotfixverval = $null
                    $versval = $null
                }


                #Check registry for HIPS values
                try {
                    $reg3 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                    $key3 = $reg3.OpenSubkey($32hipskey)
                    $hipsverval = $key3.GetValue('Version')
                }
                catch {
                    $hipsverval = "Not Installed"
                }


                #Check registry for HBSS Framework values
                try {
                    $reg4 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                    $key4 = $reg4.OpenSubkey($32epokey)
                    $frameworkverval = $key4.GetValue('Version')
                }
                catch {
                    $frameworkverval = "Not Installed"
                }

            }
#endregion 32bit tasks

            #Perform check to see if DAT is out of date
            if ($null -eq $datdateval) {$datdateval = "20000101"}
            $today = get-date -f yyyyMMdd
            $daysold = $today - $datdateval
            if ($daysold -gt $datdaysold) {$outdated = "Yes"}
            else {$outdated = "No"}

            #Perform check to see if Engine is out of date
            if ($engversionval -notlike $EngineVersion) {$engoutdated = "Yes"}
            else {$engoutdated = "No"}

            #Peform check to see if patches are needed
            if ($hotfixverval -ne $PatchesInstalled) {$hfoutdated = "Yes"}
            else {$hfoutdated = "No"}

            #Perform check to see if Antivirus version 8.8
            if ($versval -notlike $AntiVirusVersion) {$avoutdated = "Yes"}
            else {$avoutdated = "No"}

            #Perform check to see if HBSS Framework is up-to-date
            if ($frameworkverval -eq $HBSSFrameworkVersion) {$fwoutdated = "No"}
            else {$fwoutdated = "Yes"}

            #Take the extra 0's off the end of the DAT version
            if ($null -eq $DatVersionval) {$DatVersionval = "0000.0000"}
            $DATVersion = $DATVersionval.substring(0,4)

            #Create the object data
            [PSCustomObject]@{
                Computer = "$comp"
                DatDate = "$datdateval"
                DatVersion = "$DATVersion"
                DATOutdated = "$outdated"
                EngineVersion = "$engversionval"
                EngineOutdated = "$engoutdated"
                PatchesInstalled = "$hotfixverval"
                PatchesNeeded = "$hfoutdated"
                McAfeeVersion = "$versval"
                McAfeeOutdated = "$avoutdated"
                HIPSVersion = "$hipsverval"
                HBSS_Framework = "$frameworkverval"
                HBSSOutdated = "$fwoutdated"

            } | Select-Object Computer,DatDate,DatVersion,DATOutdated,EngineVersion,EngineOutdated,PatchesInstalled,PatchesNeeded,McAfeeVersion,McAfeeOutdated,HIPSVersion,HBSS_Framework,HBSSOutdated
        }#if host version gt 2
        else {
            Write-Output "  PowerShell must be at least version 3. Current version:  $version  `n  Click OK to continue.  "
            [void][reflection.assembly]::LoadWithPartialName("System.Windows.Forms")
            [System.Windows.Forms.MessageBox]::Show("                               Error:`n`nPowerShell must be at least version 3.`n`nCurrent version is:  $version");
        }#else host version
    }#foreach computer
}#get hbssstatus


function Open-HBSSStatusMonitor {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 8/7/2017
    LASTEDIT: 08/18/2017 21:11:12
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
    [Alias('HBSS')]
    param()
    if (Test-Path "$env:ProgramFiles\McAfee\Agent\cmdagent.exe") {
        Start-Process "$env:ProgramFiles\McAfee\Agent\cmdagent.exe" /s
    }
    elseif (Test-Path "$env:ProgramFiles\McAfee\Common Framework\CmdAgent.exe") {
        Start-Process "$env:ProgramFiles\McAfee\Common Framework\CmdAgent.exe" /s
    }
    elseif (Test-Path "${env:ProgramFiles(x86)}\McAfee\Common Framework\CmdAgent.exe") {
        Start-Process "${env:ProgramFiles(x86)}\McAfee\Common Framework\CmdAgent.exe" /s
    }
    else {
       Throw "HBSS Client Agent not found"
    }
}


function Open-McAfeeVirusScanConsole {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 8/7/2017
    LASTEDIT: 08/18/2017 21:11:16
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    if (Test-Path "$env:ProgramFiles\McAfee\VirusScan Enterprise\mcconsol.exe") {
        Start-Process "$env:ProgramFiles\McAfee\VirusScan Enterprise\mcconsol.exe"
    }
    else {Start-Process "${env:ProgramFiles(x86)}\McAfee\VirusScan Enterprise\mcconsol.exe"}
}


function Open-HIPSLog {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 8/7/2017
    LASTEDIT: 08/18/2017 21:11:22
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    explorer "$env:ProgramData\McAfee\Host Intrusion Prevention"
}


Function Uninstall-HBSS {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/11/2019 15:37:31
    LASTEDIT: 09/11/2019 16:20:07
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
    [Alias('Uninstall-ENS','Uninstall-ESS')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files\McAfee\Agent\x86\FrmInst.exe" /Remove=Agent /Silent' -ErrorAction Stop | Out-Null
                Start-Sleep -Seconds 30
                Get-WmiObject -Class Win32_Product -Filter "Name like 'McAfee Agent%'" -ComputerName $Comp -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "McAfee ENS (HBSS) Agent"
                    Status = "Removal Initialized"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "McAfee ENS (HBSS) Agent"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


function Update-McAfeeSecurity {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-10-30 03:14:47
    Last Edit: 2021-10-30 03:14:47
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    $fpath = "${env:ProgramFiles(x86)}\McAfee\Endpoint Security\Threat Prevention\amcfg.exe"
    if (Test-Path $fpath) {
        Start-Process $fpath -ArgumentList "/update"
    }
    else {
        Write-Error "McAfee Endpoint Security Threat Protection not installed"
    }
}


#Need to fix for new paths
function Sync-HBSSWithServer {
<#
.NOTES
    Author: Skyler Hart
    Created: Sometime before 8/7/2017
    Last Edit: 2020-04-13 20:37:25
    Keywords: HBSS
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Sync-HBSS','Sync-ENS','Sync-ESS')]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    foreach ($Comp in $ComputerName) {
        try {
            $wmiq = Get-WmiObject win32_operatingsystem -ComputerName $Comp -ErrorAction Stop | Select-Object OSArchitecture

            if ($wmiq -like "*64-bit*") {
                #Collecting and sending Props
                Write-Output "Collecting and sending Props on $Comp"
                Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c "C:\Program Files (x86)\McAfee\Common Framework\CmdAgent.exe" /P' -ErrorAction Stop | Out-Null #DevSkim: ignore DS104456
                Start-Sleep -s 10

                #Checking for new policies
                Write-Output "Checking for new policies on $Comp"
                Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c "C:\Program Files (x86)\McAfee\Common Framework\CmdAgent.exe" /C' -ErrorAction Stop | Out-Null #DevSkim: ignore DS104456
                Start-Sleep -s 10

                #Enforcing new policies
                Write-Output "Enforcing new policies on $Comp"
                Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c "C:\Program Files (x86)\McAfee\Common Framework\CmdAgent.exe" /E' -ErrorAction Stop | Out-Null #DevSkim: ignore DS104456
                Start-Sleep -s 15

                Write-Output "HBSS client on $Comp should be updating."
            }#if wmiq 64bit
            else {
                #Collecting and sending Props
                Write-Output "Collecting and sending Props on $Comp"
                Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c "C:\Program Files\McAfee\Common Framework\CmdAgent.exe" /P' -ErrorAction Stop | Out-Null #DevSkim: ignore DS104456
                Start-Sleep -s 10

                #Checking for new policies
                Write-Output "Checking for new policies on $Comp"
                Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c "C:\Program Files\McAfee\Common Framework\CmdAgent.exe" /C' -ErrorAction Stop | Out-Null #DevSkim: ignore DS104456
                Start-Sleep -s 10

                #Enforcing new policies
                Write-Output "Enforcing new policies on $Comp"
                Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c "C:\Program Files\McAfee\Common Framework\CmdAgent.exe" /E' -ErrorAction Stop | Out-Null #DevSkim: ignore DS104456
                Start-Sleep -s 15

                Write-Output "HBSS client on $Comp should be updating."
            }#else 32bit
        }#try 32or64 bit
        catch {
            Throw "Unable to connect to $Comp"
        }#catch 32or64 bit
    }#foreach comp
}


###########################################################################
###########################################################################
##                                                                       ##
##                                Splunk                                 ##
##                                                                       ##
###########################################################################
###########################################################################
function Get-SplunkStatus {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-08-13 21:52:22
    Last Edit: 2021-08-13 21:52:22
    Keywords:
    Other:
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
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    if ($ComputerName -eq $env:COMPUTERNAME) {
        $info = Get-Service -Name SplunkForwarder -ComputerName $comp
        [PSCustomObject]@{
            ComputerName = $comp
            SplunkStatus = ($info.Status)
        }#new object
    }
    else {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $i = 0
            $number = $ComputerName.length
            foreach ($Comp in $ComputerName) {
                #Progress Bar
                if ($number -gt "1") {
                    $i++
                    $amount = ($i / $number)
                    $perc1 = $amount.ToString("P")
                    Write-Progress -activity "Getting status of Splunk Service" -status "Computer $i ($comp) of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
                }#if length
                $info = Get-Service -Name SplunkForwarder -ComputerName $comp
                [PSCustomObject]@{
                    ComputerName = $comp
                    SplunkStatus = ($info.Status)
                }#new object
            }
        }
        else {Write-Error "Must be ran as administrator"}
    }
}


Export-ModuleMember -Alias '*' -Function '*'
