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
    .Notes
        AUTHOR: Skyler Hart
        CREATED: 2017-08-18 20:48:07
        LASTEDIT: 2023-02-11 13:48:55

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
    Copy-Item -Path $PSScriptRoot\Resources\powershell.json -Destination $env:APPDATA\Code\User\snippets\powershell.json -Force
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
    .NOTES
        Author: Skyler Hart
        Created: 2021-11-01 23:18:30
        Last Edit: 2021-11-01 23:18:30
        Keywords:

    .LINK
        https://wanderingstag.github.io
    #>

    $repo = ($Global:WSToolsConfig).VSCodeExtRepo
    $dst = "$env:userprofile\.vscode\extensions"

    if (!(Test-Path $dst)) {
        New-Item -Path $env:userprofile\.vscode -ItemType Directory -Name extensions -Force
    }

    robocopy $repo $dst /mir /mt:4 /r:4 /w:15 /njh /njs
}


function Copy-VSCodeSettingsToProfile {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2021-11-01 22:14:14
        Last Edit: 2021-11-01 22:14:14
        Keywords: WSTools, Visual Studio Code, Preferences

    .LINK
        https://wanderingstag.github.io
    #>
    $vscs = ($Global:WSToolsConfig).VSCodeSettingsPath
    if (!(Test-Path $env:APPDATA\Code\User)) {
        New-Item -Path $env:APPDATA\Code -ItemType Directory -Name User -Force
    }

    $i = Get-Content $vscs

    if (Test-Path "$env:APPDATA\Code\User\settings.json") {
        Set-Content -Path "$env:APPDATA\Code\User\settings.json" -Value $i -Force
    }
    else {
        Add-Content -Path "$env:APPDATA\Code\User\settings.json" -Value $i -Force
    }
}


function Disable-RDP {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2021-02-27 11:44:34
        Last Edit: 2021-02-27 11:47:07
        Requires:
            -RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 1}
    else {throw {"Must be ran as admin"}}
}


function Disable-ServerManager {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2020-05-08 23:18:39
        Last Edit: 2020-10-06 13:25:11

    .LINK
        https://wanderingstag.github.io
    #>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask}
    else {Write-Output "Must run this function as admin"}
}


function Enable-RDP {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2020-05-08 23:21:17
        Last Edit: 2021-02-27 11:47:20
        Requires:
            -RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0}
    else {throw {"Must be ran as admin"}}
}


function Enable-ServerManager {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2021-12-16 21:29:35
        Last Edit: 2021-12-16 21:29:35

    .LINK
        https://wanderingstag.github.io
    #>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {Get-ScheduledTask -TaskName ServerManager | Enable-ScheduledTask}
    else {Write-Output "Must run this function as admin"}
}


function Format-IPList {
    <#
    .SYNOPSIS
        Takes a list of IPs and sorts them.

    .DESCRIPTION
        Enter two or more IPs and it will sort them in the appropriate order.

    .PARAMETER IPs
        Used to specify the IP Addresses that you wish to sort.

    .EXAMPLE
        C:\PS>Format-IPList 127.0.0.5,127.0.0.100,10.0.1.5,10.0.1.1,10.0.1.100
        Example of how to use this cmdlet

    .EXAMPLE
        C:\PS>Format-IPList -IPs 127.0.0.5, 127.0.0.100, 10.0.1.5, 10.0.1.1, 10.0.1.100
        Another example of how to use this cmdlet but with a parameter or switch.

    .EXAMPLE
        C:\PS>Sort-IPs 127.0.0.5, 127.0.0.100, 10.0.1.5, 10.0.1.1, 10.0.1.100
        Using the alias Sort-IPs we can format the list of IPs.

    .INPUTS
        System.Net.IPAddress

    .OUTPUTS
        System.Array

    .COMPONENT
        WSTools

    .FUNCTIONALITY
        IPAddress, IPv4, Sort, List, Format

    .NOTES
        Author: Skyler Hart
        Created: 2023-10-11 10:58:24
        Last Edit: 2023-10-11 11:14:45

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [Alias('Sort-IPList','Sort-IPs')]
    param(
        [Parameter(
            HelpMessage = "Enter one or more IPs separated by commas.",
            Mandatory=$true,
            ValueFromPipeline = $true
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('IPAddresses')]
        [IPAddress[]]$IPs
    )

    Process {
        $IPs.IPAddressToString | Sort-Object {
            # Extract the first 4 numbers from the current line
            [int[]] $octets = [regex]::Matches( $_, '\d+' )[ 0..3 ].Value

            # Create tuple that consists of the octets
            [Tuple]::Create( $octets[0], $octets[1], $octets[2], $octets[3] )
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
    $slist = Import-Csv $PSScriptRoot\Resources\CommandListModules.csv

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
        $clm = Import-Csv $PSScriptRoot\Resources\CommandListModules.csv
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
    Start-Process powershell.exe -ArgumentList "`$host.ui.RawUI.WindowTitle = 'WSTools Taskbar App'; & '$PSScriptRoot\Resources\WSTools_SystemTrayApp.ps1'"
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

Export-ModuleMember -Alias '*' -Function '*'
