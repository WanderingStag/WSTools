function Add-JavaException {
<#
.NOTES
    Author: Skyler Hart
    Created: 2019-03-20 10:40:11
    Last Edit: 2019-03-20 10:40:11
    Keywords: Java, Exception
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the address of the website.",
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('Site','URL','Address')]
        [string]$Website
    )

    Add-Content -Path "$env:USERPROFILE\AppData\LocalLow\Sun\Java\Deployment\security\exception.sites" -Value "$Website"
}


function Copy-PowerShellJSON {
<#
.SYNOPSIS
    Enables PowerShell Snippets in Visual Studio Code.
.DESCRIPTION
    Copies the powershell.json file from the WSTools module folder to %AppData%\Roaming\Code\User\snippets for the currently logged on user.
.EXAMPLE
    C:\PS>Copy-PowerShellJSON
    Copies the powershell.json file from the WSTools module folder to %AppData%\Roaming\Code\User\snippets for the currently logged on user.
.NOTES
    Author: Skyler Hart
    Created: 2020-04-13 22:44:11
    Last Edit: 2020-04-17 14:24:07
    Keywords: WSTools, Visual Studio Code, PowerShell, JSON, Preferences, snippets, code blocks
.LINK
    https://wstools.dev
#>
    Copy-Item -Path $PSScriptRoot\powershell.json -Destination $env:APPDATA\Code\User\snippets\powershell.json
}
New-Alias -Name "Update-PowerShellJSON" -Value Copy-PowerShellJSON
New-Alias -Name "Set-PowerShellJSON" -Value Copy-PowerShellJSON


function Clear-ImproperProfileCopy {
<#
   .Synopsis
    Clears Application Data folder that was improperly copied which happens when copy and pasting a profile.
   .Description
    Copies nested Application Data folders to a higher level (by default to C:\f2) and deletes them.
   .Example
    Clear-ImproperProfileCopy -Source \\fileserver\example\user -Destination E:\f2
    Clears nested Application Data folders from \\fileserver\example\user. Uses E:\f2 as the folder for clearing.
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
    https://wstools.dev
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
        Write-Host "Completed Pass $i" -ForegroundColor Gray
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
    Clears harddrive space by clearing temp files and caches. Invoke method does not clear as many locations. #DevSkim: ignore DS104456
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
    Clears temp and cache data on the computers listed in the file c:\complist.txt using the Invoke-WMIMethod command. #DevSkim: ignore DS104456
   .Parameter ComputerName
    Specifies the computer or computers to clear space on
   .Parameter InvokeMethod
    Specifies the computer or computers to clear space on using the Invoke-WMIMethod command #DevSkim: ignore DS104456
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 05/19/2017 20:16:47
    LASTEDIT: 07/22/2019 14:21:15
    KEYWORDS: Delete, temp, patches, cache, prefetch, SCCM
    REMARKS: Needs to be ran as a user that has administrator rights
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
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
                #Remove C:\Temp files
                if (Test-Path CS:\Temp) {
                    Set-Location "CS:\Temp"
                    if ((Get-Location).Path -eq "CS:\Temp") {
                        Write-Output "Removing items in C:\Temp on $Comp"
                        Remove-Item * -recurse -force
                    }
                }

                #Remove Windows Temp file
                if (Test-Path CS:\Windows\Temp) {
                    Set-Location "CS:\Windows\Temp"
                    if ((Get-Location).Path -eq "CS:\Windows\Temp") {
                        Write-Output "Removing items in C:\Windows\Temp on $Comp"
                        Remove-Item * -recurse -force
                    }
                }

                #Remove Prefetch files
                if (Test-Path CS:\Windows\Prefetch) {
                    Set-Location "CS:\Windows\Prefetch"
                    if ((Get-Location).Path -eq "CS:\Windows\Prefetch") {
                        Write-Output "Removing items in C:\Windows\Prefetch on $Comp"
                        Remove-Item * -recurse -force
                    }
                }

                #Remove temp files from user profiles
                if (Test-Path CS:\Users) {
                    Set-Location "CS:\Users"
                    if ((Get-Location).Path -eq "CS:\Users") {
                        Write-Output "Removing temp items in C:\Users on $Comp"
                        Remove-Item “.\*\Appdata\Local\Temp\*” -recurse -force
                    }
                }

                #Remove cached SCCM files
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

                #Remove Windows update cache
                if (Test-Path CS:\Windows\SoftwareDistribution\Download) {
                    Set-Location "CS:\Windows\SoftwareDistribution\Download"
                    if ((Get-Location).Path -eq "CS:\Windows\SoftwareDistribution\Download") {
                        Write-Output "Removing items in C:\Windows\SoftwareDistribution\Download on $Comp"
                        Remove-Item * -recurse -force
                    }
                }

                #Remove old patches. This is more of something local to where Skyler works. If you don't need it, remove it or comment it out.
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
            }#try
            catch {
                Write-Output "Unable to connect to computer: $Comp" -ForegroundColor Red
            }
        }#if Invoke False
#endregion PSDrive Method

#region Invoke Method
        else {
            try {
                $wmiq = Get-WmiObject win32_operatingsystem -ComputerName $Comp -ErrorAction Stop | Select-Object OSArchitecture
                #Clear SCCM cache
                if ($wmiq -like "*64-bit*") {
                    $invoke = Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c del "C:\Windows\SysWOW64\ccm\cache\*.*" /f /q && FOR /D %p IN ("C:\Windows\SysWOW64\ccm\cache\*") DO rmdir "%p" /q' -ErrorAction SilentlyContinue #DevSkim: ignore DS104456
                    $id32 = $invoke.ProcessId
                    Write-Output "Waiting for deletion of files in C:\Windows\SysWOW64\ccm\cache to complete"
                    do {(Start-Sleep -Seconds 10)}
                    until ((Get-WMIobject -Class Win32_process -ComputerName $Comp) | Where-Object {$_.ProcessID -eq $id32})
                }#if64bit
                else {
                    $invoke = Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c del "C:\Windows\System32\ccm\cache\*.*" /f /q && FOR /D %p IN ("C:\Windows\System32\ccm\cache\*") DO rmdir "%p" /q' -ErrorAction SilentlyContinue #DevSkim: ignore DS104456
                    $id32 = $invoke.ProcessId
                    Write-Output "Waiting for deletion of files in C:\Windows\System32\ccm\cache to complete"
                    do {(Start-Sleep -Seconds 10)}
                    until ((Get-WMIobject -Class Win32_process -ComputerName $Comp) | Where-Object {$_.ProcessID -eq $id32})
                }#elseif32bit
                $invoke = Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c del "C:\Windows\ccmcache\*.*" /f /q && FOR /D %p IN ("C:\Windows\ccmcache\*") DO rmdir "%p" /q' -ErrorAction SilentlyContinue #DevSkim: ignore DS104456
                $id32 = $invoke.ProcessId
                Write-Output "Waiting for deletion of files in C:\Windows\ccmcache to complete"
                do {(Start-Sleep -Seconds 10)}
                until ((Get-WMIobject -Class Win32_process -ComputerName $Comp) | Where-Object {$_.ProcessID -eq $id32})

                #Remove C:\Temp files
                $invoke = Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c del "C:\Temp\*.*" /f /q && FOR /D %p IN ("C:\Temp\*") DO rmdir "%p" /q' -ErrorAction SilentlyContinue #DevSkim: ignore DS104456
                $id32 = $invoke.ProcessId
                Write-Output "Waiting for deletion of files in C:\Temp to complete"
                do {(Start-Sleep -Seconds 10)}
                until ((Get-WMIobject -Class Win32_process -ComputerName $Comp) | Where-Object {$_.ProcessID -eq $id32})

                #Remove Windows Temp files
                $invoke = Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c del "C:\Windows\Temp\*.*" /f /q && FOR /D %p IN ("C:\Windows\Temp\*") DO rmdir "%p" /q' -ErrorAction SilentlyContinue #DevSkim: ignore DS104456
                $id32 = $invoke.ProcessId
                Write-Output "Waiting for deletion of files in C:\Windows\Temp to complete"
                do {(Start-Sleep -Seconds 10)}
                until ((Get-WMIobject -Class Win32_process -ComputerName $Comp) | Where-Object {$_.ProcessID -eq $id32})

                #Remove Prefetch files
                $invoke = Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c del "C:\Windows\Prefetch\*.*" /f /q && FOR /D %p IN ("C:\Windows\Prefetch\*") DO rmdir "%p" /q' -ErrorAction SilentlyContinue #DevSkim: ignore DS104456
                $id32 = $invoke.ProcessId
                Write-Output "Waiting for deletion of files in C:\Windows\Prefetch to complete"
                do {(Start-Sleep -Seconds 10)}
                until ((Get-WMIobject -Class Win32_process -ComputerName $Comp) | Where-Object {$_.ProcessID -eq $id32})

                #Remove Windows Update cache
                $invoke = Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c del "C:\Windows\SoftwareDistribution\Download\*.*" /f /q && FOR /D %p IN ("C:\Windows\SoftwareDistribution\Download\*") DO rmdir "%p" /q' -ErrorAction SilentlyContinue #DevSkim: ignore DS104456
                $id32 = $invoke.ProcessId
                Write-Output "Waiting for deletion of files in C:\Windows\SoftwareDistribution\Download to complete"
                do {(Start-Sleep -Seconds 10)}
                until ((Get-WMIobject -Class Win32_process -ComputerName $Comp) | Where-Object {$_.ProcessID -eq $id32})
            }
            catch {
                Write-Output "Unable to connect to computer: $Comp" -ForegroundColor Red
            }
        }#invoke method
#endregion Invoke Method
    }#foreach computer
    Set-Location $path
}


function Disable-ServerManager {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-05-08 23:18:39
    Last Edit: 2020-10-06 13:25:11
    Keywords:
.LINK
    https://wstools.dev
#>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask}
    else {Write-Host "Must run this function as admin"}
}


function Enable-RDP {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-05-08 23:21:17
    Last Edit: 2020-05-08 23:21:17
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
}


Function Get-ComputerHWInfo {
<#
   .Synopsis
    Gets hardware information of local or remote computer(s.)
   .Description
    Get Manufacturer, Model, Model Version, BIOS vendor, BIOS version, and release date of BIOS update on local or remote computer.
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
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName = $true
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

        New-Object -TypeName PSObject -Property @{
            ComputerName = $comp
            Manufacturer = $SM
            Model = $SPN
            ModelVersion = $SV
            BIOSVendor = $BV
            BIOSVersion = $Bver
            BIOSReleaseDate = $BRD
        }#new object
    }#foreach computer
}


Function Get-ComputerModel {
<#
   .Parameter ComputerName
    Specifies the computer or computers
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 2018-06-20 13:05:09
    LASTEDIT: 2020-08-31 21:40:19
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
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )
    Begin {}
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

                switch ($csi.Model) {
                    "Virtual Machine" {$PorV = "Virtual"}
                    "VMware Virtual Platform" {$PorV = "Virtual"}
                    "VirtualBox" {$PorV = "Virtual"}
                    default {$PorV = "Physical"}
                }

                switch ($csi.PCSystemType) {
                    2 {$type = "Laptop/Tablet"}
                    default {$type = "Desktop"}
                }

                $manu = $csi.Manufacturer
                $model = $csi.Model

                $info = New-Object -TypeName PSObject -Property @{
                    ComputerName = $comp
                    DomainRole = $dr
                    Manufacturer = $manu
                    Model = $model
                    PorV = $PorV
                    Type = $type
                }#new object
                $info | Select-Object ComputerName,DomainRole,Manufacturer,Model,PorV,Type
            }
            catch {
                $na = "NA"
                New-Object -TypeName PSObject -Property @{
                    ComputerName = $comp
                    DomainRole = "Unable to connect"
                    Manufacturer = $na
                    Model = $na
                    PorV = $na
                    Type = $na
                }#new object
                $info | Select-Object ComputerName,DomainRole,Manufacturer,Model,PorV,Type
            }
        }
    }
    End {}
}
New-Alias -Name "Get-Model" -Value Get-ComputerModel


function Get-DirectoryStat {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-08-09 10:07:49
    Last Edit: 2020-08-09 21:35:14
    Keywords:
.LINK
    https://wstools.dev
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
            $stats = New-Object PsObject -Property @{Directory = $null; FileCount = 0; SizeBytes = [long]0; SizeKB = 0; SizeMB = 0; SizeGB = 0; Over100MB = 0; Over1GB = 0; Over5GB = 0}
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


#Look up "root\WMI" or "root\CCM" using Get-ComputerWMINamespaces
Function Get-WMIClass {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:05:10
    LASTEDIT: 09/21/2017 13:05:10
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName = $true
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
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string]$ComputerName = "$env:COMPUTERNAME",

        [string]$Namespace = "root"
    )

    Get-WmiObject -Namespace $Namespace -Class "__Namespace" -ComputerName $ComputerName | Select-Object Name
}


function Get-Drive {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-19 20:29:58
    Last Edit: 2020-04-19 20:29:58
    Keywords:
.LINK
    https://wstools.dev
#>
    Get-PSDrive -Name *
}
New-Alias -Name "Drive" -Value Get-Drive


function Get-Error {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-18 16:42:46
    Last Edit: 2020-04-18 19:08:44
    Keywords:
.LINK
    https://wstools.dev
#>
	[CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [int32]$HowMany
    )

    $Errors = $Global:Error

    if ($null -eq $HowMany -or $HowMany -eq "") {
        [int32]$HowMany = $Errors.Count
    }

    $n = $HowMany - 1
    $logs = $Errors[0..$n]
    $info = @()

    foreach ($log in $logs) {
        $scriptn = $log.InvocationInfo.ScriptName
        $line = $log.InvocationInfo.ScriptLineNumber
        $char = $log.InvocationInfo.OffsetInline
        $command = $log.InvocationInfo.Line.Trim()
        $exc = $log.Exception.GetType().fullname
        $mes = $log.Exception.message.Trim()
        $info += New-Object -TypeName PSObject -Property @{
            Exception = "[$exc]"
            Message = $mes
            Script = $scriptn
            Command = $command
            Line = $line
            Character = $char
        } | Select-Object Exception,Message,Script,Command,Line,Character
    }
    $info
}
New-Alias -Name "Error" -Value Get-Error


Function Get-ExpiredCertsComputer {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/04/2018 20:46:38
    LASTEDIT: 10/04/2018 21:08:31
    KEYWORDS:
.LINK
    https://wstools.dev
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
    KEYWORDS:
.LINK
    https://wstools.dev
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
    KEYWORDS:
    REQUIRES:
        Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    $ninfo = @()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {$Role = 'Admin'}
    else {$Role = 'User'}

    if ($Role -eq "Admin") {
        $info = (dism /online /get-capabilities | Where-Object {$_ -like "Capability Identity*" -or $_ -like "State*"})
        $idents = ($info | Where-Object {$_ -like "Capa*"}).Split(' : ') | Where-Object {$_ -ne "Capability" -and $_ -ne "Identity" -and $_ -ne $null -and $_ -ne ""}
        $state = $info | Where-Object {$_ -like "State*"}
        $state = $state -replace "State : "

        $i = 0
        foreach ($ident in $idents) {
            $state2 = $state[$i]
            $ninfo = New-Object -TypeName PSObject -Property @{
                CapabilityIdentity = $ident
                State = $state2
            }#new object
            $ninfo | Select-Object CapabilityIdentity,State
            $i++
        }
    }#if admin
    else {
        Write-Error "Not admin. Please run PowerShell as admin."
    }
}


Function Get-IEVersion {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:06:15
    LASTEDIT: 09/21/2017 13:06:15
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName = $true
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
        New-Object psobject -Property @{
            ComputerName = $comp
            IEVersion = $value
        }#new object
    }#foreach computer
}


Function Get-MTU {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:06:23
    LASTEDIT: 2020-05-23 17:39:06
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName = $true
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
                if ($null -eq $mtu -or $mtu -eq "") {
                    $mtu = "1500"
                }
                $domain = $RegKey2.GetValue('Domain')
                $dhcpaddr = $RegKey2.GetValue('DhcpIPAddress')
                $ipaddr = $RegKey2.GetValue('IPAddress')
                $ip = $null
                if ($null -eq $dhcpaddr -or $dhcpaddr -eq "") {
                    $ip = $ipaddr[0]
                }
                else {
                    $ip = $dhcpaddr
                }

                if ($null -eq $ip -or $ip -eq "" -or $ip -like "0*") {
                    #don't report
                }
                else {
                    $adprop = $netad | Where-Object {$_.GUID -eq $int}
                    New-Object -TypeName PSObject -Property @{
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
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName = $true
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
                    New-Object psobject -Property @{
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
            New-Object psobject -Property @{
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
    LASTEDIT: 2020-08-31 21:56:19
    KEYWORDS: Operating System, OS
    REMARKS: For local computer it can be ran as user. For remote computers, it needs to be ran as a user who has administrative rights on the remote computer.
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName = $true
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

                if ($OS -like "Windows 10*" -or $OS -match "2016" -or $OS -match "2019") {
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

                    if ($value -like "Windows 10*" -or $value -match "2016" -or $value -match "2019") {
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
                    }#if os win 10, srv 2016, or srv 2019
                    else {$OS = $value}

                    #Create objects
                    #New-Object psobject -Property @{
                    #    ComputerName = $comp
                    #    OS = $OS
                    #    Bit = $bit
                    #    Build = $build
                    #}#newobject
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
            New-Object -TypeName PSObject -Property @{
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

            if ($value -like "Windows 10*" -or $value -match "2016" -or $value -match "2019") {
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
            }#if os win 10, srv 2016, or srv 2019
            else {$OS = $value}

            #Create objects
            New-Object psobject -Property @{
                ComputerName = $comp
                OS = $OS
                Bit = $bit
                Build = $build
            }#newobject
        }#elseif registry
    }#continue -eq $true
    else {
        New-Object psobject -Property @{
            ComputerName = $comp
            OS = "Error: not running PowerShell as admin"
            Bit = $null
            Build = $null
        }#newobject
    }
    }#foreach comp
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
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true
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

            #Get Drives
            $drives = @()
            $d = $bi | Select-String -Pattern 'Volume '
            $drives += $d | ForEach-Object {
                $_.ToString().Trim().Substring(0,8) -replace "Volume ",""
            }#foreach drive

            #Get Size
            $size = @()
            $si = $bi | Select-String -Pattern 'Size'
            $size += $si | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }#foreach size

            #Get BitLocker Version
            $ver = @()
            $v = $bi | Select-String -Pattern 'BitLocker Version'
            $ver += $v | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }#foreach version

            #Get Status
            $status = @()
            $s = $bi | Select-String -Pattern 'Conversion Status'
            $status += $s | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }#foreach status

            #Get Percent Encrypted
            $per = @()
            $p = $bi | Select-String -Pattern 'Percentage Encrypt'
            $per += $p | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }#foreach percentage

            #Get Encryption Method
            $em = @()
            $e = $bi | Select-String -Pattern 'Encryption Method'
            $em += $e | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }#foreach encryption method

            #Get Protection Status
            $ps = @()
            $pi = $bi | Select-String -Pattern 'Protection Status'
            $ps += $pi | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }#foreach pro status

            #Get Lock Status
            $ls = @()
            $li = $bi | Select-String -Pattern 'Lock Status'
            $ls += $li | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }#foreach Lock Status

            #Get ID Field
            $id = @()
            $ii = $bi | Select-String -Pattern 'Identification Field'
            $id += $ii | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }#foreach ID

            #Get Key Protectors
            $key = @()
            $k = $bi | Select-String -Pattern 'Key Protect'
            $key += $k | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }#foreach
        }#try
        catch {
            Write-Host "Unable to connect to $Comp"
            $status = "Insuffiect permissions or unable to connect"
        }

        $num = $drives.Length
        do {
            $overall += New-Object -TypeName PSObject -Property @{
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
    }#foreach comp
    $overall | Select-Object ComputerName,Drive,Size,BitLockerVersion,Status,PercentEncrypted,EncryptionMethod,ProtectionStatus,LockStatus,ID_Field,KeyProtectors | Sort-Object ComputerName,Drive
}


Function Get-ProcessorCapability {
<#
.NOTES
    Author: Skyler Hart
    Created: Sometime before 8/7/2017
    Last Edit: 2020-04-18 22:46:31
    Keywords:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName = $true
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
        $info = New-Object psobject -Property @{
            ComputerName = $comp
            CurrentBit = $curbit
            CapableOf = $capof
            Architecture = $strCpuArchitecture
        }#newobject
        $info | Select-Object ComputerName,Architecture,CurrentBit,CapableOf
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
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            Position=0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
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
    foreach ($comp in $ComputerName) {
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
                elseif ($os -match "2016" -or $os -match "Windows 10") {$maxver = "51"}
                elseif ($os -match "2019") {$maxver = "51"}

                if ($ver -lt $maxver) {$status = "Outdated"}
                elseif ($ver -ge $maxver) {$status = "Current"}
                else {$ver = "NA"}

                $compinfo += New-Object -TypeName PSObject -Property @{
                    ComputerName = $comp
                    InstalledPowerShellVersion = $ver
                    Status = $status
                    HighestSupportedVersion = $maxver
                    OS = $os
                }#new object
            }
            catch {
                $compinfo += New-Object -TypeName PSObject -Property @{
                    ComputerName = $comp
                    InstalledPowerShellVersion = "Unable to connect"
                    Status = "NA"
                    HighestSupportedVersion = "NA"
                    OS = "NA"
                }#new object
            }
        }
    }
    $compinfo | Select-Object ComputerName,InstalledPowerShellVersion,Status,HighestSupportedVersion,OS
}
New-Alias -Name "Get-PowerShellVersion" -Value Get-PSVersion


Function Get-PublicIP {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 05:25:00
    LASTEDIT: 08/18/2017 20:44:24
    KEYWORDS:
.LINK
    https://wstools.dev
#>
        (Resolve-DnsName -Name myip.opendns.com -Server resolver1.opendns.com).IPAddress
}


Function Get-SerialNumber {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 11/02/2018 12:11:03
    LASTEDIT: 11/02/2018 12:20:44
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            Position=0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
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
            $info = New-Object -TypeName PSObject -Property @{
                ComputerName = $comp
                SerialNumber = $sn
            }#new object
        }
        catch {
            $info = New-Object -TypeName PSObject -Property @{
                ComputerName = $comp
                SerialNumber = "NA"
            }#new object
        }

        $info
    }
}
New-Alias -Name "Get-SN" -Value Get-SerialNumber


Function Get-ShutdownLog {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/28/2019 22:13:23
    LASTEDIT: 08/29/2019 00:17:09
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            Position=0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
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
    $info = @()

    #Search Each Computer
    foreach ($comp in $ComputerName) {
        $info = $null
        $info = @()
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

            $info += New-Object -TypeName PSObject -Property @{
                ComputerName = $comp
                Time = $time
                Status = $st
                Type = $type
                Program = $program
                User = $user
                Reason = $reason
            }#new object
        }#foreach event found

        $info | Select-Object ComputerName,Time,Type,Status,User,Program,Reason | Select-Object -First $MostRecent
    }#foreach computer
}


Function Get-SysInternals {
<#
    .Synopsis
        Download the SysInternals Suite
    .Description
        Downloads the SysInternals Suite. Several customizable options included.
    .Example
        Get-SysInternals
        Downloads the most recent zip file to c:\temp\SysinternalsSuite.zip, extracts it to c:\temp\SysInternalsSuite, copies the files to $env:userprofile\Downloads\SysInternals.
    .Example
        Get-SysInternals -PlaceIn "C:\Windows\System32"
        Downloads the most recent zip file to c:\temp\SysinternalsSuite.zip, extracts it to c:\temp\SysInternalsSuite, copies the files to C:\Windows\System32.
    .Parameter zipPath
        Specifies the folder path to save the zip file to.
    .Parameter tempFolder
        Specifies where to save the extracted temporary files to
    .Parameter PlaceIn
        Specifies the folder path of where to save the extracted files
    .Parameter url
        Specifies the download link for the SysInternals Suite.
    .Notes
        AUTHOR: Skyler Hart
        CREATED: 2017-08-19 19:11:47
        LASTEDIT: 2020-08-20 10:43:45
        KEYWORDS: SysInternals, tools, utilities
        REQUIRES:
            #Requires running as administrator in some instances, primarily if saving to a system path
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "SysInternals is the name of the application."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
        [string]$zipPath = "c:\temp",

        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
        [string]$tempFolder = "c:\temp\SysInternalsSuite",

        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
        [string]$PlaceIn = "$env:userprofile\Downloads\SysInternals",

        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
        [string]$url = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
    )

    $zipname = $zipPath + "\SysinternalsSuite.zip"
    $continue = $false

    if (!(Test-Path $PlaceIn)) {mkdir $PlaceIn | Out-Null}
    if (!(Test-Path $zipPath)) {mkdir $zipPath | Out-Null}
    if (!(Test-Path $tempFolder)) {mkdir $tempFolder | Out-Null}

    $ErrorActionPreference = "Stop"
    Write-Host "Downloading $url to $zipPath"
    try {
        Write-Host "--Trying System.Net.WebClinet"
        $web = New-Object System.Net.WebClient
        $web.DownloadFile($url, $zipPath)
        $continue = $true
    }
    catch {
        try {
            Write-Host "--Trying BitsTransfer"
            Start-BitsTransfer -Source $url -Destination $zipPath -ErrorAction Stop
            $continue = $true
        }
        catch {
            Write-Host "--Trying Invoke WebRequest"
            Invoke-WebRequest -Uri $url -OutFile $zipPath
            $continue = $true
        }
    }

    if ($continue) {
        Write-Host "Extracting $zipname to $tempFolder"
        try {
            Add-Type -assembly 'System.IO.Compression.FileSystem'
            [System.IO.Compression.ZipFile]::ExtractToDirectory($zipname, $tempFolder)

            try {
                Write-Host "Copying files from $tempFolder to $PlaceIn"
                Copy-Item "$tempFolder\*.*" $PlaceIn
            }
            catch {
                Write-Host "Failed to copy items from $tempFolder to $PlaceIn" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "Failed extracting zip file" -ForegroundColor Red
        }
    }#continue
    else {
        Write-Host "Failed to download SysInternalsSuite from https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite" -ForegroundColor Red
    }
}


Function Get-UpTime {
<#
.NOTES
    Author: Skyler Hart
    Created: 2017-08-18 20:42:41
    Last Edit: 2020-07-07 15:29:12
    Keywords:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName = $true
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
            $info = New-Object psobject -Property @{
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
            $info = New-Object psobject -Property @{
                ComputerName = $Comp
                LastBoot = $bootup
                Total = ""
                Days = ""
                Hours = ""
                Minutes = ""
                Seconds = ""
            }#newobject
        }#catch
        $info | Select-Object ComputerName,LastBoot,Total,Days,Hours,Minutes,Seconds
    }#foreach comp
}


function Get-UpdateHistory {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-05-23 20:44:28
    Last Edit: 2020-06-16 13:48:53
    Keywords:
.LINK
    https://wstools.dev
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

        $obj = New-Object -TypeName PSObject -Property @{
            ComputerName = $env:computername
            Date = ($e.Date)
            Result = $Result
            KB = (([regex]::match($e.Title,'KB(\d+)')).Value)
            Title = ($e.Title)
            Category = $Cat
            ClientApplicationID = ($e.ClientApplicationID)
            Description = ($e.Description)
            SupportUrl = ($e.SupportUrl)
        } | Select-Object ComputerName,Date,Result,KB,Title,Category,ClientApplicationID,Description,SupportUrl

        $obj
    }#foreach event in history

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

            $obj = New-Object -TypeName PSObject -Property @{
                ComputerName = $comp
                Date = ($e.Date)
                Result = $Result
                KB = (([regex]::match($e.Title,'KB(\d+)')).Value)
                Title = ($e.Title)
                Category = $Cat
                ClientApplicationID = ($e.ClientApplicationID)
                Description = ($e.Description)
                SupportUrl = ($e.SupportUrl)
            } | Select-Object ComputerName,Date,Result,KB,Title,Category,ClientApplicationID,Description,SupportUrl

            $obj
        }#foreach event in history
    }#foreach comp
#>
}


function Save-MaintenanceReport {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-06-16 14:39:04
    Last Edit: 2020-09-28 11:28:46
    Keywords:
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
    $info = Get-ChildItem $UHPath | Where-Object {$_.LastWriteTime -gt $stime} | Select-Object FullName -ExpandProperty FullName
    $finfo = @()
    foreach ($file in $info) {
        $fi = import-csv $file
        $finfo += $fi
    }
    $finfo | Select-Object Date,ComputerName,KB,Result,Title,Description,Category,ClientApplicationID,SupportUrl | Where-Object {$_.Date -gt $Days} | Sort-Object ComputerName | Export-Csv $sp -NoTypeInformation
}


function Save-UpdateHistory {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-06-15 13:03:22
    Last Edit: 2020-09-28 11:29:05
    Keywords:
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
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [int32]$Days = ((Get-Date -Format yyyyMMdd) - ((Get-Date -Format yyyyMMdd).Substring(0,6) + "01"))
    )
    $UHPath = ($Global:WSToolsConfig).UHPath + "\" + $env:computername + ".csv"
    $info = Get-UpdateHistory -Days $Days
    $info | Export-Csv $UHPath -Force
}


function Get-WindowsSetupLog {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 03/18/2019 15:43:03
    LASTEDIT: 08/28/2019 22:06:44
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName = $true
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

            foreach ($winevent in $winevents) {
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

                    $info += New-Object -TypeName PSObject -Property @{
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
            $info += New-Object -TypeName PSObject -Property @{
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
New-Alias -Name "Get-UpdateStatus" -Value Get-WindowsSetupLog
New-Alias -Name "Get-UpdateLog" -Value Get-WindowsSetupLog


Function Get-WSToolsAlias {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 01/31/2018 23:42:55
    LASTEDIT: 01/31/2018 23:42:55
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    Get-Alias | Where-Object {$_.Source -eq "WSTools"}
}
New-Alias -Name "WSToolsAliases" -Value Get-WSToolsAlias


Function Get-WSToolsCommand {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 01/31/2018 23:52:54
    LASTEDIT: 01/31/2018 23:52:54
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    $commands = (Get-Module WSTools | Select-Object ExportedCommands).ExportedCommands
    $commands.Values | Select-Object CommandType,Name,Source
}
New-Alias -Name "WSToolsCommands" -Value Get-WSToolsCommand


function Get-WSToolsConfig {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-05-23 12:27:36
    Last Edit: 2020-08-20 11:18:58
    Keywords:
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    $Global:WSToolsConfig
}
New-Alias -Name "Import-WSToolsConfig" -Value Get-WSToolsConfig
New-Alias -Name "WSToolsConfig" -Value Get-WSToolsConfig

Function Get-WSToolsVersion {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/09/2018 00:23:25
    LASTEDIT: 02/14/2018 11:05:37
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Remote,

        [Parameter(Mandatory=$false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
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

            $version = New-Object -TypeName PSObject -Property @{
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

        $version = New-Object -TypeName PSObject -Property @{
            ComputerName = $cn
            WSToolsVersion = $ver
            Date = $i2
            Path = $path
        }#new object
        $version | Select-Object ComputerName,WSToolsVersion,Date,Path
    }
}
New-Alias -Name "WSToolsVersion" -Value Get-WSToolsVersion


Function Import-DRAModule {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/17/2019 13:47:31
    LASTEDIT: 2020-08-20 14:42:59
    KEYWORDS:
.LINK
    https://wstools.dev
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


Function Import-XML {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/25/2017 17:03:54
    LASTEDIT: 10/25/2017 17:03:54
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Path
    )

    [xml]$XmlFile = Get-Content -Path $Path
    $XmlFile
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
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter the path of the .mof file you want to import. Ex: C:\Example\examplewmi.mof",
            Mandatory=$true,
            Position=0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
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
New-Alias -Name "Import-WMIFilter" -Value Import-MOF
New-Alias -Name "New-WMIFilter" -Value Import-MOF


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
    Created: 06/13/2018 14:17:09
    Last Edit: 2020-08-20 11:18:30
    Keywords:
.LINK
    https://wstools.dev
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
    Param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $source = $config.UpdatePath

    foreach ($comp in $ComputerName) {
        robocopy $source "\\$comp\c$\Program Files\WindowsPowerShell\Modules\WSTools" /mir /mt:4 /r:3 /w:5 /njs /njh
    }
}
New-Alias -Name "Copy-WSTools" -Value Install-WSTools


Function Set-SpeakerVolume {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 08/18/2017 20:47:06
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
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
New-Alias -Name "Volume" -Value Set-SpeakerVolume


Function Show-BalloonTip {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 08/18/2017 20:47:33
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
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
New-Alias -Name "tip" -Value Show-BalloonTip


Function Show-MessageBox {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 08/18/2017 20:47:49
    KEYWORDS:
.LINK
    https://wstools.dev
#>
#info: https://msdn.microsoft.com/en-us/library/x83z1d9f(v=vs.84).aspx
    [CmdletBinding()]
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
New-Alias -Name "message" -Value Show-MessageBox


Function Test-EmailRelay {
    <#
       .Notes
        AUTHOR: Skyler Hart
        CREATED: 08/18/2017 20:40:04
        LASTEDIT: 2020-08-09 21:36:41
        KEYWORDS: E-mail, email, relay, smtp
        REMARKS: On secure networks, port 25 has to be open
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0, HelpMessage="Enter e-mail address of recipient")]
        [string]$Recipient
    )

    $config = $Global:WSToolsConfig
    $from = $config.Sender
    $smtpserver = $config.SMTPServer
    $port = $config.SMTPPort

    $date = Get-Date
    $subject = "Test from $env:COMPUTERNAME $date"

    send-mailmessage -To $Recipient -From $from -Subject $subject -Body "Testing relay of SMTP messages.`nFrom: $from `nTo: $recip `n`nPlease delete this message." -smtpserver $smtpserver -Port $port
}


#Working. Add functionality to convert ip to computername and vice versa. Enter ip range 192.168.0.0/26
# and have it convert it. Or 192.168.0.0-255 and check all computers. Write help
# Add alias's and fix pipeline
Function Test-Online {
<#
   .Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:47:56
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
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
        New-Object psobject -Property @{
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
    https://wstools.dev
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
    https://wstools.dev
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
                Write-Host "Updating $apath"
                Robocopy.exe $env:ProgramFiles\WindowsPowerShell\Modules\WSTools $apath /mir /mt:4 /r:3 /w:5 /njh /njs
            }
        }
    }
    else {
        robocopy $UPath $env:ProgramFiles\WindowsPowerShell\Modules\WSTools /mir /mt:4 /njs /njh /r:3 /w:15
    }
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
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter the path of the folder with the part files you want to join.",
            Mandatory=$true,
            Position=0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Source','InputLocation','SourceFolder')]
        [string]$Path,

        [Parameter(HelpMessage = "Enter the path where you want the joined file placed.",
            Mandatory=$false,
            Position=1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('OutputLocation','Output','DestinationPath','Destination')]
        [string]$DestinationFolder
    )

    $og = (Get-Location).Path
    $objs = Get-ChildItem $Path | Where-Object {$_.Name -like "*_Part*"}

    $myobjs = @()
    foreach ($obj in $objs) {
        $ext = $obj.Extension
        $name = $obj.Name
        $num = $name -replace "[\s\S]*.*(_Part)","" -replace $ext,""
        $fn = $obj.FullName
        $dp = $obj.Directory.FullName

        $myobjs += New-Object -TypeName PSObject -Property @{
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
            Write-Host "Appending $_ to $fop"
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
            Write-Host "Appending $_ to $fop"
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


Function Split-File {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 04/30/2019 13:18:22
    LASTEDIT: 04/30/2019 17:27:34
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter the path of the file you want to split.",
            Mandatory=$true,
            Position=0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Source','InputLocation','SourceFile')]
        [string]$Path,

        [Parameter(HelpMessage = "Enter the path of where you want the part files placed.",
            Mandatory=$false,
            Position=1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('OutputLocation','Output','DestinationPath','Destination')]
        [string]$DestinationFolder,

        [Parameter(HelpMessage = "Enter the size you want the part files to be. Can be bytes or you can specify a size. Ex: 100MB",
            Mandatory=$false,
            Position=2,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Size','Newsize')]
        [int]$PartFileSize = 10MB
    )

    $FilePath = [IO.Path]::GetDirectoryName($Path)
    if ((null -eq $$DestinationFolder -or $DestinationFolder -eq "") -and $FilePath -ne "") {$FilePath = $FilePath + "\"}
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
    Write-Host "Saving part files to $FilePath"
    while (($BytesRead = $ReadObj.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
        $NewName = "{0}{1}{2}{3,2:00}{4}" -f ($FilePath,$FileName,$Part,$N,$Extension)
        $WriteObj = New-Object System.IO.BinaryWriter([System.IO.File]::Create($NewName))
        $WriteObj.Write($Buffer, 0, $BytesRead)
        $WriteObj.Close()
        $N++
    }
    $ReadObj.Close()
}



###########################################################################
###########################################################################
##                                                                       ##
##                             Preferences                               ##
##                                                                       ##
###########################################################################
###########################################################################
function Set-Preferences {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-18 13:00:47
    Last Edit: 2020-04-18 13:00:47
    Keywords:
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
    https://wstools.dev
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


Function Set-ShortcutText {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-18 20:44:39
    Last Edit: 2020-04-18 20:44:39
    Keywords:
.LINK
    https://wstools.dev
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
    https://wstools.dev
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
    https://wstools.dev
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
    https://wstools.dev
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


###########################################################################
###########################################################################
##                                                                       ##
##                                Admin                                  ##
##                                                                       ##
###########################################################################
###########################################################################

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
    https://wstools.dev
#>
    control.exe admintools
}
New-Alias -Name "tools" -Value Open-AdminTools
New-Alias -Name "admintools" -Value Open-AdminTools
New-Alias -Name "admin" -Value Open-AdminTools


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
    https://wstools.dev
#>
    control.exe /name Microsoft.BitLockerDriveEncryption
}
New-Alias -Name "BitLocker" -Value Open-BitLocker


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
    https://wstools.dev
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
    https://wstools.dev
#>
    certmgr.msc
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
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
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
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
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
    https://wstools.dev
#>
    control.exe printers
}
New-Alias -Name "printers" -Value Open-DevicesAndPrinters


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
    https://wstools.dev
#>
    $sh = New-Object -ComObject "Shell.Application"
    $sh.Namespace(17).Items() | Where-Object {$_.Type -eq "CD Drive"} | ForEach-Object {$_.InvokeVerb("Eject")}
}
New-Alias -Name "Eject-Disc" -Value Open-DiscDrive


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
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
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
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )
    eventvwr.msc /computer:\\$ComputerName
}
New-Alias -Name "events" -Value Open-EventViewer


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
    https://wstools.dev
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
    https://wstools.dev
#>
    gpedit.msc
}
New-Alias -Name "Open-LocalPolicyEditor" -Value Open-LocalGPeditor
New-Alias -Name "LocalPolicy" -Value Open-LocalGPeditor


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
    https://wstools.dev
#>
    control.exe ncpa.cpl
}
New-Alias -Name "network" -Value Open-NetworkConnections
New-Alias -Name "connections" -Value Open-NetworkConnections


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
    https://wstools.dev
#>
    Start-Process appwiz.cpl
}
New-Alias -Name "programs" -Value Open-ProgramsAndFeatures


function Connect-RDP {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 20:48:07
    LASTEDIT: 10/20/2017 15:25:56
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Host','Name','Computer','CN')]
        [string]$ComputerName
    )

    mstsc /v:$ComputerName /admin
}
New-Alias -Name "rdp" -Value Connect-RDP


Function Open-Remedy {
    <#
       .Notes
        AUTHOR: Skyler Hart
        CREATED: 10/03/2017 10:52:44
        LASTEDIT: 2020-04-17 15:47:44
        KEYWORDS:
        REQUIRES:
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
    $URL = $config.Remedy

    if ($Chrome) {Start-Process "chrome.exe" $URL}
    elseif ($Edge) {Start-Process shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge $URL}
    elseif ($Firefox) {Start-Process "firefox.exe" $URL}
    elseif ($InternetExplorer) {Start-Process "iexplore.exe" $URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open($URL)
    }
}
New-Alias -Name "Remedy" -Value Open-Remedy
New-Alias -Name "EITSM" -Value Open-Remedy
New-Alias -Name "Open-EITSM" -Value Open-Remedy


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
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Host','Name','Computer','CN')]
        [string]$ComputerName = "$env:COMPUTERNAME"
    )
    services.msc /computer=\\$ComputerName
}
New-Alias -Name "services" -Value Open-Services


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
    https://wstools.dev
#>
    control.exe sysdm.cpl
}


function Clear-DirtyShutdown {
<#
.EXAMPLE
    C:\PS>Clear-DirtyShutdown
    Example of how to use this cmdlet. Will clear a dirty shutdown that causes the shutdown tracker to appear.
.EXAMPLE
    C:\PS>Clear-DirtyShutdown -ComputerName COMP1
    Another example of how to use this cmdlet. Will clear the dirty shutdown on COMP1
.NOTES
    Author: Skyler Hart
    Created: 2020-05-08 17:54:09
    Last Edit: 2020-05-08 18:28:01
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true
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
    Last Edit: 2020-05-08 22:34:49
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter either PublicDesktop or UserDesktop. PublicDesktop requires admin rights.",
            Mandatory=$true,
            Position=0,
            ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true
        )]
        [ValidateSet('PublicDesktop','UserDesktop')]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if ($Path -eq "PublicDesktop") {
        $sp = "C:\Users\Public\Desktop\LAPS.lnk"
    }
    elseif ($Path -eq "UserDesktop") {
        $sp = $env:USERPROFILE + "\Desktop\LAPS.lnk"
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
        [int32]$Size = 1500
    )
    Set-NetIPInterface -AddressFamily IPv4 -NlMtuBytes $Size
}


function Set-NetworkConnectionsShortcut {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-05-08 23:01:21
    Last Edit: 2020-05-08 23:01:21
    Keywords:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter either PublicDesktop or UserDesktop. PublicDesktop requires admin rights.",
            Mandatory=$true,
            Position=0,
            ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true
        )]
        [ValidateSet('PublicDesktop','UserDesktop')]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if ($Path -eq "PublicDesktop") {
        $sp = "C:\Users\Public\Desktop\Network Connections.lnk"
    }
    elseif ($Path -eq "UserDesktop") {
        $sp = $env:USERPROFILE + "\Desktop\Network Connections.lnk"
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


function Set-Reboot0100 {
<#
   .Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:49:35
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter()]
        [switch]$Abort
     )
    $tt1 = ([decimal]::round(((Get-Date).AddDays(1).Date.AddHours(1) - (Get-Date)).TotalSeconds))
    foreach ($Comp in $ComputerName) {
        if ($Abort) {shutdown -a -m \\$Comp}
        else {
            try {
                shutdown -r -m \\$Comp -t $tt1
            }
            catch {
                Throw "Could not schedule rebooot on $Comp"
            }
        }#else
    }
}


Function Get-DefaultBrowserPath {
<#
.NOTES
    Author: Skyler Hart
    Created: Sometime before 2017-08-07
    Last Edit: 2020-08-20 15:09:53
    Keywords:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    New-PSDrive -Name HKCR -PSProvider Registry -Root Hkey_Classes_Root | Out-Null
    $BrowserPath = ((Get-ItemProperty 'HKCR:\http\shell\open\command').'(default)').Split('"')[1]
    return $BrowserPath
    Remove-PSDrive -Name HKCR -Force -ErrorAction SilentlyContinue | Out-Null
}


Function Get-FileMetaData {
  <#
   .Synopsis
    This function gets file metadata and returns it as a custom PS Object
   .Description
    This function gets file metadata using the Shell.Application object and
    returns a custom PSObject object that can be sorted, filtered or otherwise
    manipulated.
   .Example
    Get-FileMetaData -folder "e:\music"
    Gets file metadata for all files in the e:\music directory
   .Example
    Get-FileMetaData -folder (gci e:\music -Recurse -Directory).FullName
    This example uses the Get-ChildItem cmdlet to do a recursive lookup of
    all directories in the e:\music folder and then it goes through and gets
    all of the file metada for all the files in the directories and in the
    subdirectories.
   .Example
    Get-FileMetaData -folder "c:\fso","E:\music\Big Boi"
    Gets file metadata from files in both the c:\fso directory and the
    e:\music\big boi directory.
   .Example
    $meta = Get-FileMetaData -folder "E:\music"
    This example gets file metadata from all files in the root of the
    e:\music directory and stores the returned custom objects in a $meta
    variable for later processing and manipulation.
   .Parameter Folder
    The folder that is parsed for files
   .Notes
    NAME:  Get-FileMetaData
    AUTHOR: ed wilson, msft
    LASTEDIT: 01/24/2014 14:08:24
    KEYWORDS: Storage, Files, Metadata
    HSG: HSG-2-5-14
   .Link
     https://devblogs.microsoft.com/scripting/
 #Requires -Version 2.0
 #>
    Param([string[]]$folder)
    foreach($sFolder in $folder) {
        $a = 0
        $objShell = New-Object -ComObject Shell.Application
        $objFolder = $objShell.namespace($sFolder)
        foreach ($File in $objFolder.items()) {
            $FileMetaData = New-Object PSOBJECT
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
    } #end foreach $sfolder
} #end Get-FileMetaData


function Get-User {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-20 19:51:03
    Last Edit: 2020-04-20 23:14:32
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true
        )]
        [ValidateNotNullorEmpty()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(
            Mandatory=$false,
            Position=1,
            ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true
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
                New-Object -TypeName PSObject -Property @{
                    Computer = $Comp
                    User = $u.Name
                    Description = $u.Description
                    Disabled = $u.Disabled
                    Locked = $u.Lockout
                    PasswordChangeable = $u.PasswordChangeable
                    PasswordExpires = $u.PasswordExpires
                    PasswordRequired = $u.PasswordRequired
                } | Select-Object Computer,User,Description,Disabled,Locked,PasswordChangeable,PasswordExpires,PasswordRequired
            }#foreach u
        }#try
        catch {
            New-Object -TypeName PSObject -Property @{
                Computer = $Comp
                User = $null
                Description = $null
                Disabled = $null
                Locked = $null
                PasswordChangeable = $null
                PasswordExpires = $null
                PasswordRequired = $null
            } | Select-Object Computer,User,Description,Disabled,Locked,PasswordChangeable,PasswordExpires,PasswordRequired
        }#catch
    }#foreach comp
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
.NOTE
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
    }#end begin
    Process {
        #Get all domain controllers in domain
        $DomainControllers = Get-ADDomainController -Filter *
        $PDCEmulator = ($DomainControllers | Where-Object {$_.OperationMasterRoles -contains "PDCEmulator"})

        Write-Verbose "Finding the domain controllers in the domain"
        Foreach($DC in $DomainControllers)
        {
            $DCCounter++
            Write-Progress -Activity "Contacting DCs for lockout info" -Status "Querying $($DC.Hostname)" -PercentComplete (($DCCounter/$DomainControllers.Count) * 100)
            Try
            {
                $UserInfo = Get-ADUser -Identity $Identity  -Server $DC.Hostname -Properties AccountLockoutTime,LastBadPasswordAttempt,BadPwdCount,LockedOut -ErrorAction Stop
            }
            Catch
            {
                Write-Warning $_
                Continue
            }
            If($UserInfo.LastBadPasswordAttempt) {
                $LockedOutStats += New-Object -TypeName PSObject -Property @{
                        Name                   = $UserInfo.SamAccountName
                        SID                    = $UserInfo.SID.Value
                        LockedOut              = $UserInfo.LockedOut
                        BadPwdCount            = $UserInfo.BadPwdCount
                        BadPasswordTime        = $UserInfo.BadPasswordTime
                        DomainController       = $DC.Hostname
                        AccountLockoutTime     = $UserInfo.AccountLockoutTime
                        LastBadPasswordAttempt = ($UserInfo.LastBadPasswordAttempt).ToLocalTime()
                    }
            }#end if
        }#end foreach DCs
        $LockedOutStats | Format-Table -Property Name,LockedOut,DomainController,BadPwdCount,AccountLockoutTime,LastBadPasswordAttempt -AutoSize

        #Get User Info
        Try {
           Write-Verbose "Querying event log on $($PDCEmulator.HostName)"
           $LockedOutEvents = Get-WinEvent -ComputerName $PDCEmulator.HostName -FilterHashtable @{LogName='Security';Id=4740} -ErrorAction Stop | Sort-Object -Property TimeCreated -Descending
        }
        Catch {
           Write-Warning $_
           Continue
        }#end catch
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
            }#end ifevent
        }#end foreach lockedout event
    }#end process
}#end function


Function Get-InstalledProgram {
<#
.SYNOPSIS
    Displays installed programs on a computer.
.DESCRIPTION
    Displays a list of installed programs on a local or remote computer by querying the registry.
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
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
    Keywords:
.LINK
    https://wstools.dev
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
                                $installed += New-Object -TypeName PSCustomObject -Property $HashProperty |
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
    Keywords:
.LINK
    https://wstools.dev
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

    function Convert-IPtoINT64 () {
        param ($IP)
        $octets = $IP.split(".")
        return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3])
    }

    function Convert-INT64toIP() {
        param ([int64]$int)
        return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring())
    }

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


function Set-WSToolsConfig {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-17 15:00:06
    Last Edit: 2020-04-17 15:00:06
.LINK
    https://wstools.dev
#>
    PowerShell_Ise "$PSScriptRoot\config.ps1"
}
New-Alias -Name "Open-WSToolsConfig" -Value Set-WSToolsConfig
New-Alias -Name "Update-WSToolsConfig" -Value Set-WSToolsConfig


function Set-WindowState {
#source: https://gist.github.com/jakeballard/11240204
param(
    [Parameter()]
    [ValidateSet('FORCEMINIMIZE','HIDE','MAXIMIZE','MINIMIZE','RESTORE',
                 'SHOW','SHOWDEFAULT','SHOWMAXIMIZED','SHOWMINIMIZED',
                 'SHOWMINNOACTIVE','SHOWNA','SHOWNOACTIVATE','SHOWNORMAL')]
    $Style = 'SHOW',

    [Parameter()]
    $MainWindowHandle = (Get-Process –id $pid).MainWindowHandle
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

    $Win32ShowWindowAsync = Add-Type –memberDefinition @”
    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
“@ -name “Win32ShowWindowAsync” -namespace Win32Functions –passThru

    $Win32ShowWindowAsync::ShowWindowAsync($MainWindowHandle, $WindowStates[$Style]) | Out-Null
    Write-Verbose ("Set Window Style '{1} on '{0}'" -f $MainWindowHandle, $Style)

}


function Start-CommandMultiThreaded {
<#.Synopsis
#    This is a quick and open-ended script multi-threader searcher
#.Description
#    This script will allow any general, external script to be multithreaded by providing a single
#    argument to that script and opening it in a seperate thread.  It works as a filter in the
#    pipeline, or as a standalone script.  It will read the argument either from the pipeline
#    or from a filename provided.  It will send the results of the child script down the pipeline,
#    so it is best to use a script that returns some sort of object.
#
#    Authored by Ryan Witschger - http://www.Get-Blog.com
#.PARAMETER Command
#    This is where you provide the PowerShell Cmdlet / Script file that you want to multithread.
#    You can also choose a built in cmdlet.  Keep in mind that your script.  This script is read into
#    a scriptblock, so any unforeseen errors are likely caused by the conversion to a script block.
#.PARAMETER ObjectList
#    The objectlist represents the arguments that are provided to the child script.  This is an open ended
#    argument and can take a single object from the pipeline, an array, a collection, or a file name.  The
#    multithreading script does it's best to find out which you have provided and handle it as such.
#    If you would like to provide a file, then the file is read with one object on each line and will
#    be provided as is to the script you are running as a string.  If this is not desired, then use an array.
#
#.PARAMETER InputParam
#    This allows you to specify the parameter for which your input objects are to be evaluated.  As an example,
#    if you were to provide a computer name to the Get-Process cmdlet as just an argument, it would attempt to
#    find all processes where the name was the provided computername and fail.  You need to specify that the
#    parameter that you are providing is the "ComputerName".
#
#.PARAMETER AddParam
#    This allows you to specify additional parameters to the running command.  For instance, if you are trying
#    to find the status of the "BITS" service on all servers in your list, you will need to specify the "Name"
#    parameter.  This command takes a hash pair formatted as follows:
#
#    @{"ParameterName" = "Value"}
#    @{"ParameterName" = "Value" ; "ParameterTwo" = "Value2"}
#.PARAMETER AddSwitch
#    This allows you to add additional switches to the command you are running.  For instance, you may want
#    to include "RequiredServices" to the "Get-Service" cmdlet.  This parameter will take a single string, or
#    an aray of strings as follows:
#
#    "RequiredServices"
#    @("RequiredServices", "DependentServices")
#.PARAMETER MaxThreads
#    This is the maximum number of threads to run at any given time.  If resources are too congested try lowering
#    this number.  The default value is 20.
#
#.PARAMETER SleepTimer
#    This is the time between cycles of the child process detection cycle.  The default value is 200ms.  If CPU
#    utilization is high then you can consider increasing this delay.  If the child script takes a long time to
#    run, then you might increase this value to around 1000 (or 1 second in the detection cycle).
#.EXAMPLE
#    Both of these will execute the script named ServerInfo.ps1 and provide each of the server names in AllServers.txt
#    while providing the results to the screen.  The results will be the output of the child script.
#
#    gc AllServers.txt | .\Start-CommandMultiThreaded.ps1 -Command .\ServerInfo.ps1
#    .\Run-CommandMultiThreaded.ps1 -Command .\ServerInfo.ps1 -ObjectList (gc .\AllServers.txt)
#.EXAMPLE
#    The following demonstrates the use of the AddParam statement
#    $ObjectList | .\Start-CommandMultiThreaded.ps1 -Command "Get-Service" -InputParam ComputerName -AddParam @{"Name" = "BITS"}
#.EXAMPLE
#    The following demonstrates the use of the AddSwitch statement
#    $ObjectList | .\Start-CommandMultiThreaded.ps1 -Command "Get-Service" -AddSwitch @("RequiredServices", "DependentServices")
#.EXAMPLE
#    The following demonstrates the use of the script in the pipeline
#    $ObjectList | .\Start-CommandMultiThreaded.ps1 -Command "Get-Service" -InputParam ComputerName -AddParam @{"Name" = "BITS"} | Select Status, MachineName
#.Link
#    http://www.get-blog.com/?p=189
#>
Param($Command = $(Read-Host "Enter the script file"),
    [Parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]$ObjectList,
    $InputParam = $Null,
    $MaxThreads = 20,
    $SleepTimer = 200,
    $MaxResultTime = 120,
    [HashTable]$AddParam = @{},
    [Array]$AddSwitch = @()
)
Begin{
    $ISS = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $ISS, $Host)
    $RunspacePool.Open()
    If ($(Get-Command | Select-Object Name) -match $Command){
        $Code = $Null
    }Else{
        $OFS = "`r`n"
        $Code = [ScriptBlock]::Create($(Get-Content $Command))
        Remove-Variable OFS
    }
    $Jobs = @()
}
Process{
    Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
    ForEach ($Object in $ObjectList){
        If ($null -eq $Code){
            $PowershellThread = [powershell]::Create().AddCommand($Command)
        }Else{
            $PowershellThread = [powershell]::Create().AddScript($Code)
        }
        If ($null -ne $InputParam){
            $PowershellThread.AddParameter($InputParam, $Object.ToString()) | out-null
        }Else{
            $PowershellThread.AddArgument($Object.ToString()) | out-null
        }
        ForEach($Key in $AddParam.Keys){
            $PowershellThread.AddParameter($Key, $AddParam.$key) | out-null
        }
        ForEach($Switch in $AddSwitch){
            $Switch
            $PowershellThread.AddParameter($Switch) | out-null
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


function Update-BrokenInheritance {
<#
Find and fix broken permissions inheritance.

All envrionments perform differently. Please test this code before using it
in production.

THIS CODE AND ANY ASSOCIATED INFORMATION ARE PROVIDED “AS IS” WITHOUT WARRANTY
OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
PURPOSE. THE ENTIRE RISK OF USE, INABILITY TO USE, OR RESULTS FROM THE USE OF
THIS CODE REMAINS WITH THE USER.

Author: Aaron Guilmette
		aaron.guilmette@microsoft.com
#>

<#
.SYNOPSIS
Find objects without permissions inheritance enabled and optionally
update.

.DESCRIPTION
This script will search Active Directory for objects with permissions
inheritance disabled.

.PARAMETER Confirm
Confirm changes to Active Directory objects.

.PARAMETER Identity
Optionally specify sAMAccountName or distinguishedDName of a user to check.

.PARAMETER Logfile
Specify logfile for operations.

.PARAMETER SearchBase
Set the BaseDN for the search query.  Defaults to the DN of the current
domain.

.EXAMPLE
.\Fix-BrokenInheritance.ps1 -LogFile output.txt
Find objects with disabled inheritance and output to logfile output.txt.

.EXAMPLE
.\Fix-BrokenInheritance.ps1 -Logfile output.txt -Confirm
Find objects with disabled inheritance, update them, and log changes
to output.txt.

.EXAMPLE
.\Fix-BrokenInheritance.ps1 -Identity "CN=Joe,CN=Users,DC=contoso,DC=com"
Checks object CN=Joe for disabled inheritance.

.LINK
https://gallery.technet.microsoft.com/Find-and-Fix-Broken-Object-5ae18ab1

#>
Param(
    [Parameter(Mandatory=$false,HelpMessage="Active Directory Base DN")]
		[string]$SearchBase = (Get-ADDomain).DistinguishedName,
	[Parameter(Mandatory=$false,HelpMessage="Log File")]
		[string]$LogFile,
	[Parameter(Mandatory=$false,HelpMessage="Enter User ID (sAMAccountName or DN)")]
		[string]$Identity,
    [Parameter(Mandatory=$false,HelpMessage="Confirm")]
        [switch]$Confirm
	)

If (!(Get-Module ActiveDirectory))
	{
	Import-Module ActiveDirectory
	}

# Start Logfile
If ($LogFile)
	{
	$head = """" + "DistinguishedName" + """" + "," + """" + "UPN" + """" + "," + """" + "InheritanceDisabled-Before" + """" + "," + """" + "InheritanceDisabled-After" + """" + "," + """" + "adminSDHolderProtected" + """"
	$head | Out-File $LogFile
	}

# Instantiate Directory Searcher
If (!($Identity))
	{
	$DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$SearchBase","(&(objectcategory=user)(objectclass=user))")
	}
Else
	{
	Write-Host "Searching for User $($Identity)"
	If ($Identity -like "CN=*")
        {
        $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Identity")
	    }
    Else
        {
        $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$SearchBase","(&(objectcategory=user)(objectclass=user)(samaccountname=$($Identity)))")
	    }
    }

# Find All Matching Users
$Users = $DirectorySearcher.FindAll()

Foreach ($obj in $users) {
    # Set 'objBefore' to the current object so we can track any changes
    $objBefore = $obj.GetDirectoryEntry()

    # Check to see if user has Inheritance Disabled; $True is inheritance disabled, $False is inheritance enabled
    If ($objBefore.psBase.ObjectSecurity.AreAccessRulesProtected -eq $True) {
        Write-Host "User: $($objBefore.sAMAccountName) Inheritance is disabled: $($objBefore.psBase.ObjectSecurity.AreAccessRulesProtected) ; adminSDHolder: $($objBefore.Properties.AdminCount)"
        $objBeforeACL = $($objBefore.psBase.ObjectSecurity.AreAccessRulesProtected)
        #$user.psBase.ObjectSecurity | GM "*get*access*"

        # If Confirm switch was enabled to make changes
        If ($Confirm) {
            Write-Host -ForegroundColor Green "Updating $($objBefore.sAMAccountName)."
            $objBefore.psbase.ObjectSecurity.SetAccessRuleProtection($false,$true)
            $objBefore.psbase.CommitChanges()
        }

        # Set 'objAfter' so we can see the updated change
        $objAfter = $obj.GetDirectoryEntry()
        $objAfterACL = $($objAfter.psBase.ObjectSecurity.AreAccessRulesProtected)

        # If logging is enabled, write a log file
        If ($LogFile)
		    {
		    $LogData = """" + $objBefore.DistinguishedName + """" + "," + """" + $objBefore.UserPrincipalName + """" + "," + """" + $objBeforeACL + """" + "," + """" + $objAfterACL + """" + "," + """" + $objBefore.Properties.AdminCount + """"
		    $LogData | Out-File $LogFile -Append
		    }
    }
    Else {
        # User has inheritance enabled, so do nothing
    }
    }
}

Export-ModuleMember -Alias * -Function *