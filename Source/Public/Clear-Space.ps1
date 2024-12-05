function Clear-Space {
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
