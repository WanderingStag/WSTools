function Get-OperatingSystem {
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
