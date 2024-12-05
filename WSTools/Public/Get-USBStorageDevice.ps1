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
