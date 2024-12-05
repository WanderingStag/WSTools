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
