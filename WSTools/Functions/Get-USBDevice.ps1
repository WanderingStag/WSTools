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
