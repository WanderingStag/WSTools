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
