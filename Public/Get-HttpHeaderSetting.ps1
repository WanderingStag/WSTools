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
