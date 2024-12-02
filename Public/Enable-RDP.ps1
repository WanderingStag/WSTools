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
