function Disable-RDP {
    <#
    .SYNOPSIS
        Disables Remote Desktop Protocol (RDP) on the local computer.

    .DESCRIPTION
        This function disables RDP on the local computer by modifying the appropriate registry key to deny RDP connections.
        It requires administrative privileges to execute.

    .EXAMPLE
        Disable-RDP
        Disables RDP on the local computer.

    .NOTES
        AUTHOR: Skyler Hart
        CREATED: 2021-02-27 11:44:34
        LASTEDIT: 2024-11-27 13:00:00
        REQUIRES: RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param ()

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
    } else {
        throw "Must be run as administrator."
    }
}