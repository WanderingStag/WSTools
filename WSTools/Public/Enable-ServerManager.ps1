function Enable-ServerManager {
    <#
    .SYNOPSIS
        Enables the Server Manager to launch automatically on the local computer.

    .DESCRIPTION
        This function enables the Server Manager to launch automatically on the local computer by enabling the related scheduled task.
        It requires administrative privileges to execute.

    .EXAMPLE
        Enable-ServerManager
        Enables the Server Manager to launch automatically on the local computer.

    .NOTES
        AUTHOR: Skyler Hart
        CREATED: 2021-12-16 21:29:35
        LASTEDIT: 2024-11-27 13:00:00
        REQUIRES: RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param ()

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Get-ScheduledTask -TaskName "ServerManager" | Enable-ScheduledTask
    } else {
        throw "Must be run as administrator."
    }
}
