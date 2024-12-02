function Disable-ServerManager {
    <#
    .SYNOPSIS
        Disables the Server Manager from launching automatically on the local computer.

    .DESCRIPTION
        This function disables the Server Manager from launching automatically on the local computer by disabling the related scheduled task.
        It requires administrative privileges to execute.

    .EXAMPLE
        Disable-ServerManager
        Disables the Server Manager from launching automatically on the local computer.

    .NOTES
        AUTHOR: Skyler Hart
        CREATED: 2020-05-08 23:18:39
        LASTEDIT: 2024-11-27 13:00:00
        REQUIRES: RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param ()

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Get-ScheduledTask -TaskName "ServerManager" | Disable-ScheduledTask
    } else {
        throw "Must be run as administrator."
    }
}
