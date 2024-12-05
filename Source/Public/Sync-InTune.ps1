function Sync-InTune {
<#
.SYNOPSIS
    Will sync device with InTune/MEM.
.DESCRIPTION
    Will initiate the sync process with InTune/Microsoft EndPoint Manager to receive new policies and report information.
.EXAMPLE
    C:\PS>Sync-InTune
    Example of how to use this cmdlet.
.COMPONENT
    WSTools
.FUNCTIONALITY
    InTune, Microsoft Endpoint Manager, MEM
.NOTES
    Author: Skyler Hart
    Created: 2022-09-25 01:38:28
    Last Edit: 2022-09-25 01:38:28
    Other:
    Requires:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Sync-MEM')]
    param()

    try {
        Get-ScheduledTask -TaskName PushLaunch -ErrorAction Stop | Start-ScheduledTask
    }
    catch {
        Write-Warning "Device is not InTune/Microsoft Endpoint Manager (MEM) managed."
    }
}
