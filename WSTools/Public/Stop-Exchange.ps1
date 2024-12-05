function Stop-Exchange {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-10-24 11:00:45
    Last Edit: 2020-10-24 11:00:45
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Get-Service -Name * | Where-Object {$_.DisplayName -match "Exchange"} | Stop-Service -Force
    }
    else {
        Write-Output "Must run PowerShell as admin to run Stop-Exchange."
    }
}
