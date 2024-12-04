function Stop-AppService {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-19 23:06:20
    Last Edit: 2021-10-12 16:00:59
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    $AppNames = ($Global:WSToolsConfig).AppNames
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $services = Get-Service | Where-Object {$_.Status -eq "Running"}
        foreach ($app in $AppNames) {
            $services | Where-Object {$_.DisplayName -match $app -or $_.Name -match $app} | Stop-Service -Force
        }
    }
    else {
        Write-Output "Must run PowerShell as admin to run Stop-AppService."
    }
    Write-Output "Completed stopping application services."
}
