function Stop-Database {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-10-24 19:01:26
    Last Edit: 2023-02-07 22:33:18
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Stop-Oracle','Stop-SQL','Stop-MongoDB')]
    param()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Get-Service -Name * | Where-Object {$_.DisplayName -match "Oracle" -or $_.DisplayName -match "SQL" -or $_.DisplayName -match "MongoDB"} | Stop-Service -Force
    }
    else {
        Write-Output "Must run PowerShell as admin to run Stop-Database."
    }
}
