function Set-HiveNightmareFix {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-10-19 11:25:39
    Last Edit: 2021-10-19 11:25:39
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        icacls $env:windir\system32\config\*.* /inheritance:e
        vssadmin.exe delete shadows /all
    }
    else {Write-Error "Must be ran as admin"}
}
