function Restore-WindowsUpdate {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-12-03 19:41:37
    LASTEDIT: 2021-12-03 19:41:37
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {dism.exe /Online /Cleanup-image /Restorehealth}
    else {Write-Error "Must be ran as admin"}
}
