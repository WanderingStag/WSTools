function Get-Role {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/20/2017 16:30:43
    LASTEDIT: 10/20/2017 16:30:43
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {$Role = "Admin"}
    else {$Role = "Non-Admin"}
    $Role
}
