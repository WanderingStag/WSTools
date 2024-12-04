function Update-HelpFromFile {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-12-17 22:54:13
    Last Edit: 2021-12-17 22:54:13
    Keywords:
    Other:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter()]
        [Alias('Path','Folder','Source')]
        [string]$SourcePath
    )

    if ([string]::IsNullOrWhiteSpace($Source)) {
        $SourcePath = ($Global:WSToolsConfig).HelpFolder
    }
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {Update-Help -SourcePath $SourcePath -Module * -Force}
    else {Write-Error "Must be ran as administrator."}
}
