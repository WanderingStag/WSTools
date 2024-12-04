function Open-CMTrace {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-10-19 15:07:45
    Last Edit: 2021-10-19 15:15:48
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Open-CCMTrace','CMTrace','CCMTrace')]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [Alias('File','FileName','Name','Source')]
        [string]$Path
    )

    $lcm = "C:\Windows\CCM\CMTrace.exe"
    $ncm = ($Global:WSToolsConfig).CMTrace

    if ([string]::IsNullOrWhiteSpace($Path)) {
        if (Test-Path $lcm) {Start-Process $lcm}
        else {Start-Process $ncm}
    }
    else {
        if (Test-Path $lcm) {Start-Process $lcm -ArgumentList $Path}
        else {Start-Process $ncm -ArgumentList $Path}
    }
}
