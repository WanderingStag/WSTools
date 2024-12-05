function Open-NetworkDiagram {
<#
.NOTES
    Author: Skyler Hart
    Created: 2022-07-07 20:59:35
    Last Edit: 2022-07-07 20:59:35
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('NetDiagram','NetworkDiagram')]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Chrome,

        [Parameter(Mandatory=$false)]
        [Switch]$Edge,

        [Parameter(Mandatory=$false)]
        [Switch]$Firefox,

        [Parameter(Mandatory=$false)]
        [Switch]$InternetExplorer
    )

    $config = $Global:WSToolsConfig
    $dpath = $config.NetDiagram

    if ($dpath -like "http*") {
        if ($Chrome) {Start-Process "chrome.exe" $dpath}
        elseif ($Edge) {Start-Process Microsoft-Edge:$dpath}
        elseif ($Firefox) {Start-Process "firefox.exe" $dpath}
        elseif ($InternetExplorer) {Start-Process "iexplore.exe" $dpath}
        else {
            #open in default browser
            (New-Object -com Shell.Application).Open($dpath)
        }
    }#is web address
    else {
        Invoke-Item $dpath
    }
}
