function Update-VisioStencils {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-05-18 20:56:13
    Last Edit: 2021-10-13 20:33:20
    Keywords: Visio, Stencils
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does."
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Copy-VisioStencils','Get-VisioStencils')]
    param()

    $vspath = ($Global:WSToolsConfig).Stencils
    $rpath = [System.Environment]::GetFolderPath("MyDocuments") + "\My Shapes"

    if (Test-Path $rpath) {
        $confirmation = Read-Host "Are you sure you want to overwrite the files in $rpath with files in $vspath`? `nPress y for yes and then press enter. To cancel enter any other value then press enter."
        if ($confirmation -eq 'y') {
            robocopy $vspath $rpath /mir /mt:4 /r:3 /w:15 /njh /njs
        }
    }
    else {
        robocopy $vspath $rpath /mir /mt:4 /r:3 /w:15 /njh /njs
    }
}
