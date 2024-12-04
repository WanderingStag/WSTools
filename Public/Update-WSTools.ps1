function Update-WSTools {
<#
   .Synopsis
    This updates the WSTools module
   .Description
    Updates the WSTools module in various locations
   .Example
    Update-WSTools
    Will update the WSTools module
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 14:48:46
    LASTEDIT: 10/17/2019 23:14:22
    KEYWORDS: PowerShell, module, WSTools, personal
    REMARKS:
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "WSTools is the proper name for the module."
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    $config = $Global:WSToolsConfig
    $UPath = $config.UpdatePath
    $UComp = $config.UpdateComp
    $APaths = $config.AdditionalUpdatePaths

    if ($null -ne $UComp -and $env:COMPUTERNAME -eq $UComp) {
        Robocopy.exe $env:ProgramFiles\WindowsPowerShell\Modules\WSTools $UPath /mir /mt:4 /r:3 /w:5 /njh /njs
        if ($null -ne $APaths -or $APaths -eq "") {
            ForEach ($apath in $APaths) {
                Write-Output "Updating $apath"
                Robocopy.exe $env:ProgramFiles\WindowsPowerShell\Modules\WSTools $apath /mir /mt:4 /r:3 /w:5 /njh /njs
            }
        }
    }
    else {
        robocopy $UPath $env:ProgramFiles\WindowsPowerShell\Modules\WSTools /mir /mt:4 /njs /njh /r:3 /w:15
    }
}
