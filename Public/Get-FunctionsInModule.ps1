function Get-FunctionsInModule {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/21/2017 13:06:27
    LASTEDIT: 08/21/2017 13:06:27
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Module
    )

    $mod = (Get-Module $Module -ListAvailable).ExportedCommands
    $mod.Values.Name | Sort-Object
}
