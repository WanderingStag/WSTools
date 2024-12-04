function Set-Title {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:47:14
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('title')]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$titleText
    )
    $Host.UI.RawUI.WindowTitle = $titleText
}
