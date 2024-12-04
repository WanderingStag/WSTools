function Import-XML {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/25/2017 17:03:54
    LASTEDIT: 10/25/2017 17:03:54
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Path
    )

    [xml]$XmlFile = Get-Content -Path $Path
    $XmlFile
}
