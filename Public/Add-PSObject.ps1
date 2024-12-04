function Add-PSObject {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/27/2017 17:13:32
    LASTEDIT: 12/21/2019 23:35:03
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Switch]$CustomObject
    )

    if ($CustomObject) {
        $objectText = @"
`$object = [ordered]@{
    'Property1'        = `$null
    'LongPropertyEx'   = `$null
}#pscustom object
[pscustomobject]`$object
#or
[pscustomobject]@{Property1=`$null;LongPropertyEx=`$null}
"@
    }#if custom object
    else {
        $objectText = @"
[PSCustomObject]@{
    ComputerName = `$comp
}#new object
"@
    }#else
    $psise.CurrentFile.Editor.InsertText($objectText)
}
