function Add-Switch {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 07/31/2019 22:17:04
    LASTEDIT: 07/31/2019 22:17:04
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    $objectText = @"
switch (`$variable) {
    value {`$variable2 = "something"}

    {'value1','value2' -contains `$_} {`$variable2 = "something"}

    {`$anothervariable -match `$variable} {`$variable2 = "something"}
}
"@
    $psise.CurrentFile.Editor.InsertText($objectText)
}
