function Add-ProgressBar {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 10:53:40
    LASTEDIT: 04/23/2018 10:53:40
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    $objectText = @"
`$i = 0
`$number = `$ComputerName.length

#Progress Bar
if (`$number -gt "1") {
    `$i++
    `$amount = (`$i / `$number)
    `$perc1 = `$amount.ToString("P")
    `Write-Progress -activity "Currently doing..." -status "Computer `$i of `$number. Percent complete:  `$perc1" -PercentComplete ((`$i / `$ComputerName.length)  * 100)
}#if length
"@
    $psise.CurrentFile.Editor.InsertText($objectText)
}
