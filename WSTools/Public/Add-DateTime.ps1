function Add-DateTime {
<#
   .Synopsis
    This function adds the date and time at current insertion point.
   .Example
    Add-DateTime
    Adds date and time at current insertion point in a PowerShell ISE window.
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 19:51:23
    LASTEDIT: 10/26/2017 09:48:00
    KEYWORDS: Scripting Techniques, Windows PowerShell ISE
.LINK
    https://wanderingstag.github.io
#Requires -Version 2.0
#>
    $timeText = @"
$(Get-Date)
"@
    $psise.CurrentFile.Editor.InsertText($timeText)
}
