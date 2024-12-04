function Show-MessageBox {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 08/18/2017 20:47:49
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
#info: https://msdn.microsoft.com/en-us/library/x83z1d9f(v=vs.84).aspx
    [CmdletBinding()]
    [Alias('message')]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Text,

        [Parameter(Mandatory=$true)]
        [string]$Title,

        [Parameter(Mandatory=$false)]
        [int32]$Timeout = 10
    )

    $wshell = New-Object -ComObject Wscript.Shell
    $wshell.Popup($Text,$Timeout,$Title,0x0 + 0x40)

#First option:
#0x0 Show OK button.
#0x1 Show OK and Cancel buttons.
#0x2 Show Abort, Retry, and Ignore buttons.
#0x3 Show Yes, No, and Cancel buttons.
#0x4 Show Yes and No buttons.
#0x5 Show Retry and Cancel buttons.
#0x6 Show Cancel, Try Again, and Continue buttons.

#Second Option
#0x10 Show "Stop Mark" icon.
#0x20 Show "Question Mark" icon.
#0x30 Show "Exclamation Mark" icon.
#0x40 Show "Information Mark" icon.

#Return values
#-1 The user did not click a button before nSecondsToWait seconds elapsed.
#1 OK button
#2 Cancel button
#3 Abort button
#4 Retry button
#5 Ignore button
#6 Yes button
#7 No button
#10 Try Again button
#11 Continue button
}
