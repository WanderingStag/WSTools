function Start-WSToolsGUI {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-10-30 00:55:48
    Last Edit: 2021-10-30 00:55:48
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('wsgui','wstgui','Start-WSToolsTrayApp')]
    param()
    Start-Process powershell.exe -ArgumentList "`$host.ui.RawUI.WindowTitle = 'WSTools Taskbar App'; & '$PSScriptRoot\WSTools_SystemTrayApp.ps1'"
}
