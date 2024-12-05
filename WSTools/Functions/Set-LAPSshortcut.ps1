function Set-LAPSshortcut {
<#
.PARAMETER Path
    Specifies whether to save to the Public Desktop or the logged on users desktop.
.EXAMPLE
    C:\PS>Set-LAPSshortcut PublicDesktop
    Shows how to setup the LAPS shortcut on the Public Desktop.
.EXAMPLE
    C:\PS>Set-LAPSshortcut UserDesktop
    Shows how to setup the LAPS shortcut on the logged on users desktop.
.EXAMPLE
    C:\PS>Set-LAPSshortcut -Path PublicDesktop
    Shows how to setup the LAPS shortcut on the Public Desktop.
.EXAMPLE
    C:\PS>Set-LAPSshortcut -Path UserDesktop
    Shows how to setup the LAPS shortcut on the logged on users desktop.
.NOTES
    Author: Skyler Hart
    Created: 2020-05-08 22:34:49
    Last Edit: 2021-10-13 20:48:50
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter either PublicDesktop or UserDesktop. PublicDesktop requires admin rights.",
            Mandatory=$true,
            Position=0
        )]
        [ValidateSet('PublicDesktop','UserDesktop')]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if ($Path -eq "PublicDesktop") {
        $sp = "C:\Users\Public\Desktop\LAPS.lnk"
    }
    elseif ($Path -eq "UserDesktop") {
        $sp = ([System.Environment]::GetFolderPath("Desktop")) + "\LAPS.lnk"
    }
    $AppLocation = "C:\Program Files\LAPS\AdmPwd.UI.exe"
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$sp")
    $Shortcut.TargetPath = $AppLocation
    $Shortcut.IconLocation = "C:\Program Files\LAPS\AdmPwd.UI.exe,0"
    $Shortcut.Description ="LAPS Admin Console"
    $Shortcut.WorkingDirectory ="C:\Program Files\LAPS"
    $Shortcut.Save()
}
