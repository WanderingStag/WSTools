function Set-NetworkConnectionsShortcut {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-05-08 23:01:21
    Last Edit: 2021-10-13 20:55:00
    Keywords:
    Requires:
        -RunAsAdministrator if placing in Public Desktop.
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
        $sp = "C:\Users\Public\Desktop\Network Connections.lnk"
    }
    elseif ($Path -eq "UserDesktop") {
        $sp = ([System.Environment]::GetFolderPath("Desktop")) + "\Network Connections.lnk"
    }
    $AppLocation = "explorer.exe"
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$sp")
    $Shortcut.TargetPath = $AppLocation
    $Shortcut.Arguments = "shell:::{992CFFA0-F557-101A-88EC-00DD010CCC48}"
    $Shortcut.IconLocation = "$env:systemroot\system32\netshell.dll,0"
    $Shortcut.Description = "Network Connection Properties"
    $Shortcut.WorkingDirectory = "C:\Windows\System32"
    $Shortcut.Save()
}
