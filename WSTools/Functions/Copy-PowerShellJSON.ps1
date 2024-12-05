function Copy-PowerShellJSON {
    <#
    .SYNOPSIS
        Enables PowerShell Snippets in Visual Studio Code.

    .DESCRIPTION
        Copies the powershell.json file from the WSTools module folder to %AppData%\Roaming\Code\User\snippets for
        the currently logged on user.

    .EXAMPLE
        C:\PS>Copy-PowerShellJSON
        Copies the powershell.json file from the WSTools module folder to %AppData%\Roaming\Code\User\snippets for
        the currently logged on user.

    .NOTES
        Author: Skyler Hart
        Created: 2020-04-13 22:44:11
        Last Edit: 2021-10-19 16:59:47
        Keywords: WSTools, Visual Studio Code, PowerShell, JSON, Preferences, snippets, code blocks

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [Alias('Update-PowerShellJSON','Set-PowerShellJSON')]
    param()

    if (!(Test-Path $env:APPDATA\Code\User)) {
        New-Item -Path $env:APPDATA\Code -ItemType Directory -Name User -Force
    }
    if (!(Test-Path $env:APPDATA\Code\User\snippets)) {
        New-Item -Path $env:APPDATA\Code\User -ItemType Directory -Name snippets -Force
    }
    Copy-Item -Path $PSScriptRoot\powershell.json -Destination $env:APPDATA\Code\User\snippets\powershell.json -Force
}
