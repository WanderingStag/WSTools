function Register-NotificationApp {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-11-03 21:36:05
    Last Edit: 2020-11-03 21:36:05
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the short name of the application.",
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$AppID,

        [Parameter(
            HelpMessage = "Enter the display name of the application.",
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$AppDisplayName,

        [Parameter(
            Mandatory=$false
        )]
        [int]$ShowInSettings = 0
    )

    $HKCR = Get-PSDrive -Name HKCR -ErrorAction SilentlyContinue
    if (!($HKCR)) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root Hkey_Classes_Root -Scope Script
    }

    $AppRegPath = "HKCR:\AppUserModelId"
    $RegPath = "$AppRegPath\$AppID"
    if (!(Test-Path $RegPath)) {
        $null = New-Item -Path $AppRegPath -Name $AppID -Force
    }

    $DisplayName = Get-ItemProperty -Path $RegPath -Name DisplayName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
    if ($DisplayName -ne $AppDisplayName) {
        $null = New-ItemProperty -Path $RegPath -Name DisplayName -Value $AppDisplayName -PropertyType String -Force
    }

    $ShowInSettingsValue = Get-ItemProperty -Path $RegPath -Name ShowInSettings -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ShowInSettings -ErrorAction SilentlyContinue
    if ($ShowInSettingsValue -ne $ShowInSettings) {
        $null = New-ItemProperty -Path $RegPath -Name ShowInSettings -Value $ShowInSettings -PropertyType DWORD -Force
    }
    Remove-PSDrive -Name HKCR -Force
}
