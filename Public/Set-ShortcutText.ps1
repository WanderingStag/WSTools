function Set-ShortcutText {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-18 20:44:39
    Last Edit: 2020-04-18 20:44:39
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Switch]$Yes,
        [Switch]$No
    )

    if ($Yes) {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name Link -Value ([byte[]](00,00,00,00)) -Force}
    elseif ($No) {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name Link -Value ([byte[]](17,00,00,00)) -Force}
    else {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name NoUseStoreOpenWith -Value ([byte[]](00,00,00,00)) -Force}
}
