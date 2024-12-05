function Set-Preferences {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-18 13:00:47
    Last Edit: 2021-10-12 11:23:19
    Keywords:
    Requires:
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    $config = $Global:WSToolsConfig
    $explorer = $config.Explorer
    $store = $config.StoreLookup
    $hidden = $config.HiddenFiles
    $exten = $config.FileExtensions
    $sctext = $config.ShortcutText

    if ($explorer -eq $true) {
        try {
            Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1 -Force -ErrorAction Stop
        }
        catch {
            New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name Advanced -Force -ErrorAction Stop
            New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -PropertyType DWord -Value 1 -Force -ErrorAction Stop
        }
    }
    else {
        try {
            Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 2 -Force -ErrorAction Stop
        }
        catch {
            New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name Advanced -Force -ErrorAction Stop
            New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -PropertyType DWord -Value 2 -Force -ErrorAction Stop
        }
    }

    if ($store -eq $false) {
        try {
            Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Type DWord -Value 1 -Force -ErrorAction Stop
        }
        catch {
            New-Item -Path HKCU:\Software\Policies\Microsoft\Windows -Name Explorer -Force -ErrorAction SilentlyContinue
            New-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        try {
            Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Type DWord -Value 0 -Force -ErrorAction Stop
        }
        catch {
            New-Item -Path HKCU:\Software\Policies\Microsoft\Windows -Name Explorer -Force -ErrorAction Stop
            New-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -PropertyType DWord -Value 0 -Force -ErrorAction Stop
        }
    }

    if ($hidden -eq $true) {
        try {
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
        }
        catch {
            New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        try {
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -Type DWord -Value 2 -Force -ErrorAction SilentlyContinue
        }
        catch {
            New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -PropertyType DWord -Value 2 -Force -ErrorAction SilentlyContinue
        }
    }

    if ($exten -eq $true) {
        try {
            Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
        }
        catch {
            New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        try {
            Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
        }
        catch {
            New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue
        }
    }

    if ($sctext -eq $false) {
        try {
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name Link -Value ([byte[]](00,00,00,00)) -Force -ErrorAction SilentlyContinue
        }
        catch {
            New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name Link -PropertyType Binary -Value ([byte[]](00,00,00,00)) -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        try {
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name Link -Value ([byte[]](17,00,00,00)) -Force -ErrorAction SilentlyContinue
        }
        catch {
            New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name Link -PropertyType Binary -Value ([byte[]](17,00,00,00)) -Force -ErrorAction SilentlyContinue
        }
    }

    try {
        Set-PSReadLineOption -PredictionSource $predictionsource -ErrorAction Stop
    }
    catch {
        Set-PSReadLineOption -PredictionSource History -ErrorAction SilentlyContinue
    }
    Write-Output "Some settings will not apply until after you log off and then log back on."
}
