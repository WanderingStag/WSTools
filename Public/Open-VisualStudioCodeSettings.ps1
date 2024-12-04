function Open-VisualStudioCodeSettings {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-05-18 21:18:59
    Last Edit: 2021-05-18 21:27:47
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does."
    )]
    [CmdletBinding()]
    [Alias('Open-VSCCodeSettings')]
    param()

    $vssettings = "$env:APPDATA\Code\User\settings.json"
    if ($host.Name -match "Visual Studio Code") {
        code $vssettings
    }
    else {
        powershell_ise $vssettings
    }
}
