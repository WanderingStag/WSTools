function Register-ADSIEdit {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-19 19:53:38
    Last Edit: 2022-09-04 12:18:51
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Initialize-ADSIEdit','Enable-ADSIEdit')]
    param()

    if (Test-Path $env:windir\System32\adsiedit.dll) {
        regsvr32.exe adsiedit.dll
    }
    else {
        Write-Warning "adsiedit.dll not found. Please ensure Active Directory tools are installed."
    }
}
