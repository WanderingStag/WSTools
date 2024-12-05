function Open-FileWithCMTrace {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-22 17:35:23
    Last Edit: 2021-06-22 17:35:23
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Open-Log')]
    param(
        [Parameter(
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('File','Path')]
        [string[]]$FileName
    )
    $Continue = $false
    if (Test-Path "c:\Windows\ccm\CMTrace.exe") {
        $app = "c:\Windows\ccm\CMTrace.exe"
        $Continue = $true
    }
    elseif (Test-Path "C:\ProgramData\OSI\CMTrace.exe") {
        $app = "C:\ProgramData\OSI\CMTrace.exe"
        $Continue = $true
    }
    elseif (Test-Path "J:\Patches\CMTrace.exe") {
        $app = "J:\Patches\CMTrace.exe"
        $Continue = $true
    }
    else {
        Write-Error "Cannot find CMTrace.exe"
        $Continue = $false
    }

    if ($Continue) {
        foreach ($file in $FileName) {
            Start-Process $app -ArgumentList $file
        }
    }
}
