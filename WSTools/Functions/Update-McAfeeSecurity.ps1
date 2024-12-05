function Update-McAfeeSecurity {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-10-30 03:14:47
    Last Edit: 2021-10-30 03:14:47
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    $fpath = "${env:ProgramFiles(x86)}\McAfee\Endpoint Security\Threat Prevention\amcfg.exe"
    if (Test-Path $fpath) {
        Start-Process $fpath -ArgumentList "/update"
    }
    else {
        Write-Error "McAfee Endpoint Security Threat Protection not installed"
    }
}
