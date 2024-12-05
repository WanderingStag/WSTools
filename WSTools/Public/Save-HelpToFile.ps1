function Save-HelpToFile {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-12-17 23:05:01
    Last Edit: 2021-12-17 23:05:01
    Keywords:
    Other:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter()]
        [Alias('Path','Folder','Destination')]
        [string]$DestinationPath
    )

    if ([string]::IsNullOrWhiteSpace($Source)) {
        $DestinationPath = ($Global:WSToolsConfig).HelpFolder
    }

    if (Test-Path $DestinationPath) {
        Save-Help -DestinationPath $DestinationPath -Module * -Force
    }
    else {
        Write-Error 'Destination folder "$DestinationPath" not found.'
    }
}
