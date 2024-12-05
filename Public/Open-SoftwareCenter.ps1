function Open-SoftwareCenter {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-09-28 09:36:19
    Last Edit: 2020-09-28 09:36:19
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('SoftwareCenter','SCCM','MECM')]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [ValidateSet('AvailableSoftware','Updates','OSD','InstallationStatus','Compliance','Options')]
        [ValidateNotNullOrEmpty()]
        [Alias('Tab')]
        [string]$Page = "AvailableSoftware"
    )

    Start-Process softwarecenter:Page=$Page
}
