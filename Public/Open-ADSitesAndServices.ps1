function Open-ADSitesAndServices {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:29:08
    LASTEDIT: 2022-09-04 12:06:04
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    try {
        $ErrorActionPreference = "Stop"
        dssite.msc
    }
    catch {
        Write-Output "Active Directory snapins are not installed/enabled."
    }
}
