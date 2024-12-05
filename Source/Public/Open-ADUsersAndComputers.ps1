function Open-ADUsersAndComputers {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:28:17
    LASTEDIT: 2022-09-04 12:07:24
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('aduc','dsa')]
    param()
    try {
        $ErrorActionPreference = "Stop"
        dsa.msc
    }
    catch {
        Write-Output "Active Directory snapins are not installed/enabled."
    }
}
