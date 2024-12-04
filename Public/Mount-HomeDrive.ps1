function Mount-HomeDrive {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-11-03 14:58:38
    Last Edit: 2020-11-03 14:58:38
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Add-HomeDrive')]
    param()
    net use $env:HOMEDRIVE $env:HOMESHARE /persistent:yes
}
