function Set-AutoLoadPreference {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/01/2018 10:23:26
    LASTEDIT: 02/01/2018 10:23:26
    KEYWORDS:
    REQUIRES:
        -Version 2.0 only doesn't apply to Version 3.0 or newer
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [ValidateSet("All","None")]
        $mode = "All"
    )
    $PSModuleAutoloadingPreference = $mode
}
