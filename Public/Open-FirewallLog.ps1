function Open-FirewallLog {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 09/11/2017 14:50:51
    LASTEDIT: 09/11/2017 14:50:51
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Switch]$Domain,

        [Parameter()]
        [Switch]$Private,

        [Parameter()]
        [Switch]$Public
    )

    if ($Private -eq $true) {notepad %systemroot%\system32\logfiles\firewall\domainfirewall.log}
    elseif ($Public -eq $true) {notepad %systemroot%\system32\logfiles\firewall\privatefirewall.log}
    elseif ($Domain -eq $true -or ($Private -eq $false -and $Public -eq $false)) {notepad %systemroot%\system32\logfiles\firewall\publicfirewall.log}
}
