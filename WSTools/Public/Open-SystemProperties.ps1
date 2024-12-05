function Open-SystemProperties {
<#
   .Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:49:29
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    control.exe sysdm.cpl
}
