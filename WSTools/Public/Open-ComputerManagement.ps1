function Open-ComputerManagement {
<#
   .Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:48:35
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
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string]$ComputerName = "$env:COMPUTERNAME"
    )
    compmgmt.msc /computer:\\$ComputerName
}
