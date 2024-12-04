function Open-DiskManagement {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 22:19:32
    LASTEDIT: 08/19/2017 22:19:32
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
    diskmgmt.msc /computer:\\$ComputerName
}
