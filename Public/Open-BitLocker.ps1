function Open-BitLocker {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 21:56:03
    LASTEDIT: 08/19/2017 21:56:03
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
    [Alias('BitLocker')]
    param()
    control.exe /name Microsoft.BitLockerDriveEncryption
}
