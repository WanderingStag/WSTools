function Test-RegistryValue {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 02/08/2018 22:32:46
    LASTEDIT: 02/08/2018 22:32:46
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
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]$Path,

        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]$Value
    )

    try {
        Get-ItemPropertyValue -Path $Path -Name $Value -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}
