#Look up "root\WMI" or "root\CCM" using Get-ComputerWMINamespaces
function Get-WMIClass {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:05:10
    LASTEDIT: 09/21/2017 13:05:10
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string]$ComputerName = "$env:COMPUTERNAME"
    )

    Get-WmiObject -Namespace root\WMI -ComputerName $ComputerName -List
}
