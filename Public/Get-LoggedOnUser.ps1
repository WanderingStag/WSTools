function Get-LoggedOnUser {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:58:59
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
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Switch]$Lookup
     )

    foreach ($comp in $ComputerName) {
        if ($Lookup) {
            try {
                #$comp = "tvyxl-vpn119"
                $Hardware = get-wmiobject Win32_computerSystem -Computername $comp
                $username = $Hardware.Username
                $username2 = $username -creplace '^[^\\]*\\', ''
                $disp = (Get-ADUser $username2 -Properties DisplayName).DisplayName

                [PSCustomObject]@{
                    Computer = $Comp
                    Username = $Username
                    DisplayName = $disp
                } | Select-Object Computer,Username,DisplayName
            }#try
            catch {
                $Username = "Comm Error"
                [PSCustomObject]@{
                    Computer = $Comp
                    Username = $Username
                    DisplayName = $null
                } | Select-Object Computer,Username,DisplayName
            }#catch
        }#if need to lookup
        else {
            try {
                $Hardware = get-wmiobject Win32_computerSystem -Computername $comp
                $username = $Hardware.Username
                [PSCustomObject]@{
                    Computer = $Comp
                    Username = $Username
                } | Select-Object Computer,Username
            }#try
            catch {
                $Username = "Comm Error"
                [PSCustomObject]@{
                    Computer = $Comp
                    Username = $Username
                } | Select-Object Computer,Username
            }#catch
        }#else
    }#foreach comp
}
