function Get-NetworkLevelAuthentication {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-18 15:28:10
    Last Edit: 2020-04-18 15:28:10
    Keywords: Network, NLA, Network Level Authentication, RDP, Remote Desktop
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Get-NLA')]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    foreach ($Comp in $ComputerName) {
        try {
            $ErrorActionPreference = "Stop"
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Comp)
            $key = $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp")
            [Bool]$ua = $key.GetValue('UserAuthentication')

            [PSCustomObject]@{
                ComputerName = $Comp
                UserAuthentication = $ua
            }#new object
        }
        catch [System.Management.Automation.MethodInvocationException] {
            $err = $_.Exception.message.Trim()
            if ($err -match "network path") {
                $ua = "Could not connect"
            }
            elseif ($err -match "access is not allowed") {
                $ua = "Insufficient permissions"
            }
            else {
                $ua = "Unknown error"
            }
            [PSCustomObject]@{
                ComputerName = $Comp
                UserAuthentication = $ua
            }#new object
        }
        catch {
            [PSCustomObject]@{
                ComputerName = $Comp
                UserAuthentication = "Unknown error"
            }#new object
        }
    }
}
