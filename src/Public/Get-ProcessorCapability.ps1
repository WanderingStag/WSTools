function Get-ProcessorCapability {
<#
.NOTES
    Author: Skyler Hart
    Created: Sometime before 8/7/2017
    Last Edit: 2020-04-18 22:46:31
    Keywords:
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
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    foreach ($comp in $ComputerName) {
        try {
            $ErrorActionPreference = "Stop"
            $strComputerName = $comp
            $strCpuArchitecture = $null
            $intCurrentAddressWidth = 0
            $intSupportableAddressWidth = 0

            $objWmi = Get-WmiObject -class "Win32_Processor" -namespace "root\cimV2" -computer $strComputerName -ErrorAction Stop

            $intCurrentAddressWidth = $objWmi.AddressWidth
            $intSupportableAddressWidth = $objWmi.DataWidth

            switch ($objWmi.Architecture) {
                0 {$strCpuArchitecture = "x86"}
                1 {$strCpuArchitecture = "MIPS"}
                2 {$strCpuArchitecture = "Alpha"}
                3 {$strCpuArchitecture = "PowerPC"}
                6 {$strCpuArchitecture = "Itanium"}
                9 {$strCpuArchitecture = "x64"}
            }

            if ($null -eq $intCurrentAddressWidth) {$curbit = $null}
            else {$curbit = "$intCurrentAddressWidth-bit"}

            if ($null -eq $intSupportableAddressWidth) {$capof = $null}
            else {$capof = "$intSupportableAddressWidth-bit"}
        }
        catch [System.UnauthorizedAccessException],[System.Management.Automation.MethodInvocationException] {
            $err = $_.Exception.message.Trim()
            if ($err -match "network path") {
                $strCpuArchitecture = "Could not connect"
                $curbit = $null
                $capof = $null
            }
            elseif ($err -match "access is not allowed" -or $err -match "Access is denied") {
                $strCpuArchitecture = "Insufficient Permissions"
                $curbit = $null
                $capof = $null
            }
            else {
                $strCpuArchitecture = "Error - unknown issue"
                $curbit = $null
                $capof = $null
            }
        }
        catch {
            $strCpuArchitecture = "Could not connect"
            $curbit = $null
            $capof = $null
        }
        [PSCustomObject]@{
            ComputerName = $comp
            CurrentBit = $curbit
            CapableOf = $capof
            Architecture = $strCpuArchitecture
        }
    }#foreach comp
}
