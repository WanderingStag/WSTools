function Get-ComputerModel {
    <#
    .Parameter ComputerName
        Specifies the computer or computers

    .Notes
        AUTHOR: Skyler Hart
        CREATED: 2018-06-20 13:05:09
        LASTEDIT: 2020-08-31 21:40:19
        REQUIRES:
            -RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [Alias('Get-Model')]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )
    Process {
        foreach ($comp in $ComputerName) {
            try {
                $csi = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $comp -ErrorAction Stop

                switch ($csi.DomainRole) {
                    0 {$dr = "Standalone Workstation"}
                    1 {$dr = "Member Workstation"}
                    2 {$dr = "Standalone Server"}
                    3 {$dr = "Member Server"}
                    4 {$dr = "Domain Controller"}
                    5 {$dr = "Primary Domain Controller"}
                }

                if ($csi.Model -contains "Virtual") {$PorV = "Virtual"}
                else {$PorV = "Physical"}

                switch ($csi.PCSystemType) {
                    2 {$type = "Laptop/Tablet"}
                    default {$type = "Desktop"}
                }

                $manu = $csi.Manufacturer
                $model = $csi.Model

                [PSCustomObject]@{
                    ComputerName = $comp
                    DomainRole = $dr
                    Manufacturer = $manu
                    Model = $model
                    PorV = $PorV
                    Type = $type
                }
            }
            catch {
                $na = "NA"
                [PSCustomObject]@{
                    ComputerName = $comp
                    DomainRole = "Unable to connect"
                    Manufacturer = $na
                    Model = $na
                    PorV = $na
                    Type = $na
                }
            }
        }
    }
}
