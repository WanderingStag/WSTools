function Get-ModuleList {
    <#
    .SYNOPSIS
        Short description
    .DESCRIPTION
        Long description
    .PARAMETER ComputerName
        Specifies the name of one or more computers.
    .PARAMETER Path
        Specifies a path to one or more locations.
    .EXAMPLE
        C:\PS>Get-ModuleList
        Example of how to use this cmdlet
    .EXAMPLE
        C:\PS>Get-ModuleList -PARAMETER
        Another example of how to use this cmdlet but with a parameter or switch.
    .NOTES
        Author: Skyler Hart
        Created: 2021-08-11 23:22:30
        Last Edit: 2021-08-11 23:41:15
        Keywords:
        Other:
        Requires:
            -Module ActiveDirectory
            -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
            -RunAsAdministrator
    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param(
        [switch]$NotInCommandListModules
    )

    $modules = Get-Module -ListAvailable | Select-Object -Unique
    if ($NotInCommandListModules) {
        $nil = @()
        $clm = Import-Csv $PSScriptRoot\CommandListModules.csv
        $cm = $clm.Module
        foreach ($m in $modules) {
            $mn = $m.Name
            if ($cm -match $mn) {
                #do nothing
            }
            else {
                $nil += $mn
            }
        }

        $nil
    }
    else {
        $modules | Select-Object * | Sort-Object Name
    }
}
