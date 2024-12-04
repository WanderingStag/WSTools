function Stop-AxwayTrayApp {
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
    C:\PS>Stop-AxwayTrayApp
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Stop-AxwayTrayApp -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.NOTES
    Author: Skyler Hart
    Created: 2021-06-16 23:28:20
    Last Edit: 2021-06-16 23:28:20
    Keywords:
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    Get-Process | Where-Object {$_.Name -match "dvtray"} | Stop-Process -Force
}
