function Copy-UpdateHistory {
    <#
    .SYNOPSIS
        Copies the UpdateHistory.csv report to the UHPath config item path.

    .DESCRIPTION
        Copies the UpdateHistory.csv report created with Save-UpdateHistory to the UHPath config item path for the
        local computer or remote computers.

    .PARAMETER ComputerName
        Specifies the name of one or more computers.

    .EXAMPLE
        C:\PS>Copy-UpdateHistory
        Example of how to use this cmdlet to copy the UpdateHistory.csv file for the local computer to the UHPath
        location.

    .EXAMPLE
        C:\PS>Copy-UpdateHistory -ComputerName Server1
        Example of how to use this cmdlet to copy the UpdateHistory.csv file for the remote computer Server1 to the
        UHPath location.

    .INPUTS
        System.String

    .OUTPUTS
        System.String

    .COMPONENT
        WSTools

    .FUNCTIONALITY
        UpdateHistory, update history

    .NOTES
        Author: Skyler Hart
        Created: 2022-07-15 22:54:09
        Last Edit: 2022-07-15 22:54:09
        Other:
        Requires:
            -RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $uhpath = ($Global:WSToolsConfig).UHPath
    $i = 0
    $number = $ComputerName.length
    foreach ($Comp in $ComputerName) {
        # Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Copying Update Reports. Current computer: $Comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }# if length

        if ($Comp -eq $env:COMPUTERNAME) {
            if (Test-Path C:\ProgramData\WSTools\Reports\$Comp`_UpdateHistory.csv) {
                robocopy C:\ProgramData\WSTools\Reports $uhpath *_UpdateHistory.csv /r:3 /w:5 /njh /njs | Out-Null
            }
            else {
                Write-Error "Report not found. Please use Save-UpdateHistory to create a report."
            }
        }
        else {
            robocopy \\$Comp\c$\ProgramData\WSTools\Reports $uhpath *_UpdateHistory.csv /r:3 /w:5 /njh /njs | Out-Null
        }
    }
}
