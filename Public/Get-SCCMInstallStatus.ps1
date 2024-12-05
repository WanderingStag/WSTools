function Get-SCCMInstallStatus {
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
    C:\PS>Get-SCCMInstallStatus
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Get-SCCMInstallStatus -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    The functionality (keywords) that best describes this cmdlet
.NOTES
    Author: Skyler Hart
    Created: 2023-03-29 23:01:59
    Last Edit: 2023-03-29 23:01:59
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias()]
    param(
        [Parameter(
            #HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false#,
            #Position=0,
            #ValueFromPipeline = $true
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateCount(min,max)]
        [ValidateLength(min,max)]
        [ValidateSet('Info','Error','Warning','One','Two','Three')]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $status = Invoke-Command -ComputerName $ComputerName -ScriptBlock {#DevSkim: ignore DS104456
        try {
            $CCMUpdate = get-wmiobject -query "SELECT * FROM CCM_SoftwareUpdate" -namespace "ROOT\ccm\ClientSDK" -ErrorAction stop
            if (@($CCMUpdate | Where-Object {$_.EvaluationState -eq 2 -or $_.EvaluationState -eq 3 -or $_.EvaluationState -eq 4 -or $_.EvaluationState -eq 5 -or $_.EvaluationState -eq 6 -or $_.EvaluationState -eq 7 -or $_.EvaluationState -eq 11 }).length -ne 0) {
                [pscustomobject]@{Computer = $env:computername; UpdateStatus = "3 - In Progress"}
            } elseif(@($CCMUpdate | Where-Object {$_.EvaluationState -eq 13}).length -ne 0) {
                [pscustomobject]@{Computer = $env:computername; UpdateStatus = "4 - Update Failed"}
            } elseif(@($CCMUpdate | Where-Object { $_.EvaluationState -eq 8 -or $_.EvaluationState -eq 9 -or $_.EvaluationState -eq 10 }).length -ne 0) {
                [pscustomobject]@{Computer = $env:computername; UpdateStatus = "2 - Requires Reboot"}
            } elseif(@($CCMUpdate | Where-Object { $_.EvaluationState -eq 0 -or $_.EvaluationState -eq 1}).length -ne 0) {
                [pscustomobject]@{Computer = $env:computername; UpdateStatus = "0 - Updates Available"}
            } else {
                [pscustomobject]@{Computer = $env:computername; UpdateStatus = "1 - Completed"}
            }
        } catch {
            [pscustomobject]@{Computer = $env:computername; UpdateStatus = "5 - Error Reading Update History"}
        }
    } -ErrorAction SilentlyContinue
    ForEach ($server in $servers) {
        if ($status.computer -notcontains $server) {
            $status += [pscustomobject]@{Computer = $server;UpdateStatus = "6 - Remote Connection Failure"}
        }
    }
    $status | Select-Object Computer,UpdateStatus | Sort-Object -Property UpdateStatus,Computer
}
