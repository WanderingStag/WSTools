function Start-SCCMUpdateScan {
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
    C:\PS>Start-SCCMUpdateScan
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Start-SCCMUpdateScan -PARAMETER
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
    Created: 2023-03-29 21:50:02
    Last Edit: 2023-03-29 21:50:02
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
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    Process {
        foreach ($Comp in $ComputerName) {
            if ($Comp -eq $env:COMPUTERNAME) {
                Get-WmiObject -Query "SELECT * FROM CCM_UpdateStatus" -Namespace "root\ccm\SoftwareUpdates\UpdatesStore" | ForEach-Object {
                    if($_.ScanTime -gt $ScanTime) { $ScanTime = $_.ScanTime }
                }; $LastScan = ([System.Management.ManagementDateTimeConverter]::ToDateTime($ScanTime)); $LastScan;
	            if(((get-date) - $LastScan).minutes -ge 10) {
		            [void]([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000113}');
		            ([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000108}'); "Update scan and evaluation"
	            }
            }
            else {
                Invoke-Command -ComputerName $Comp -ScriptBlock {#DevSkim: ignore DS104456
                    Get-WmiObject -Query "SELECT * FROM CCM_UpdateStatus" -Namespace "root\ccm\SoftwareUpdates\UpdatesStore" | ForEach-Object {
                        if($_.ScanTime -gt $ScanTime) { $ScanTime = $_.ScanTime }
                    }; $LastScan = ([System.Management.ManagementDateTimeConverter]::ToDateTime($ScanTime)); $LastScan;
                    if(((get-date) - $LastScan).minutes -ge 10) {
                        [void]([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000113}');
                        ([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000108}'); "Update scan and evaluation"
                    }
                }
            }#not local
        }#foreach comp
    }
}
