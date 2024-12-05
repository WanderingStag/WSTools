function Get-SplunkStatus {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-08-13 21:52:22
    Last Edit: 2021-08-13 21:52:22
    Keywords:
    Other:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    if ($ComputerName -eq $env:COMPUTERNAME) {
        $info = Get-Service -Name SplunkForwarder -ComputerName $comp
        [PSCustomObject]@{
            ComputerName = $comp
            SplunkStatus = ($info.Status)
        }#new object
    }
    else {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $i = 0
            $number = $ComputerName.length
            foreach ($Comp in $ComputerName) {
                #Progress Bar
                if ($number -gt "1") {
                    $i++
                    $amount = ($i / $number)
                    $perc1 = $amount.ToString("P")
                    Write-Progress -activity "Getting status of Splunk Service" -status "Computer $i ($comp) of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
                }#if length
                $info = Get-Service -Name SplunkForwarder -ComputerName $comp
                [PSCustomObject]@{
                    ComputerName = $comp
                    SplunkStatus = ($info.Status)
                }#new object
            }
        }
        else {Write-Error "Must be ran as administrator"}
    }
}
