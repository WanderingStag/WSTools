function Get-CurrentUser {
<#
.NOTES
    Author: Skyler Hart
    Created: 08/18/2017 20:58:42
    Last Edit: 2021-01-25 15:35:47
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName
    )

    Write-Output "`n Checking Users . . . "
    $i = 0

    $number = $ComputerName.length
    $ComputerName | Foreach-object {
    $Computer = $_
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting current user on computers. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length
    try
        {
            $processinfo = @(Get-WmiObject -class win32_process -ComputerName $Computer -EA "Stop")
                if ($processinfo) {
                    $processinfo | Foreach-Object {$_.GetOwner().User} |
                    Where-Object {$_ -ne "NETWORK SERVICE" -and $_ -ne "LOCAL SERVICE" -and $_ -ne "SYSTEM" -and $_ -ne "DWM-1" -and $_ -ne "UMFD-0" -and $_ -ne "UMFD-1 "} |
                    Sort-Object -Unique |
                    ForEach-Object {[PSCustomObject]@{Computer=$Computer;LoggedOn=$_} } |
                    Select-Object Computer,LoggedOn
                }#If
        }
    catch
        {
            "Cannot find any processes running on $computer" | Out-Host
        }
     }#Forech-object(ComputerName)
}#Get-CurrentUser
