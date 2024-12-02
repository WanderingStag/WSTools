function Get-SerialNumber {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 11/02/2018 12:11:03
    LASTEDIT: 11/02/2018 12:20:44
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Get-SN')]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $i = 0
    $number = $ComputerName.length
    foreach ($comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting Serial NUmber of computers" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length
        try {
            $sn = (Get-WmiObject win32_bios -ComputerName $comp | Select-Object SerialNumber).SerialNumber
            [PSCustomObject]@{
                ComputerName = $comp
                SerialNumber = $sn
            }#new object
        }
        catch {
            [PSCustomObject]@{
                ComputerName = $comp
                SerialNumber = "NA"
            }#new object
        }
    }
}
