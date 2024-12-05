function Test-Online {
<#
   .Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:47:56

    TODO: Add functionality to convert ip to computername and vice versa. Enter ip range 192.168.0.0/26
    and have it convert it. Or 192.168.0.0-255 and check all computers. Write help. Add aliases and fix pipeline.

    .LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $i = 0
    $number = $ComputerName.length
    foreach ($comp in $ComputerName){
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Testing whether computers are online or offline. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length
        try {
            $testcon = Test-Connection -ComputerName $comp -Count 3 -ErrorAction Stop
            if ($testcon) {
                $status = "Online"
            }#if test
            else {
                $status = "Offline"
            }#else
        }#try
        catch [System.Net.NetworkInformation.PingException] {
            $status = "Comm error"
        }#catch
        catch [System.Management.Automation.InvocationInfo] {
            $status = "Comm error"
        }
        catch {
            $status = "Comm error"
        }
        [PSCustomObject]@{
            Name = $comp
            Status = $status
        }#newobject
    }#foreach computer
}
