function Convert-DatesToDays {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-03 08:54:49
    Last Edit: 2021-06-03 09:23:27
    Keywords: date, converter
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [ValidateLength(8,10)]
        [Alias('Day1')]
        [string]$Date1 = (Get-Date -Format "yyyy-MM-dd"),

        [Parameter(
            Mandatory=$false,
            Position=1
        )]
        [ValidateLength(8,10)]
        [Alias('Day2')]
        [string]$Date2 = (Get-Date -Format "yyyy-MM-dd")
    )

    $c1 = $Date1.Length
    if ($c1 -eq 8) {
        $y = $Date1.Substring(0,4)
        $m = $Date1.Substring(4)
        $m = $m.Substring(0,2)
        $d = $Date1.Substring(6)
        $start = (Get-Date -Year $y -Month $m -Day $d)
    }
    elseif ($c1 -eq 10) {
        $y = $Date1.Substring(0,4)
        $m = $Date1.Substring(5)
        $m = $m.Substring(0,2)
        $d = $Date1.Substring(8)
        $start = (Get-Date -Year $y -Month $m -Day $d)
    }

    $c2 = $Date2.Length
    if ($c2 -eq 8) {
        $y = $Date2.Substring(0,4)
        $m = $Date2.Substring(4)
        $m = $m.Substring(0,2)
        $d = $Date2.Substring(6)
        $end = (Get-Date -Year $y -Month $m -Day $d)
    }
    elseif ($c2 -eq 10) {
        $y = $Date2.Substring(0,4)
        $m = $Date2.Substring(5)
        $m = $m.Substring(0,2)
        $d = $Date2.Substring(8)
        $end = (Get-Date -Year $y -Month $m -Day $d)
    }

    $ts = New-TimeSpan -Start $start -End $end
    $ts.Days
}
