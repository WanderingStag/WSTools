function Get-DayOfYear {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2021-05-20 20:48:46
        Last Edit: 2021-05-20 21:48:24
        Keywords: Day of year, Julian

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [Alias('Get-JulianDay','Get-JulianDate')]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [ValidateLength(1,10)]
        [Alias('Date')]
        [string]$Day = (Get-Date -Format "yyyy-MM-dd"),

        [Parameter(
            Mandatory=$false,
            Position=1
        )]
        [ValidateLength(4,4)]
        [string]$Year
    )

    $c = $Day.Length
    if ($c -le 3) {
        $nd = $Day - 1
        if ([string]::IsNullOrWhiteSpace($Year)) {
            [string]$Year = (Get-Date).Year
            $info = (Get-Date -Day 1 -Month 1 -Year $Year).AddDays($nd)
        }
        else {
            $info = (Get-Date -Day 1 -Month 1 -Year $Year).AddDays($nd)
        }
        $info
    }
    elseif ($c -eq 8) {
        $y = $Day.Substring(0,4)
        $m = $Day.Substring(4)
        $m = $m.Substring(0,2)
        $d = $Day.Substring(6)
        $info = (Get-Date -Year $y -Month $m -Day $d).DayOfYear
        $info
    }
    elseif ($c -eq 10) {
        $y = $Day.Substring(0,4)
        $m = $Day.Substring(5)
        $m = $m.Substring(0,2)
        $d = $Day.Substring(8)
        $info = (Get-Date -Year $y -Month $m -Day $d).DayOfYear
        $info
    }
    else {
        Write-Error "Not in the correct format. Format must be entered in the format x, xx, or xxx for a day of the year. Ex: 12. For a date, it must be entered in the format yyyyMMdd or yyyy-MM-dd. Ex: 2021-05-20" -Category SyntaxError
    }
}
