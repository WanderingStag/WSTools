function Convert-DaysToWorkDay {
<#
.EXAMPLE
    C:\PS>Convert-DaysToWorkDay 1
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Convert-DaysToWorkDay -1
    Another example of how to use this cmdlet.
.NOTES
    Author: Skyler Hart
    Created: 2021-03-04 18:54:31
    Last Edit: 2021-06-20 17:13:33
    Keywords:
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
            HelpMessage = "Enter the amount of days you want to convert. Must an a positive or negative integer (Ex: 1 or -1).",
            Mandatory=$true,
            Position=0
        )]
        [int32]$Days,

        [Parameter(
            HelpMessage = "Must be in the format yyyy-MM-dd.",
            Mandatory=$false,
            Position=1
        )]
        [datetime]$StartDay = (Get-Date).Date
    )

    $holidays = ($Global:WSToolsConfig).Holidays.Date

    if ($Days -lt 0) {
        $sub = "sub"
    }
    elseif ($Days -gt 0) {
        $sub = "add"
    }
    else {$sub = "zero"}

    if ($sub -eq "sub") {
        $i = -1
        do {
            $StartDay = $StartDay.AddDays(-1)

            if ($holidays -contains $StartDay) {
                $StartDay = $StartDay.AddDays(-1)
            }

            if ($StartDay.DayOfWeek -match "Sunday") {
                $StartDay = $StartDay.AddDays(-1)
            }

            if ($StartDay.DayOfWeek -match "Saturday") {
                $StartDay = $StartDay.AddDays(-1)
            }

            if ($holidays -contains $StartDay) {
                $StartDay = $StartDay.AddDays(-1)
            }

            $i--
        } until ($i -lt $Days)

        if ($holidays -contains $StartDay) {
            $StartDay = $StartDay.AddDays(-1)
        }

        if ($StartDay.DayOfWeek -match "Sunday") {
            $StartDay = $StartDay.AddDays(-1)
        }

        if ($StartDay.DayOfWeek -match "Saturday") {
            $StartDay = $StartDay.AddDays(-1)
        }

        if ($holidays -contains $StartDay) {
            $StartDay = $StartDay.AddDays(-1)
        }
        $StartDay
    }
    elseif ($sub -eq "add") {
        $i = 1
        do {
            $StartDay = $StartDay.AddDays(1)

            if ($holidays -contains $StartDay) {
                $StartDay = $StartDay.AddDays(1)
            }

            if ($StartDay.DayOfWeek -match "Saturday") {
                $StartDay = $StartDay.AddDays(1)
            }

            if ($StartDay.DayOfWeek -match "Sunday") {
                $StartDay = $StartDay.AddDays(1)
            }

            if ($holidays -contains $StartDay) {
                $StartDay = $StartDay.AddDays(1)
            }

            $i++
        } until ($i -gt $Days)

        if ($holidays -contains $StartDay) {
            $StartDay = $StartDay.AddDays(1)
        }

        if ($StartDay.DayOfWeek -match "Saturday") {
            $StartDay = $StartDay.AddDays(1)
        }

        if ($StartDay.DayOfWeek -match "Sunday") {
            $StartDay = $StartDay.AddDays(1)
        }

        if ($holidays -contains $StartDay) {
            $StartDay = $StartDay.AddDays(1)
        }
        $StartDay
    }
    else {$StartDay}
}
