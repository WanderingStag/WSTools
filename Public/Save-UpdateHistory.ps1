function Save-UpdateHistory {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-06-15 13:03:22
    Last Edit: 2023-03-22 08:26:33
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
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [int32]$ThrottleLimit = 5
    )

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {#DevSkim: ignore DS104456
        [int32]$Days = ((Get-Date -Format yyyyMMdd) - ((Get-Date -Format yyyyMMdd).Substring(0,6) + "01") + 1)
        $fn = $env:computername + "_UpdateHistory.csv"
        $lf = $env:ProgramData + "\WSTools\Reports"
        $lp = $lf + "\" + $fn

        $stime = (Get-Date) - (New-TimeSpan -Day $Days)
        $session = New-Object -ComObject 'Microsoft.Update.Session'
        $ec = ($session.CreateUpdateSearcher()).GetTotalHistoryCount()
        $history = ($session.QueryHistory("",0,$ec) |
            Select-Object ResultCode,Date,Title,Description,ClientApplicationID,Categories,SupportUrl)
        $ef = $history | Where-Object {$_.Date -gt $stime -and !([string]::IsNullOrWhiteSpace($_.Title))}

        $wsusupdates = foreach ($e in $ef) {
            switch ($e.ResultCode) {
                0 {$Result = "Not Started"}
                1 {$Result = "Restart Required"}
                2 {$Result = "Succeeded"}
                3 {$Result = "Succeeded With Errors"}
                4 {$Result = "Failed"}
                5 {$Result = "Aborted"}
                Default {$Result = ($e.ResultCode)}
            }#switch

            $Cat = $e.Categories | Select-Object -First 1 -ExpandProperty Name

            [PSCustomObject]@{
                ComputerName = $env:computername
                Date = ($e.Date)
                Result = $Result
                KB = (([regex]::match($e.Title,'KB(\d+)')).Value)
                Title = ($e.Title)
                Category = $Cat
                ClientApplicationID = ($e.ClientApplicationID)
                Description = ($e.Description)
                SupportUrl = ($e.SupportUrl)
            }
        }#foreach event in history

        $WSUSkbs = $wsusupdates | Where-Object {$_.Result -eq "Succeeded"} | Select-Object -ExpandProperty KB -Unique

        $setuplogevents = Get-WinEvent -FilterHashtable @{logname = 'setup'} | Where-Object {($_.Id -eq 2 -or $_.Id -eq 3) -and $_.TimeCreated -gt $stime}
        $manualupdates = foreach ($update in $setuplogevents) {
            $updatekb = ($update.Message | Select-String -Pattern 'KB(\d+)' -AllMatches) | Select-Object -ExpandProperty Matches

            if ($updatekb -in $WSUSkbs) {
                #do nothing
            }
            else {
                if ($update.Id -eq 2) {$status = "Succeeded"}
                else {$status = "Failed"}

                [PSCustomObject]@{
                    ComputerName = $env:computername
                    Date = $update.TimeCreated
                    Result = $status
                    KB = $updatekb
                    Title = $null
                    Category = $null
                    ClientApplicationID = "Manual or Remote Script"
                    Description = $null
                    SupportUrl = $null
                }#new object
            }
        }

        $allupdates = @()
        $allupdates += $wsusupdates
        $allupdates += $manualupdates

        if (Test-Path $env:ProgramData\WSTools) {
            #do nothing
        }
        else {
            New-Item -Path $env:ProgramData -Name WSTools -ItemType Directory
        }

        if (Test-Path $lf) {
            #do nothing
        }
        else {
            New-Item -Path $env:ProgramData\WSTools -Name Reports -ItemType Directory
        }

        $allupdates | Sort-Object Date -Descending | Export-Csv $lp -Force
    } -ThrottleLimit $ThrottleLimit
}
