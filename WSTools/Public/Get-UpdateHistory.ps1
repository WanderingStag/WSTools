function Get-UpdateHistory {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2020-05-23 20:44:28
        Last Edit: 2023-03-12 22:08:43
        Keywords:
    .LINK
        https://wanderingstag.github.io
    #>
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$false, Position=0)]
            [Alias('DaysBackToSearch')]
            [int32]$Days = "7"
        )

        $stime = (Get-Date) - (New-TimeSpan -Day $Days)
        $session = New-Object -ComObject 'Microsoft.Update.Session'
        $ec = ($session.CreateUpdateSearcher()).GetTotalHistoryCount()
        $history = ($session.QueryHistory("",0,$ec) | Select-Object ResultCode,Date,Title,Description,ClientApplicationID,Categories,SupportUrl)
        $ef = $history | Where-Object {$_.Date -gt $stime}

        $wsusupdates = foreach ($e in $ef | Where-Object {$null -ne ($e.Title) -or ($e.Title) -ne ""}) {
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

        $allupdates | Sort-Object Date -Descending

    <#
        This remote piece requires a firewall change in order to get it to work...
        New-NetFirewallRule -DisplayName "RPC Dynamic Ports" -Enabled:True -Profile:Domain -Direction:Inbound -Action:Allow -Protocol "TCP" -Program "%systemroot%\system32\dllhost.exe"

        The error that it gets is:
        Exception calling "CreateInstance" with "1" argument(s): "Retrieving the COM class factory for remote component with
        CLSID {4CB43D7F-7EEE-4906-8698-60DA1C38F2FE} from machine SN1001 failed due to the following error: 800706ba SN1001."

        foreach ($comp in $ComputerName) {
            $session = [Activator]::CreateInstance([type]::GetTypeFromProgID('Microsoft.Update.Session',$comp))
            $ec = ($session.CreateUpdateSearcher()).GetTotalHistoryCount()
            $history = ($session.QueryHistory("",0,$ec) | Select-Object ResultCode,Date,Title,Description,ClientApplicationID,Categories,SupportUrl)
            $ef = $history | Where-Object {$_.Date -gt $stime}

            foreach ($e in $ef | Where-Object {$null -ne ($e.Title) -or ($e.Title) -ne ""}) {
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

                $obj = [PSCustomObject]@{
                    ComputerName = $comp
                    Date = ($e.Date)
                    Result = $Result
                    KB = (([regex]::match($e.Title,'KB(\d+)')).Value)
                    Title = ($e.Title)
                    Category = $Cat
                    ClientApplicationID = ($e.ClientApplicationID)
                    Description = ($e.Description)
                    SupportUrl = ($e.SupportUrl)
                }

                $obj
            }#foreach event in history
        }#foreach comp
    #>
    }
