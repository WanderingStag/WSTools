function Get-ShutdownLog {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/28/2019 22:13:23
    LASTEDIT: 08/29/2019 00:17:09
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [Alias('Days')]
        [int32]$DaysBackToSearch = 30,

        [Parameter(Mandatory=$false)]
        [int32]$MostRecent = 10
    )

    #Event ID(s) to search for
    [int32[]]$ID = @(1074,6005,6006,6008)

    #Setting initial values
    $i = 0
    $number = $ComputerName.length
    $stime = (Get-Date) - (New-TimeSpan -Day $DaysBackToSearch)

    #Search Each Computer
    foreach ($comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting Setup log for computers. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        $winevents = Get-WinEvent -ComputerName $Comp -FilterHashTable @{Logname='system'; ID= $ID; StartTime=$stime} -ErrorAction Stop | Select-Object ProviderName,Message,Id,TimeCreated
        foreach ($winevent in $winevents) {
            $st = $null
            switch ($winevent.Id) {
                6005 {
                    $st = "Startup completed"
                    $type = "Startup"
                }
                6006 {
                    $st = "Shutdown completed"
                    $type = "Shutdown"
                }
                6008 {
                    $st = "Unexpected shutdown"
                    $type = "Shutdown"
                }
            }#switch

            $eid = $winevent.Id
            $mess = $winevent.Message
            $time = $winevent.TimeCreated

            if ($eid -eq 6005 -or $eid -eq 6006 -or $eid -eq 6008) {
                $user = $null
                $program = $null
                $reason = $null
            }
            else {
                $program = $mess.Substring(0, $mess.IndexOf('(')) -replace "The process ",""
                $program = $program.trim()
                $us1 = $mess.Split('')
                $us2 = $null
                $us2 = $us1 | Where-Object {$_ -Like "$env:userdomain\*"}
                $us3 = $null
                $us3 = $us1 | Where-Object {$_ -Like "AUTHORITY\*"}
                if ($null -ne $us2) {
                    $user = $us2
                }
                else {
                    $user = "NT " + $us3
                }
                $tx1 = ($mess.Substring(0, $mess.IndexOf(': '))).length + 2
                $tx2 = $mess.Substring($tx1)
                $reason = ($tx2 -split '["\n\r"|"\r\n"|\n|\r]' | Where-Object {$_ -notlike "Reason code*" -and $_ -notlike "Shutdown Type*" -and $_ -notlike "Comment*"})[0]

                $re = $mess.Substring(65,40)
                if ($re -match "restart") {
                    $st = "Reboot initiated"
                    $type = "Restart"
                }
                else {
                    $st = "Shutdown"
                    $type = "Shutdown initiated"
                }
            }

            [PSCustomObject]@{
                ComputerName = $comp
                Time = $time
                Status = $st
                Type = $type
                Program = $program
                User = $user
                Reason = $reason
            }#new object
        }#foreach event found
    }#foreach computer
}
