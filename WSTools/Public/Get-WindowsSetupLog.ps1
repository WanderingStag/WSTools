function Get-WindowsSetupLog {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 03/18/2019 15:43:03
    LASTEDIT: 08/28/2019 22:06:44
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Get-UpdateStatus','Get-UpdateLog')]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [Alias('Days')]
        [int32]$DaysBackToSearch = 180,

        [Parameter(Mandatory=$false)]
        [int32]$MostRecent = 6
    )

    #Event ID(s) to search for
    [int32[]]$ID = @(1,2,3,4)

    #Setting initial values
    $i = 0
    $number = $ComputerName.length
    $stime = (Get-Date) - (New-TimeSpan -Day $DaysBackToSearch)
    $info = @()

    #Search Each Computer
    foreach ($Comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting Setup log for computers. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        try {
            #Gather events
            $winevents = Get-WinEvent -ComputerName $Comp -FilterHashTable @{Logname='setup'; ID= $ID; StartTime=$stime} -ErrorAction Stop | Select-Object ProviderName,Message,Id,TimeCreated

            $info += foreach ($winevent in $winevents) {
                if ($winevent.ProviderName -eq "Microsoft-Windows-Servicing" -or ($winevent.ProviderName -eq "Microsoft-Windows-WUSA" -and $winevent.Id -eq "3")) {
                    switch ($winevent.Id) {
                        1 {$st = "Initiating Update"}
                        2 {$st = "Installed"}
                        3 {$st = "Error"}
                        4 {$st = "Reboot Required"}
                    }

                    $eid = $winevent.Id
                    $mess = $winevent.Message
                    $time = $winevent.TimeCreated

                    if ($eid -eq 3) {
                        $update = "NA"
                    }
                    else {
                        $update = $mess -replace "Package ","" -replace " was successfully*","" -replace "A reboot is necessary before package ","" -replace " can be changed to the Installed state.","" `
                            -replace " changed to the Installed state.","" -replace "A reboot is necessary before ","" -replace "Initiating changes for ","" -replace ". Current State is Absent. Target state is Installed. Client id: WindowsUpdateAgent.","" `
                            -replace ". Current state is Superseded. Target state is Absent. Client id: DISM Manager Provider.","" -replace ". Current state is Absent. Target state is Installed. Client id: DISM Manager Provider.","" `
                            -replace ". Current state is Superseded. Target state is Installed. Client id: DISM Manager Provider.","" -replace ". Current state is Installed. Target state is Installed. Client id: DISM Manager Provider.","" `
                            -replace ". Current state is Superseded. Target state is Absent. Client id: CbsTask.","" -replace ". Current state is Installed. Target state is Absent. Client id: DISM Manager Provider.","" `
                            -replace ". Current state is Installed. Target state is Absent. Client id: CbsTask.","" -replace ". Current state is Staged. Target state is Absent. Client id: CbsTask.","" `
                            -replace ". Current state is Absent. Target state is Installed. Client id: UpdateAgentLCU.",""
                    }

                    [PSCustomObject]@{
                        ComputerName = $comp
                        Update = $update
                        Status = $st
                        Message = $mess
                        Time = $time
                    }#new object
                }#if servicing provider or error
            }#foreach event
        }
        catch {
            $info += [PSCustomObject]@{
                ComputerName = $comp
                Update = "NA"
                Status = ""
                Message = ""
                Time = ""
            }#new object
        }

        $info | Select-Object ComputerName,Update,Status,Time,Message -First $MostRecent
    }#foreach computer
}
