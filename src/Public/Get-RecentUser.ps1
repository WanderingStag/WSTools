function Get-RecentUser {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 8/7/2017
    LASTEDIT: 2023-09-20 17:47:45
    KEYWORDS:
    REQUIRES:
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    Process {
        foreach ($Comp in $ComputerName) {

            if ($number -gt "1") {
                $i++
                $amount = ($i / $number)
                $perc1 = $amount.ToString("P")
                Write-Progress -activity "Getting recent users on computers. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
            }#if length

            #Gather events
            $eventlogSplat = @{
                'LogName' = 'Security'
                'ComputerName' = "$Comp"
                'FilterXPath' = '*[System[EventID=4624]] and (*[EventData[Data[@Name="LogonType"] = "2"]] or *[EventData[Data[@Name="LogonType"] = "3"]] or *[EventData[Data[@Name="LogonType"] = "7"]] or *[EventData[Data[@Name="LogonType"] = "10"]] or *[EventData[Data[@Name="LogonType"] = "11"]]) and (*[EventData[Data[@Name="TargetDomainName"] != "NT Authority"]] and *[EventData[Data[@Name="TargetDomainName"] != "Window Manager"]])'
                'MaxEvents' = 1000
            }
            $winevents = Get-WinEvent @eventlogSplat

            $events = foreach ($event in $winevents) {
                $event | Select-Object @{label='Time';expression={$_.TimeCreated}},
                    @{label='ComputerName';expression={$Comp}},
                    @{label='Username';expression={$_.Properties[5].Value}},
                    @{label='LogonType';expression={$_.Properties[8].Value}} |
                    Where-Object {$_.Username -notmatch "$Comp" -and $_.Username -notlike "UMFD-*"}
            }#foreach event in winevent

            #Filter by type of logon, username, and domain
            $events2 = $events | Select-Object Time,ComputerName,Username,LogonType | ForEach-Object {
                    if ($_.LogonType -eq 2) {$type2 = "Local"}#if 2
                    if ($_.LogonType -eq 3) {$type2 = "Remote"}#if 3
                    if ($_.LogonType -eq 7) {$type2 = "UnlockScreen"}#if 7
                    if ($_.LogonType -eq 10) {$type2 = "Remote"}#if 10
                    if ($_.LogonType -eq 11) {$type2 = "CachedLocal"}#if 11
                    [PSCustomObject]@{
                        When = $_.Time
                        Computer = $_.ComputerName
                        Type = $type2
                        User = $_.Username
                    }
                }

            #Get 2nd and 3rd most recent users
            #$users = $null
            Clear-Variable -Name notuser1,notuser2,user2,user3 -ErrorAction SilentlyContinue | Out-Null

            if ($null -ne $($events2).User) {$user1 = ($events2).User[0]}

            $events2 | ForEach-Object {
                if ($_.User -ne $user1) {[string[]]$notuser1 += $_.User}
            }#get unique users

            if ($null -ne $notuser1) {
                $user2 = $notuser1[0]
                foreach ($person in $notuser1) {
                    if ($null -ne $person) {
                        if ($person -ne $user2) {[string[]]$notuser2 += $person}
                        if ($null -ne $notuser2) {$user3 = $notuser2[0]}
                    }#if person not null
                }#previous user3
            }#if users not null

            #Get most recent logon event for each of the 3 users
            Clear-Variable -Name user1events,user2events,user3events -ErrorAction SilentlyContinue | Out-Null

            $user1events = $events2 | Where-Object {$_.User -eq $user1}
            $user2events = $events2 | Where-Object {$_.User -eq $user2}
            $user3events = $events2 | Where-Object {$_.User -eq $user3}

            if ($null -ne $user1events) {$user1events[0]}
            if ($null -ne $user2events) {$user2events[0]}
            if ($null -ne $user3events) {$user3events[0]}
        }#foreach computer
    }
}
