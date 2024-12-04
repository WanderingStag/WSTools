function Get-UserLogonLogoffTime {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 21:00:47
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(Mandatory=$false, Position=1)]
        [Alias('Date','Time')]
        [string]$DaysBackToSearch = "1"
    )

    #Values for testing
    #$Comp = "$env:ComputerName"
    #$DaysBackToSearch = "1"

    #Event ID(s) to search for
    [int32[]]$ID = @(4624,4634)

    #Strings to search for
    $filecontent = "TaskDisplayName
MachineName
TimeCreated
Account Name:
Account Domain:
Logon Type:
Process Name:"

    #Setting initial values
    $i = 0
    $number = $ComputerName.length
    $stime = (Get-Date) - (New-TimeSpan -Day $DaysBackToSearch)


    #Search Each Computer
    foreach ($Comp in $ComputerName) {

        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting recent users on computers. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length


        #Other Variables
        $dnsdomain = "." + $env:USERDNSDOMAIN
        $csvcontent = "Task,When1,Computer1,AccountName,Domain2,LogonType1,Username1,Domain1,ProcessName1
            "


        #Create new files used during processing
        New-Item $env:Temp\searchlist.lst -ItemType File -Force -Value $filecontent | Out-Null
        New-Item $env:Temp\events.csv -ItemType File -Force -Value $csvcontent | Out-Null


        #Gather events
        $winevent = Get-WinEvent -ComputerName $Comp -FilterHashTable @{Logname='security'; ID= $ID; StartTime=$stime}


        foreach ($event in $winevent) {
            ($event | Select-Object TaskDisplayName,TimeCreated,MachineName,Message | Format-List * | findstr /G:"$env:TEMP\searchlist.lst") -replace "  ","" `
            -replace "TimeCreated : ","" -replace "MachineName : ","" -replace "Security ID:","" -replace "Account Name:","" `
            -replace "Account Domain:","" -replace "Logon ID:","" -replace "Logon Type:","" -replace "Security ID:","" `
            -replace "Account Name:","" -replace "Account Domain:","" -replace "Logon ID:","" -replace "Logon GUID:","" `
            -replace "Process Name:","" -replace "$dnsdomain","" -join "," -replace "TaskDisplayName : ","" | Out-File "$env:Temp\events.csv" -Append utf8
        }#foreach event in winevent


        #Process information on all events for the computer
        $events = Import-Csv "$env:Temp\events.csv"

        $notcomp = $comp + "$"
        $notcomp2 = "*$*"

        #Filter by type of logon, username, and domain
        $events | Where-Object {$_.LogonType1 -eq "2" -or $_.LogonType1 -eq "3" -or $_.LogonType1 -eq "7" -or $_.LogonType1 -eq "10" -or $_.LogonType1 -eq "11" `
            -and ($_.Domain1 -eq "$env:USERDOMAIN" -or $null -eq $_.Domain1) -and $_.Username1 -ne "$notcomp" -and $_.Username1 -notlike "$notcomp2"} |
            Select-Object Computer1,When1,Task,LogonType1,AccountName,Username1,ProcessName1 | ForEach-Object {
                $usrnm = $null
                if ($null -ne $_.Username1 -and $_.Username1 -ne "$notcomp" -and $_.Username1 -ne "$notcomp2") {$usrnm = $_.Username1}
                if ($null -eq $_.Username1  -and $_.AccountName -ne "$notcomp" -and $_.AccountName -ne "$notcomp2") {$usrnm = $_.AccountName}
                #if ($_.AccountName -ne "$notcomp" -or $_.AccountName -ne "$notcomp2") {$User = $_.AccountName}
                if ($_.LogonType1 -eq 2) {$type2 = "Local"}#if 2
                if ($_.LogonType1 -eq 3) {$type2 = "Remote"}#if 3
                if ($_.LogonType1 -eq 7) {$type2 = "UnlockScreen"}#if 7
                if ($_.LogonType1 -eq 11) {$type2 = "CachedLocal"}#if 11
                [PSCustomObject]@{
                    When = $_.When1
                    Computer = $_.Computer1
                    Task = $_.Task
                    Type = $type2
                    User = $usrnm
                    ProcessName = $_.ProcessName1
                } | Select-Object Computer,When,Task,Type,User,ProcessName
            } | Select-Object Computer,When,Task,Type,User | Export-Csv "$env:Temp\events2.csv" -Force -NoTypeInformation


        $events2 = Import-Csv "$env:Temp\events2.csv"
        ($events2) | Select-Object Computer,When,Task,Type,User


        Remove-Item "$env:TEMP\searchlist.lst" -Force
        Remove-Item "$env:Temp\events.csv" -Force
        Remove-Item "$env:Temp\events2.csv" -Force
    }#foreach computer
}
