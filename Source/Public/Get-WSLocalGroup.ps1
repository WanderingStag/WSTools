function Get-WSLocalGroup {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-02-28 19:52:59
    Last Edit: 2021-02-28 21:06:49
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200,

        [Parameter()]
        [string]$Output = $null

    )
    Begin {
        $config = $Global:WSToolsConfig
        $ScriptWD = $config.ScriptWD

        $ISS = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $ISS, $Host)
        $RunspacePool.Open()
        $Code = {
            [CmdletBinding()]
            Param (
                [Parameter(
                    Mandatory=$true,
                    Position=0
                )]
                [string]$comp,

                [Parameter(
                    Mandatory=$true,
                    Position=1
                )]
                [string]$Output
            )

            $info = @()
            try {
                $Role = (Get-WmiObject -ComputerName $comp -Class Win32_ComputerSystem -Property DomainRole -ErrorAction Stop).DomainRole
            }
            catch {
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    DatePulled = $Null
                    Description = $Null
                    Group = $Null
                    Members = $Null
                    Status = "Comm Error"
                }#new object
            }

            if ($Role -match "4|5") {
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    DatePulled = $Null
                    Description = $Null
                    Group = $Null
                    Members = $Null
                    Status = "Domain Controller - no local groups"
                }#new object
            }#if DC
            elseif ($Role -match "0|1|2|3") {
                $td = Get-Date
                $GI = ([ADSI]"WinNT://$comp").Children | Where-Object {$_.SchemaClassName -eq 'Group'}
                foreach ($group in $GI) {
                    $members = ($group.Invoke('Members') | ForEach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}) -join ", "
                    $info += [PSCustomObject]@{
                        ComputerName = $comp
                        DatePulled = $td
                        Description = $group.Description[0]
                        Group = $group.Name[0]
                        Members = $members
                        Status = "Connected"
                    }#new object
                }#foreach group on computer
            }#not DC

            if (Test-Path $Output) {
                $info | Select-Object ComputerName,Status,Group,Description,Members,DatePulled | Export-Csv $Output -NoTypeInformation -Append
            }
            else {
                $info | Select-Object ComputerName,Status,Group,Description,Members,DatePulled | Export-Csv $Output -NoTypeInformation
            }
        }#end code block
        $Jobs = @()
    }
    Process {
        if ([string]::IsNullOrWhiteSpace($Output)) {
            if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
            $Output = $ScriptWD + "\WS_LocalGroup.csv"
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($Output.ToString()) | out-null
            $PowershellThread.RunspacePool = $RunspacePool
            $Handle = $PowershellThread.BeginInvoke()
            $Job = "" | Select-Object Handle, Thread, object
            $Job.Handle = $Handle
            $Job.Thread = $PowershellThread
            $Job.Object = $Object.ToString()
            $Jobs += $Job
        }
    }
    End {
        $ResultTimer = Get-Date
        While (@($Jobs | Where-Object {$Null -ne $_.Handle}).count -gt 0)  {
            $Remaining = "$($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).object)"
            If ($Remaining.Length -gt 60){
                $Remaining = $Remaining.Substring(0,60) + "..."
            }
            Write-Progress `
                -Activity "Waiting for Jobs - $($MaxThreads - $($RunspacePool.GetAvailableRunspaces())) of $MaxThreads threads running" `
                -PercentComplete (($Jobs.count - $($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).count)) / $Jobs.Count * 100) `
                -Status "$(@($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False})).count) remaining - $remaining"
            ForEach ($Job in $($Jobs | Where-Object {$_.Handle.IsCompleted -eq $True})){
                $Job.Thread.EndInvoke($Job.Handle)
                $Job.Thread.Dispose()
                $Job.Thread = $Null
                $Job.Handle = $Null
                $ResultTimer = Get-Date
            }
            If (($(Get-Date) - $ResultTimer).totalseconds -gt $MaxResultTime){
                Write-Error "Child script appears to be frozen, try increasing MaxResultTime"
                Exit
            }
            Start-Sleep -Milliseconds $SleepTimer
        }
        $RunspacePool.Close() | Out-Null
        $RunspacePool.Dispose() | Out-Null
    }
}
