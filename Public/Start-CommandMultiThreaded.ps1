function Start-CommandMultiThreaded {
<#
.SYNOPSIS
    Takes a single command and multithreads it.
.DESCRIPTION
    Will multithread any command/cmdlet/function you specify.
.PARAMETER Command
    Where you specify the command you want to multithread.
.PARAMETER Objects
    The arguments that are provided to the command. Generally used for specifying the name of one or more computers. However, it can be used for specifying other arguments such as a list of users.
.PARAMETER MaxThreads
    The maximum threads to run. Can cause resource issues.
.PARAMETER MaxTime
    The amount of seconds to run the script after last job (object) is started.
.PARAMETER SleepTimer
    The amount of milliseconds between each time the script checks the status of jobs. For high resource utilization on the system or if the script is going to take longer to run, this should be increased.
.PARAMETER AddParameter
    Allows specifying additional parameters beyond what is used in Objects. Need to format in a hash table. Ex:
    @{"ParameterName" = "Value"}
    or
    @{"ParameterName" = "Value";"AnotherParameter" = "AnotherValue"}
.PARAMETER AddSwitch
    Allows specifying additional switches to add to the command you run. Need to format in a single string or an array of strings. Ex:
    "TotalCount"
    or
    @("TotalCount","All")
.EXAMPLE
    C:\PS>Start-CommandMultiThreaded Clear-Space (gc c:\Scripts\comps.txt)
    Will run the Clear-Space command against nine of the computers in the comps.txt file at a time. This is because the -MaxThreads parameter isn't set so it runs at the default of 9 objects at a time.
.EXAMPLE
    C:\PS>gc c:\Scripts\comps.txt | Start-CommandMultiThreaded Clear-Space
    Will run the Clear-Space command against nine of the computers in the comps.txt file at a time. This is because the -MaxThreads parameter isn't set so it runs at the default of 9 objects at a time.
.EXAMPLE
    C:\PS>Start-CommandMultiThreaded -Command Get-Service -Objects (gc c:\Scripts\comps.txt) -AddParameter @{"Name" = "wuauserv"} -AddSwitch @('RequiredServices','DependentServices')
    Will get the service "wuauserv" and it's dependent/required services from the computers listed in comps.txt.
.EXAMPLE
    C:\PS>Start-CommandMultiThreaded -Command Set-AxwayConfig -Objects COMP1,COMP2 -AddParameter @{"ConfigFile" = "C:\PKI\MyOrgsAxwayConfig.txt"}
    Will set the Axway config file on both the computer COMP1 and COMP2 at the same time using C:\PKI\MyOrgsAxwayConfig.txt on those computers as the file to import.
.INPUTS
    System.Management.Automation.PSObject.System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    Multithread, multitask
.NOTES
    Author: Skyler Hart
    Created: Sometime before 2017-08-07
    Last Edit: 2022-09-05 22:19:49
    Other:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [string]$Command,

        [Parameter(
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string[]]$Objects,

        [Parameter()]
        [int32]$MaxThreads = 9,

        [Parameter()]
        [int32]$MaxTime = 300,

        [Parameter()]
        [int32]$SleepTimer = 500,

        [Parameter()]
        [HashTable]$AddParameter,

        [Parameter()]
        [Array]$AddSwitch
    )

    Begin {
        $ISS = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads, $ISS, $Host)
        $RunspacePool.Open()
        If ($(Get-Command | Select-Object Name) -match $Command) {
            $Code = $Null
        }
        Else {
            $Code = [ScriptBlock]::Create($(Get-Content $Command))
        }
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Loading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $Objects){
            If ([string]::IsNullOrWhiteSpace($Code)) {
                $PowershellThread = [PowerShell]::Create().AddCommand($Command)
            }
            Else {
                $PowershellThread = [PowerShell]::Create().AddScript($Code)
            }

            $PowershellThread.AddArgument($Object.ToString()) | Out-Null
            ForEach ($Key in $AddParameter.Keys) {
                $PowershellThread.AddParameter($Key, $AddParameter.$key) | Out-Null
            }
            ForEach ($Switch in $AddSwitch) {
                $Switch
                $PowershellThread.AddParameter($Switch) | Out-Null
            }
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
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
            $Remaining = "$($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).object)"
            If ($Remaining.Length -gt 60) {
                $Remaining = $Remaining.Substring(0,60) + "..."
            }
            Write-Progress -Activity "Waiting for Jobs To Finish - $($MaxThreads - $($RunspacePool.GetAvailableRunspaces())) of $MaxThreads threads running" `
                -PercentComplete (($Jobs.count - $($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).count)) / $Jobs.Count * 100) `
                -Status "$(@($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False})).count) remaining - $remaining"
            ForEach ($Job in $($Jobs | Where-Object {$_.Handle.IsCompleted -eq $True})) {
                $Job.Thread.EndInvoke($Job.Handle)
                $Job.Thread.Dispose()
                $Job.Thread = $Null
                $Job.Handle = $Null
                $ResultTimer = Get-Date
            }
            If (($(Get-Date) - $ResultTimer).totalseconds -gt $MaxTime) {
                Write-Error "Script appears to be frozen, try increasing MaxResultTime"
                Exit
            }
            Start-Sleep -Milliseconds $SleepTimer
        }
        $RunspacePool.Close() | Out-Null
        $RunspacePool.Dispose() | Out-Null
    }
}
