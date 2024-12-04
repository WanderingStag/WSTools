function Get-WSLocalUser {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-02-27 22:05:08
    Last Edit: 2021-02-28 21:05:57
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
                    Disabled = $Null
                    LastLogin = $Null
                    Locked = $Null
                    PasswordExpired = $Null
                    PasswordLastSet = $Null
                    PasswordLastSetDays = $Null
                    PasswordNeverExpires = $Null
                    PasswordNotChangable = $Null
                    PasswordNotRequired = $Null
                    Status = "Comm Error"
                    User = $Null
                }#new object
            }

            if ($Role -match "4|5") {
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    DatePulled = $Null
                    Description = $Null
                    Disabled = $Null
                    LastLogin = $Null
                    Locked = $Null
                    PasswordExpired = $Null
                    PasswordLastSet = $Null
                    PasswordLastSetDays = $Null
                    PasswordNeverExpires = $Null
                    PasswordNotChangable = $Null
                    PasswordNotRequired = $Null
                    Status = "Domain Controller - no local users"
                    User = $Null
                }#new object
            }#if DC
            elseif ($Role -match "0|1|2|3") {
                $UI = ([ADSI]"WinNT://$comp").Children | Where-Object {$_.SchemaClassName -eq 'User'}
                $td = Get-Date
                $info = foreach ($user in $UI) {
                    $uflags = $user.UserFlags[0]
                    $flags = New-Object System.Collections.ArrayList
                    switch ($uflags) {
                        ($uflags -BOR 0x0002) {[void]$flags.Add('Disabled')}
                        ($uflags -BOR 0x0010) {[void]$flags.Add('Locked')}
                        ($uflags -BOR 0x0020) {[void]$flags.Add('PwdNotReq')}
                        ($uflags -BOR 0x0040) {[void]$flags.Add('PwdNotChangable')}
                        ($uflags -BOR 0x10000) {[void]$flags.Add('NeverExp')}
                        ($uflags -BOR 0x800000) {[void]$flags.Add('PwdExp')}
                    }
                    $List = $flags -join ', '
                    [int32]$pa = 0
                    $pa = $user.PasswordAge[0]
                    $pls = ((Get-Date).AddSeconds(-($pa)))
                    $plsd = (New-TimeSpan -Start $pls -End (Get-Date)).Days

                    [PSCustomObject]@{
                        ComputerName = $comp
                        DatePulled  = $td
                        Description = $user.Description[0]
                        Disabled = if ($List -match "Disabled") {$true} else {$false}
                        LastLogin = (($user.LastLogin[0]).DateTime)
                        Locked = if ($List -match "Locked") {$true} else {$false}
                        PasswordExpired = if ($List -match "PwdExp") {$true} else {$false}
                        PasswordLastSet = $pls
                        PasswordLastSetDays = $plsd
                        PasswordNeverExpires = if ($List -match "NeverExp") {$true} else {$false}
                        PasswordNotChangable = if ($List -match "PwdNotChangable") {$true} else {$false}
                        PasswordNotRequired = if ($List -match "PwdNotReq") {$true} else {$false}
                        Status = "Connected"
                        User = $user.Name[0]
                    }#new object
                }#foreach user on computer
            }#not DC

            if (Test-Path $Output) {
                $info | Select-Object ComputerName,Status,User,Description,Disabled,LastLogin,Locked,PasswordExpired,PasswordLastSet,PasswordLastSetDays,PasswordNeverExpires,PasswordNotChangable,PasswordNotRequired,DatePulled | Export-Csv $Output -NoTypeInformation -Append
            }
            else {
                $info | Select-Object ComputerName,Status,User,Description,Disabled,LastLogin,Locked,PasswordExpired,PasswordLastSet,PasswordLastSetDays,PasswordNeverExpires,PasswordNotChangable,PasswordNotRequired,DatePulled | Export-Csv $Output -NoTypeInformation
            }
        }#end code block
        $Jobs = @()
    }
    Process {
        if ([string]::IsNullOrWhiteSpace($Output)) {
            if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
            $Output = $ScriptWD + "\WS_LocalUser.csv"
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
