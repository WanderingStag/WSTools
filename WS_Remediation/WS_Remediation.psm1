Function Clear-Patches {
<#
.SYNOPSIS
    Clears the C:\Patches folder.
.DESCRIPTION
    Removes items in the C:\Patches folder on the local or remote computer.
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Recursive
    Removes all files and folders in the Patches folder on the specified computer.
.PARAMETER Old
    Removes files in the root of the C:\Patches folder (except Install.ps1) that are older than 28 days.
.EXAMPLE
    C:\PS>Clear-Patches
    Clears C:\Patches folder on the local computer (but not the inidividual program folders.)
.EXAMPLE
    C:\PS>Clear-Patches -ComputerName COMP1
    Clears C:\Patches folder on the computer COMP1.
.EXAMPLE
    C:\PS>Clear-Patches -ComputerName (gc c:\complist.txt) -Recursive
    Clears all files and folders in C:\Patches on the computers listed in the file c:\complist.txt.
.EXAMPLE
    C:\PS>Clear-Patches -ComputerName (gc c:\complist.txt) -Old
    Clears files in the root of C:\Patches that are older than 28 days on the computers listed in the file c:\complist.txt.
.NOTES
    Author: Skyler Hart
    Created: 2020-08-18 09:58:51
    Last Edit: 2020-08-18 09:58:51
    Keywords: Delete, temp, patches
    Other: Needs to be ran as a user that has administrator rights
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does and is what the folder name is called."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [switch]$Recursive,

        [Parameter()]
        [switch]$Old,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        $ISS = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $ISS, $Host)
        $RunspacePool.Open()

        if ($Recursive) {
            $Code = {
                [CmdletBinding()]
                Param (
                    [Parameter(
                        Mandatory=$true,
                        Position=0
                    )]
                    [string]$comp
                )

                $psdpath = "\\$comp\c$"
                $dn = $comp + "CS"
                $patches = $dn + ":\Patches"
                try {
                    New-PSDrive -Name $dn -PSProvider FileSystem -root "$psdpath" -ErrorAction Stop | Out-Null
                    if (Test-Path $patches) {
                        Set-Location $patches -ErrorAction Stop
                        if ((Get-Location).Path -eq $patches) {
                            Remove-Item * -Recurse -force -ErrorAction SilentlyContinue
                        }
                        $info = [PSCustomObject]@{
                            ComputerName = $Comp
                            Status = "Cleared"
                        }#new object
                    }
                    else {
                        $info = [PSCustomObject]@{
                            ComputerName = $Comp
                            Status = "No patches folder"
                        }#new object
                    }
                    Remove-PSDrive -Name $dn -ErrorAction SilentlyContinue -Force | Out-Null
                }#try
                catch {
                    $info = [PSCustomObject]@{
                        ComputerName = $Comp
                        Status = "Unable to clear"
                    }#new object
                }#catch

                $info
            }#end code block
        }#if recursive
        elseif ($Old) {
            $Code = {
                [CmdletBinding()]
                Param (
                    [Parameter(
                        Mandatory=$true,
                        Position=0
                    )]
                    [string]$comp
                )

                $psdpath = "\\$comp\c$"
                $dn = $comp + "CS"
                $patches = $dn + ":\Patches"
                try {
                    New-PSDrive -Name $dn -PSProvider FileSystem -root "$psdpath" -ErrorAction Stop | Out-Null
                    if (Test-Path $patches) {
                        Set-Location $patches -ErrorAction Stop
                        $op = Get-ChildItem $patches | Where-Object {$_.Attributes -ne "Directory" -and $_.Name -notmatch "Install.ps1" -and $_.LastWriteTime -lt ((Get-Date).AddDays(-28))} | Select-Object FullName -ExpandProperty FullName

                        foreach ($p in $op) {
                            Remove-Item -Path $p -Force -ErrorAction SilentlyContinue
                        }
                        $info = [PSCustomObject]@{
                            ComputerName = $Comp
                            Status = "Cleared"
                        }#new object
                    }
                    else {
                        $info = [PSCustomObject]@{
                            ComputerName = $Comp
                            Status = "No patches folder"
                        }#new object
                    }
                    Remove-PSDrive -Name $dn -ErrorAction SilentlyContinue -Force | Out-Null
                }#try
                catch {
                    $info = [PSCustomObject]@{
                        ComputerName = $Comp
                        Status = "Unable to clear"
                    }#new object
                }#catch

                $info
            }#end code block
        }#elseif Old
        else {
            $Code = {
                [CmdletBinding()]
                Param (
                    [Parameter(
                        Mandatory=$true,
                        Position=0
                    )]
                    [string]$comp
                )

                $psdpath = "\\$comp\c$"
                $dn = $comp + "CS"
                $patches = $dn + ":\Patches"
                try {
                    New-PSDrive -Name $dn -PSProvider FileSystem -root "$psdpath" -ErrorAction Stop | Out-Null
                    if (Test-Path $patches) {
                        Set-Location $patches -ErrorAction Stop
                        if ((Get-Location).Path -eq $patches) {
                            Remove-Item .\*.* -force -ErrorAction SilentlyContinue
                            Remove-Item .\cab\* -Recurse -Force -ErrorAction SilentlyContinue
                        }
                        $info = [PSCustomObject]@{
                            ComputerName = $Comp
                            Status = "Cleared"
                        }#new object
                    }
                    else {
                        $info = [PSCustomObject]@{
                            ComputerName = $Comp
                            Status = "No patches folder"
                        }#new object
                    }
                    Remove-PSDrive -Name $dn -ErrorAction SilentlyContinue -Force | Out-Null
                }#try
                catch {
                    $info = [PSCustomObject]@{
                        ComputerName = $Comp
                        Status = "Unable to clear"
                    }#new object
                }#catch
                $info
            }#end code block
        }#else not recursive or old
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null

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


Function Copy-7Zip {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2019-07-23 20:37:02
    LASTEDIT: 2020-08-28 14:40:13
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        $config = $Global:WSToolsConfig
        $app = $config.a7Zip
        $appname = "7Zip"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" *x64.exe /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-90Meter {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 01/22/2019 13:47:08
    LASTEDIT: 01/22/2019 13:47:08
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        $config = $Global:WSToolsConfig
        $app = $config.a90Meter
        $appname = "90Meter"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-ActivClient {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 01/22/2019 13:47:08
    LASTEDIT: 01/22/2019 13:47:08
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )
    Begin {
        $config = $Global:WSToolsConfig
        $app = $config.ActivClient
        $appname = "ActivClient"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-AdobeAcrobat {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 01/22/2019 13:47:08
    LASTEDIT: 01/22/2019 13:47:08
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Copy-Acrobat')]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )
    Begin {
        $config = $Global:WSToolsConfig
        $app = $config.Acrobat
        $appname = "Acrobat"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-AdobeExperienceManager {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 12:49:48
    Last Edit: 2021-01-25 12:49:48
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Copy-AdobeAEM','Copy-AEM')]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )
    Begin {
        $config = $Global:WSToolsConfig
        $app = $config.AEM
        $appname = "AEM"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Axway {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 01/22/2019 13:47:08
    LASTEDIT: 01/22/2019 13:47:08
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )
    Begin {
        $config = $Global:WSToolsConfig
        $app = $config.AxwayClient
        $appserver = $config.AxwayServer
        $appname = "Axway"
        $ScriptWD = $config.ScriptWD
        if (!(Test-Path C:\Scripts)) {mkdir C:\Scripts}
        if (!(Test-Path C:\Scripts\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv C:\Scripts\CopyStatus.csv -NoTypeInformation
        }

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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appserver,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=4
                )]
                [string]$ScriptWD
            )
            try {
                $os = Get-OperatingSystem $comp | Select-Object OS -ExpandProperty OS
                if ($os -match "Server") {
                    robocopy $appserver \\$comp\c$\Patches\$appname /mir /mt:3 /r:3 /w:15 /njh /njs
                }
                else {
                    robocopy $app \\$comp\c$\Patches\$appname /mir /mt:3 /r:3 /w:15 /njh /njs
                }
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appserver.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Chrome {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 01/22/2019 13:47:08
    LASTEDIT: 01/22/2019 13:47:08
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )
    Begin {
        $config = $Global:WSToolsConfig
        $app = $config.Chrome
        $appname = "Chrome"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-DSET {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 01/22/2019 13:47:08
    LASTEDIT: 01/22/2019 13:47:08
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.DSET
    $appname = "DSET"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Edge {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-05-25 22:41:47
    LASTEDIT: 2022-09-04 22:05:04
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200,

        [Parameter()]
        [switch]$Vanilla
    )

    Begin {
        $config = $Global:WSToolsConfig
        if ($Vanilla) {
            $app = $config.EdgeVanilla
            $appname = "EdgeVanilla"
        }
        else {
            $app = $config.Edge
            $appname = "Edge"
        }
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Encase {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 03/24/2020 11:09:14
    LASTEDIT: 03/24/2020 11:09:14
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        $config = $Global:WSToolsConfig
        $app = $config.Encase
        $appname = "Encase"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Firefox {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 05/15/2019 15:54:58
    LASTEDIT: 08/16/2019 10:42:37
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.Firefox
    $appname = "Firefox"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Git {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-06-15 22:39:40
    LASTEDIT: 2021-06-15 22:43:20
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.Git
    $appname = "GitSCM"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-IE11 {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 05/21/2019 15:46:43
    LASTEDIT: 05/21/2019 15:46:43
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.IE11
    $appname = "IE11"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-MicrosoftInfoPath {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 13:16:45
    Last Edit: 2021-01-25 13:16:45
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Copy-InfoPath')]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )
    Begin {
        $config = $Global:WSToolsConfig
        $app = $config.InfoPath
        $appname = "InfoPath"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Java {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 01/22/2019 13:47:08
    LASTEDIT: 01/22/2019 13:47:08
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.Java
    $appname = "Java"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-NetBanner {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 01/22/2019 13:47:08
    LASTEDIT: 01/22/2019 13:47:08
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.NetBanner
    $appname = "NetBanner"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Office2016 {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 01/22/2019 13:47:08
    LASTEDIT: 01/22/2019 13:47:08
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.Office2016
    $appname = "Office2016"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-OneDrive {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-08-04 21:39:06
    LASTEDIT: 2021-08-04 21:39:06
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.OneDrive
    $appname = "OneDrive"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Silverlight {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 12/04/2019 17:47:48
    LASTEDIT: 12/04/2019 17:48:57
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.Silverlight
    $appname = "Silverlight"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-SQLServerManagementStudio {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-07-24 21:03:23
    LASTEDIT: 2021-07-24 21:03:23
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
[Alias('Copy-SSMS')]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.SSMS
    $appname = "SSMS"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-SplunkForwarder {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-07-21 23:37:25
    LASTEDIT: 2021-07-21 23:43:29
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.SplunkUF
    $appname = "SplunkForwarder"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Tanium {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 11/08/2019 14:21:26
    LASTEDIT: 11/08/2019 14:21:26
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.Tanium
    $appname = "Tanium"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Teams {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 12/04/2019 17:43:21
    LASTEDIT: 12/04/2019 17:45:37
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Teams is the name of the application."
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.Teams
    $appname = "Teams"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Titus {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 01/22/2019 13:47:08
    LASTEDIT: 01/22/2019 13:47:08
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Titus is the name of the application and is not plural."
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.Titus
    $appname = "Titus"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-VisualStudioCode {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-06-15 21:43:12
    LASTEDIT: 2021-11-18 22:31:01
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
[Alias('Copy-VSCode')]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.VSCode
    $appname = "VSCode"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:2 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-VMwareTools {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-07-21 23:47:48
    LASTEDIT: 2021-07-21 23:49:09
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.VMwareTools
    $appname = "VMwareTools"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-VPN {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 03/24/2020 11:17:02
    LASTEDIT: 03/24/2020 11:17:02
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.VPN
    $appname = "VPN"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-VLC {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 07/23/2019 20:44:10
    LASTEDIT: 07/23/2019 20:46:11
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.VLC
    $appname = "VLC"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Wireshark {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 07/23/2019 20:53:52
    LASTEDIT: 07/23/2019 20:56:26
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.Wireshark
    $appname = "Wireshark"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" *.exe /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-WMF3 {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/19/2019 12:45:57
    LASTEDIT: 04/19/2019 12:45:57
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.WMF3
    $appname = "WMF3"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-WMF4 {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/19/2019 12:45:57
    LASTEDIT: 04/19/2019 12:45:57
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.WMF4
    $appname = "WMF4"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-WMF5 {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/19/2019 13:02:13
    LASTEDIT: 04/19/2019 13:02:13
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.WMF5
    $appname = "WMF5"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:3 /r:3 /w:15 /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Copy-Zoom {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2022-03-22 20:11:02
    LASTEDIT: 2022-03-22 20:11:02
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
[CmdletBinding()]
Param (
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [Alias('Host','Name','Computer','CN')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [int32]$MaxThreads = 5,

    [Parameter()]
    $SleepTimer = 200,

    [Parameter()]
    $MaxResultTime = 1200
)

Begin {
    $config = $Global:WSToolsConfig
    $app = $config.Zoom
    $appname = "Zoom"
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
                [string]$app,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$appname,

                [Parameter(
                    Mandatory=$true,
                    Position=3
                )]
                [string]$ScriptWD
            )
            try {
                robocopy $app "\\$comp\c$\Patches\$appname" /mir /mt:2 /r:3 /w:15 /xf *.exe /njh /njs
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Copied"
                    Time = $end
                }#new object
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Program = $appname
                    Status = "Failed"
                    Time = $end
                }#new object
            }
            $info | Select-Object ComputerName,Program,Status,Time | Export-Csv $ScriptWD\CopyStatus.csv -NoTypeInformation -Append
        }#end code block
        $Jobs = @()
    }
    Process {
        if (!(Test-Path $ScriptWD)) {mkdir $ScriptWD}
        if (!(Test-Path $ScriptWD\CopyStatus.csv)) {
            $info = [PSCustomObject]@{
                ComputerName = "NA"
                Program = "NA"
                Status = "NA"
                Time = "NA"
            }#new object
            $info | Select-Object ComputerName,Program,Status,Time | export-csv $ScriptWD\CopyStatus.csv -NoTypeInformation
        }
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($app.ToString()) | out-null
            $PowershellThread.AddArgument($appname.ToString()) | out-null
            $PowershellThread.AddArgument($ScriptWD.ToString()) | out-null
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


Function Install-Edge {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-05-25 22:50:45
    Last Edit: 2022-09-04 22:08:12
    Other:
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter]
        [switch]$Vanilla
    )

    $config = $Global:WSToolsConfig
    if ($Vanilla) {
        $app = $config.EdgeVanilla
    }
    else {
        $app = $config.Edge
    }

    $b = 0
    $n = $ComputerName.Count
    foreach ($comp in $ComputerName) {
        if ($n -gt 1) {
            $b++
            $p = ($b / $n)
            $p1 = $p.ToString("P")
            Write-Progress -Id 1 -activity "Copying Edge to computer and then initiating install" -status "Computer $b of $n. Percent complete:  $p1" -PercentComplete (($b / $n)  * 100)
        }

        try {
            if ($Vanilla) {
                if ($host.Name -notmatch "ServerRemoteHost") {
                    robocopy $app \\$comp\c$\Patches\EdgeVanilla /mir /mt:2 /r:3 /w:15 /njh /njs
                }
                $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList "cmd /c msiexec.exe /i c:\Patches\EdgeVanilla\MicrosoftEdgeEnterpriseX64.msi /qn /norestart" -ErrorAction Stop #DevSkim: ignore DS104456
            }
            else {
                if ($host.Name -notmatch "ServerRemoteHost") {
                    robocopy $app \\$comp\c$\Patches\Edge /mir /mt:2 /r:3 /w:15 /njh /njs
                }
                $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList "cmd /c c:\Patches\Edge\Deploy-application.exe -DeployMode 'NonInteractive'" -ErrorAction Stop #DevSkim: ignore DS104456
            }

            $end = Get-Date
            $info = New-Object -TypeName PSObject -Property @{
                ComputerName = $comp
                Status = "Install Initialized"
                Time = $end
            }#new object
        }
        catch {
            $end = Get-Date
            $info = New-Object -TypeName PSObject -Property @{
                ComputerName = $comp
                Status = "Unable to install"
                Time = $end
            }#new object
        }
        $info
    }
    Write-Host "Please wait at least five minutes before installing another program" -ForegroundColor Yellow
}


Function Install-GitSCM {
<#
   .Parameter ComputerName
    Specifies the computer or computers
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2022-09-04 21:50:21
    LASTEDIT: 2022-09-04 21:53:03
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $app = $config.Git

    $b = 0
    $n = $ComputerName.Count
    foreach ($comp in $ComputerName) {
        if ($n -gt 1) {
            $b++
            $p = ($b / $n)
            $p1 = $p.ToString("P")
            Write-Progress -Id 1 -activity "Copying Git SCM to computer and then initiating install" -status "Computer $b of $n. Percent complete:  $p1" -PercentComplete (($b / $n)  * 100)
        }

        try {
            if ($host.Name -notmatch "ServerRemoteHost") {
                robocopy $app \\$comp\c$\Patches\GitSCM /mir /mt:2 /r:3 /w:15 /njh /njs
            }
            $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList "cmd /c c:\Patches\GitSCM\Git-64-bit.exe /SP- /VERYSILENT /SUPPRESSMSGBOXES /NOCANCEL /NORESTART /CLOSEAPPLICATIONS /NORESTARTAPPLICATIONS /TYPE=full" -ErrorAction Stop #DevSkim: ignore DS104456
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Install Initialized"
                Time = $end
            }#pscustomobject
        }
        catch {
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Unable to install"
                Time = $end
            }#pscustomobject
        }
        $info
    }
}


Function Install-MECM {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-10-12 11:49:19
    LASTEDIT: 2021-10-12 11:55:08
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Install-SCCM')]
    Param (
        [Parameter()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $app = $config.MECM

    $b = 0
    $n = $ComputerName.Count
    foreach ($comp in $ComputerName) {
        if ($n -gt 1) {
            $b++
            $p = ($b / $n)
            $p1 = $p.ToString("P")
            Write-Progress -Id 1 -activity "Copying MECM to computer and then initiating install" -status "Computer $b of $n. Percent complete:  $p1" -PercentComplete (($b / $n)  * 100)
        }

        try {
            if ($host.Name -notmatch "ServerRemoteHost") {
                robocopy $app \\$comp\c$\Patches\MECM ccmsetup.exe /r:3 /w:15 /njh /njs
            }
            $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList "cmd /c c:\Patches\MECM\ccmsetup.exe" -ErrorAction Stop #DevSkim: ignore DS104456
            $install | Out-Null
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Install Initialized"
                Time = $end
            }#new object
        }
        catch {
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Unable to install"
                Time = $end
            }#new object
        }
        $info
    }
    Write-Output "The MECM install can take over an install to fully complete. Please wait a minimum of 30 minutes before rebooting or installing another program."
}


Function Install-OneDrive {
<#
   .Parameter ComputerName
    Specifies the computer or computers
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2022-09-04 22:24:27
    LASTEDIT: 2022-09-04 22:24:27
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $app = $config.OneDrive

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $b = 0
        $n = $ComputerName.Count
        foreach ($comp in $ComputerName) {
            if ($n -gt 1) {
                $b++
                $p = ($b / $n)
                $p1 = $p.ToString("P")
                Write-Progress -Id 1 -activity "Copying OneDrive to computer and then initiating install" -status "Computer $b of $n. Percent complete:  $p1" -PercentComplete (($b / $n)  * 100)
            }

            try {
                if ($host.Name -notmatch "ServerRemoteHost") {
                    robocopy $app \\$comp\c$\Patches\OneDrive /mir /mt:2 /r:3 /w:15 /njh /njs
                }
                $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList "cmd /c c:\Patches\OneDrive\OneDriveSetup.exe /silent /allusers" -ErrorAction Stop #DevSkim: ignore DS104456
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Status = "Install Initialized"
                    Time = $end
                }#pscustomobject
            }
            catch {
                $end = Get-Date
                $info = [PSCustomObject]@{
                    ComputerName = $comp
                    Status = "Unable to install"
                    Time = $end
                }#pscustomobject
            }
            $info
        }
    }
    else {
        if ($ComputerName -eq $env:COMPUTERNAME) {
            robocopy $app \\$comp\c$\Patches\OneDrive /mir /mt:2 /r:3 /w:15 /njh /njs
            Start-Process -FilePath "C:\Patches\OneDrive\OneDriveSetup.exe" -ArgumentList "/Silent"
        }
        else {
            Write-Warning "Must be ran as admin to install on remote computers."
        }
    }
}


Function Install-Patches {
<#
.SYNOPSIS
    Will install patches in the local patches folder.
.DESCRIPTION
    Installes patches in the LocalPatches config setting path (default is C:\Patches.)
.PARAMETER ComputerName
    Specifies the name of one or more computers to install patches on.
.EXAMPLE
    C:\PS>Install-Patches
    Will install patches in the LocalPatches config setting path (default is C:\Patches.)
.EXAMPLE
    C:\PS>Install-Patches -ComputerName COMP1,COMP2
    Will install patches in the LocalPatches config setting path (default is C:\Patches) on COMP1 and COMP2.
.NOTES
    Author: Skyler Hart
    Created: 2017-03-25 08:30:23
    Last Edit: 2021-08-12 00:36:14
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does."
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Install-Updates')]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $Patches = $config.LocalPatches

    $fp = $PSScriptRoot.Substring(0,($PSScriptRoot.Length-15)) + "\Resources\InstallRemote.ps1"

    if ($ComputerName -eq $env:COMPUTERNAME) {
        Copy-Item -Path $fp -Destination $Patches
        & "$Patches\InstallRemote.ps1"
    }
    else {
        Invoke-Command -ComputerName $ComputerName -FilePath $fp -ErrorAction Stop  #DevSkim: ignore DS104456
    }
}#install patches


Function Install-SQLServerManagementStudio {
<#
   .Parameter ComputerName
    Specifies the computer or computers
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-07-24 21:25:32
    LASTEDIT: 2021-07-24 21:25:32
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Install-SSMS')]
    Param (
        [Parameter()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $app = $config.SSMS

    $b = 0
    $n = $ComputerName.Count
    foreach ($comp in $ComputerName) {
        if ($n -gt 1) {
            $b++
            $p = ($b / $n)
            $p1 = $p.ToString("P")
            Write-Progress -Id 1 -activity "Copying SSMS to computer and then initiating install" -status "Computer $b of $n. Percent complete:  $p1" -PercentComplete (($b / $n)  * 100)
        }

        try {
            if ($host.Name -notmatch "ServerRemoteHost") {
                robocopy $app \\$comp\c$\Patches\SSMS SSMS-Setup*.exe /r:3 /w:15 /njh /njs
            }
            $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c c:\Patches\SSMS\SSMS-Setup-ENU.exe /Quiet SSMSInstallRoot="C:\Program Files (x86)\Microsoft SQL Server Management Studio 18" DoNotInstallAzureDataStudio=1' -ErrorAction Stop #DevSkim: ignore DS104456
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Install Initialized"
                Time = $end
            }#new object
        }
        catch {
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Unable to install"
                Time = $end
            }#new object
        }
        $info
    }
}


Function Install-VisualStudioCode {
<#
   .Parameter ComputerName
    Specifies the computer or computers
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-06-15 21:56:38
    LASTEDIT: 2021-11-18 22:32:44
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Install-VSCode')]
    Param (
        [Parameter()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $app = $config.VSCode

    $b = 0
    $n = $ComputerName.Count
    foreach ($comp in $ComputerName) {
        if ($n -gt 1) {
            $b++
            $p = ($b / $n)
            $p1 = $p.ToString("P")
            Write-Progress -Id 1 -activity "Copying Visual Studio Code to computer and then initiating install" -status "Computer $b of $n. Percent complete:  $p1" -PercentComplete (($b / $n)  * 100)
        }

        try {
            if ($host.Name -notmatch "ServerRemoteHost") {
                robocopy $app \\$comp\c$\Patches\VSCode /mir /mt:2 /r:3 /w:15 /njh /njs
            }
            $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList "cmd /c c:\Patches\VSCode\VSCodeSetup-x64.exe /SP- /VERYSILENT /SUPPRESSMSGBOXES /NOCANCEL /NORESTART /CLOSEAPPLICATIONS /NORESTARTAPPLICATIONS /TYPE=full" -ErrorAction Stop #DevSkim: ignore DS104456
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Install Initialized"
                Time = $end
            }#new object
        }
        catch {
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Unable to install"
                Time = $end
            }#new object
        }
        $info
    }
}


Function Install-VMwareTools {
<#
.SYNOPSIS
    Will install VMware tools on one or more computers.
.DESCRIPTION
    Installes VMware Tools from the C:\Patches\VMware directory. Uses config file to determine network path to copy to the local computer first. On remote computers, install file will need to already exist (use Copy-VMwareTools).
.PARAMETER ComputerName
    Specifies the name of one or more computers to install VMware Tools on.
.EXAMPLE
    C:\PS>Install-VMwareTools
    Will install VMware Tools from setup file in C:\Patches\VMwareTools.
.EXAMPLE
    C:\PS>Install-VMwareTools -ComputerName COMP1,COMP2
    Will install VMware Tools from setup file in C:\Patches\VMwareTools on COMP1 and COMP2.
.NOTES
    Author: Skyler Hart
    Created: 2022-12-16 22:04:04
    Last Edit: 2022-12-16 22:04:04
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does."
    )]
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
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $vmtsource = $config.VMwareTools

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        if ($ComputerName -eq $env:COMPUTERNAME) {
            if ($host.Name -notmatch "ServerRemoteHost") {
                Copy-Item -Path $vmtsource -Destination "C:\Patches\VMwareTools"
            }
            Start-Process C:\Patches\VMwareTools\vmware-tools.exe -ArgumentList "/S /v ""/qn REBOOT=R ADDLOCAL=ALL""" -Wait; $rn = (Get-Date).ToUniversalTime().ToString("yyyyMMdd HH:mm:ss UTC"); $string = $rn + " - " + $env:COMPUTERNAME + ":"; Write-Output "$string VMware tools install initiated."
        }
        else {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {#DevSkim: ignore DS104456
                Start-Process C:\Patches\VMwareTools\vmware-tools.exe -ArgumentList "/S /v ""/qn REBOOT=R ADDLOCAL=ALL""" -Wait; $rn = (Get-Date).ToUniversalTime().ToString("yyyyMMdd HH:mm:ss UTC"); $string = $rn + " - " + $env:COMPUTERNAME + ":"; Write-Output "$string VMware tools install initiated."
            } -ErrorAction SilentlyContinue
        }
    }
    else {
        Write-Error "Must be ran as admin."
    }
}


Function Install-Zoom {
<#
   .Parameter ComputerName
    Specifies the computer or computers
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2022-03-22 20:16:54
    LASTEDIT: 2022-03-24 21:35:15
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $config = $Global:WSToolsConfig
    $app = $config.Zoom

    $b = 0
    $n = $ComputerName.Count
    foreach ($comp in $ComputerName) {
        if ($n -gt 1) {
            $b++
            $p = ($b / $n)
            $p1 = $p.ToString("P")
            Write-Progress -Id 1 -activity "Copying Zoom to computer and then initiating install" -status "Computer $b of $n. Percent complete:  $p1" -PercentComplete (($b / $n)  * 100)
        }

        try {
            if ($host.Name -notmatch "ServerRemoteHost") {
                robocopy $app \\$comp\c$\Patches\Zoom /mir /xf *.exe /r:3 /w:15 /njh /njs
            }
            $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c msiexec.exe /i c:\Patches\Zoom\ZoomInstallerFull.msi /qn' -ErrorAction Stop #DevSkim: ignore DS104456
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Install Initialized"
                Time = $end
            }#new object
        }
        catch {
            $end = Get-Date
            $info = [PSCustomObject]@{
                ComputerName = $comp
                Status = "Unable to install"
                Time = $end
            }#new object
        }
        $info
    }
}


#regionUninstall
###########################################################################
###########################################################################
##                                                                       ##
##                              Uninstall                                ##
##                                                                       ##
###########################################################################
###########################################################################


Function Uninstall-7Zip {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 07/22/2019 20:52:09
    LASTEDIT: 07/22/2019 20:53:01
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )

            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='7-Zip%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "7-Zip"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "7-Zip"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-90Meter {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/29/2019 13:33:05
    LASTEDIT: 08/29/2019 13:33:05
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )

            try {
                $uninstall =  Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList "cmd /c c:\windows\system32\msiexec.exe /uninstall {54C965FF-E457-4993-A083-61B9A6AEFEC1} /quiet /norestart" -ErrorAction Stop #DevSkim: ignore DS104456
                $uninstall
                Start-Sleep -Seconds 20
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE '90Meter%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "90Meter"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "90Meter"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process{
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.RunspacePool = $RunspacePool
            $Handle = $PowershellThread.BeginInvoke()
            $Job = "" | Select-Object Handle, Thread, object
            $Job.Handle = $Handle
            $Job.Thread = $PowershellThread
            $Job.Object = $Object.ToString()
            $Jobs += $Job
        }
    }
    End{
        $ResultTimer = Get-Date
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-ActivClient {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2022-12-19 23:13:27
    LASTEDIT: 2022-12-19 23:13:27
    KEYWORDS:
    REQUIRES:
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%ActivClient%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "ActivClient"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "ActivClient"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process{
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.RunspacePool = $RunspacePool
            $Handle = $PowershellThread.BeginInvoke()
            $Job = "" | Select-Object Handle, Thread, object
            $Job.Handle = $Handle
            $Job.Thread = $PowershellThread
            $Job.Object = $Object.ToString()
            $Jobs += $Job
        }
    }
    End{
        $ResultTimer = Get-Date
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-AdobeAir {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:08:38
    LASTEDIT: 07/22/2019 20:23:33
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Adobe Air%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Air"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Air"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process{
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.RunspacePool = $RunspacePool
            $Handle = $PowershellThread.BeginInvoke()
            $Job = "" | Select-Object Handle, Thread, object
            $Job.Handle = $Handle
            $Job.Thread = $PowershellThread
            $Job.Object = $Object.ToString()
            $Jobs += $Job
        }
    }
    End{
        $ResultTimer = Get-Date
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-AdobeExperienceManager {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 12:37:42
    Last Edit: 2021-01-25 12:37:42
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>
    [CmdletBinding()]
    [Alias('Uninstall-AEM','Uninstall-AdobeAEM','Uninstall-Designer','Uninstall-Forms')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Adobe Experienc%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Designe%' AND Vendor LIKE 'Adobe%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Experience Manager (AEM)"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Experience Manager (AEM)"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process{
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.RunspacePool = $RunspacePool
            $Handle = $PowershellThread.BeginInvoke()
            $Job = "" | Select-Object Handle, Thread, object
            $Job.Handle = $Handle
            $Job.Thread = $PowershellThread
            $Job.Object = $Object.ToString()
            $Jobs += $Job
        }
    }
    End{
        $ResultTimer = Get-Date
        While (@($Jobs | Where-Object {$null -ne $_.Handle}).count -gt 0)  {
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


Function Uninstall-AdobeFlash {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:08:42
    LASTEDIT: 07/22/2019 20:26:17
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Uninstall-Flash')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Adobe Flash%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Flash"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Flash"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-AdobePro {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:08:49
    LASTEDIT: 07/22/2019 20:29:01
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Uninstall-AdobeAcrobat','Uninstall-Acrobat')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Adobe Acrobat%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Acrobat Pro"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Acrobat Pro"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-AdobeLiveCycleFormsDesigner {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2022-08-25 20:48:03
    LASTEDIT: 2022-08-25 20:48:03
    KEYWORDS:
    REQUIRES:
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Adobe LiveCycle%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe LiveCycle Forms Designer"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe LiveCycle Forms Designer"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-AdobeReader {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:08:53
    LASTEDIT: 07/22/2019 20:31:36
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Adobe Reader%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Reader"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Reader"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-AdobeShockwave {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:08:57
    LASTEDIT: 07/22/2019 20:34:05
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Uninstall-Shockwave')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Adobe Shockwave%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Shockwave"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Adobe Shockwave"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-Axway {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2022-08-25 20:52:32
    LASTEDIT: 2022-08-25 20:52:32
    KEYWORDS:
    REQUIRES:
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Axwa%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Axway"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Axway"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-CiscoAnyConnect {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 13:44:09
    Last Edit: 2021-01-25 13:44:09
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Uninstall-AnyConnect')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Cisco AnyConnect%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Cisco AnyConnect"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Cisco AnyConnect"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-DamewareMiniRemoteControl {
<#
.NOTES
    Author: Skyler Hart
    Created: 2022-04-19 11:19:52
    Last Edit: 2022-04-19 11:19:52
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Dameware Mini Remote%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Dameware Mini Remote Control"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Dameware Mini Remote Control"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-F5BigIPEdgeClient {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 13:55:11
    Last Edit: 2021-01-25 13:55:11
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Uninstall-BigIPEdgeClient')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'BIG-IP Edge%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "F5 BIG-IP Edge Client"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "F5 BIG-IP Edge Client"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-GoogleChrome {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 07/22/2019 15:29:24
    LASTEDIT: 07/22/2019 20:36:24
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Uninstall-Chrome')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Chrome%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Google Chrome"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Google Chrome"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-HPInsightAgent {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:09:07
    LASTEDIT: 07/22/2019 20:41:20
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'HP Insight%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "HP Insight Agent"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "HP Insight Agent"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-HPVersionControlAgent {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:09:12
    LASTEDIT: 07/22/2019 20:42:42
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'HP Version%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "HP Version Control Agent"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "HP Version Control Agent"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-IBMForms {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:09:25
    LASTEDIT: 07/22/2019 20:47:05
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does and is the name of the application."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name like 'IBM Forms%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "IBM Forms"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "IBM Forms"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-McAfeeVSE {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:09:30
    LASTEDIT: 07/22/2019 20:49:03
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='McAfee VirusScan%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "McAfee VirusScan"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "McAfee VirusScan"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-MicrosoftInfoPath {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 13:10:44
    Last Edit: 2021-01-25 13:10:44
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseSingularNouns",
        "",
        Justification = "Expresses exactly what the function does and is the name of the application."
    )]
    [CmdletBinding()]
    [Alias('Uninstall-InfoPath')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name like '%InfoPath%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "InfoPath"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "InfoPath"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-MozillaFirefox {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 07/22/2019 20:19:10
    LASTEDIT: 11/26/2019 14:25:58
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Uninstall-Firefox')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files\Mozilla Firefox\uninstall\helper.exe" -ms' -ErrorAction SilentlyContinue | Out-Null
                Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files (x86)\Mozilla Firefox\uninstall\helper.exe" -ms' -ErrorAction SilentlyContinue | Out-Null
                Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files\Mozilla Maintenance Service\uninstall.exe" /S' -ErrorAction SilentlyContinue | Out-Null
                Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files (x86)\Mozilla Maintenance Service\uninstall.exe" /S' -ErrorAction SilentlyContinue | Out-Null
                Start-Sleep -Seconds 30
                Get-WmiObject -Class Win32_Product -Filter "Name like '%Firefox%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Mozilla Firefox"
                    Status = "Removal Initialized"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Mozilla Firefox"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-MozillaMaintenanceService {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/01/2019 16:36:26
    LASTEDIT: 08/01/2019 16:36:26
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Uninstall-FirefoxMaintenanceService')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files\Mozilla Maintenance Service\uninstall.exe" /S' -ErrorAction SilentlyContinue | Out-Null
                Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files (x86)\Mozilla Maintenance Service\uninstall.exe" /S' -ErrorAction Stop | Out-Null
                Start-Sleep -Seconds 30
                Get-WmiObject -Class Win32_Product -Filter "Name like '%Firefox%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Mozilla Maintenance Service"
                    Status = "Removal Initialized"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Mozilla Maintenance Service"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-OracleJava {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:09:20
    LASTEDIT: 07/22/2019 20:44:41
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Uninstall-Java')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name like 'Java%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Java"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Java"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-TransVerse {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 14:42:32
    Last Edit: 2022-08-26 20:59:03
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )

            if ($comp -eq $env:COMPUTERNAME) {
                & ${env:ProgramFiles(x86)}\Transverse\unins000.exe /SILENT
                Start-Sleep -Seconds 10
                Get-WmiObject -Class Win32_Product -Filter "Name like '%TransVerse%'" -ErrorAction Stop | Remove-WmiObject -ErrorAction SilentlyContinue
            }
            else {
                Invoke-Command -ComputerName $comp -ScriptBlock {& ${env:ProgramFiles(x86)}\Transverse\unins000.exe /SILENT}
                try {
                    Get-WmiObject -Class Win32_Product -Filter "Name like '%TransVerse%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                    [PSCustomObject]@{
                        ComputerName = $comp
                        Program = "TransVerse"
                        Status = "Removed"
                    }#new object
                }#try
                catch {
                    [PSCustomObject]@{
                        ComputerName = $comp
                        Program = "TransVerse"
                        Status = "Failed"
                    }#new object
                }#catch
            }#if not local
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-VLC {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 07/22/2019 20:55:21
    LASTEDIT: 07/22/2019 20:56:10
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='VLC%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "VLC"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "VLC"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-Wireshark {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 15:04:23
    Last Edit: 2021-01-25 15:04:23
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='Wireshar%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Wireshark"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Wireshark"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-WinRAR {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 18:16:01
    Last Edit: 2021-01-25 18:16:01
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='WinRA%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "WinRAR"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "WinRAR"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-WinSCP {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 07/22/2019 20:54:29
    LASTEDIT: 07/22/2019 20:54:42
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='WinSCP%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "WinSCP"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "WinSCP"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-WinZip {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-01-25 18:12:40
    Last Edit: 2021-01-25 18:12:40
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='WinZi%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "WinZip"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "WinZip"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


Function Uninstall-Zoom {
<#
.NOTES
    Author: Skyler Hart
    Created: 2022-03-22 20:57:00
    Last Edit: 2022-03-22 20:57:00
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Get-WmiObject -Class Win32_Product -Filter "Name='Zoom%'" -ComputerName $Comp -ErrorAction Stop | Remove-WmiObject -ErrorAction Stop
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Zoom"
                    Status = "Removed"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "Zoom"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


#endregionUninstall

###########################################################################
###########################################################################
##                                                                       ##
##                                Other                                  ##
##                                                                       ##
###########################################################################
###########################################################################


Function Disable-3DES {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 14:40:00
    LASTEDIT: 04/23/2018 14:40:00
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $Valuedata = 0

    foreach ($comp in $ComputerName) {
        #.
        #. Ciphers
        #.

        #Disable Triple DES #############remove trailing /168 for everything 2008R2/7 and newer
        $wmiq = Get-WmiObject Win32_OperatingSystem -ComputerName $Comp -ErrorAction Stop
        $os = $wmiq.Caption
        if ($os -match "Windows 7" -or $os -match "Windows Server 2008 R2" -or $os -match "2012" -or $os -match "2016") {
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168') #DevSkim: ignore DS106863
            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168',$true) #DevSkim: ignore DS106863
            $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        }
        else {
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168') #DevSkim: ignore DS106863
            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168',$true) #DevSkim: ignore DS106863
            $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        }
    }
}#function disable 3des


Function Enable-3DES {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 14:41:22
    LASTEDIT: 04/23/2018 14:41:22
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $Valuedata = 1

    foreach ($comp in $ComputerName) {
        #.
        #. Ciphers
        #.

        #Enable Triple DES #############remove trailing /168 for everything 2008R2/7 and newer
        $wmiq = Get-WmiObject Win32_OperatingSystem -ComputerName $Comp -ErrorAction Stop
        $os = $wmiq.Caption
        if ($os -match "Windows 7" -or $os -match "Windows Server 2008 R2" -or $os -match "2012" -or $os -match "2016") {
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168') #DevSkim: ignore DS106863
            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168',$true) #DevSkim: ignore DS106863
            $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        }
        else {
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168') #DevSkim: ignore DS106863
            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168',$true) #DevSkim: ignore DS106863
            $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        }
    }
}#function enable 3des


Function Disable-DiffieHellman {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 16:38:23
    LASTEDIT: 04/23/2018 16:38:23
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $Valuedata = 0

    foreach ($comp in $ComputerName) {
        #.
        #. Ciphers
        #.

        #Disable Diffie-Hellman
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}#function disable diffie-hellman


Function Enable-DiffieHellman {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 16:38:31
    LASTEDIT: 04/23/2018 16:38:31
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $Valuedata = 1

    foreach ($comp in $ComputerName) {
        #.
        #. Ciphers
        #.

        #Disable Diffie-Hellman
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}#function enable diffie-hellman


Function Disable-RC4 {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 15:00:09
    LASTEDIT: 04/23/2018 15:00:09
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $Valuedata = 0

    foreach ($comp in $ComputerName) {
        #.
        #. Ciphers
        #.

        #Disable RC4
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128')
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128')
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128')
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}#function disable rc4


Function Enable-RC4 {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 15:00:19
    LASTEDIT: 04/23/2018 15:00:19
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $Valuedata = 1

    foreach ($comp in $ComputerName) {
        #.
        #. Ciphers
        #.

        #Enable RC4
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128')
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128')
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128')
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}#function enable rc4


function Disable-TLS1.0 { #DevSkim: ignore DS169125,DS440000
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-04-22 11:49:33
    Last Edit: 2021-07-14 23:13:18
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $ValueName2 = "DisabledByDefault"
    $ValueData = 0
    $ValueData1 = 1

    foreach ($Comp in $ComputerName) {
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client',$true)
        $SubKey.SetValue($ValueName, $ValueData1, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($ValueName2, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $SubKey2 = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server',$true)
        $SubKey2.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey2.SetValue($ValueName2, $ValueData1, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}


function Enable-TLS1.0 { #DevSkim: ignore DS169125,DS440000
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-04-22 12:03:16
    Last Edit: 2021-07-14 23:14:51
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $ValueName2 = "DisabledByDefault"
    $Valuedata = 0
    $Valuedata2 = 1

    foreach ($Comp in $ComputerName) {
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client',$true)
        $SubKey.SetValue($ValueName, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($ValueName2, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $SubKey2 = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server',$true)
        $SubKey2.SetValue($ValueName, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey2.SetValue($ValueName2, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}


function Disable-TLS1.1 { #DevSkim: ignore DS169125,DS440000
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-04-22 19:16:08
    Last Edit: 2021-04-22 19:16:08
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $ValueName2 = "DisabledByDefault"
    $Valuedata = 0
    $Valuedata2 = 1

    foreach ($Comp in $ComputerName) {
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($ValueName2, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $SubKey2 = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server',$true)
        $SubKey2.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}


function Enable-TLS1.1 { #DevSkim: ignore DS169125,DS440000
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-04-22 19:16:48
    Last Edit: 2021-04-22 19:16:48
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $ValueName2 = "DisabledByDefault"
    $Valuedata = 0
    $Valuedata2 = 1

    foreach ($Comp in $ComputerName) {
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client',$true)
        $SubKey.SetValue($ValueName, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($ValueName2, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $SubKey2 = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server',$true)
        $SubKey2.SetValue($ValueName, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}


function Disable-TLS1.2 { #DevSkim: ignore DS169125,DS440000
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-04-22 19:18:49
    Last Edit: 2021-04-22 19:18:49
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $ValueName2 = "DisabledByDefault"
    $Valuedata = 0
    $Valuedata2 = 1

    foreach ($Comp in $ComputerName) {
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($ValueName2, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $SubKey2 = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server',$true)
        $SubKey2.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}


function Enable-TLS1.2 { #DevSkim: ignore DS169125,DS440000
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-04-22 19:19:26
    Last Edit: 2021-04-22 19:19:26
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "Enabled"
    $ValueName2 = "DisabledByDefault"
    $Valuedata = 0
    $Valuedata2 = 1

    foreach ($Comp in $ComputerName) {
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client',$true)
        $SubKey.SetValue($ValueName, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($ValueName2, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $SubKey2 = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server',$true)
        $SubKey2.SetValue($ValueName, $ValueData2, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}


function Get-HttpHeaderSetting {
<#
.SYNOPSIS
    Gets the Http Header setting on the current machine.
.DESCRIPTION
    Displays the name and value of Http Header settings on the local computer. Blank entries means the value is not created.
.EXAMPLE
    C:\PS>Get-HttpHeaderSetting
    Example of how to use this cmdlet. Will show Http Header settings on the computer. Will output something similar to this:
    Name       Disabled FullPath
    ----       -------- --------
    Parameters        1 HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    HTTP Header, registry, remediation
.NOTES
    Author: Skyler Hart
    Created: 2022-11-30 23:43:58
    Last Edit: 2022-11-30 23:43:58
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param()

    $schannel = @()
    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\HTTP) {
        $schannel += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\HTTP -Recurse | ForEach-Object {Get-ItemProperty Registry::$_}
    }

    $schannel = $schannel | Select-Object PSPath,Disabled

    $formattedschannel = foreach ($obj in $schannel) {
        $shortpath = $obj.PSPath -replace "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\",""
        $fullpath = $obj.PSPath -replace "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE","HKLM:"
        if ($shortpath -eq "Parameters") {
            [PSCustomObject]@{
                Name = $shortpath
                Disabled = $obj.Disabled
                FullPath = $fullpath
            }#new object
        }
    }
    $formattedschannel
}


function Get-SCHANNELSetting {
<#
.SYNOPSIS
    Gets the SCHANNEL settings on the current machine.
.DESCRIPTION
    Displays the name and value of SCHANNEL settings on the local computer. Blank entries means the value is not created.
.PARAMETER Name
    Used to specify the name of a SCHANNEL setting to display. Uses matching.
.EXAMPLE
    C:\PS>Get-SCHANNELSetting
    Example of how to use this cmdlet. Will show all SCHANNEL settings on the computer. Will output something similar to this:
    Name                                 DisabledByDefault    Enabled FullPath
    ----                                 -----------------    ------- --------
    Ciphers\DES 56/56                                               0 HKLM:\SYSTEM\CurrentControlSet\Control\SecurityPro...
    Ciphers\NULL                                                    0 HKLM:\SYSTEM\CurrentControlSet\Control\SecurityPro.
.EXAMPLE
    C:\PS>Get-SCHANNELSetting -Name Ciphers
    Will show all the Ciphers configured in the SCHANNEL registry settings.
.EXAMPLE
    C:\PS>Get-SCHANNELSetting -Name "TLS 1.0"
    Will show all the TLS 1.0 SCHANNEL registry settings configured on the computer.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    SCHANNEL, registry, remediation
.NOTES
    Author: Skyler Hart
    Created: 2022-09-05 00:24:25
    Last Edit: 2022-09-05 00:56:53
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [Alias('Path')]
        [string]$Name
    )

    $schannel = @()
    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers) {
        $schannel += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers -Recurse | ForEach-Object {Get-ItemProperty Registry::$_}
    }

    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites) {
        $schannel += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites -Recurse | ForEach-Object {Get-ItemProperty Registry::$_}
    }

    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes) {
        $schannel += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes -Recurse | ForEach-Object {Get-ItemProperty Registry::$_}
    }

    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms) {
        $schannel += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms -Recurse | ForEach-Object {Get-ItemProperty Registry::$_}
    }

    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols) {
        $schannel += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols -Recurse | ForEach-Object {Get-ItemProperty Registry::$_}
    }

    $schannel = $schannel | Select-Object PSPath,DisabledByDefault,Enabled

    $formattedschannel = foreach ($obj in $schannel) {
        $shortpath = $obj.PSPath -replace "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\",""
        $fullpath = $obj.PSPath -replace "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE","HKLM:"
        [PSCustomObject]@{
            Name = $shortpath
            DisabledByDefault = $obj.DisabledByDefault
            Enabled = $obj.Enabled
            FullPath = $fullpath
        }#new object
    }

    if (!([string]::IsNullOrWhiteSpace($Name))) {
        $formattedschannel = $formattedschannel | Where-Object {$_.Name -match $Name}
    }
    $formattedschannel
}


function Initialize-GPUpdate {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-16 21:41:53
    Last Edit: 2021-06-16 21:41:53
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        gpupdate.exe /force
    }
    else {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $i = 0
            $number = $ComputerName.length
            foreach ($Comp in $ComputerName) {
                #Progress Bar
                if ($number -gt "1") {
                    $i++
                    $amount = ($i / $number)
                    $perc1 = $amount.ToString("P")
                    Write-Progress -activity "Forcing a GPUpdate" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
                }#if length

                try {
                    $install = Invoke-WMIMethod -Class Win32_Process -ComputerName $Comp -Name Create -ArgumentList "cmd /c gpupdate /force" -ErrorAction Stop #DevSkim: ignore DS104456
                    $info = [PSCustomObject]@{
                        ComputerName = $Comp
                        Status = "GPUpdate Initialized"
                    }#new object
                }
                catch {
                    $info = [PSCustomObject]@{
                        ComputerName = $Comp
                        Status = "Unable to initialize GPUpdate"
                    }#new object
                }
                $info
            }#foreach computer
        }#if admin
        else {Write-Error "Must be ran as admin when running against remote computers"}#not admin
    }#else not local
}


Function Set-FeatureSettingsOverride {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 03/26/2019 21:30:15
    LASTEDIT: 2021-04-22 12:51:51
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $RES = @()
    $infos = @()
    $infos += @{
        Value = 'FeatureSettingsOverride'
        Data = 72
    }
    $infos += @{
        Value = 'FeatureSettingsOverrideMask'
        Data = 3
    }


    foreach ($info in $infos) {
        $RES += [PSCustomObject]$info
    }


    $i = 0
    $number = $ComputerName.length
    foreach ($comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Setting remediation values" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        foreach ($RE in $RES) {
            $ValueName = $RE.Value
            $ValueData = $RE.Data
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management')
            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',$true)
            $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
        }
    }#foreach computer
}


Function Set-FirefoxAutoUpdate {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-06-20 01:01:26
    LASTEDIT: 2021-06-20 01:08:02
    KEYWORDS:
    REQUIRES:
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter()]
        [Switch]$Enable
    )

    $v1 = 'DisableAppUpdate'
    if ($Enable) {$d = 0}
    else {$d = 1}

    $i = 0
    $number = $ComputerName.length

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        foreach ($comp in $ComputerName) {
            #Progress Bar
            if ($number -gt "1") {
                $i++
                $amount = ($i / $number)
                $perc1 = $amount.ToString("P")
                Write-Progress -activity "Setting Firefox Auto Update value" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
            }#if length

            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Policies\Mozilla\Firefox')
            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Mozilla\Firefox',$true)
            $SubKey.SetValue($v1, $d, [Microsoft.Win32.RegistryValueKind]::DWORD)
        }#foreach computer
    }#if admin
    else {Write-Error "Set-FirefoxAutoUpdate must be ran as administrator"}
}


function Set-MS15124 {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 12/21/2017 12:43:44
    LASTEDIT: 12/21/2017 12:48:58
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "iexplore.exe"
    $Valuedata = 1

    foreach ($comp in $ComputerName) {
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING')
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING',$true)
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}#function set-ms15-124


function Set-HiveNightmareFix {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-10-19 11:25:39
    Last Edit: 2021-10-19 11:25:39
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        icacls $env:windir\system32\config\*.* /inheritance:e
        vssadmin.exe delete shadows /all
    }
    else {Write-Error "Must be ran as admin"}
}


function Set-PrintNightmareFix {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-07-14 20:47:02
    Last Edit: 2021-10-19 10:39:03
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [switch]$DisableSpooler
    )

    $v1 = 'NoWarningNoElevationOnInstall'
    $v2 = 'UpdatePromptSettings'
    $v3 = 'RestrictDriverInstallationToAdministrators'
    $d0 = 0
    $d1 = 1

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        foreach ($Comp in $ComputerName) {
            ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint')
            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',$true)
            $SubKey.SetValue($v1, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',$true)
            $SubKey.SetValue($v2, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

            $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
            $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',$true)
            $SubKey.SetValue($v3, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

            if ($Comp -eq $env:COMPUTERNAME) {
                if ($DisableSpooler) {
                    Stop-Service -Name Spooler -Force | Out-Null
                    Set-Service -Name Spooler -StartupType Disabled
                }
            }
        }#foreach computer
    }
    else {Write-Error "Must be ran as administrator"}
}


Function Set-RemediationValues {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/08/2018 22:10:17
    LASTEDIT: 2022-02-18 19:37:37
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $v1 = 'iexplore.exe'
    $v2 = 'SchUseStrongCrypto'
    $v3 = 'Enabled'
    $v4 = 'DisabledByDefault'
    $v5 = 'FeatureSettingsOverride'
    $v6 = 'FeatureSettingsOverrideMask'
    $v7 = 'SMB1'

    #PrintNightmare
    $v8 = 'NoWarningNoElevationOnInstall'
    $v9 = 'UpdatePromptSettings'
    $v10 = 'RestrictDriverInstallationToAdministrators'

    $d0 = 0
    $d1 = 1
    $d3 = 3
    $d72 = 72 #change to 8264 for systems without hyper-threading
    #value for enabling SCHANNEL things
    #4294967295

    $i = 0
    $number = $ComputerName.length
    foreach ($comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Setting remediation values" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        #regionInternetExplorer
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING',$true)
        $SubKey.SetValue($v1, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING',$true)
        $SubKey.SetValue($v1, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX',$true)
        $SubKey.SetValue($v1, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX',$true)
        $SubKey.SetValue($v1, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionNETFramework
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\.NETFramework\v2.0.50727')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\.NETFramework\v2.0.50727',$true)
        $SubKey.SetValue($v2, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727',$true)
        $SubKey.SetValue($v2, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\.NETFramework\v4.0.30319')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\.NETFramework\v4.0.30319',$true)
        $SubKey.SetValue($v2, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319',$true)
        $SubKey.SetValue($v2, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionSCHANNELProtocols
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols')

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client',$true)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client',$true)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client',$true)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client',$true)
        $SubKey.SetValue($v3, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client',$true)
        $SubKey.SetValue($v4, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client',$true)
        $SubKey.SetValue($v3, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client',$true)
        $SubKey.SetValue($v4, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server',$true)
        $SubKey.SetValue($v3, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client',$true)
        $SubKey.SetValue($v3, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client',$true)
        $SubKey.SetValue($v4, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionSCHANNELCiphers
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/56')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/56',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168')  #DevSkim: ignore DS106863
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168',$true) #DevSkim: ignore DS106863
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56')  #DevSkim: ignore DS106863
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56',$true) #DevSkim: ignore DS106863
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionSCHANNELHashes
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA',$true)
        #$SubKey.SetValue($v3, 4294967295, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #Known Microsoft bug causes this to error out

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5')  #DevSkim: ignore DS126858
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5',$true) #DevSkim: ignore DS126858
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionSCHANNELKeyExchangeAlgorithms
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS',$true)
        #$SubKey.SetValue($v3, 4294967295, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #Known Microsoft bug causes this to error out

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #For local computer, properly set SHA and PKCS
        if ($comp -eq $env:COMPUTERNAME) {
            $filepath = $PSScriptRoot.Substring(0,($PSScriptRoot.Length-15)) + "\Resources\SHAandPKCS.reg"
            reg import $filepath
        }

        #regionSessionManager
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',$true)
        $SubKey.SetValue($v5, $d72, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',$true)
        $SubKey.SetValue($v6, $d3, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionSMB
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',$true)
        $SubKey.SetValue($v7, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        if ($comp -eq $env:COMPUTERNAME) {
            $os = (Get-OperatingSystem).OS
            if ($os -match "2008" -or $os -match "Windows 7") {
                #Disable SMB1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 –Force
                sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
                sc.exe config mrxsmb10 start= disabled
                Start-Sleep 3

                #Enable SMB2
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 1 –Force
                sc.exe config lanmanworkstation depend= bowser/mrxsmb10/mrxsmb20/nsi
                sc.exe config mrxsmb20 start= auto
            }
            else {
                #Disable SMB1
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
                Start-Sleep 3

                #Enable SMB2
                Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
            }
        }
        #endregion

        #PrintNightmare
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',$true)
        $SubKey.SetValue($v8, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',$true)
        $SubKey.SetValue($v9, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',$true)
        $SubKey.SetValue($v10, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        Set-NLA -ComputerName $comp
    }#foreach computer
}


#need to finish https://support.microsoft.com/en-us/help/2696547/how-to-detect-enable-and-disable-smbv1-smbv2-and-smbv3-in-windows-and
Function Set-SMBv1 {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 01/31/2018 09:32:17
    LASTEDIT: 02/09/2018 00:47:46
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Switch]$On
    )

    #Determine OS
    $os = (Get-OperatingSystem).OS

    if ($On) {
        if ($os -match "2008" -or $os -match "7") {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 1 –Force
        }
        else {
            Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
        }
    }
    else {
        if ($os -match "2008" -or $os -match "7") {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 –Force
        }
        else {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
        }
    }
}


Function Set-SMBv1Fix {
<#
   .Synopsis
    This fix action is purpose built for the issues seen accessing the NetApp from OSI computers on Windows 10.
   .Description
    Turns SMBv1 on. This fix action is purpose built for the issues seen accessing the NetApp from OSI computers on Windows 10. While this fix action turns SMBv1 on, group policy specifically turns SMBv1 off, which is counted on.
   .Example
    Set-SMBv1Fix COMP1
    Sets the fix action on COMP1. After the fix action is applied, COMP1 will need to be rebooted.
   .Example
    Set-SMBv1Fix
    Sets the fix action on the local computer. After the fix action is applied, the local computer will need to be rebooted.
   .Parameter ComputerName
    Specifies the computer or computers
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 12/18/2018 09:36:43
    LASTEDIT: 12/18/2018 10:25:19
    KEYWORDS: fix action, fix, SMB, SMBv1
    REQUIRES:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "SMB1"
    $Valuedata = 1
    $i = 0
    $number = $ComputerName.length

    foreach ($comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Setting SMBv1 registry fix" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        Invoke-Command -ComputerName $comp -ScriptBlock {Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart} #DevSkim: ignore DS104456

        #([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters') #DevSkim: ignore DS106863
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',$true) #DevSkim: ignore DS106863
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}


function Get-NetworkLevelAuthentication {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-18 15:28:10
    Last Edit: 2020-04-18 15:28:10
    Keywords: Network, NLA, Network Level Authentication, RDP, Remote Desktop
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Get-NLA')]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    foreach ($Comp in $ComputerName) {
        try {
            $ErrorActionPreference = "Stop"
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Comp)
            $key = $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp")
            [Bool]$ua = $key.GetValue('UserAuthentication')

            [PSCustomObject]@{
                ComputerName = $Comp
                UserAuthentication = $ua
            }#new object
        }
        catch [System.Management.Automation.MethodInvocationException] {
            $err = $_.Exception.message.Trim()
            if ($err -match "network path") {
                $ua = "Could not connect"
            }
            elseif ($err -match "access is not allowed") {
                $ua = "Insufficient permissions"
            }
            else {
                $ua = "Unknown error"
            }
            [PSCustomObject]@{
                ComputerName = $Comp
                UserAuthentication = $ua
            }#new object
        }
        catch {
            [PSCustomObject]@{
                ComputerName = $Comp
                UserAuthentication = "Unknown error"
            }#new object
        }
    }
}


function Set-NetworkLevelAuthentication {
<#
.PARAMETER Disable
    Specifies to disable Network Level Authentication. Without this NLA will be enabled.
.EXAMPLE
    C:\PS>Set-NetworkLevelAuthentication
    Will enable network level authentication on the local computer.
.EXAMPLE
    C:\PS>Set-NetworkLevelAuthentication -Disable
    Will disable network level authentication on the local computer.
.EXAMPLE
    C:\PS>Set-NetworkLevelAuthentication -ComputerName COMP1
    Will enable network level authentication on the computer COMP1.
.NOTES
    Author: Skyler Hart
    Created: 2020-04-18 16:01:02
    Last Edit: 2020-04-18 16:01:02
    Keywords: Network, NLA, Network Level Authentication, RDP, Remote Desktop
    Requires:
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Set-NLA')]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(
            Mandatory=$false
        )]
        [Switch]$Disable
    )

    foreach ($Comp in $ComputerName) {
        try {
            $ErrorActionPreference = "Stop"
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Comp)
            $key = $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",$true)
            if ($Disable) {
                $key.SetValue('UserAuthentication', 0, [Microsoft.Win32.RegistryValueKind]::DWORD)
            }
            else {
                $key.SetValue('UserAuthentication', 1, [Microsoft.Win32.RegistryValueKind]::DWORD)
            }
        }
        catch [System.Management.Automation.MethodInvocationException] {
            $err = $_.Exception.message.Trim()
            if ($err -match "network path") {
                $ua = "Could not connect"
            }
            elseif ($err -match "access is not allowed") {
                $ua = "Insufficient permissions"
            }
            else {
                $ua = "Unknown error"
            }
            [PSCustomObject]@{
                ComputerName = $Comp
                UserAuthentication = $ua
            }#new object
        }
    }
}


###########################################################################
###########################################################################
##                                                                       ##
##                              MECM/SCCM                                ##
##                                                                       ##
###########################################################################
###########################################################################

function Get-SCCMInstallStatus {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Get-SCCMInstallStatus
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Get-SCCMInstallStatus -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    The functionality (keywords) that best describes this cmdlet
.NOTES
    Author: Skyler Hart
    Created: 2023-03-29 23:01:59
    Last Edit: 2023-03-29 23:01:59
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias()]
    param(
        [Parameter(
            #HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false#,
            #Position=0,
            #ValueFromPipeline = $true
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateCount(min,max)]
        [ValidateLength(min,max)]
        [ValidateSet('Info','Error','Warning','One','Two','Three')]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $status = Invoke-Command -ComputerName $ComputerName -ScriptBlock {#DevSkim: ignore DS104456
        try {
            $CCMUpdate = get-wmiobject -query "SELECT * FROM CCM_SoftwareUpdate" -namespace "ROOT\ccm\ClientSDK" -ErrorAction stop
            if (@($CCMUpdate | Where-Object {$_.EvaluationState -eq 2 -or $_.EvaluationState -eq 3 -or $_.EvaluationState -eq 4 -or $_.EvaluationState -eq 5 -or $_.EvaluationState -eq 6 -or $_.EvaluationState -eq 7 -or $_.EvaluationState -eq 11 }).length -ne 0) {
                [pscustomobject]@{Computer = $env:computername; UpdateStatus = "3 - In Progress"}
            } elseif(@($CCMUpdate | Where-Object {$_.EvaluationState -eq 13}).length -ne 0) {
                [pscustomobject]@{Computer = $env:computername; UpdateStatus = "4 - Update Failed"}
            } elseif(@($CCMUpdate | Where-Object { $_.EvaluationState -eq 8 -or $_.EvaluationState -eq 9 -or $_.EvaluationState -eq 10 }).length -ne 0) {
                [pscustomobject]@{Computer = $env:computername; UpdateStatus = "2 - Requires Reboot"}
            } elseif(@($CCMUpdate | Where-Object { $_.EvaluationState -eq 0 -or $_.EvaluationState -eq 1}).length -ne 0) {
                [pscustomobject]@{Computer = $env:computername; UpdateStatus = "0 - Updates Available"}
            } else {
                [pscustomobject]@{Computer = $env:computername; UpdateStatus = "1 - Completed"}
            }
        } catch {
            [pscustomobject]@{Computer = $env:computername; UpdateStatus = "5 - Error Reading Update History"}
        }
    } -ErrorAction SilentlyContinue
    ForEach ($server in $servers) {
        if ($status.computer -notcontains $server) {
            $status += [pscustomobject]@{Computer = $server;UpdateStatus = "6 - Remote Connection Failure"}
        }
    }
    $status | Select-Object Computer,UpdateStatus | Sort-Object -Property UpdateStatus,Computer
}


function Get-SCCMPendingUpdate {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Get-SCCMPendingUpdate
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Get-SCCMPendingUpdate -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    The functionality (keywords) that best describes this cmdlet
.NOTES
    Author: Skyler Hart
    Created: 2023-03-29 22:31:19
    Last Edit: 2023-03-29 22:31:19
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias()]
    param(
        [Parameter(
            #HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false#,
            #Position=0,
            #ValueFromPipeline = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    Process {
        foreach ($Comp in $ComputerName) {
            if ($Comp -eq $env:COMPUTERNAME) {
                $Updates = (Get-WmiObject -Query "SELECT * FROM CCM_SoftwareUpdate" -namespace "ROOT\ccm\ClientSDK")
                foreach ($Update in $Updates) {
                    [PSCustomObject]@{
                        ComputerName = $Update.PSComputerName
                        Update = $Update.Name
                    }#new object
                }
            }
            else {
                Invoke-Command -ComputerName $Comp -ScriptBlock {#DevSkim: ignore DS104456
                    $Updates = (Get-WmiObject -Query "SELECT * FROM CCM_SoftwareUpdate" -namespace "ROOT\ccm\ClientSDK")
                    foreach ($Update in $Updates) {
                        [PSCustomObject]@{
                            ComputerName = $Update.PSComputerName
                            Update = $Update.Name
                        }#new object
                    }
                }
            }#not local
        }
    }
}

function Install-SCCMUpdate {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Install-SCCMUpdate
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Install-SCCMUpdate -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    The functionality (keywords) that best describes this cmdlet
.NOTES
    Author: Skyler Hart
    Created: 2023-03-29 22:42:28
    Last Edit: 2023-03-29 22:42:28
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias()]
    param(
        [Parameter(
            #HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false#,
            #Position=0,
            #ValueFromPipeline = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    Begin {}
    Process {
        foreach ($Comp in $ComputerName) {
            if ($Comp -eq $env:COMPUTERNAME) {
                ([wmiclass]'ROOT\ccm\ClientSDK:CCM_SoftwareUpdatesManager').InstallUpdates([System.Management.ManagementObject[]] (get-wmiobject -query 'SELECT * FROM CCM_SoftwareUpdate' -namespace 'ROOT\ccm\ClientSDK'))
            }
            else {
                Invoke-Command -ComputerName $Comp -ScriptBlock {#DevSkim: ignore DS104456
                    ([wmiclass]'ROOT\ccm\ClientSDK:CCM_SoftwareUpdatesManager').InstallUpdates([System.Management.ManagementObject[]] (get-wmiobject -query 'SELECT * FROM CCM_SoftwareUpdate' -namespace 'ROOT\ccm\ClientSDK'))
                }
            }#not local
        }
    }
    End {}
}

function Open-CMTrace {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-22 17:29:32
    Last Edit: 2021-06-22 17:29:32
    Keywords:
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>
    if (Test-Path "c:\Windows\ccm\CMTrace.exe") {
        Start-Process "c:\Windows\ccm\CMTrace.exe"
    }
    elseif (Test-Path "C:\ProgramData\OSI\CMTrace.exe") {
        Start-Process "C:\ProgramData\OSI\CMTrace.exe"
    }
    elseif (Test-Path "J:\Patches\CMTrace.exe") {
        Start-Process "J:\Patches\CMTrace.exe"
    }
    else {
        Write-Error "Cannot find CMTrace.exe"
    }
}

function Open-ConfigurationManager {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 2020-09-28 09:31:24
    KEYWORDS:
    REQUIRES:
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('configmgr')]
    param()
    if (Test-Path "C:\Windows\CCM\SMSCFGRC.cpl") {Start-Process C:\Windows\CCM\SMSCFGRC.cpl}
    elseif (Test-Path "C:\Windows\SysWOW64\CCM\SMSCFGRC.cpl") {Start-Process C:\Windows\SysWOW64\CCM\SMSCFGRC.cpl}
    elseif (Test-Path "C:\Windows\System32\CCM\SMSCFGRC.cpl") {Start-Process C:\Windows\System32\CCM\SMSCFGRC.cpl}
    else {Throw "Configuration Manager not found"}
}


function Open-FileWithCMTrace {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-22 17:35:23
    Last Edit: 2021-06-22 17:35:23
    Keywords:
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>
    [CmdletBinding()]
    [Alias('Open-Log')]
    param(
        [Parameter(
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('File','Path')]
        [string[]]$FileName
    )
    $Continue = $false
    if (Test-Path "c:\Windows\ccm\CMTrace.exe") {
        $app = "c:\Windows\ccm\CMTrace.exe"
        $Continue = $true
    }
    elseif (Test-Path "C:\ProgramData\OSI\CMTrace.exe") {
        $app = "C:\ProgramData\OSI\CMTrace.exe"
        $Continue = $true
    }
    elseif (Test-Path "J:\Patches\CMTrace.exe") {
        $app = "J:\Patches\CMTrace.exe"
        $Continue = $true
    }
    else {
        Write-Error "Cannot find CMTrace.exe"
        $Continue = $false
    }

    if ($Continue) {
        foreach ($file in $FileName) {
            Start-Process $app -ArgumentList $file
        }
    }
}


function Open-RunAdvertisedPrograms {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 21:10:15
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('rap')]
    param()
    if (Test-Path "C:\Windows\SysWOW64\CCM\SMSRAP.cpl") {Start-Process C:\Windows\SysWOW64\CCM\SMSRAP.cpl}
    elseif (Test-Path "C:\Windows\System32\CCM\SMSRAP.cpl") {Start-Process C:\Windows\System32\CCM\SMSRAP.cpl}
    else {Throw "Run Advertised Programs not found"}
}


function Open-SoftwareCenter {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-09-28 09:36:19
    Last Edit: 2020-09-28 09:36:19
    Keywords:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('SoftwareCenter','SCCM','MECM')]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [ValidateSet('AvailableSoftware','Updates','OSD','InstallationStatus','Compliance','Options')]
        [ValidateNotNullOrEmpty()]
        [Alias('Tab')]
        [string]$Page = "AvailableSoftware"
    )

    Start-Process softwarecenter:Page=$Page
}


function Open-SCCMLogsFolder {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 2020-09-28 09:25:48
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator on remote computers
.LINK
    https://wstools.dev
#>
<#--
CAS.log
Provides information about the process of downloading software updates to the local cache and cache management.

CIAgent.log
Provides information about processing configuration items, including software updates.

LocationServices.log
Provides information about the location of the WSUS server when a scan is initiated on the client.

PatchDownloader.log
Provides information about the process for downloading software updates from the update source to the download destination on the site server.

Note
On 64-bit operating systems and on 32-bit operating systems without Configuration Manager 2007 installed, PatchDownloader.log is created in the server logs directory. On 32-bit operating systems, if the Configuration Manager 2007 client is installed, and on the synchronization host computer for the Inventory Tool for Microsoft Updates, PatchDownloader.log is created in the client logs directory.

PolicyAgent.log
Provides information about the process for downloading, compiling, and deleting policies on client computers.

PolicyEvaluator
Provides information about the process for evaluating policies on client computers, including policies from software updates.

RebootCoordinator.log
Provides information about the process for coordinating system restarts on client computers after software update installations.

ScanAgent.log
Provides information about the scan requests for software updates, what tool is requested for the scan, the WSUS location, and so on.

ScanWrapper
Provides information about the prerequisite checks and the scan process initialization for the Inventory Tool for Microsoft Updates on Systems Management Server (SMS) 2003 clients.

SdmAgent.log
Provides information about the process for verifying and decompressing packages that contain configuration item information for software updates.

ServiceWindowManager.log
Provides information about the process for evaluating configured maintenance windows.

smscliUI.log
Provides information about the Configuration Manager Control Panel user interactions, such as initiating an Software Updates Scan Cycle from the Configuration Manager Properties dialog box, opening the Program Download Monitor, and so on.

SmsWusHandler
Provides information about the scan process for the Inventory Tool for Microsoft Updates on SMS 2003 client computers.

StateMessage.log
Provides information about when software updates state messages are created and sent to the management point.

UpdatesDeployment.log
Provides information about the deployment on the client, including software update activation, evaluation, and enforcement. Verbose logging shows additional information about the interaction with the client user interface.

UpdatesHandler.log
Provides information about software update compliance scanning, and the download and installation of software updates on the client.

UpdatesStore.log
Provides information about the compliance status for the software updates that were assessed during the compliance scan cycle.

WUAHandler.log
Provides information about when the Windows Update Agent on the client searches for software updates.

WUSSyncXML.log
Provides information about the Inventory Tool for Microsoft Updates synchronization process.
This log is only on the client computer configured as the synchronization host for the Inventory Tool for Microsoft Updates.
--#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    foreach ($comp in $ComputerName) {
        if (Test-Path \\$comp\c$\Windows\CCM\Logs) {
            explorer \\$comp\c$\Windows\CCM\Logs
        }
        else {
            try {
                $wmiq = Get-WmiObject win32_operatingsystem -ComputerName $comp -ErrorAction Stop | Select-Object OSArchitecture
                if ($wmiq -like "*64-bit*") {
                    explorer \\$comp\c$\Windows\SysWOW64\CCM\Logs
                }
                else {
                    explorer \\$comp\c$\Windows\System32\CCM\Logs
                }
            }#try
            catch {
                Throw "Unable to connect to $comp"
            }
        }
    }#foreach computer
}


function Open-WindowsUpdateLog {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 05/03/2016 20:06:39
    LASTEDIT: 08/07/2018 15:53:00
    KEYWORDS:
    REQUIRES:
.LINK
    https://wstools.dev
#>
<#--
Found on the Configuration Manager Client computer, by default, in %windir%.

WindowsUpdate.log
Provides information about when the Windows Update Agent connects to the WSUS server and retrieves the
software updates for compliance assessment and whether there are updates to the agent components.
--#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Continues querying system(s)."
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","Cancels the command."
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

    $title = "Alert!"
    $message = "This command doesn't work on Windows 10 or newer computers. Do you want to continue running it?"
    $result = $host.ui.PromptForChoice($title, $message, $options, 1)
    switch ($result) {
        0 {
            Write-Output "Yes"
        }
        1 {
            Write-Output "No"
        }
    }

    if ($result -eq 0) {
        foreach ($comp in $ComputerName) {
            try {
                notepad \\$comp\c$\Windows\WindowsUpdate.log
            }
            catch {
                Throw "Unable to connect to $comp"
            }
        }
    }#if yes then continue
    else {
        #do nothing
    }
}


Function Restore-WindowsUpdate {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-12-03 19:41:37
    LASTEDIT: 2021-12-03 19:41:37
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wstools.dev
#>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {dism.exe /Online /Cleanup-image /Restorehealth}
    else {Write-Error "Must be ran as admin"}
}


function Start-SCCMUpdateScan {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Start-SCCMUpdateScan
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Start-SCCMUpdateScan -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    The functionality (keywords) that best describes this cmdlet
.NOTES
    Author: Skyler Hart
    Created: 2023-03-29 21:50:02
    Last Edit: 2023-03-29 21:50:02
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias()]
    param(
        [Parameter(
            #HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false#,
            #Position=0,
            #ValueFromPipeline = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    Process {
        foreach ($Comp in $ComputerName) {
            if ($Comp -eq $env:COMPUTERNAME) {
                Get-WmiObject -Query "SELECT * FROM CCM_UpdateStatus" -Namespace "root\ccm\SoftwareUpdates\UpdatesStore" | ForEach-Object {
                    if($_.ScanTime -gt $ScanTime) { $ScanTime = $_.ScanTime }
                }; $LastScan = ([System.Management.ManagementDateTimeConverter]::ToDateTime($ScanTime)); $LastScan;
	            if(((get-date) - $LastScan).minutes -ge 10) {
		            [void]([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000113}');
		            ([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000108}'); "Update scan and evaluation"
	            }
            }
            else {
                Invoke-Command -ComputerName $Comp -ScriptBlock {#DevSkim: ignore DS104456
                    Get-WmiObject -Query "SELECT * FROM CCM_UpdateStatus" -Namespace "root\ccm\SoftwareUpdates\UpdatesStore" | ForEach-Object {
                        if($_.ScanTime -gt $ScanTime) { $ScanTime = $_.ScanTime }
                    }; $LastScan = ([System.Management.ManagementDateTimeConverter]::ToDateTime($ScanTime)); $LastScan;
                    if(((get-date) - $LastScan).minutes -ge 10) {
                        [void]([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000113}');
                        ([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000108}'); "Update scan and evaluation"
                    }
                }
            }#not local
        }#foreach comp
    }
}

###########################################################################
###########################################################################
##                                                                       ##
##                                 HBSS                                  ##
##                                                                       ##
###########################################################################
###########################################################################
Function Get-ENSStatus {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/10/2019 21:57:28
    LASTEDIT: 09/25/2019 14:43:59
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('ENS','Get-ENSInfo','ESS','Get-ESSInfo')]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    #Set variables needed for overall script
    $i = 0
    $number = $ComputerName.length
    [int32]$version = $PSVersionTable.PSVersion.Major
    $hname = $host.Name
    $64na = 'SOFTWARE\\WOW6432Node\\Network Associates\\ePolicy Orchestrator\\Agent'
    $64ens = 'SOFTWARE\\WOW6432Node\\Network Associates\\TVD\\Shared Components\\Framework'
    $32ens = 'SOFTWARE\\Network Associates\\TVD\\Shared Components\\Framework'
    $d = $env:USERDNSDOMAIN
    $dn = $d.Split('.') | Select-Object -Last 1

    #For each computer, check ENS
    foreach ($comp in $ComputerName) {
        #Set variables required per computer
        Clear-Variable -Name value2,reg,key,key2,datold,daysdatold,daysold,ensversion,epolist,epoinfo,ePOServers,ePOServerList,lasc,lascd,luc,lucd,name -ErrorAction SilentlyContinue | Out-Null

        $continue = $false
        $ensinstalled = $false

        #Progress Bar... Computers checked
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting ENS status. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#progress bar

        #Make sure running at least PowerShell v3
        if ($version -gt 2 -or $hname -like "ServerRemote*") {

            #try 64 if fails then try 32-bit and if that fails then mark as unable to connect
            try {
                $ErrorActionPreference = "Stop"
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                $key = $reg.OpenSubKey($64na)
                try {
                    $key2 = $reg.OpenSubKey($64ens)
                    $ensinstalled = $true
                }
                catch {
                    $ensinstalled = $false
                }

                $epolist = $key.GetValue('ePOServerList')

                if ($ensinstalled -eq $true) {
                    [string]$luc = $key2.GetValue('LastUpdateCheck')
                    [string]$lasc = $key2.GetValue('LastASCI')
                    $ensversion = $key2.GetValue('Version')

                    if ([string]::IsNullOrWhiteSpace($epolist)) {
                        $ensinstalled = "Partial - not functional"
                    }

                    $continue = $true
                }
            }
            catch {
                try {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                    $key = $reg.OpenSubKey($32ens)
                    $value2 = $key.GetValue('CurrentVersion')
                    $value2 | Out-Null
                    $continue = $true
                }
                catch {
                    $value2 = $null
                    $continue = $false
                }
            }

            if ($continue) {
                $epoinfo = $epolist.Split('|')
                $epoinfo = $epoinfo.Split(';')
                $ePOServers = $epoinfo | Where-Object {$_ -match $dn}
                foreach ($ePOServer in $ePOServers) {
                    $name = $null
                    $name = $ePOServer.Substring(0, $ePOServer.IndexOf('.'))
                    if ([string]::IsNullOrWhiteSpace($ePOServerList)) {
                        $ePOServerList = $name
                    }
                    else {
                        $ePOServerList = $ePOServerList + ", " + $name
                    }
                }
                $ePOServerList = $ePOServerList.Trim()

                $lucd = [datetime]::ParseExact($luc, 'yyyyMMddHHmmss', $null)
                $lascd = [datetime]::ParseExact($lasc, 'yyyyMMddHHmmss', $null)

                #Perform check to see if DAT is out of date
                if ($lucd -eq $null) {
                    [string]$ldfj = "20000101"
                    $lucd = [datetime]::ParseExact($ldfj, 'yyyyMMdd', $null)
                }
                #$today = get-date
                #$daysold = $today - $lucd
                #if ($daysold -gt $datdaysold) {$datout = "Yes"}
                #else {$datout = "No"}
                #$daysdatold = $daysold.Days
            }

            #Create the object data
            [PSCustomObject]@{
                ComputerName = $comp
                FrameworkInstalled = $ensinstalled
                FrameworkVersion = $ensversion
                ePOServerList = $ePOServerList
                LastServerComms = $lascd
                LastSecurityUpdateCheck = $lucd

            }
        }#if host version gt 2
        else {
            Write-Output "  PowerShell must be at least version 3. Current version:  $version"
        }#else host version
    }#foreach computer
}#get ensstatus


# Working. To Do:
# Get-HBSSStatus (Get-Content .\computers.txt) | Format-Table -AutoSize
# Get-HBSSStatus (Get-Content .\computers.txt) | Export-Csv .\hbssstatus.csv -NoTypeInformation
function Get-HBSSStatus {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:11:01
    LASTEDIT: 09/25/2019 14:42:42
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    #Set variables needed for overall script
    $i = 0
    $number = $ComputerName.length
    $64keyname = 'SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion'
    $64hbsskey = 'SOFTWARE\\Wow6432Node\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\VIRUSCAN8800'
    $64hipskey = 'SOFTWARE\\Wow6432Node\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\HOSTIPS_8000'
    $64epokey = 'SOFTWARE\\Wow6432Node\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\EPOAGENT3000'
    $32hbsskey = 'SOFTWARE\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\VIRUSCAN8800'
    $32hipskey = 'SOFTWARE\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\HOSTIPS_8000'
    $32epokey = 'SOFTWARE\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\EPOAGENT3000'
    $version = $host.Version.Major
    $hname = $host.Name
    $datdaysold = "4" #specific number of days old the DAT can be
    $EngineVersion = "5900*" #has to be a generic version such as 5700* or 5800*
    $PatchesInstalled = "12" #specific number of patches that should be installed
    $AntiVirusVersion = "8.8*" #has to be a generic version such as 8.8* or 8.9* or even 9.1*
    $HBSSFrameworkVersion = "5.6.1.308" #specific framework version that is required

    $64enskey = 'SOFTWARE\WOW6432Node\Network Associates\TVD\Shared Components\Framework'

    #For each computer, check HBSS
    foreach ($comp in $ComputerName) {
        #Set variables required per computer
        Clear-Variable value2,reg,reg2,reg3,key,key2,key3,datdateval,DATVersionval,DATVersion,engversionval,hotfixverval,versval,hipsverval,frameworkverval,outdated,engoutdated,hfoutdated,avoutdated,fwoutdated,ePOServers | Out-Null

        #Progress Bar... Computers checked
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting HBSS status. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#progress bar

        #Make sure running at least PowerShell v3
        if ($version -gt "2" -or $hname -like "ServerRemote*") {
            #64-bit test
            try {
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                $key = $reg.OpenSubKey($64keyname)
                $value2 = $key.GetValue('CurrentVersion')
            }
            catch {$value2 = $null}

#region 64-bit tasks
            if ($null -ne $value2) {
                #Get HBSS values (not ENS)
                try {
                    $reg2 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                    $key2 = $reg2.OpenSubkey($64hbsskey)
                    $datdateval = $key2.GetValue('DatDate')
                    $DATVersionval = $key2.GetValue('DATVersion')
                    $engversionval = $key2.GetValue('EngineVersion')
                    $hotfixverval = $key2.GetValue('HotFixVersions')
                    $versval = $key2.GetValue('Version')

                    #Check registry for HIPS values
                    try {
                        $reg3 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                        $key3 = $reg3.OpenSubkey($64hipskey)
                        $hipsverval = $key3.GetValue('Version')
                    }
                    catch {
                        $hipsverval = "Not Installed"
                    }

                    #Check registry for HBSS Framework values
                    try {
                        $reg4 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                        $key4 = $reg4.OpenSubkey($64epokey)
                        $frameworkverval = $key4.GetValue('Version')
                        $type = "HBSS"
                        $type | Out-Null
                    }
                    catch {
                        $frameworkverval = "Not Installed"
                        $type = $null
                    }
                }
                catch {
                    $datdateval = $null
                    $DATVersionval = $null
                    $engversionval = $null
                    $hotfixverval = $null
                    $versval = $null
                    $type = $null
                }
                #Get ENS values
            }#if 64-bit
#endregion 64bit tasks


#region 32-bit tasks
            if ($null -eq $value2) {
                #See if HBSS has been installed
                #if (Test-Path "$psdpath\Program Files\Common Files\McAfee\Engine\OldEngine\config.dat") {$hbssstatus = "Yes"}
                #else {$hbssstatus = "No"}


                #Check registry for Virus Scan values
                try {
                    $reg2 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                    $key2 = $reg2.OpenSubkey($32hbsskey)
                    $datdateval = $key2.GetValue('DatDate')
                    $DATVersionval = $key2.GetValue('DATVersion')
                    $engversionval = $key2.GetValue('EngineVersion')
                    $hotfixverval = $key2.GetValue('HotFixVersions')
                    $versval = $key2.GetValue('Version')
                }
                catch {
                    $datdateval = $null
                    $DATVersionval = $null
                    $engversionval = $null
                    $hotfixverval = $null
                    $versval = $null
                }


                #Check registry for HIPS values
                try {
                    $reg3 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                    $key3 = $reg3.OpenSubkey($32hipskey)
                    $hipsverval = $key3.GetValue('Version')
                }
                catch {
                    $hipsverval = "Not Installed"
                }


                #Check registry for HBSS Framework values
                try {
                    $reg4 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                    $key4 = $reg4.OpenSubkey($32epokey)
                    $frameworkverval = $key4.GetValue('Version')
                }
                catch {
                    $frameworkverval = "Not Installed"
                }

            }
#endregion 32bit tasks

            #Perform check to see if DAT is out of date
            if ($null -eq $datdateval) {$datdateval = "20000101"}
            $today = get-date -f yyyyMMdd
            $daysold = $today - $datdateval
            if ($daysold -gt $datdaysold) {$outdated = "Yes"}
            else {$outdated = "No"}

            #Perform check to see if Engine is out of date
            if ($engversionval -notlike $EngineVersion) {$engoutdated = "Yes"}
            else {$engoutdated = "No"}

            #Peform check to see if patches are needed
            if ($hotfixverval -ne $PatchesInstalled) {$hfoutdated = "Yes"}
            else {$hfoutdated = "No"}

            #Perform check to see if Antivirus version 8.8
            if ($versval -notlike $AntiVirusVersion) {$avoutdated = "Yes"}
            else {$avoutdated = "No"}

            #Perform check to see if HBSS Framework is up-to-date
            if ($frameworkverval -eq $HBSSFrameworkVersion) {$fwoutdated = "No"}
            else {$fwoutdated = "Yes"}

            #Take the extra 0's off the end of the DAT version
            if ($null -eq $DatVersionval) {$DatVersionval = "0000.0000"}
            $DATVersion = $DATVersionval.substring(0,4)

            #Create the object data
            [PSCustomObject]@{
                Computer = "$comp"
                DatDate = "$datdateval"
                DatVersion = "$DATVersion"
                DATOutdated = "$outdated"
                EngineVersion = "$engversionval"
                EngineOutdated = "$engoutdated"
                PatchesInstalled = "$hotfixverval"
                PatchesNeeded = "$hfoutdated"
                McAfeeVersion = "$versval"
                McAfeeOutdated = "$avoutdated"
                HIPSVersion = "$hipsverval"
                HBSS_Framework = "$frameworkverval"
                HBSSOutdated = "$fwoutdated"

            } | Select-Object Computer,DatDate,DatVersion,DATOutdated,EngineVersion,EngineOutdated,PatchesInstalled,PatchesNeeded,McAfeeVersion,McAfeeOutdated,HIPSVersion,HBSS_Framework,HBSSOutdated
        }#if host version gt 2
        else {
            Write-Output "  PowerShell must be at least version 3. Current version:  $version  `n  Click OK to continue.  "
            [void][reflection.assembly]::LoadWithPartialName("System.Windows.Forms")
            [System.Windows.Forms.MessageBox]::Show("                               Error:`n`nPowerShell must be at least version 3.`n`nCurrent version is:  $version");
        }#else host version
    }#foreach computer
}#get hbssstatus


function Open-HBSSStatusMonitor {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 8/7/2017
    LASTEDIT: 08/18/2017 21:11:12
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('HBSS')]
    param()
    if (Test-Path "$env:ProgramFiles\McAfee\Agent\cmdagent.exe") {
        Start-Process "$env:ProgramFiles\McAfee\Agent\cmdagent.exe" /s
    }
    elseif (Test-Path "$env:ProgramFiles\McAfee\Common Framework\CmdAgent.exe") {
        Start-Process "$env:ProgramFiles\McAfee\Common Framework\CmdAgent.exe" /s
    }
    elseif (Test-Path "${env:ProgramFiles(x86)}\McAfee\Common Framework\CmdAgent.exe") {
        Start-Process "${env:ProgramFiles(x86)}\McAfee\Common Framework\CmdAgent.exe" /s
    }
    else {
       Throw "HBSS Client Agent not found"
    }
}


function Open-McAfeeVirusScanConsole {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 8/7/2017
    LASTEDIT: 08/18/2017 21:11:16
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    if (Test-Path "$env:ProgramFiles\McAfee\VirusScan Enterprise\mcconsol.exe") {
        Start-Process "$env:ProgramFiles\McAfee\VirusScan Enterprise\mcconsol.exe"
    }
    else {Start-Process "${env:ProgramFiles(x86)}\McAfee\VirusScan Enterprise\mcconsol.exe"}
}


function Open-HIPSLog {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 8/7/2017
    LASTEDIT: 08/18/2017 21:11:22
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    explorer "$env:ProgramData\McAfee\Host Intrusion Prevention"
}


Function Uninstall-HBSS {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/11/2019 15:37:31
    LASTEDIT: 09/11/2019 16:20:07
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Uninstall-ENS','Uninstall-ESS')]
    Param (
        [Parameter(
            HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string[]]$ObjectList,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200
    )

    Begin {
        if ([string]::IsNullOrWhiteSpace($ObjectList)) {
            $ObjectList = $env:COMPUTERNAME
        }
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
                [string]$comp
            )
            try {
                Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files\McAfee\Agent\x86\FrmInst.exe" /Remove=Agent /Silent' -ErrorAction Stop | Out-Null
                Start-Sleep -Seconds 30
                Get-WmiObject -Class Win32_Product -Filter "Name like 'McAfee Agent%'" -ComputerName $Comp -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "McAfee ENS (HBSS) Agent"
                    Status = "Removal Initialized"
                }#new object
            }#try
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    Program = "McAfee ENS (HBSS) Agent"
                    Status = "Failed"
                }#new object
            }#catch
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ObjectList){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
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


function Update-McAfeeSecurity {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-10-30 03:14:47
    Last Edit: 2021-10-30 03:14:47
    Keywords:
.LINK
    https://wstools.dev
#>
    $fpath = "${env:ProgramFiles(x86)}\McAfee\Endpoint Security\Threat Prevention\amcfg.exe"
    if (Test-Path $fpath) {
        Start-Process $fpath -ArgumentList "/update"
    }
    else {
        Write-Error "McAfee Endpoint Security Threat Protection not installed"
    }
}


#Need to fix for new paths
function Sync-HBSSWithServer {
<#
.NOTES
    Author: Skyler Hart
    Created: Sometime before 8/7/2017
    Last Edit: 2020-04-13 20:37:25
    Keywords: HBSS
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    [Alias('Sync-HBSS','Sync-ENS','Sync-ESS')]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    foreach ($Comp in $ComputerName) {
        try {
            $wmiq = Get-WmiObject win32_operatingsystem -ComputerName $Comp -ErrorAction Stop | Select-Object OSArchitecture

            if ($wmiq -like "*64-bit*") {
                #Collecting and sending Props
                Write-Output "Collecting and sending Props on $Comp"
                Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c "C:\Program Files (x86)\McAfee\Common Framework\CmdAgent.exe" /P' -ErrorAction Stop | Out-Null #DevSkim: ignore DS104456
                Start-Sleep -s 10

                #Checking for new policies
                Write-Output "Checking for new policies on $Comp"
                Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c "C:\Program Files (x86)\McAfee\Common Framework\CmdAgent.exe" /C' -ErrorAction Stop | Out-Null #DevSkim: ignore DS104456
                Start-Sleep -s 10

                #Enforcing new policies
                Write-Output "Enforcing new policies on $Comp"
                Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c "C:\Program Files (x86)\McAfee\Common Framework\CmdAgent.exe" /E' -ErrorAction Stop | Out-Null #DevSkim: ignore DS104456
                Start-Sleep -s 15

                Write-Output "HBSS client on $Comp should be updating."
            }#if wmiq 64bit
            else {
                #Collecting and sending Props
                Write-Output "Collecting and sending Props on $Comp"
                Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c "C:\Program Files\McAfee\Common Framework\CmdAgent.exe" /P' -ErrorAction Stop | Out-Null #DevSkim: ignore DS104456
                Start-Sleep -s 10

                #Checking for new policies
                Write-Output "Checking for new policies on $Comp"
                Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c "C:\Program Files\McAfee\Common Framework\CmdAgent.exe" /C' -ErrorAction Stop | Out-Null #DevSkim: ignore DS104456
                Start-Sleep -s 10

                #Enforcing new policies
                Write-Output "Enforcing new policies on $Comp"
                Invoke-WMIMethod -Class Win32_Process -Name Create -Computername $Comp -ArgumentList 'cmd /c "C:\Program Files\McAfee\Common Framework\CmdAgent.exe" /E' -ErrorAction Stop | Out-Null #DevSkim: ignore DS104456
                Start-Sleep -s 15

                Write-Output "HBSS client on $Comp should be updating."
            }#else 32bit
        }#try 32or64 bit
        catch {
            Throw "Unable to connect to $Comp"
        }#catch 32or64 bit
    }#foreach comp
}


###########################################################################
###########################################################################
##                                                                       ##
##                                Splunk                                 ##
##                                                                       ##
###########################################################################
###########################################################################
function Get-SplunkStatus {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-08-13 21:52:22
    Last Edit: 2021-08-13 21:52:22
    Keywords:
    Other:
        -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    if ($ComputerName -eq $env:COMPUTERNAME) {
        $info = Get-Service -Name SplunkForwarder -ComputerName $comp
        [PSCustomObject]@{
            ComputerName = $comp
            SplunkStatus = ($info.Status)
        }#new object
    }
    else {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $i = 0
            $number = $ComputerName.length
            foreach ($Comp in $ComputerName) {
                #Progress Bar
                if ($number -gt "1") {
                    $i++
                    $amount = ($i / $number)
                    $perc1 = $amount.ToString("P")
                    Write-Progress -activity "Getting status of Splunk Service" -status "Computer $i ($comp) of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
                }#if length
                $info = Get-Service -Name SplunkForwarder -ComputerName $comp
                [PSCustomObject]@{
                    ComputerName = $comp
                    SplunkStatus = ($info.Status)
                }#new object
            }
        }
        else {Write-Error "Must be ran as administrator"}
    }
}

Export-ModuleMember -Alias * -Function *