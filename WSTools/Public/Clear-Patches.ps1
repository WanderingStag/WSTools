function Clear-Patches {
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
    https://wanderingstag.github.io
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
