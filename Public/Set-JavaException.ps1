function Set-JavaException {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 2021-11-09 22:51:15
    LASTEDIT: 2021-11-09 23:32:06
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator
.Link
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Add-JavaException')]
    Param (
        [Parameter(
            Mandatory=$false
        )]
        [Alias('URI','Address')]
        [string]$URL,

        [Parameter(
            Mandatory = $false
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [int32]$MaxThreads = 5,

        [Parameter()]
        $SleepTimer = 200,

        [Parameter()]
        $MaxResultTime = 1200,

        [switch]$FromShare
    )

    Begin {
        if ($FromShare) {$Share = "FromShareTrue"}
        else {$Share = ""}
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
                [string]$URL,

                [Parameter(
                    Mandatory=$true,
                    Position=2
                )]
                [string]$FromShare
            )

            if ($comp -eq $env:COMPUTERNAME) {
                $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
                if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                    if ($FromShare -eq "FromShareTrue") {
                        Import-Module WSTools
                        $jes = ($Global:WSToolsConfig).JException
                        try {$Path = Get-ChildItem "$env:ProgramFiles\Java" -ErrorAction Stop | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                        catch {$Path = Get-ChildItem "${env:ProgramFiles(x86)}\Java" | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                        $lib = [environment]::ExpandEnvironmentVariables("%PROGRAMFILES%\Java\$Path\lib")
                        $lib32 = [environment]::ExpandEnvironmentVariables("%PROGRAMFILES(x86)%\Java\$Path\lib")

                        if (Test-Path $lib) {
                            Copy-Item -Path $jes\exception.sites -Destination $lib -Force
                        }

                        if (Test-Path $lib32) {
                            Copy-Item -Path $jes\exception.sites -Destination $lib32 -Force
                        }
                    }
                    else {
                        try {$Path = Get-ChildItem "$env:ProgramFiles\Java" -ErrorAction Stop | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                        catch {$Path = Get-ChildItem "${env:ProgramFiles(x86)}\Java" | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                        $lib = [environment]::ExpandEnvironmentVariables("%PROGRAMFILES%\Java\$Path\lib")
                        $lib32 = [environment]::ExpandEnvironmentVariables("%PROGRAMFILES(x86)%\Java\$Path\lib")

                        if (Test-Path $lib) {
                            Add-Content -Path $lib\exception.sites -Value $URL -Force
                        }

                        if (Test-Path $lib32) {
                            Add-Content -Path $lib32\exception.sites -Value $URL -Force
                        }
                    }
                }
                else {Write-Error "Must be ran as administrator"}
            }#if local comp
            else {
                if ($FromShare -eq "FromShareTrue") {
                    Import-Module WSTools
                    $jes = ($Global:WSToolsConfig).JException
                    try {$Path = Get-ChildItem "\\$comp\c$\Program Files\Java" -ErrorAction Stop | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                    catch {$Path = Get-ChildItem "\\$comp\c$\Program Files (x86)\Java" | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                    $lib = "\\" + $comp + "\c$\Program Files\Java\" + $Path + "\lib"
                    $lib32 = "\\" + $comp + "\c$\Program Files (x86)\Java\" + $Path + "\lib"
                    #$je = Get-Content $jes\exception.sites

                    if (Test-Path $lib) {
                        Robocopy.exe $jes $lib exception.sites
                        #if (Test-Path $lib\exception.sites) {
                        #    Set-Content -Path $lib\exception.sites -Value $je -Force
                        #}
                        #else {
                        #    Add-Content -Path $lib\exception.sites -Value $je -Force
                        #}
                    }

                    if (Test-Path $lib32) {
                        Robocopy.exe $jes $lib32 exception.sites
                        #if (Test-Path $lib32\exception.sites) {
                        #    Set-Content -Path $lib32\exception.sites -Value $je -Force
                        #}
                        #else {
                        #    Add-Content -Path $lib32\exception.sites -Value $je -Force
                        #}
                    }
                }
                else {
                    try {$Path = Get-ChildItem "\\$comp\c$\Program Files\Java" -ErrorAction Stop | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                    catch {$Path = Get-ChildItem "\\$comp\c$\Program Files (x86)\Java" | Where-Object {$_.Name -like "jre*.*_*"} | Select-Object -ExpandProperty Name}
                    $lib = "\\" + $comp + "\c$\Program Files\Java\" + $Path + "\lib"
                    $lib32 = "\\" + $comp + "\c$\Program Files (x86)\Java\" + $Path + "\lib"

                    if (Test-Path $lib) {
                        Add-Content -Path $lib\exception.sites -Value $URL -Force
                    }

                    if (Test-Path $lib32) {
                        Add-Content -Path $lib32\exception.sites -Value $URL -Force
                    }
                }
            }#if remote comp
        }#end code block
        $Jobs = @()
    }
    Process {
        Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count)"
        ForEach ($Object in $ComputerName){
            $PowershellThread = [powershell]::Create().AddScript($Code)
            $PowershellThread.AddArgument($Object.ToString()) | out-null
            $PowershellThread.AddArgument($URL.ToString()) | out-null
            $PowershellThread.AddArgument($Share.ToString()) | out-null
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
