function Set-Shutdown {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-10 21:26:41
    Last Edit: 2021-06-10 21:36:56
    Keywords:
    Requires:
        -RunAsAdministrator for remote computers
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [ValidateLength(4,4)]
        [string]$Time = (($Global:WSToolsConfig).ShutdownTime),

        [Parameter()]
        [switch]$Abort
    )

    $hr = $Time.Substring(0,2)
    $mm = $Time.Substring(2)
    $d = 0

    #Having the time calculation here will provide a rolling shutdown. The more computers you have the longer the shutdown period will be.
    #Ex: If you have 200 computers and you specify a 0100 start time, it could last until 0130. It all depends on how long the script takes to run.
    #Move the code below to the specified place if you don't want a rolling shutdown.
    $info = Get-Date
    if (($info.Hour) -gt $hr) {
        $d = 1
    }
    elseif (($info.Hour) -eq $hr) {
        if (($info.Minute) -ge $mm) {
            $d = 1
        }
    }

    if ($d -eq 0) {
        $tt1 = ([decimal]::round(((Get-Date).Date.AddHours($hr).AddMinutes($mm) - (Get-Date)).TotalSeconds))
    }
    else {
        $tt1 = ([decimal]::round(((Get-Date).AddDays($d).Date.AddHours($hr).AddMinutes($mm) - (Get-Date)).TotalSeconds))
    }
    #Move the code above to the specified place if you don't want a rolling shutdown.

    foreach ($Comp in $ComputerName) {
        if ($Abort) {shutdown -a -m \\$Comp}
        else {
            #
            # Move the code above to here if you don't want a rolling shutdown
            #
            try {
                shutdown -s -m \\$Comp -t $tt1
            }
            catch {
                Throw "Could not schedule shutdown on $Comp"
            }
        }#else
    }
}
