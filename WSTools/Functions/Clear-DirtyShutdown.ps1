function Clear-DirtyShutdown {
    <#
    .SYNOPSIS
        Clears dirty shutdown registry key.

    .DESCRIPTION
        Clears the registry key that prompts you to enter a reason the computer/server was shutdown, even after a
        clean shutdown.

    .PARAMETER ComputerName
        Specifies the name of one or more computers.

    .EXAMPLE
        C:\PS>Clear-DirtyShutdown
        Will clear a dirty shutdown that causes the shutdown tracker to appear.

    .EXAMPLE
        C:\PS>Clear-DirtyShutdown -ComputerName COMP1
        Will clear the dirty shutdown on COMP1. You must have admin rights on the remote computer.

    .INPUTS
        System.String

    .OUTPUTS
        No output

    .COMPONENT
        WSTools

    .FUNCTIONALITY
        registry, dirty shutdown, computer management, server

    .NOTES
        Author: Skyler Hart
        Created: 2020-05-08 17:54:09
        Last Edit: 2021-12-19 23:58:28
        Requires -RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $i = 0
    $number = $ComputerName.length
    foreach ($Comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Setting Dirty Shutdown Fix" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        $k = "DirtyShutdown"
        $v = 0
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $Comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability',$true)
        $SubKey.SetValue($k, $v, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}
