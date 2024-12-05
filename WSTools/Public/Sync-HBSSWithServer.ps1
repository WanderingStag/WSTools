function Sync-HBSSWithServer {
<#
.NOTES
    Author: Skyler Hart
    Created: Sometime before 8/7/2017
    Last Edit: 2020-04-13 20:37:25
    Keywords: HBSS
.LINK
    https://wanderingstag.github.io
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
