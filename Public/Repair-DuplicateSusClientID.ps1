function Repair-DuplicateSusClientID {
<#
.SYNOPSIS
    Removes SusClientID registry key on the local or remote computer.
.DESCRIPTION
    When creating a computer from a template (virtual disc) the SusClientID isn't changed and will result in WSUS only having one object for all the computers created. This function clears the SusClientID from the registry on the local or remote computer(s) so when syncing with WSUS a new SusClientID will be created. The first initial sync with WSUS typically fails. It may take several minutes for the computer to sync appropriately with WSUS.
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.EXAMPLE
    C:\PS>Repair-DuplicateSusClientID
    Example of how to use this cmdlet to fix a duplicate SusClientID on the local computer.
.EXAMPLE
    C:\PS>Repair-DuplicateSusClientID -ComputerName Server1
    Another example of how to use this cmdlet but with the ComputerName parameter. In this example, Server1 is a remote computer.
.INPUTS
    System.String
.OUTPUTS
    System.String
.COMPONENT
    WSTools
.FUNCTIONALITY
    WSUS, fix, repair, SusClientID
.NOTES
    Author: Skyler Hart
    Created: 2022-07-15 21:05:27
    Last Edit: 2022-07-15 21:05:27
    Other:
    Requires:
        -RunAsAdministrator
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

    if ($ComputerName -eq $env:COMPUTERNAME) {
        Write-Output "$(Get-Date) - ${ComputerName}: Stoppping Services"
        Get-Service -Name BITS | Stop-Service
        Get-Service -Name wuauserv | Stop-Service
        Write-Output "$(Get-Date) - ${ComputerName}: Removing registry keys"
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "AccountDomainSid" -Force | Out-Null
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "PingID" -Force | Out-Null
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientId" -Force | Out-Null
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientIdValidation" -Force | Out-Null
        Write-Output "$(Get-Date) - ${ComputerName}: Removing SoftwareDistribution folder"
        Remove-Item -Path C:\Windows\SoftwareDistribution -Force | Out-Null
        Write-Output "$(Get-Date) - ${ComputerName}: Starting Services"
        Get-Service -Name BITS | Start-Service
        Get-Service -Name wuauserv | Start-Service
        Write-Output "$(Get-Date) - ${ComputerName}: Reauthorizing client"
        Start-Process -FilePath "C:\Windows\System32\wuauclt.exe" -ArgumentList "/resetauthorization /detectnow" -Wait
        Start-Sleep -Seconds 10
        Write-Output "$(Get-Date) - ${ComputerName}: Starting detection"
        (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
    }
    else{
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {#DevSkim: ignore DS104456
            $comp = $env:COMPUTERNAME
            Write-Output "$(Get-Date) - ${comp}: Stoppping Services"
            Get-Service -Name BITS | Stop-Service
            Get-Service -Name wuauserv | Stop-Service
            Write-Output "$(Get-Date) - ${comp}: Removing registry keys"
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "AccountDomainSid" -Force | Out-Null
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "PingID" -Force | Out-Null
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientId" -Force | Out-Null
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientIdValidation" -Force | Out-Null
            Write-Output "$(Get-Date) - ${comp}: Removing SoftwareDistribution folder"
            Remove-Item -Path C:\Windows\SoftwareDistribution -Force | Out-Null
            Write-Output "$(Get-Date) - ${comp}: Starting Services"
            Get-Service -Name BITS | Start-Service
            Get-Service -Name wuauserv | Start-Service
            Write-Output "$(Get-Date) - ${comp}: Reauthorizing client"
            Start-Process -FilePath "C:\Windows\System32\wuauclt.exe" -ArgumentList "/resetauthorization /detectnow" -Wait
            Start-Sleep -Seconds 10
            Write-Output "$(Get-Date) - ${comp}: Starting detection"
            (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
        } -ThrottleLimit 5
    }
}
