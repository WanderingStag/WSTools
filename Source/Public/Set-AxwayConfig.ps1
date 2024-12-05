function Set-AxwayConfig {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-16 22:10:29
    Last Edit: 2021-06-16 23:22:15
    Keywords:
    Other:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Import-AxwayConfig')]
    param(
        [Parameter(
            #HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName,

        [Parameter(
            HelpMessage = "Enter the path for the configuration file to import.",
            Mandatory=$true,
            Position=1
        )]
        [ValidateNotNullOrEmpty()]
        [string]$ConfigFile
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Start-Process "$env:ProgramFiles\Tumbleweed\Desktop Validator\dvconfig.exe" -ArgumentList "-command write -file $ConfigFile"
        }
        else {Write-Error "Must be ran as administrator."}
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
                    Write-Progress -activity "Setting Axway config" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
                }#if length

                try {
                    Invoke-Command -ComputerName $Comp -ScriptBlock {Start-Process "$env:ProgramFiles\Tumbleweed\Desktop Validator\dvconfig.exe" -ArgumentList "-command write -file $ConfigFile"} -ErrorAction Stop #DevSkim: ignore DS104456
                    #$install = Invoke-WMIMethod -Class Win32_Process -ComputerName $Comp -Name Create -ArgumentList 'cmd /c "c:\Program Files\Tumbleweed\Desktop Validator\dvconfig.exe" -command write -file $ConfigFile' -ErrorAction Stop #DevSkim: ignore DS104456
                    $info = [PSCustomObject]@{
                        ComputerName = $Comp
                        Status = "Axway config imported"
                    }#new object
                }
                catch {
                    $info = [PSCustomObject]@{
                        ComputerName = $Comp
                        Status = "Unable to import Axway config"
                    }#new object
                }
                $info
            }#foreach computer
        }#if admin
        else {Write-Error "Must be ran as admin when running against remote computers"}#not admin
    }#else not local
}
