function Set-PrintNightmareFix {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-07-14 20:47:02
    Last Edit: 2021-10-19 10:39:03
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
