function Get-InstalledProgram {
    <#
    .SYNOPSIS
        Displays installed programs on a computer.

    .DESCRIPTION
        Displays a list of installed programs on a local or remote computer by querying the registry.

    .PARAMETER ComputerName
        Specifies the name of one or more computers.

    .PARAMETER Property
        Will add additional properties to pull from the Uninstall key in the registry.

    .EXAMPLE
        C:\PS>Get-InstalledProgram
        Shows the installed programs on the local computer.

    .EXAMPLE
        C:\PS>Get-InstalledProgram -ComputerName COMPUTER1
        Shows the installed programs on the remote computer COMPUTER1.

    .EXAMPLE
        C:\PS>Get-InstalledProgram -ComputerName COMPUTER1,COMPUTER2
        Shows the installed programs on the remote computers COMPUTER1 and COMPUTER2.

    .EXAMPLE
        C:\PS>Get-InstalledProgram (gc C:\Temp\computers.txt)
        Shows the installed programs on the remote computers listed in the computers.txt file (each computer name on a new line.)

    .EXAMPLE
        C:\PS>Get-InstalledProgram COMPUTER1 -Property InstallSource
        Shows the installed programs on the remote computer COMPUTER1 and also shows the additional property InstallSource from the registry.

    .EXAMPLE
        C:\PS>Get-InstalledProgram COMPUTER1,COMPUTER2 -Property InstallSource,Comments
        Shows the installed programs on the remote computers COMPUTER1 and COMPUTER2. Also shows the additional properties InstallSource and Comments from the registry.

    .NOTES
        Author: Skyler Hart
        Created: Sometime prior to 2017-08
        Last Edit: 2020-08-19 23:03:32
        Keywords: Software, Programs, management

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Alias('Host','Name','DNSHostName','Computer')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Position=1)]
        [string[]]$Property
    )

    Begin {
        $RegistryLocation = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
                            'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'
        $HashProperty = @{}
        $SelectProperty = @('ComputerName','Installed','ProgramName','Version','Uninstall','Comment')
        if ($Property) {
            $SelectProperty += $Property
        }
    }#begin

    Process {
        foreach ($Computer in $ComputerName) {
            $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer)
            $installed = @()
            foreach ($CurrentReg in $RegistryLocation) {
                if ($RegBase) {
                    $CurrentRegKey = $RegBase.OpenSubKey($CurrentReg)
                    if ($CurrentRegKey) {
                        $CurrentRegKey.GetSubKeyNames() | ForEach-Object {
                            if ($Property) {
                                foreach ($CurrentProperty in $Property) {
                                    $HashProperty.$CurrentProperty = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue($CurrentProperty)
                                }
                            }
                            $HashProperty.ComputerName = $Computer
                            $HashProperty.ProgramName = ($DisplayName = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('DisplayName'))
                            $HashProperty.Version = ($DisplayVersion = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('DisplayVersion'))
                            $HashProperty.Installed = ($InstallDate = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('InstallDate'))
                            $HashProperty.Uninstall = ($UninstallString = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('UninstallString'))
                            $HashProperty.Comment = ($Comments = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('Comments'))
                            if ($DisplayName -and ($DisplayName -notmatch "Update for" -and $DisplayName -notmatch " Security Update for" -and $DisplayName -notmatch "Hotfix for" -and $DisplayName -notlike "Windows Setup Remediations*" `
                                -and $DisplayName -notlike "Outils de v*" -and $DisplayName -notlike "Intel(R) Processor*" -and $DisplayName -notlike "Intel(R) Chipset*" -and $DisplayName -notlike "herramientas de corr*" `
                                -and $DisplayName -notlike "Dell Touchpa*" -and $DisplayName -notmatch "Crystal Reports" -and $DisplayName -notmatch "Catalyst Control" -and $DisplayName -notlike "AMD *" -and $DisplayName -notlike "Microsoft * MUI*" `
                                -and $DisplayName -notlike "Microsoft Visual C* Redist*" -and $DisplayName -notlike "Vulkan Run Time Libraries*" -and $DisplayName -notlike "Microsoft Visual C* Minimum*" -and $DisplayName -notlike "Microsoft Visual C* Additional*")) {
                                $installed += [PSCustomObject]$HashProperty |
                                Select-Object -Property $SelectProperty
                            }
                            $DisplayVersion | Out-Null
                            $InstallDate | Out-Null
                            $UninstallString | Out-Null
                            $Comments | Out-Null
                        }#foreach object
                    }#if currentregkey
                }#if regbase
            }#foreach registry entry in registry location
            $installed | Select-Object $SelectProperty | Sort-Object ProgramName
        }#foreach computer
    }#process
}
