#
# Generated on: 1/25/2020
#

@{
# Script module or binary module file associated with this manifest.
RootModule = 'WSTools.psm1'

# Version number of this module.
ModuleVersion = '1.3.0.1'

# Author of this module
Author = 'Skyler Hart and others as listed in individual functions'

# Company or vendor of this module
CompanyName = 'Wandering Stag, LLC'

# ID used to uniquely identify this module
GUID = 'ceb3bb6b-dfdc-4f41-bab0-43624ff14605'

# Copyright statement for this module
Copyright = 'Public Domain (except where noted otherwise in individual functions.) See license file for more information.'

# Description of the functionality provided by this module
Description = 'Provides lots of shortcuts to open management tools, ability to perform a lot of tasks in an automated manner, Insider Threat detection, remediations, and enhancements to PowerShell.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Supported PSEditions
# CompatiblePSEditions = @('Desktop') #only importable on PowerShell 5.1 or later if this is used.

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
ScriptsToProcess = @('.\config.ps1')

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @('WS_DomainMgmt\WS_DomainMgmt.psm1',
    'WS_InTh\WS_InTh.psm1',
    'WS_PowerShell\WS_PowerShell.psm1',
    'WS_Remediation\WS_Remediation.psm1')

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Import-XML', 'Enable-RDP', 'Open-BitLocker', 'Get-BitLockerStatus', 
'Get-OperatingSystem', 'Open-DeviceManager', 'Mount-HomeDrive', 
'Test-Online', 'Get-InstalledProgram', 'Stop-Database', 
'Set-ShortcutText', 'Get-MTU', 'Get-LockedOutLocation', 
'Update-BrokenInheritance', 'Open-Remedy', 'Open-LocalGPeditor', 
'Get-DefaultBrowserPath', 'Get-WSToolsConfig', 'Get-ExpiredCertsUser', 
'Connect-RDP', 'Get-WSToolsVersion', 'Open-FirewallLog', 
'Open-AdminTools', 'Set-SpeakerVolume', 'Open-DiscDrive', 
'Get-UserGroup', 'Stop-Exchange', 'Get-UpTime', 
'Register-NotificationApp', 'Set-Explorer', 'Get-FeaturesOnDemand', 
'Get-Error', 'Set-NetworkConnectionsShortcut', 'Get-User', 
'Open-DevicesAndPrinters', 'Get-HomeDrive', 'Update-WSTools', 
'Get-NICInfo', 'Get-DirectoryStat', 'Get-SerialNumber', 
'Open-CertificatesUser', 'Get-ExpiredCertsComputer', 
'Get-FileMetaData', 'Open-HomeDrive', 'Get-ShutdownLog', 
'Open-SystemProperties', 'Set-LAPSshortcut', 'Set-MTU', 
'Set-WindowState', 'Get-PublicIP', 'Open-NetworkConnections', 
'Join-File', 'Start-CommandMultiThreaded', 'Get-PSVersion', 
'Show-HiddenFiles', 'Get-WMIClass', 'Get-WSToolsAlias', 
'Open-ComputerManagement', 'Get-ProcessorCapability', 'Import-MOF', 
'Get-Drive', 'Add-JavaException', 'Split-File', 'Show-BalloonTip', 
'Set-WSToolsConfig', 'Copy-PowerShellJSON', 'Save-MaintenanceReport', 
'Show-FileExtensions', 'Convert-AppIconToBase64', 'Install-WSTools', 
'Disable-ServerManager', 'Set-ServerConfig', 'Get-WSToolsCommand', 
'Save-UpdateHistory', 'Convert-ImageToBase64', 'Open-EventViewer', 
'Open-ProgramsAndFeatures', 'Clear-ImproperProfileCopy', 
'Open-CertificatesComputer', 'Open-Services', 'Import-DRAModule', 
'Clear-DirtyShutdown', 'Show-MessageBox', 'Get-IPrange', 
'Get-WindowsSetupLog', 'Set-Preferences', 'Get-IEVersion', 
'Clear-Space', 'Set-StoreLookup', 'Open-DiskManagement', 
'Get-ComputerHWInfo', 'Test-RegistryValue', 'Test-EmailRelay', 
'Get-WMINameSpace', 'Get-SysInternals', 'Get-UpdateHistory', 
'Get-ComputerModel', 'Set-Reboot0100', 'Get-ComputerADSite', 
'Open-DHCPmgmt', 'Get-LockedOutStatus', 'Restart-DNS', 
'Get-ProtectedUser', 'Restart-ActiveDirectory', 
'Open-ADSitesAndServices', 'Open-ADDomainsAndTrusts', 'Open-LAPS', 
'Restart-KDC', 'Set-ADProfilePicture', 'Get-PrivilegedGroups', 
'Get-NewADGroup', 'Open-HyperVmgmt', 'Find-HiddenGALUser', 'Find-SID', 
'Get-ProtectedGroup', 'Register-Schema', 'Open-iLO', 
'Open-GroupPolicyMgmt', 'Open-ADSIEdit', 'Get-FSMO', 'Find-EmptyGroup', 
'Get-NewADUser', 'Get-ReplicationStatus', 'Get-DaysSinceLastLogon', 
'Open-ADUsersAndComputers', 'Open-SharedFolders', 'Register-ADSIEdit', 
'Get-UserWithThumbnail', 'Open-DNSmgmt', 'Open-vCenter', 
'Export-MessagesToPST', 'Get-LoggedOnUser', 'Get-UserLogonLogoffTime', 
'Get-USBDevice', 'Find-UserProfile', 'Find-UserProfileWithPSTSearch', 
'Get-RecentUser', 'Get-ExchangeLastLoggedOnUser', 
'Get-USBStorageDevice', 'Get-CurrentUser', 'Copy-UserProfile', 
'Add-PSObject', 'Set-AutoLoadPreference', 'Get-FolderPath', 
'Add-ParamSwitchWithOption', 'Add-Switch', 'Add-ParamBlock', 
'Add-DomainCheck', 'Set-Profile', 'Add-ParamInternetBrowser', 
'Get-FilePath', 'Add-Function', 'Set-Title', 'Start-PowerShell', 
'Get-Accelerators', 'Add-InternetBrowsersBlock', 'Add-ProgressBar', 
'Add-DateTime', 'Get-Role', 'Send-ToastNotification', 'Add-Help', 
'Get-FunctionsInModule', 'Get-ENSStatus', 'Copy-Axway', 
'Open-RunAdvertisedPrograms', 'Copy-NetBanner', 'Open-SoftwareCenter', 
'Open-ConfigurationManager', 'Open-McAfeeVirusScanConsole', 
'Uninstall-IBMForms', 'Uninstall-AdobeShockwave', 
'Disable-DiffieHellman', 'Uninstall-VLC', 'Open-SCCMLogsFolder', 
'Copy-90Meter', 'Uninstall-MicrosoftInfoPath', 
'Uninstall-HPInsightAgent', 'Uninstall-McAfeeVSE', 
'Set-FeatureSettingsOverride', 'Uninstall-Wireshark', 'Copy-VLC', 
'Install-Patches', 'Clear-Patches', 'Copy-MicrosoftInfoPath', 
'Enable-3DES', 'Copy-WMF3', 'Set-SMBv1Fix', 'Copy-WMF5', 'Copy-WMF4', 
'Uninstall-HBSS', 'Set-RemediationValues', 
'Uninstall-F5BigIPEdgeClient', 'Uninstall-OracleJava', 
'Sync-HBSSWithServer', 'Copy-Teams', 'Copy-AdobeAcrobat', 
'Open-HIPSLog', 'Uninstall-TransVerse', 'Copy-VPN', 
'Uninstall-AdobeFlash', 'Copy-ActivClient', 'Uninstall-AdobeAir', 
'Disable-3DES', 'Enable-DiffieHellman', 'Open-HBSSStatusMonitor', 
'Enable-RC4', 'Copy-Firefox', 'Copy-IE11', 'Copy-Tanium', 
'Get-NetworkLevelAuthentication', 'Copy-DSET', 
'Uninstall-HPVersionControlAgent', 'Uninstall-MozillaFirefox', 
'Copy-AdobeExperienceManager', 'Copy-TransVerse', 'Copy-Wireshark', 
'Set-MS15124', 'Uninstall-7Zip', 'Copy-Java', 'Uninstall-AdobePro', 
'Uninstall-AdobeReader', 'Uninstall-AdobeExperienceManager', 
'Uninstall-90Meter', 'Uninstall-GoogleChrome', 'Copy-Chrome', 
'Uninstall-WinSCP', 'Set-NetworkLevelAuthentication', 
'Uninstall-MozillaMaintenanceService', 'Copy-Titus', 'Get-HBSSStatus', 
'Copy-Encase', 'Copy-Office2016', 'Set-SMBv1', 'Copy-7Zip', 
'Set-SCHANNELsettings', 'Copy-Silverlight', 'Open-WindowsUpdateLog', 
'Uninstall-CiscoAnyConnect', 'Disable-RC4','Uninstall-WinRAR',
'Uninstall-WinZip'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = 'Remedy', 'Eject-Disc', 'Get-SN', 'Set-PowerShellJSON', 'Get-Model', 
'WSToolsCommands', 'Open-LocalPolicyEditor', 'Get-UpdateLog', 'Volume', 
'Open-EITSM', 'Import-WSToolsConfig', 'Drive', 'Open-WSToolsConfig', 
'Push-WSTools', 'Convert-ICOtoBase64', 'programs', 'services', 'network', 
'Get-PowerShellVersion', 'rdp', 'Stop-Oracle', 'LocalPolicy', 
'Update-WSToolsConfig', 'Stop-SQL', 'printers', 'admin', 'events', 
'WSToolsAliases', 'connections', 'Copy-WSTools', 'Add-HomeDrive', 
'admintools', 'WSToolsVersion', 'WSToolsConfig', 'Import-WMIFilter', 
'EITSM', 'tip', 'Error', 'BitLocker', 'New-WMIFilter', 'Get-UpdateStatus', 
'tools', 'Update-PowerShellJSON', 'message', 'adsi', 'Shares', 'vCenter', 
'iLO', 'gpo', 'replsum', 'FSMO', 'Get-Shares', 'dhcp', 'GroupPolicy', 
'Initialize-ADSIEdit', 'Enable-ADSIEdit', 'trusts', 'laps', 'hyperv', 
'aduc', 'dns', 'usb', 'Edit-Profile', 'title', 'Get-TypeAccelerators', 
'Open-PowerShell', 'accelerators', 'Profile', 'Copy-AdobeAEM', 'rap', 'ENS', 
'Uninstall-Designer', 'Uninstall-AdobeAEM', 'Uninstall-Acrobat', 
'Uninstall-BigIPEdgeClient', 'Copy-InfoPath', 'softwarecenter', 
'Install-Updates', 'Uninstall-AEM', 'Sync-ENS', 'Uninstall-InfoPath', 
'HBSS', 'Uninstall-ENS', 'Uninstall-FirefoxMaintenanceService', 
'Uninstall-Shockwave', 'Copy-AEM', 'MECM', 'Get-ENSInfo', 'Get-NLA', 
'Uninstall-Chrome', 'configmgr', 'Uninstall-Forms', 'Set-NLA', 
'Uninstall-AnyConnect', 'Uninstall-Firefox', 'Sync-HBSS', 
'Uninstall-AdobeAcrobat', 'Uninstall-Flash', 'Copy-Acrobat', 
'Uninstall-Java', 'SCCM'

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = 'PSEdition_Desktop','Windows','Automation','ActiveDirectory','Security',
            'Logging','Network','Reporting','Monitoring','Configuration','GroupPolicy'

        # A URL to the license for this module.
        LicenseUri = 'https://dev.azure.com/wanderingstag/_git/WSTools?path=%2FLICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://wstools.dev'

        # A URL to an icon representing this module.
        IconUri = 'https://wstools.dev/wp-content/uploads/2020/08/WSToolsLogo.png'

        # ReleaseNotes of this module
        ReleaseNotes = 'https://dev.azure.com/wanderingstag/_git/WSTools?path=%2FChangeLog.txt'

        # Prerelease string of this module
        # Prerelease = ''

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        # ExternalModuleDependencies = @()
    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

