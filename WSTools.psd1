#
# Generated on: 11 OCTOBER 2023
#

@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'WSTools.psm1'

    # Version number of this module.
    ModuleVersion = '2023.10.0'

    # Author of this module
    Author = 'Skyler Hart'

    # Company or vendor of this module
    CompanyName = 'Wandering Stag, LLC'

    # ID used to uniquely identify this module
    GUID = 'ceb3bb6b-dfdc-4f41-bab0-43624ff14605'

    # Copyright statement for this module
    Copyright = '2023 Wandering Stag, LLC'

    # Description of the functionality provided by this module
    Description = 'Provides ability to perform a lot of tasks in an automated manner, Insider Threat detection, remediations, and enhancements to PowerShell. Also provides numerous shortcuts.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '3.0'

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
    ScriptsToProcess = @('.\config.ps1','.\Resources\classes.ps1')

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
    FunctionsToExport = '*'

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = '*'

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = '*'

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
            ProjectUri = 'https://wanderingstag.github.io'

            # A URL to an icon representing this module.
            IconUri = 'https://wanderingstag.github.io/wp-content/uploads/2020/08/WSToolsLogo.png'

            # ReleaseNotes of this module
            ReleaseNotes = 'https://dev.azure.com/wanderingstag/_git/WSTools?path=%2FChangeLog.txt'

            # Prerelease string of this module
            # Prerelease = ''

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            RequireLicenseAcceptance = $false

            # External dependent modules of this module
            ExternalModuleDependencies = @('ActiveDirectory') #only for limited functions
        } # End of PSData hashtable

    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

}
