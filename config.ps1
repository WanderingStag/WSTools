$Global:WSToolsConfig = New-Object -TypeName PSObject -Property @{
    # WSTools config v1.0.5
    # Remove the # symbol infront of a line to enable it

    ###########################################################################################################################################
    #Path to where module files are stored on a central server. Used in Install-WSTools (aka Copy-WSTools) and Update-WSTools
    UpdatePath = "J:\PowerShell\Modules\WSTools"

    #Update computer. Used when you have a computer you modify the module on then push it out to the update path from that computers local repository (hardcoded to $env:ProgramFiles\WindowsPowerShell\Modules\WSTools).
    #Additional paths is used for pushing out to folders in addtion to UpdatePath.
    UpdateComp = "snib1" #do not use the fqdn, only the shortname
    AdditionalUpdatePaths = @('D:\OneDrive\Scripts\Modules\WSTools')

    ################################
    ##        Ignore List         ##
    ################################
    #Computers, users, and groups to ignore that cause issues. Objects such as clustered object computer names, non-windows systems, and other such things. Uses -match in some places and -eq in others so be as precise as possible.
    #Ignore = @('comp1','comp2','user1','user2','group1','group2')


    ################################
    ##    App/Patching settings   ##
    ################################
    #Location on network where you store applications
    AppRepo = "J:\"

    #Local Patches folder on machines
    LocalPatches = "C:\Patches"

    #Network Patch Repository
    PatchRepo = "J:\Patches"

    #Save-UpdateHistory path also changes Save-MaintenanceReport path
    UHPath = "J:\ComputerInfo\Updates"

    ################################
    ##       Script settings      ##
    ################################
    #Script Repository
    ScriptRepo = "D:\OneDrive\Scripts"

    #Script Working Directory
    ScriptWD = "C:\Scripts"

    #Privileged groups list - used for some monitoring and reporting features.
    #PrivGroups = @()

    #Settings for Test-EmailRelay
    #Sender = "noreply@somedomain.com"
    #SMTPServer = "smtprelay.somedomain.com"
    #SMTPPort = 25

    ####
    #### Management and support URLs
    ####

    #HP iLO management in the WSTools\WS_DomainMgmt Open-iLO function
    #iLO = "https://iloaddress.somedomain.com"

    #Open-Remedy. Because of the aliases (Open-EITSM, EITSM) this can be used for any ticketing system
    #Remedy = "https://remedy.somedomain.com"

    #Open-vCenter
    #vCenter = "https://virtualcenter.somedomain.com/"

    ####
    #### NetIQ DRA Server info
    #### only remove the # in front of these and modify them if you have DRA Host/REST servers
    ####

    #DRADomain = "somedomain.com"
    #DRAHostServer = "server.somedomain.com"
    #DRAHostPort = 11192 #if not specified 11192 is used by default
    #DRARESTServer = "server.somedomain.com"
    #DRARESTPort = 8755 #if not specified 8755 is used by default
    #DRAInstallLocation = "C:\Program Files (x86)\netiq\DRA Extensions\modules\NetIQ.DRA.PowerShellExtensions"
    #DRAInstallFile = "J:\Microsoft\PowerShell\Modules\DRA"

    ####
    #### Preferences (will be set when using Set-Preferences)
    ####

    #Set whether you want explorer to open to Quick Access or This PC. Windows defaults to QuickAccess ($false). I recommend setting this to This PC ($true) if you are an admin.
    Explorer = $true

    #When opening documents of unknown file types, recommend to lookup an App that can open them in the Windows Store ($true - Windows default) or not recommend an App in the Store ($false.)
    #Doesn't always work
    StoreLookup = $false

    #Show hidden files ($true) or do not show hidden files ($false - Windows default.)
    HiddenFiles = $true

    #Show file extensions ($true) or do not show file extensions ($false - Windows default.)
    FileExtensions = $true

    #Add "Shortcut - " text to any new shortcut. Requires you to log off then log back on before changes take effect.
    ShortcutText = $false

    ###########################################################################################################################################
}#new object