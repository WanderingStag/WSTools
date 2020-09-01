﻿$Global:WSToolsConfig = New-Object -TypeName PSObject -Property @{
    # WSTools config v1.0.6
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

    #Local Patches folder on machines - this does not change the copy and install functions under WS_Remediation. They will still try to copy to C:\Patches on the remote machine.
    LocalPatches = "C:\Patches"

    #Network Patch Repository
    PatchRepo = "J:\Patches"

    #Save-UpdateHistory path also changes Save-MaintenanceReport path
    UHPath = "J:\ComputerInfo\Updates"

    ################################
    ##            DRA             ##
    ################################
    #### only remove the # in front of these and modify them if you have DRA Host/REST servers
    #DRADomain = "somedomain.com"
    #DRAHostServer = "server.somedomain.com"
    #DRAHostPort = 11192 #if not specified 11192 is used by default
    #DRARESTServer = "server.somedomain.com"
    #DRARESTPort = 8755 #if not specified 8755 is used by default
    #DRAInstallLocation = "C:\Program Files (x86)\netiq\DRA Extensions\modules\NetIQ.DRA.PowerShellExtensions"
    #DRAInstallFile = "J:\Microsoft\PowerShell\Modules\DRA"

    ################################
    ##         Email relay        ##
    ################################
    #Settings for Test-EmailRelay
    #Sender = "noreply@somedomain.com"
    #SMTPServer = "smtprelay.somedomain.com"
    #SMTPPort = 25

    ################################
    ##      Mgmt/Suport URLs      ##
    ################################
    #HP iLO management in the WSTools\WS_DomainMgmt Open-iLO function
    #iLO = "https://iloaddress.somedomain.com"

    #Open-Remedy. Because of the aliases (Open-EITSM, EITSM) this can be used for any ticketing system
    #Remedy = "https://remedy.somedomain.com"

    #Open-vCenter
    #vCenter = "https://virtualcenter.somedomain.com/"

    ################################
    ##         Preferences        ##
    ################################
    # (will be set when using Set-Preferences)

    #Set whether you want explorer to open to Quick Access or This PC. Windows defaults to QuickAccess ($false). We recommend setting this to This PC ($true) if you are an admin.
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

    ################################
    ##         Remediation        ##
    ################################

    #Install file locations - for normal installation files.
    a7Zip = "J:\Tools\7zip" #64-bit only unless you change Copy-7Zip to use 32-bit
    Firefox = "J:\Tools\Firefox" #32-bit only unless you change Copy-Firefox to use 64-bit
    IE11 = "J:\Patches\IE\IE11"
    SysInternals = "J:\Tools\SysinternalsSuite"
    VLC = "J:\Tools\VLC"
    Wireshark = "J:\Tools\Wireshark"
    WMF3 = "J:\Microsoft\Windows Management Framework 3.0"
    WMF4 = "J:\Microsoft\Windows Management Framework 4.0"
    WMF5 = "J:\Microsoft\Windows Management Framework 5.1"
    
    #Install file locations that use the PowerShell App Deployment Toolkit from https://psappdeploytoolkit.com/
    a90Meter = "J:\Patches\SDC-APPS\90Meter"
    ActivClient = "J:\Patches\SDC-APPS\ActivClient"
    Acrobat = "J:\Patches\SDC-APPS\Adobe\Acrobat NIPR"
    AxwayServer = "J:\Patches\SDC-APPS\Axway\DSCC"
    AxwayClient = "J:\Patches\SDC-APPS\Axway\NIPR"
    Chrome = "J:\Patches\SDC-APPS\Chrome"
    DSET = "J:\Patches\SDC-APPS\DSET"
    Encase = "J:\Patches\SDC-APPS\Encase"
    #Firefox = "\\serverunc\apps\Firefox"
    Flash = "J:\Patches\SDC-APPS\Adobe\Flash"
    Java = "J:\Patches\SDC-APPS\Java\NIPR"
    NetBanner = "J:\Patches\SDC-APPS\NetBanner"
    Office2016 = "J:\Patches\SDC-APPS\Office2016"
    Silverlight = "J:\Patches\SDC-APPS\Silverlight"
    Tanium = "J:\Patches\SDC-APPS\Tanium\NIPR"
    Teams = "J:\Patches\SDC-APPS\Teams"
    Titus = "J:\Patches\SDC-APPS\Titus"
    VPN = "J:\Patches\SDC-APPS\VPN"

    #Ciphers - changes take effect immediately after change
    ##Set to 4294967295 to enable. Set to 0 to disable.
    RC2_56_56Enabled = 0
    RC2_40_128Enabled = 0
    RC2_56_128Enabled = 0
    RC2_128_128Enabled = 0

    RC4_40_128Enabled = 0
    RC4_56_128Enabled = 0
    RC4_64_128Enabled = 0
    RC4_128_128Enabled = 0
    
    DES56_56Enabled = 0
    TripleDES168Enabled = 0

    NullEnabled = 0

    #Hashes - changes take effect immediately after change
    ##Set to 4294967295 to enable. Set to 0 to disable.
    MD5Enabled = 0 #DevSkim: ignore DS126858 
    SHAEnabled = 4294967295

    #KeyExchangeAlgorithms - changes take effect after reboot
    ##Set to 4294967295 to enable. Set to 0 to disable.
    PKCSEnabled = 4294967295
    DiffieHellmanEnabled = 0

    #Protocols - changes take effect after reboot
    ##Set to 0 to disable and 1 to enable.
    PCT1ClientEnabled = 0
    PCT1ClientDisabledByDefault = 1
    PCT1ServerEnabled = 0

    SSL2_0ClientEnabled = 0 #DevSkim: ignore DS440000
    SSL2_0ClientDisabledByDefault = 1 #DevSkim: ignore DS440000
    SSL2_0ServerEnabled = 0 #DevSkim: ignore DS440000

    SSL3_0ClientEnabled = 0 #DevSkim: ignore DS440000
    SSL3_0ClientDisabledByDefault = 1 #DevSkim: ignore DS440000
    SSL3_0ServerEnabled = 0 #DevSkim: ignore DS440000

    TLS1_0ClientEnabled = 0 #DevSkim: ignore DS440000
    TLS1_0ClientDisabledByDefault = 1 #DevSkim: ignore DS440000
    TLS1_0ServerEnabled = 0 #DevSkim: ignore DS440000

    TLS1_1ClientEnabled = 0 #DevSkim: ignore DS440000
    TLS1_1ClientDisabledByDefault = 1 #DevSkim: ignore DS440000
    TLS1_1ServerEnabled = 0 #DevSkim: ignore DS440000

    TLS1_2ClientEnabled = 1 #DevSkim: ignore DS440000
    TLS1_2ClientDisabledByDefault = 0 #DevSkim: ignore DS440000
    TLS1_2ServerEnabled = 1 #DevSkim: ignore DS440000

    TLS1_3ClientEnabled = 1 #DevSkim: ignore DS440000
    TLS1_3ClientDisabledByDefault = 0 #DevSkim: ignore DS440000
    TLS1_3ServerEnabled = 1 #DevSkim: ignore DS440000

    #SMB - only works when running against local computer
    ##Set to 0 to disable and 1 to enable.
    SMB1 = 0
    SMB2 = 1

    ################################
    ##       Script settings      ##
    ################################
    #Script Repository
    ScriptRepo = "D:\OneDrive\Scripts"

    #Script Working Directory. Some functions use this directory to pull/save files from/to by default.
    ScriptWD = "C:\Scripts"

    #Privileged groups list - used for some monitoring and reporting features.
    #PrivGroups = @('group1','group2')
    ###########################################################################################################################################
}#new object