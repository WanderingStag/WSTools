[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    "PSAvoidGlobalVars",
    "",
    Justification = "Have tried other methods and they do not work consistently."
)]

$Global:WSToolsConfig = [PSCustomObject]@{
    # WSTools config v2023.5
    # Remove the # symbol infront of a line to enable it
    ###########################################################################################################################################
    #Application Service Names - used in Stop-AppService. Uses match to match the name of a service that is running and stops it.
    AppNames = @('BarTender','Cognos','Commvault','Dameware','Exchange','IBM','IDenticard','IIS','InstallRoot','LiveLink','Moodle','Oracle','Seagull','SharePoint','SolarWinds','Splunk','SQL','Tanium','Tumbleweed','World Wide Web','WSUS')

    #Ignore list. Used in several functions. Computers, users, and groups to ignore that cause issues. Objects such as clustered object computer names, non-windows systems, and other such things. Uses -match in some places and -eq in others so be as precise as possible.
    #Ignore = @('comp1','comp2','user1','user2','group1','group2')

    #Network speed test settings, paths are for folder where files will be created. File size can be entered in the format 100KB, 5MB, 1GB, etc.
    NSLocal = "$env:Temp"
    NSRemote = "\\snse\Temp"
    NSFileSize = 5MB

    #Privileged groups list - used for some monitoring and reporting features. You should populate this with groups that grant admin permissions.
    PrivGroups = @('CompAdmins_AD','CompAdmins_Local','DHCP Administrators','UserAdmins_AD','Priv Role - Admins','Priv Role - Domain Admin')

    #Default time of reboot when no time is specified in Set-Reboot. Must be entered in HHmm (24 hour/military time) format. Ex: For 7 PM enter 1900.
    RebootTime = "0030"

    #Script Repository. Can be local or network. If network it needs to be the UNC.
    ScriptRepo = "D:\OneDrive\Scripts"

    #Script Working Directory. Some functions use this directory to pull/save files from/to by default.
    ScriptWD = "C:\Scripts"

    #Default time of shutdown when no time is specified in Set-Shutdown. Must be entered in HHmm (24 hour/military time) format. Ex: For 7 PM enter 1900.
    ShutdownTime = "0040"

    #Update computer. Used when you have a computer you modify the module on then push it out to the update path from that computers local repository (hardcoded to $env:ProgramFiles\WindowsPowerShell\Modules\WSTools).
    UpdateComp = "sky" #do not use the fqdn, only the shortname

    #Path to where module files are stored on a central server. Used in Install-WSTools (aka Copy-WSTools) and Update-WSTools
    UpdatePath = "\\snse\Apps\Microsoft\PowerShell\Modules\WSTools"

    #Additional paths is used for pushing out to folders in addtion to UpdatePath.
    #AdditionalUpdatePaths = @('\\192.168.201.10\apps\Microsoft\PowerShell\Modules\WSTools','D:\OneDrive\Scripts\Modules\WSTools')

    #Old PowerShell Modules. Used in Remove-OldPowerShellModule.
    OldPSModule = @('SHTool','SHTools','SkysTool')

    #Help folder location used by Update-HelpFromFile
    HelpFolder = "\\192.168.201.10\apps\Microsoft\PowerShell\OfflineHelp"

    # Used in Get-ADComplianceReport. OU's must be entered in distinguishedName format.
    # Ex for single OU: UserOUs = 'OU=Users,DC=wstools,DC=dev'
    # Ex for multiple OUs: UserOUs = @('OU=Users,OU=TestLab,DC=wstools,DC=dev','OU=Users,DC=wstools,DC=dev')
    AdminOUs = @()
    AdminGroupOUs = @()
    ComputerOUs = @()           # regular computers/workstations. Can exclude ServerOUs value and just use this if you want.
    MSAOUs = @()                # standalone/group Managed Service Accounts (sMSA/gMSA respectively)
    OrgAccountOUs = @()         # organizational/shared accounts
    ServerOUs = @()             # member servers and domain controllers
    ServiceAccountOUs = @()     # regular service accounts NOT group managed service accounts
    UserOUs = @()
    UserGroupOUs = @()


    ################################
    ##    App/Patching settings   ##
    ################################
    #Location on network where you store applications
    AppRepo = "\\192.168.201.10\apps\"

    #CMTrace application location on network (if can't be found on computer it looks here)
    CMTrace = "\\192.168.201.10\apps\Tools\CMTrace.exe"

    #Java exception.sites file path. Only give path to the folder it's in.
    JException = "\\192.168.201.10\apps\Java"

    #Local Patches folder on machines - this does not change the copy and install functions under WS_Remediation. They will still try to copy to C:\Patches on the remote machine.
    LocalPatches = "C:\Patches"

    #Network Patch Repository
    PatchRepo = "\\192.168.201.10\apps\Patches"

    #Local/Network PowerShell Repository
    LocalPSRepo = "\\192.168.201.10\Apps\Microsoft\PowerShell\Modules"

    #Visio Stencil Path
    Stencils = "\\192.168.201.10\apps\Tools\Visio Stencils"

    #Save-UpdateHistory path also changes Save-MaintenanceReport path
    UHPath = "\\192.168.201.10\apps\ComputerInfo\Updates"

    #Visual Studio Code extensions path (network share or local path) used in Copy-VSCodeExtensions.
    VSCodeExtRepo = "\\192.168.201.10\apps\Patches\VisualStudioCode\Extensions"

    #Visual Studio Code settings path (network share or local path) used in Copy-VSCodeSettingsToProfile. Needs to be a txt or JSON file.
    VSCodeSettingsPath = "\\192.168.201.10\apps\Patches\VisualStudioCode\Settings.txt"

    ################################
    ##            DRA             ##
    ################################
    #### only remove the # in front of these and modify them if you have DRA Host/REST servers
    #DRADomain = "wstools.dev"
    #DRAHostServer = "server.wstools.dev"
    #DRAHostPort = 11192 #if not specified 11192 is used by default
    #DRARESTServer = "server.wstools.dev"
    #DRARESTPort = 8755 #if not specified 8755 is used by default
    #DRAInstallLocation = "C:\Program Files (x86)\netiq\DRA Extensions\modules\NetIQ.DRA.PowerShellExtensions"
    #DRAInstallFile = "\\192.168.201.10\apps\Microsoft\PowerShell\Modules\DRA"

    ################################
    ##         Email relay        ##
    ################################
    #Settings for Test-EmailRelay
    #Sender = "noreply@wstools.dev"
    #SMTPServer = "smtprelay.wstools.dev"
    #SMTPPort = 25

    ################################
    ##      Mgmt/Suport URLs      ##
    ################################
    #Open-CMLibrary
    #CMLibrary = "https://cmlibrary.wstools.dev"

    #Open-ECP/Open-EAC #exchange control panel aka exchange admin center (eac)
    #EAC = "https://owa.wstools.dev/ecp"

    #Open-HomeAssistant
    HomeAssistant = "https://homeassistant.wanderingstag.com"

    #HP iLO management in the WSTools\WS_DomainMgmt Open-iLO function
    #iLO = "https://iloaddress.wstools.dev"

    #Open-LexmarkManagementConsole and Open-PrintRelease
    #LMC = "https://lmcserver.wstools.dev/lmc"
    #PrintRelease = "https://lmcserver.wstools.dev/PrintRelease"

    #Open diagrams (Open-NetworkDiagram and Open-RackElevation). Can be file/unc path or URL.
    NetDiagram = "\\192.168.201.10\apps\ComputerInfo\Diagram\networkdiagram.vsdx"
    RackEl = "\\192.168.201.10\apps\ComputerInfo\Diagram\rackelevation.vsdx"

    #Open-OWA
    #OWA = "https://owa.wstools.dev"

    #Open-Remedy. Because of the aliases (Open-EITSM, EITSM) this can be used for any ticketing system
    #Remedy = "https://remedy.wstools.dev"

    #Open-SharePoint
    #SharePoint = "https://sharepoint.wstools.dev"

    #Open-SDNManagement aka Open-Unifi
    SDNMgmt = "https://unifi.wanderingstag.com"

    #Open-SEIM
    #SEIM = "https://seim.wstools.dev"

    #Open-vCenter
    #vCenter = "https://vcenter.wstools.dev/"

    ################################
    ##         Preferences        ##
    ################################
    # (will be set when using Set-Preferences)

    #Set whether you want explorer to open to Quick Access or This PC. Windows defaults to QuickAccess ($false). We recommend setting this to This PC ($true) if you are an admin.
    Explorer = $true

    #Show file extensions ($true) or do not show file extensions ($false - Windows default.)
    FileExtensions = $true

    #Show hidden files ($true) or do not show hidden files ($false - Windows default.)
    HiddenFiles = $true

    #Add "Shortcut - " text to any new shortcut. Requires you to log off then log back on before changes take effect.
    ShortcutText = $false

    #When opening documents of unknown file types, recommend to lookup an App that can open them in the Windows Store ($true - Windows default) or not recommend an App in the Store ($false.)
    #Doesn't always work
    StoreLookup = $false

    ################################
    ##         Remediation        ##
    ################################
    #Install file locations - for normal installation files.
    a7Zip = "\\192.168.201.10\apps\Tools\7zip" #64-bit only unless you change Copy-7Zip to use 32-bit
    EdgeVanilla = "\\192.168.201.10\apps\Patches\Edge"
    Git = "\\192.168.201.10\apps\Patches\GitSCM"
    IE11 = "\\192.168.201.10\apps\Patches\IE\IE11"
    MECM = "\\192.168.201.10\apps\Microsoft\SCCM"
    OneDrive = "\\192.168.201.10\apps\Patches\OneDrive"
    SplunkUF = "\\192.168.201.10\apps\Patches\Splunk_Forwarder"
    SSMS = "\\192.168.201.10\apps\Patches\SQL\SSMS" #sql server management studio
    SysInternals = "\\192.168.201.10\apps\Tools\SysinternalsSuite"
    VSCode = "\\192.168.201.10\apps\Patches\VisualStudioCode\VSCode_Installer"
    VLC = "\\192.168.201.10\apps\Tools\VLC"
    VMwareTools = "\\192.168.201.10\apps\Patches\VMware_Tools"
    Wireshark = "\\192.168.201.10\apps\Tools\Wireshark"
    WMF3 = "\\192.168.201.10\apps\Microsoft\Windows Management Framework 3.0"
    WMF4 = "\\192.168.201.10\apps\Microsoft\Windows Management Framework 4.0"
    WMF5 = "\\192.168.201.10\apps\Microsoft\Windows Management Framework 5.1"
    Zoom = "\\192.168.201.10\apps\Approved\Zoom"

    #Install file locations that use the PowerShell App Deployment Toolkit from https://psappdeploytoolkit.com/
    a90Meter = "\\192.168.201.10\apps\Patches\SDC-APPS\90Meter"
    ActivClient = "\\192.168.201.10\apps\Patches\SDC-APPS\ActivClient"
    Acrobat = "\\192.168.201.10\apps\Patches\SDC-APPS\Adobe\Acrobat NIPR"
    AEM = "\\192.168.201.10\apps\Patches\SDC-APPS\Adobe\AEM_FormsDesigner"
    AxwayServer = "\\192.168.201.10\apps\Patches\SDC-APPS\Axway\DSCC"
    AxwayClient = "\\192.168.201.10\apps\Patches\SDC-APPS\Axway\NIPR"
    Chrome = "\\192.168.201.10\apps\Patches\SDC-APPS\Chrome"
    DSET = "\\192.168.201.10\apps\Patches\SDC-APPS\DSET"
    Edge = "\\192.168.201.10\apps\Patches\SDC-APPS\Edge"
    Encase = "\\192.168.201.10\apps\Patches\SDC-APPS\Encase\NIPR"
    Firefox = "\\192.168.201.10\apps\Patches\SDC-APPS\Firefox"
    InfoPath = "\\192.168.201.10\apps\Patches\SDC-APPS\InfoPath"
    Java = "\\192.168.201.10\apps\Patches\SDC-APPS\Java\NIPR"
    JRSS = "\\192.168.201.10\apps\Patches\SDC-APPS\JRSS"
    NetBanner = "\\192.168.201.10\apps\Patches\SDC-APPS\NetBanner"
    Office2016 = "\\192.168.201.10\apps\Patches\SDC-APPS\Office2016"
    Silverlight = "\\192.168.201.10\apps\Patches\SDC-APPS\Silverlight"
    Tanium = "\\192.168.201.10\apps\Patches\SDC-APPS\Tanium\NIPR"
    Teams = "\\192.168.201.10\apps\Patches\SDC-APPS\Teams"
    Titus = "\\192.168.201.10\apps\Patches\SDC-APPS\Titus"
    VPN = "\\192.168.201.10\apps\Patches\SDC-APPS\VPN"

    ########################################
    ##         Remediation Settings       ##
    ##            not in use yet          ##
    ########################################
    #Ciphers - changes take effect immediately after change
    ##Set to "ffffffff" to enable. Set to 0 to disable.
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
    ##Set to "ffffffff" to enable. Set to 0 to disable.
    MD5Enabled = 0 #DevSkim: ignore DS126858
    SHAEnabled = "ffffffff" #THIS DOES NOT WORK. There is a Microsoft bug that prevents it. Must be set manually or by importing a .reg file.

    #KeyExchangeAlgorithms - changes take effect after reboot
    ##Set to "ffffffff" (aka 4294967295) to enable. Set to 0 to disable.
    PKCSEnabled = "ffffffff" #THIS DOES NOT WORK. There is a Microsoft bug that prevents it. Must be set manually or by importing a .reg file.
    DiffieHellmanEnabled = 0

    #Protocols - changes take effect after reboot
    ##Set to 0 to disable and 1 to enable.
    PCT1ClientEnabled = 0
    PCT1ClientDisabledByDefault = 1
    PCT1ServerEnabled = 0
    PCT1ServerDisabledByDefault = 1

    SSL2_0ClientEnabled = 0 #DevSkim: ignore DS440000
    SSL2_0ClientDisabledByDefault = 1 #DevSkim: ignore DS440000
    SSL2_0ServerEnabled = 0 #DevSkim: ignore DS440000

    SSL3_0ClientEnabled = 0 #DevSkim: ignore DS440000
    SSL3_0ClientDisabledByDefault = 1 #DevSkim: ignore DS440000
    SSL3_0ServerEnabled = 0 #DevSkim: ignore DS440000

    TLS1_0ClientEnabled = 1 #DevSkim: ignore DS440000
    TLS1_0ClientDisabledByDefault = 0 #DevSkim: ignore DS440000
    TLS1_0ServerEnabled = 0 #DevSkim: ignore DS440000
    TLS1_0ServerDisabledByDefault = 1 #DevSkim: ignore DS440000

    TLS1_1ClientEnabled = 0 #DevSkim: ignore DS440000
    TLS1_1ClientDisabledByDefault = 1 #DevSkim: ignore DS440000
    TLS1_1ServerEnabled = 0 #DevSkim: ignore DS440000
    TLS1_1ServerDisabledByDefault = 1 #DevSkim: ignore DS440000

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
    ##        Server Config       ##
    ################################
    #Used in Set-ServerConfig

    #DHCP Enabled or Disabled. $true=Enable $false=Disable
    SCDHCP = $false

    #IPv6 $true=Enable $false=Disable
    SCIPv6 = $false

    #Link-Layer Topology Discovery Mapper I/O Driver $true=Enable $false=Disable
    #The Mapper I/O network protocol (LLTDIO) driver allows the discovery of the connected network and allows various options to be enabled. Disabling this helps protect the system from potentially discovering and connecting to unauthorized devices.
    SClltdio = $false

    #Link-Layer Topology Discovery Responder $true=Enable $false=Disable
    #The Responder network protocol driver allows a computer to be discovered and located on a network. Disabling this helps protect the system from potentially being discovered and connected to by unauthorized devices.
    SCllrspndr = $false

    #NetBIOS over TCP/IP
    # 0=use default from DHCP. If static enable NetBios over TCP/IP. 1=Enable NetBIOS over TCP/IP. 2=Disable NetBIOS over TCP/IP
    SCNetBios = 1

    #Offloading of Checksums and Large Files to the NIC see more info at https://docs.microsoft.com/en-us/windows-server/networking/technologies/hpn/hpn-hardware-only-features
    <#Skyler speaking here, I personally and professionally recommend disabling these on older (2008 R2 and older) Operating Systems. I've ran into WAY to many issues over my 20 years in
    IT that have been caused by these being enabled. I've had several Premier Field Engineers from Microsoft also tell me to disable them and 10/10 times it will improve network performance.
    If you have a small site at a single location you might be able to get away with enabling these. But even on my small personal network at home I've noticed significant network
    improvements by disabling these offload settings.

    However, please note on newer operating systems and hardware disabling this (setting to $false) may actually hinder performance. Such as on Windows 10, Windows Server 2016/2019, and
    newer operating systems or those running on VMWare 6.7+.
    #>
    # $true=Enable $false=Disable
    SCOffload = $true

    #RDP 0=Enable 1=Disable
    SCRDP = 0

    #Server Manager $true=Enable $false=Disable
    SCServerMgr = $false

    #WINS settings
    ##true = Domain Name System (DNS) is enabled for name resolution over WINS resolution.
    SCWDNS = $false

    ##true = local lookup files are used. Lookup files will contain mappings of IP addresses to host names.
    SCLMHost = $false

    ################################
    ##      Federal Holidays      ##
    ################################
    Holidays = @(#Used in Show-FederalHoliday and Convert-DaysToWorkDay. These are the observed holidays according to OPM (https://www.opm.gov/policy-data-oversight/pay-leave/federal-holidays/)
        (New-Object -TypeName PSObject -Property @{Year = 2018; Date = (Get-Date -Date '2018-01-01'); DayOfWeek = ((Get-Date -Date '2018-01-01').DayOfWeek); Name = "New Years"}),
        (New-Object -TypeName PSObject -Property @{Year = 2018; Date = (Get-Date -Date '2018-01-15'); DayOfWeek = ((Get-Date -Date '2018-01-15').DayOfWeek); Name = "Martin Luther King Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2018; Date = (Get-Date -Date '2018-02-19'); DayOfWeek = ((Get-Date -Date '2018-02-19').DayOfWeek); Name = "Washingtons Birthday"}),
        (New-Object -TypeName PSObject -Property @{Year = 2018; Date = (Get-Date -Date '2018-05-28'); DayOfWeek = ((Get-Date -Date '2018-05-28').DayOfWeek); Name = "Memorial Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2018; Date = (Get-Date -Date '2018-07-04'); DayOfWeek = ((Get-Date -Date '2018-07-04').DayOfWeek); Name = "Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2018; Date = (Get-Date -Date '2018-09-03'); DayOfWeek = ((Get-Date -Date '2018-09-03').DayOfWeek); Name = "Labor Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2018; Date = (Get-Date -Date '2018-10-08'); DayOfWeek = ((Get-Date -Date '2018-10-08').DayOfWeek); Name = "Columbus Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2018; Date = (Get-Date -Date '2018-11-12'); DayOfWeek = ((Get-Date -Date '2018-11-12').DayOfWeek); Name = "Veterans Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2018; Date = (Get-Date -Date '2018-11-22'); DayOfWeek = ((Get-Date -Date '2018-11-22').DayOfWeek); Name = "Thanksgiving Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2018; Date = (Get-Date -Date '2018-12-25'); DayOfWeek = ((Get-Date -Date '2018-12-25').DayOfWeek); Name = "Christmas Day"}),

        (New-Object -TypeName PSObject -Property @{Year = 2019; Date = (Get-Date -Date '2019-01-01'); DayOfWeek = ((Get-Date -Date '2019-01-01').DayOfWeek); Name = "New Years"}),
        (New-Object -TypeName PSObject -Property @{Year = 2019; Date = (Get-Date -Date '2019-01-21'); DayOfWeek = ((Get-Date -Date '2019-01-21').DayOfWeek); Name = "Martin Luther King Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2019; Date = (Get-Date -Date '2019-02-18'); DayOfWeek = ((Get-Date -Date '2019-02-18').DayOfWeek); Name = "Washingtons Birthday"}),
        (New-Object -TypeName PSObject -Property @{Year = 2019; Date = (Get-Date -Date '2019-05-27'); DayOfWeek = ((Get-Date -Date '2019-05-27').DayOfWeek); Name = "Memorial Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2019; Date = (Get-Date -Date '2019-07-04'); DayOfWeek = ((Get-Date -Date '2019-07-04').DayOfWeek); Name = "Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2019; Date = (Get-Date -Date '2019-09-02'); DayOfWeek = ((Get-Date -Date '2019-09-02').DayOfWeek); Name = "Labor Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2019; Date = (Get-Date -Date '2019-10-14'); DayOfWeek = ((Get-Date -Date '2019-10-14').DayOfWeek); Name = "Columbus Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2019; Date = (Get-Date -Date '2019-11-11'); DayOfWeek = ((Get-Date -Date '2019-11-11').DayOfWeek); Name = "Veterans Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2019; Date = (Get-Date -Date '2019-11-28'); DayOfWeek = ((Get-Date -Date '2019-11-28').DayOfWeek); Name = "Thanksgiving Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2019; Date = (Get-Date -Date '2019-12-25'); DayOfWeek = ((Get-Date -Date '2019-12-25').DayOfWeek); Name = "Christmas Day"}),

        (New-Object -TypeName PSObject -Property @{Year = 2020; Date = (Get-Date -Date '2020-01-01'); DayOfWeek = ((Get-Date -Date '2020-01-01').DayOfWeek); Name = "New Years"}),
        (New-Object -TypeName PSObject -Property @{Year = 2020; Date = (Get-Date -Date '2020-01-20'); DayOfWeek = ((Get-Date -Date '2020-01-20').DayOfWeek); Name = "Martin Luther King Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2020; Date = (Get-Date -Date '2020-02-17'); DayOfWeek = ((Get-Date -Date '2020-02-17').DayOfWeek); Name = "Washingtons Birthday"}),
        (New-Object -TypeName PSObject -Property @{Year = 2020; Date = (Get-Date -Date '2020-05-25'); DayOfWeek = ((Get-Date -Date '2020-05-25').DayOfWeek); Name = "Memorial Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2020; Date = (Get-Date -Date '2020-07-03'); DayOfWeek = ((Get-Date -Date '2020-07-03').DayOfWeek); Name = "Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2020; Date = (Get-Date -Date '2020-09-07'); DayOfWeek = ((Get-Date -Date '2020-09-07').DayOfWeek); Name = "Labor Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2020; Date = (Get-Date -Date '2020-10-12'); DayOfWeek = ((Get-Date -Date '2020-10-12').DayOfWeek); Name = "Columbus Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2020; Date = (Get-Date -Date '2020-11-11'); DayOfWeek = ((Get-Date -Date '2020-11-11').DayOfWeek); Name = "Veterans Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2020; Date = (Get-Date -Date '2020-11-26'); DayOfWeek = ((Get-Date -Date '2020-11-26').DayOfWeek); Name = "Thanksgiving Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2020; Date = (Get-Date -Date '2020-12-25'); DayOfWeek = ((Get-Date -Date '2020-12-25').DayOfWeek); Name = "Christmas Day"}),

        (New-Object -TypeName PSObject -Property @{Year = 2021; Date = (Get-Date -Date '2021-01-01'); DayOfWeek = ((Get-Date -Date '2021-01-01').DayOfWeek); Name = "New Years"}),
        (New-Object -TypeName PSObject -Property @{Year = 2021; Date = (Get-Date -Date '2021-01-18'); DayOfWeek = ((Get-Date -Date '2021-01-18').DayOfWeek); Name = "Martin Luther King Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2021; Date = (Get-Date -Date '2021-02-15'); DayOfWeek = ((Get-Date -Date '2021-02-15').DayOfWeek); Name = "Washingtons Birthday"}),
        (New-Object -TypeName PSObject -Property @{Year = 2021; Date = (Get-Date -Date '2021-05-31'); DayOfWeek = ((Get-Date -Date '2021-05-31').DayOfWeek); Name = "Memorial Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2022; Date = (Get-Date -Date '2021-06-18'); DayOfWeek = ((Get-Date -Date '2021-06-18').DayOfWeek); Name = "Juneteenth National Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2021; Date = (Get-Date -Date '2021-07-05'); DayOfWeek = ((Get-Date -Date '2021-07-05').DayOfWeek); Name = "Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2021; Date = (Get-Date -Date '2021-09-06'); DayOfWeek = ((Get-Date -Date '2021-09-06').DayOfWeek); Name = "Labor Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2021; Date = (Get-Date -Date '2021-10-11'); DayOfWeek = ((Get-Date -Date '2021-10-11').DayOfWeek); Name = "Columbus Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2021; Date = (Get-Date -Date '2021-11-11'); DayOfWeek = ((Get-Date -Date '2021-11-11').DayOfWeek); Name = "Veterans Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2021; Date = (Get-Date -Date '2021-11-25'); DayOfWeek = ((Get-Date -Date '2021-11-25').DayOfWeek); Name = "Thanksgiving Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2021; Date = (Get-Date -Date '2021-12-24'); DayOfWeek = ((Get-Date -Date '2021-12-24').DayOfWeek); Name = "Christmas Day"}),

        (New-Object -TypeName PSObject -Property @{Year = 2022; Date = (Get-Date -Date '2021-12-31'); DayOfWeek = ((Get-Date -Date '2021-12-31').DayOfWeek); Name = "New Years"}),
        (New-Object -TypeName PSObject -Property @{Year = 2022; Date = (Get-Date -Date '2022-01-17'); DayOfWeek = ((Get-Date -Date '2022-01-17').DayOfWeek); Name = "Martin Luther King Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2022; Date = (Get-Date -Date '2022-02-21'); DayOfWeek = ((Get-Date -Date '2022-02-21').DayOfWeek); Name = "Washingtons Birthday"}),
        (New-Object -TypeName PSObject -Property @{Year = 2022; Date = (Get-Date -Date '2022-05-30'); DayOfWeek = ((Get-Date -Date '2022-05-30').DayOfWeek); Name = "Memorial Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2022; Date = (Get-Date -Date '2022-06-20'); DayOfWeek = ((Get-Date -Date '2022-06-20').DayOfWeek); Name = "Juneteenth National Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2022; Date = (Get-Date -Date '2022-07-04'); DayOfWeek = ((Get-Date -Date '2022-07-04').DayOfWeek); Name = "Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2022; Date = (Get-Date -Date '2022-09-05'); DayOfWeek = ((Get-Date -Date '2022-09-05').DayOfWeek); Name = "Labor Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2022; Date = (Get-Date -Date '2022-10-10'); DayOfWeek = ((Get-Date -Date '2022-10-10').DayOfWeek); Name = "Columbus Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2022; Date = (Get-Date -Date '2022-11-11'); DayOfWeek = ((Get-Date -Date '2022-11-11').DayOfWeek); Name = "Veterans Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2022; Date = (Get-Date -Date '2022-11-24'); DayOfWeek = ((Get-Date -Date '2022-11-24').DayOfWeek); Name = "Thanksgiving Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2022; Date = (Get-Date -Date '2022-12-26'); DayOfWeek = ((Get-Date -Date '2022-12-26').DayOfWeek); Name = "Christmas Day"}),

        (New-Object -TypeName PSObject -Property @{Year = 2023; Date = (Get-Date -Date '2023-01-02'); DayOfWeek = ((Get-Date -Date '2023-01-02').DayOfWeek); Name = "New Years"}),
        (New-Object -TypeName PSObject -Property @{Year = 2023; Date = (Get-Date -Date '2023-01-16'); DayOfWeek = ((Get-Date -Date '2023-01-16').DayOfWeek); Name = "Martin Luther King Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2023; Date = (Get-Date -Date '2023-02-20'); DayOfWeek = ((Get-Date -Date '2023-02-20').DayOfWeek); Name = "Washingtons Birthday"}),
        (New-Object -TypeName PSObject -Property @{Year = 2023; Date = (Get-Date -Date '2023-05-29'); DayOfWeek = ((Get-Date -Date '2023-05-29').DayOfWeek); Name = "Memorial Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2023; Date = (Get-Date -Date '2023-06-19'); DayOfWeek = ((Get-Date -Date '2023-06-19').DayOfWeek); Name = "Juneteenth National Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2023; Date = (Get-Date -Date '2023-07-04'); DayOfWeek = ((Get-Date -Date '2023-07-04').DayOfWeek); Name = "Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2023; Date = (Get-Date -Date '2023-09-04'); DayOfWeek = ((Get-Date -Date '2023-09-04').DayOfWeek); Name = "Labor Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2023; Date = (Get-Date -Date '2023-10-09'); DayOfWeek = ((Get-Date -Date '2023-10-09').DayOfWeek); Name = "Columbus Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2023; Date = (Get-Date -Date '2023-11-10'); DayOfWeek = ((Get-Date -Date '2023-11-10').DayOfWeek); Name = "Veterans Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2023; Date = (Get-Date -Date '2023-11-23'); DayOfWeek = ((Get-Date -Date '2023-11-23').DayOfWeek); Name = "Thanksgiving Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2023; Date = (Get-Date -Date '2023-12-25'); DayOfWeek = ((Get-Date -Date '2023-12-25').DayOfWeek); Name = "Christmas Day"}),

        (New-Object -TypeName PSObject -Property @{Year = 2024; Date = (Get-Date -Date '2024-01-01'); DayOfWeek = ((Get-Date -Date '2024-01-01').DayOfWeek); Name = "New Years"}),
        (New-Object -TypeName PSObject -Property @{Year = 2024; Date = (Get-Date -Date '2024-01-15'); DayOfWeek = ((Get-Date -Date '2024-01-15').DayOfWeek); Name = "Martin Luther King Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2024; Date = (Get-Date -Date '2024-02-19'); DayOfWeek = ((Get-Date -Date '2024-02-19').DayOfWeek); Name = "Washingtons Birthday"}),
        (New-Object -TypeName PSObject -Property @{Year = 2024; Date = (Get-Date -Date '2024-05-27'); DayOfWeek = ((Get-Date -Date '2024-05-27').DayOfWeek); Name = "Memorial Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2024; Date = (Get-Date -Date '2024-06-19'); DayOfWeek = ((Get-Date -Date '2024-06-19').DayOfWeek); Name = "Juneteenth National Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2024; Date = (Get-Date -Date '2024-07-04'); DayOfWeek = ((Get-Date -Date '2024-07-04').DayOfWeek); Name = "Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2024; Date = (Get-Date -Date '2024-09-02'); DayOfWeek = ((Get-Date -Date '2024-09-02').DayOfWeek); Name = "Labor Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2024; Date = (Get-Date -Date '2024-10-14'); DayOfWeek = ((Get-Date -Date '2024-10-14').DayOfWeek); Name = "Columbus Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2024; Date = (Get-Date -Date '2024-11-11'); DayOfWeek = ((Get-Date -Date '2024-11-11').DayOfWeek); Name = "Veterans Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2024; Date = (Get-Date -Date '2024-11-28'); DayOfWeek = ((Get-Date -Date '2024-11-28').DayOfWeek); Name = "Thanksgiving Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2024; Date = (Get-Date -Date '2024-12-25'); DayOfWeek = ((Get-Date -Date '2024-12-25').DayOfWeek); Name = "Christmas Day"}),

        (New-Object -TypeName PSObject -Property @{Year = 2025; Date = (Get-Date -Date '2025-01-01'); DayOfWeek = ((Get-Date -Date '2025-01-01').DayOfWeek); Name = "New Years"}),
        (New-Object -TypeName PSObject -Property @{Year = 2025; Date = (Get-Date -Date '2025-01-20'); DayOfWeek = ((Get-Date -Date '2025-01-20').DayOfWeek); Name = "Martin Luther King Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2025; Date = (Get-Date -Date '2025-02-17'); DayOfWeek = ((Get-Date -Date '2025-02-17').DayOfWeek); Name = "Washingtons Birthday"}),
        (New-Object -TypeName PSObject -Property @{Year = 2025; Date = (Get-Date -Date '2025-05-26'); DayOfWeek = ((Get-Date -Date '2025-05-26').DayOfWeek); Name = "Memorial Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2025; Date = (Get-Date -Date '2025-06-19'); DayOfWeek = ((Get-Date -Date '2025-06-19').DayOfWeek); Name = "Juneteenth National Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2025; Date = (Get-Date -Date '2025-07-04'); DayOfWeek = ((Get-Date -Date '2025-07-04').DayOfWeek); Name = "Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2025; Date = (Get-Date -Date '2025-09-01'); DayOfWeek = ((Get-Date -Date '2025-09-01').DayOfWeek); Name = "Labor Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2025; Date = (Get-Date -Date '2025-10-13'); DayOfWeek = ((Get-Date -Date '2025-10-13').DayOfWeek); Name = "Columbus Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2025; Date = (Get-Date -Date '2025-11-11'); DayOfWeek = ((Get-Date -Date '2025-11-11').DayOfWeek); Name = "Veterans Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2025; Date = (Get-Date -Date '2025-11-27'); DayOfWeek = ((Get-Date -Date '2025-11-27').DayOfWeek); Name = "Thanksgiving Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2025; Date = (Get-Date -Date '2025-12-25'); DayOfWeek = ((Get-Date -Date '2025-12-25').DayOfWeek); Name = "Christmas Day"}),

        (New-Object -TypeName PSObject -Property @{Year = 2026; Date = (Get-Date -Date '2026-01-01'); DayOfWeek = ((Get-Date -Date '2026-01-01').DayOfWeek); Name = "New Years"}),
        (New-Object -TypeName PSObject -Property @{Year = 2026; Date = (Get-Date -Date '2026-01-19'); DayOfWeek = ((Get-Date -Date '2026-01-19').DayOfWeek); Name = "Martin Luther King Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2026; Date = (Get-Date -Date '2026-02-16'); DayOfWeek = ((Get-Date -Date '2026-02-16').DayOfWeek); Name = "Washingtons Birthday"}),
        (New-Object -TypeName PSObject -Property @{Year = 2026; Date = (Get-Date -Date '2026-05-25'); DayOfWeek = ((Get-Date -Date '2026-05-25').DayOfWeek); Name = "Memorial Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2026; Date = (Get-Date -Date '2026-06-19'); DayOfWeek = ((Get-Date -Date '2026-06-19').DayOfWeek); Name = "Juneteenth National Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2026; Date = (Get-Date -Date '2026-07-03'); DayOfWeek = ((Get-Date -Date '2026-07-03').DayOfWeek); Name = "Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2026; Date = (Get-Date -Date '2026-09-07'); DayOfWeek = ((Get-Date -Date '2026-09-07').DayOfWeek); Name = "Labor Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2026; Date = (Get-Date -Date '2026-10-12'); DayOfWeek = ((Get-Date -Date '2026-10-12').DayOfWeek); Name = "Columbus Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2026; Date = (Get-Date -Date '2026-11-11'); DayOfWeek = ((Get-Date -Date '2026-11-11').DayOfWeek); Name = "Veterans Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2026; Date = (Get-Date -Date '2026-11-26'); DayOfWeek = ((Get-Date -Date '2026-11-26').DayOfWeek); Name = "Thanksgiving Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2026; Date = (Get-Date -Date '2026-12-25'); DayOfWeek = ((Get-Date -Date '2026-12-25').DayOfWeek); Name = "Christmas Day"}),

        (New-Object -TypeName PSObject -Property @{Year = 2027; Date = (Get-Date -Date '2027-01-01'); DayOfWeek = ((Get-Date -Date '2027-01-01').DayOfWeek); Name = "New Years"}),
        (New-Object -TypeName PSObject -Property @{Year = 2027; Date = (Get-Date -Date '2027-01-18'); DayOfWeek = ((Get-Date -Date '2027-01-18').DayOfWeek); Name = "Martin Luther King Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2027; Date = (Get-Date -Date '2027-02-15'); DayOfWeek = ((Get-Date -Date '2027-02-15').DayOfWeek); Name = "Washingtons Birthday"}),
        (New-Object -TypeName PSObject -Property @{Year = 2027; Date = (Get-Date -Date '2027-05-31'); DayOfWeek = ((Get-Date -Date '2027-05-31').DayOfWeek); Name = "Memorial Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2027; Date = (Get-Date -Date '2027-06-18'); DayOfWeek = ((Get-Date -Date '2027-06-18').DayOfWeek); Name = "Juneteenth National Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2027; Date = (Get-Date -Date '2027-07-05'); DayOfWeek = ((Get-Date -Date '2027-07-05').DayOfWeek); Name = "Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2027; Date = (Get-Date -Date '2027-09-06'); DayOfWeek = ((Get-Date -Date '2027-09-06').DayOfWeek); Name = "Labor Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2027; Date = (Get-Date -Date '2027-10-11'); DayOfWeek = ((Get-Date -Date '2027-10-11').DayOfWeek); Name = "Columbus Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2027; Date = (Get-Date -Date '2027-11-11'); DayOfWeek = ((Get-Date -Date '2027-11-11').DayOfWeek); Name = "Veterans Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2027; Date = (Get-Date -Date '2027-11-25'); DayOfWeek = ((Get-Date -Date '2027-11-25').DayOfWeek); Name = "Thanksgiving Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2027; Date = (Get-Date -Date '2027-12-24'); DayOfWeek = ((Get-Date -Date '2027-12-24').DayOfWeek); Name = "Christmas Day"}),

        (New-Object -TypeName PSObject -Property @{Year = 2028; Date = (Get-Date -Date '2027-12-31'); DayOfWeek = ((Get-Date -Date '2027-12-31').DayOfWeek); Name = "New Years"}),
        (New-Object -TypeName PSObject -Property @{Year = 2028; Date = (Get-Date -Date '2028-01-17'); DayOfWeek = ((Get-Date -Date '2028-01-17').DayOfWeek); Name = "Martin Luther King Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2028; Date = (Get-Date -Date '2028-02-21'); DayOfWeek = ((Get-Date -Date '2028-02-21').DayOfWeek); Name = "Washingtons Birthday"}),
        (New-Object -TypeName PSObject -Property @{Year = 2028; Date = (Get-Date -Date '2028-05-29'); DayOfWeek = ((Get-Date -Date '2028-05-29').DayOfWeek); Name = "Memorial Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2028; Date = (Get-Date -Date '2028-06-19'); DayOfWeek = ((Get-Date -Date '2028-06-19').DayOfWeek); Name = "Juneteenth National Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2028; Date = (Get-Date -Date '2028-07-04'); DayOfWeek = ((Get-Date -Date '2028-07-04').DayOfWeek); Name = "Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2028; Date = (Get-Date -Date '2028-09-04'); DayOfWeek = ((Get-Date -Date '2028-09-04').DayOfWeek); Name = "Labor Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2028; Date = (Get-Date -Date '2028-10-09'); DayOfWeek = ((Get-Date -Date '2028-10-09').DayOfWeek); Name = "Columbus Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2028; Date = (Get-Date -Date '2028-11-10'); DayOfWeek = ((Get-Date -Date '2028-11-10').DayOfWeek); Name = "Veterans Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2028; Date = (Get-Date -Date '2028-11-23'); DayOfWeek = ((Get-Date -Date '2028-11-23').DayOfWeek); Name = "Thanksgiving Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2028; Date = (Get-Date -Date '2028-12-25'); DayOfWeek = ((Get-Date -Date '2028-12-25').DayOfWeek); Name = "Christmas Day"}),

        (New-Object -TypeName PSObject -Property @{Year = 2029; Date = (Get-Date -Date '2029-01-01'); DayOfWeek = ((Get-Date -Date '2029-01-01').DayOfWeek); Name = "New Years"}),
        (New-Object -TypeName PSObject -Property @{Year = 2029; Date = (Get-Date -Date '2029-01-15'); DayOfWeek = ((Get-Date -Date '2029-01-15').DayOfWeek); Name = "Martin Luther King Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2029; Date = (Get-Date -Date '2029-02-19'); DayOfWeek = ((Get-Date -Date '2029-02-19').DayOfWeek); Name = "Washingtons Birthday"}),
        (New-Object -TypeName PSObject -Property @{Year = 2029; Date = (Get-Date -Date '2029-05-28'); DayOfWeek = ((Get-Date -Date '2029-05-28').DayOfWeek); Name = "Memorial Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2029; Date = (Get-Date -Date '2029-06-19'); DayOfWeek = ((Get-Date -Date '2029-06-19').DayOfWeek); Name = "Juneteenth National Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2029; Date = (Get-Date -Date '2029-07-04'); DayOfWeek = ((Get-Date -Date '2029-07-04').DayOfWeek); Name = "Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2029; Date = (Get-Date -Date '2029-09-03'); DayOfWeek = ((Get-Date -Date '2029-09-03').DayOfWeek); Name = "Labor Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2029; Date = (Get-Date -Date '2029-10-08'); DayOfWeek = ((Get-Date -Date '2029-10-08').DayOfWeek); Name = "Columbus Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2029; Date = (Get-Date -Date '2029-11-12'); DayOfWeek = ((Get-Date -Date '2029-11-12').DayOfWeek); Name = "Veterans Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2029; Date = (Get-Date -Date '2029-11-22'); DayOfWeek = ((Get-Date -Date '2029-11-22').DayOfWeek); Name = "Thanksgiving Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2029; Date = (Get-Date -Date '2029-12-25'); DayOfWeek = ((Get-Date -Date '2029-12-25').DayOfWeek); Name = "Christmas Day"}),

        (New-Object -TypeName PSObject -Property @{Year = 2030; Date = (Get-Date -Date '2030-01-01'); DayOfWeek = ((Get-Date -Date '2030-01-01').DayOfWeek); Name = "New Years"}),
        (New-Object -TypeName PSObject -Property @{Year = 2030; Date = (Get-Date -Date '2030-01-21'); DayOfWeek = ((Get-Date -Date '2030-01-21').DayOfWeek); Name = "Martin Luther King Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2030; Date = (Get-Date -Date '2030-02-18'); DayOfWeek = ((Get-Date -Date '2030-02-18').DayOfWeek); Name = "Washingtons Birthday"}),
        (New-Object -TypeName PSObject -Property @{Year = 2030; Date = (Get-Date -Date '2030-05-27'); DayOfWeek = ((Get-Date -Date '2030-05-27').DayOfWeek); Name = "Memorial Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2030; Date = (Get-Date -Date '2030-06-19'); DayOfWeek = ((Get-Date -Date '2030-06-19').DayOfWeek); Name = "Juneteenth National Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2030; Date = (Get-Date -Date '2030-07-04'); DayOfWeek = ((Get-Date -Date '2030-07-04').DayOfWeek); Name = "Independence Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2030; Date = (Get-Date -Date '2030-09-02'); DayOfWeek = ((Get-Date -Date '2030-09-02').DayOfWeek); Name = "Labor Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2030; Date = (Get-Date -Date '2030-10-14'); DayOfWeek = ((Get-Date -Date '2030-10-14').DayOfWeek); Name = "Columbus Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2030; Date = (Get-Date -Date '2030-11-11'); DayOfWeek = ((Get-Date -Date '2030-11-11').DayOfWeek); Name = "Veterans Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2030; Date = (Get-Date -Date '2030-11-28'); DayOfWeek = ((Get-Date -Date '2030-11-28').DayOfWeek); Name = "Thanksgiving Day"}),
        (New-Object -TypeName PSObject -Property @{Year = 2030; Date = (Get-Date -Date '2030-12-25'); DayOfWeek = ((Get-Date -Date '2030-12-25').DayOfWeek); Name = "Christmas Day"})
    )
    ###########################################################################################################################################
}#new object