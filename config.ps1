[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    "PSAvoidGlobalVars",
    "",
    Justification = "Have tried other methods and they do not work consistently."
)]

$Global:WSToolsConfig = New-Object -TypeName PSObject -Property @{
    # WSTools config v1.2.1
    # Remove the # symbol infront of a line to enable it
    ###########################################################################################################################################
    #Ignore list. Used in several functions. Computers, users, and groups to ignore that cause issues. Objects such as clustered object computer names, non-windows systems, and other such things. Uses -match in some places and -eq in others so be as precise as possible.
    #Ignore = @('comp1','comp2','user1','user2','group1','group2')

    #Privileged groups list - used for some monitoring and reporting features. You should populate this with groups that grant admin permissions.
    #PrivGroups = @('group1','group2')

    #Default time of reboot when no time is specified in Set-Reboot. Must be entered in HHmm (24 hour/military time) format. Ex: For 7 PM enter 1900.
    RebootTime = "0030"

    #Script Repository. Can be local or network. If network it needs to be the UNC.
    ScriptRepo = "D:\OneDrive\Scripts"

    #Script Working Directory. Some functions use this directory to pull/save files from/to by default.
    ScriptWD = "C:\Scripts"

    #Default time of shutdown when no time is specified in Set-Shutdown. Must be entered in HHmm (24 hour/military time) format. Ex: For 7 PM enter 1900.
    ShutdownTime = "0040"

    #Update computer. Used when you have a computer you modify the module on then push it out to the update path from that computers local repository (hardcoded to $env:ProgramFiles\WindowsPowerShell\Modules\WSTools).
    UpdateComp = "snib1" #do not use the fqdn, only the shortname

    #Path to where module files are stored on a central server. Used in Install-WSTools (aka Copy-WSTools) and Update-WSTools
    UpdatePath = "J:\PowerShell\Modules\WSTools"

    #Additional paths is used for pushing out to folders in addtion to UpdatePath.
    AdditionalUpdatePaths = @('D:\OneDrive\Scripts\Modules\WSTools')


    ################################
    ##    App/Patching settings   ##
    ################################
    #Location on network where you store applications
    AppRepo = "J:\"

    #Local Patches folder on machines - this does not change the copy and install functions under WS_Remediation. They will still try to copy to C:\Patches on the remote machine.
    LocalPatches = "C:\Patches"

    #Network Patch Repository
    PatchRepo = "J:\Patches"

    #Visio Stencil Path
    Stencils = "J:\Microsoft\VisioStencils"

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
    a7Zip = "J:\Tools\7zip" #64-bit only unless you change Copy-7Zip to use 32-bit
    Edge = "J:\Patches\Edge"
    Git = "J:\Patches\GitSCM"
    IE11 = "J:\Patches\IE\IE11"
    SysInternals = "J:\Tools\SysinternalsSuite"
    VSCode = "J:\Patches\VisualStudioCode"
    VLC = "J:\Tools\VLC"
    Wireshark = "J:\Tools\Wireshark"
    WMF3 = "J:\Microsoft\Windows Management Framework 3.0"
    WMF4 = "J:\Microsoft\Windows Management Framework 4.0"
    WMF5 = "J:\Microsoft\Windows Management Framework 5.1"

    #Install file locations that use the PowerShell App Deployment Toolkit from https://psappdeploytoolkit.com/
    a90Meter = "J:\Patches\SDC-APPS\90Meter"
    ActivClient = "J:\Patches\SDC-APPS\ActivClient"
    Acrobat = "J:\Patches\SDC-APPS\Adobe\Acrobat NIPR"
    AEM = "J:\Patches\SDC-APPS\Adobe\AEM_FormsDesigner"
    AxwayServer = "J:\Patches\SDC-APPS\Axway\DSCC"
    AxwayClient = "J:\Patches\SDC-APPS\Axway\NIPR"
    Chrome = "J:\Patches\SDC-APPS\Chrome"
    DSET = "J:\Patches\SDC-APPS\DSET"
    Encase = "J:\Patches\SDC-APPS\Encase\NIPR"
    Firefox = "J:\Patches\SDC-APPS\Firefox"
    InfoPath = "J:\Patches\SDC-APPS\InfoPath"
    Java = "J:\Patches\SDC-APPS\Java\NIPR"
    JRSS = "J:\Patches\SDC-APPS\JRSS"
    NetBanner = "J:\Patches\SDC-APPS\NetBanner"
    Office2016 = "J:\Patches\SDC-APPS\Office2016"
    Silverlight = "J:\Patches\SDC-APPS\Silverlight"
    Tanium = "J:\Patches\SDC-APPS\Tanium\NIPR"
    Teams = "J:\Patches\SDC-APPS\Teams"
    Titus = "J:\Patches\SDC-APPS\Titus"
    TransVerse = "J:\Patches\SDC-APPS\TransVerse"
    VPN = "J:\Patches\SDC-APPS\VPN"

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
    TLS1_1ServerEnabled = 1 #DevSkim: ignore DS440000

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
    ###########################################################################################################################################
}#new object