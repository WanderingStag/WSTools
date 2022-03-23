Function Get-InstalledProgram {
<#
.SYNOPSIS
    Displays installed programs on a computer.
.DESCRIPTION
    Displays a list of installed programs on a local or remote computer by querying the registry.
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
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
    Keywords:
.LINK
    https://wstools.dev
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

Function Join-File {
<#
    .Notes
    AUTHOR: Skyler Hart
    CREATED: 04/30/2019 14:52:40
    LASTEDIT: 04/30/2019 17:17:50
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter the path of the folder with the part files you want to join.",
            Mandatory=$true,
            Position=0
        )]
        [Alias('Source','InputLocation','SourceFolder')]
        [string]$Path,

        [Parameter(
            Mandatory=$false,
            Position=1
        )]
        [Alias('OutputLocation','Output','DestinationPath','Destination')]
        [string]$DestinationFolder
    )

    $og = (Get-Location).Path
    $objs = Get-ChildItem $Path | Where-Object {$_.Name -like "*_Part*"}
    $myobjs = foreach ($obj in $objs) {
        $ext = $obj.Extension
        $name = $obj.Name
        $num = $name -replace "[\s\S]*.*(_Part)","" -replace $ext,""
        $fn = $obj.FullName
        $dp = $obj.Directory.FullName

        [PSCustomObject]@{
            FullName = $fn
            Name = $name
            Extension = $ext
            Num = [int]$num
            Directory = $dp
        }#new object
    }

    $sobj = $myobjs | Sort-Object Num | Select-Object FullName,Name,Extension,Directory
    $fo = $sobj[0]
    $fon = $fo.Name
    $fon = $fon -replace "_Part01",""
    $fd = $fo.Directory
    if ($DestinationFolder -eq "") {
        $fop = $fd + "\" + $fon
        Set-Location $fd
    }
    else {
        $fop = $DestinationFolder + "\" + $fon
        if (!(Test-Path $DestinationFolder)) {
         New-Item -Path $DestinationFolder -ItemType Directory
        }
        Set-Location $DestinationFolder
    }
    $WriteObj = New-Object System.IO.BinaryWriter([System.IO.File]::Create($fop))

    if ($host.Version.Major -ge 3) {
        $sobj.FullName | ForEach-Object {
            Write-Output "Appending $_ to $fop"
            $ReadObj = New-Object System.IO.BinaryReader([System.IO.File]::Open($_, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read))
            $WriteObj.BaseStream.Position = $WriteObj.BaseStream.Length
            $ReadObj.BaseStream.CopyTo($WriteObj.BaseStream)
            $WriteObj.BaseStream.Flush()
            $ReadObj.Close()
        }
    }
    else {
        [Byte[]]$Buffer = New-Object Byte[] 100MB
        $sobj.FullName | ForEach-Object {
            Write-Output "Appending $_ to $fop"
            $ReadObj = New-Object System.IO.BinaryReader([System.IO.File]::Open($_, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read))
            while ($ReadObj.BaseStream.Position -lt $ReadObj.BaseStream.Length) {
                $ReadBytes = $ReadObj.Read($Buffer, 0, $Buffer.Length)
                $WriteObj.Write($Buffer, 0, $ReadBytes)
            }
            $ReadObj.Close()
        }
    }
    $WriteObj.Close()
    Set-Location $og
}

function Get-NotificationApp {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-07-14 23:42:57
    Last Edit: 2021-07-16 01:57:31
    Keywords:
    Requires:
.LINK
    https://wstools.dev
#>
    $info = @()
    $HKCR = Get-PSDrive -Name HKCR -ErrorAction SilentlyContinue
    if (!($HKCR)) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root Hkey_Classes_Root -Scope Script | Out-Null
    }

    $AppRegPath = "HKCR:\AppUserModelId"
    $apps = Get-ChildItem $AppRegPath | Where-Object {$_.Name -notmatch "Andromeda_cw5n1h2txyewy!App" -and $_.Name -notmatch "Microsoft.Windows.Defender" -and `
        $_.Name -notlike "*Windows.Defender" -and $_.Name -notmatch "DeviceManagementTokenRenewalRequired" -and $_.Name -notmatch "Messaging.SystemAlertNotification" -and `
        $_.Name -notmatch "Windows.SystemToast.Suggested" -and $_.Name -notmatch "Windows.SystemToast.WindowsTip"
    }

    $info = foreach ($app in $apps) {
        $name = $app.Name -replace "HKEY_CLASSES_ROOT\\AppUserModelId\\",""
        $apppath = $AppRegPath + "\" + $name
        $dn = Get-ItemProperty -Path $apppath -Name DisplayName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue

        if ($name -eq 'Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge') {$dn = "Microsoft Edge"}
        elseif ($name -eq 'Microsoft.Office.OUTLOOK.EXE.15') {$dn = "Outlook"}
        #elseif ($name -eq "Microsoft.Office.OUTLOOK.EXE.16") {$dn = "Microsoft.Office.OUTLOOK.EXE.16"}
        elseif ($name -eq "Microsoft.Windows.ControlPanel") {$dn = "Control Panel"}
        elseif ($name -eq "Microsoft.Windows.Explorer") {$dn = "File Explorer"}
        elseif ($name -eq "Microsoft.Windows.InputSwitchToastHandler") {$dn = "Input Switch Notification"}
        elseif ($name -eq "Microsoft.Windows.LanguageComponentsInstaller") {$dn = "Language settings"}
        elseif ($name -eq "Microsoft.Windows.ParentalControls") {$dn = "Microsoft family features"}
        elseif ($name -eq "Windows.ActionCenter.QuietHours") {$dn = "Focus assist"}
        elseif ($name -eq "Windows.Defender.MpUxDlp") {$dn = "Data Loss Prevention"}
        elseif ($name -eq "Windows.Defender.SecurityCenter") {$dn = "Windows Security"}
        elseif ($name -eq "Windows.System.AppInitiatedDownload") {$dn = "Automatic file downloads"}
        elseif ($name -eq "Windows.System.Audio") {$dn = "Volume Warning"}
        elseif ($name -eq "Windows.System.Continuum") {$dn = "Tablet mode"}
        elseif ($name -eq "Windows.System.MiracastReceiver") {$dn = "Connect"}
        elseif ($name -eq "Windows.System.NearShareExperienceReceive") {$dn = "Nearby sharing"}
        elseif ($name -eq "Windows.System.ShareExperience") {$dn = "Nearby sharing"}
        elseif ($name -eq "Windows.SystemToast.AudioTroubleshooter") {$dn = "Audio"}
        elseif ($name -eq "Windows.SystemToast.AutoPlay") {$dn = "AutoPlay"}
        elseif ($name -eq "Windows.SystemToast.BackgroundAccess") {$dn = "Battery saver"}
        elseif ($name -eq "Windows.SystemToast.BackupReminder") {$dn = "Backup settings"}
        elseif ($name -eq "Windows.SystemToast.BdeUnlock") {$dn = "BitLocker Drive Encryption"}
        elseif ($name -eq "Windows.SystemToast.BitLockerPolicyRefresh") {$dn = "Device Encryption"}
        elseif ($name -eq "Windows.SystemToast.Bthprops") {$dn = "Add a device"}
        elseif ($name -eq "Windows.SystemToast.BthQuickPair") {$dn = "Bluetooth"}
        elseif ($name -eq "Windows.SystemToast.Calling") {$dn = "Incoming call"}
        elseif ($name -eq "Windows.SystemToast.Calling.SystemAlertNotification") {$dn = "Alert"}
        elseif ($name -eq "Windows.SystemToast.CloudExperienceHostLauncher") {$dn = "Device Setup"}
        elseif ($name -eq "Windows.SystemToast.CloudExperienceHostLauncherCustom") {$dn = "Device Setup"}
        elseif ($name -eq "Windows.SystemToast.Compat") {$dn = "Compatibility Assistant"}
        #elseif ($name -eq "Windows.SystemToast.DeviceConsent") {$dn = ""}
        elseif ($name -eq "Windows.SystemToast.DeviceEnrollmentActivity") {$dn = "Device Management Enrollment Service"}
        elseif ($name -eq "Windows.SystemToast.DeviceManagement") {$dn = "Work or School Account"}
        elseif ($name -eq "Windows.SystemToast.Devices") {$dn = "Devices"}
        elseif ($name -eq "Windows.SystemToast.DisplaySettings") {$dn = "Display Settings"}
        elseif ($name -eq "Windows.SystemToast.EnterpriseDataProtection") {$dn = "Windows Information Protection"}
        elseif ($name -eq "Windows.SystemToast.Explorer") {$dn = "File Explorer"}
        elseif ($name -eq "Windows.SystemToast.FodHelper") {$dn = "Optional Features"}
        elseif ($name -eq "Windows.SystemToast.HelloFace") {$dn = "Windows Hello"}
        elseif ($name -eq "Windows.SystemToast.LocationManager") {$dn = "Location"}
        elseif ($name -eq "Windows.SystemToast.LowDisk") {$dn = "Storage settings"}
        elseif ($name -eq "Windows.SystemToast.MobilityExperience") {$dn = "Continue from your phone"}
        elseif ($name -eq "Windows.SystemToast.NfpAppAcquire") {$dn = "System Notification"}
        elseif ($name -eq "Windows.SystemToast.NfpAppLaunch") {$dn = "Tap and start"}
        elseif ($name -eq "Windows.SystemToast.NfpDevicePairing") {$dn = "Tap and setup"}
        elseif ($name -eq "Windows.SystemToast.NfpReceiveContent") {$dn = "Tap and send"}
        elseif ($name -eq "Windows.SystemToast.Print.Notification") {$dn = "Print Notification"}
        elseif ($name -eq "Windows.SystemToast.RasToastNotifier") {$dn = "VPN"}
        elseif ($name -eq "Windows.SystemToast.SecurityAndMaintenance") {$dn = "Security and Maintenance"}
        elseif ($name -eq "Windows.SystemToast.SecurityCenter") {$dn = "Security and Maintenance"}
        elseif ($name -eq "Windows.SystemToast.SEManagement") {$dn = "Payment"}
        elseif ($name -eq "Windows.SystemToast.ServiceInitiatedHealing.Notification" ) {$dn = "Service Initiated Healing"}
        elseif ($name -eq "Windows.SystemToast.Share") {$dn = "Share"}
        elseif ($name -eq "Windows.SystemToast.SoftLanding") {$dn = "Tips"}
        elseif ($name -eq "Windows.SystemToast.SpeechServices") {$dn = "Microsoft Speech Recognition"}
        elseif ($name -eq "Windows.SystemToast.StorSvc") {$dn = "Storage settings"}
        elseif ($name -eq "Windows.SystemToast.Usb.Notification") {$dn = "USB"}
        elseif ($name -eq "Windows.SystemToast.WiFiNetworkManager") {$dn = "Wireless"}
        elseif ($name -eq "Windows.SystemToast.WindowsUpdate.Notification") {$dn = "Windows Update"}
        elseif ($name -eq "Windows.SystemToast.Winlogon") {$dn = "Windows logon reminder"}
        elseif ($name -eq "Windows.SystemToast.Wwansvc") {$dn = "Cellular"}
        elseif ([string]::IsNullOrWhiteSpace($dn)) {$dn = "unknown"}

        $zname = $dn + " (" + $name + ")"
        [PSCustomObject]@{
            Name = $name
            DisplayName = $dn
            zName = $zname
        }#new object
    }

    $info
    #Remove-PSDrive -Name HKCR -Force
}

function Send-ToastNotification {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Send-ToastNotification
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Send-ToastNotification -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.NOTES
    Author: Skyler Hart
    Created: 2020-11-08 14:57:29
    Last Edit: 2021-07-16 23:08:42
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the message to send.",
            Mandatory=$true,
            Position=0
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(
            HelpMessage = "Enter the name of the sender.",
            Mandatory=$false,
            Position=1
        )]
        [string]$Sender = "     ",

        [Parameter(
            Mandatory=$false,
            Position=2
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName,

        [Parameter(
            Mandatory=$false
        )]
        [string]$Title,

        [Parameter(Mandatory=$false)]
        [ValidateSet('ms-winsoundevent:Notification.Default',
        'ms-winsoundevent:Notification.IM',
        'ms-winsoundevent:Notification.Mail',
        'ms-winsoundevent:Notification.Reminder',
        'ms-winsoundevent:Notification.SMS',
        'ms-winsoundevent:Notification.Looping.Alarm',
        'ms-winsoundevent:Notification.Looping.Alarm2',
        'ms-winsoundevent:Notification.Looping.Alarm3',
        'ms-winsoundevent:Notification.Looping.Alarm4',
        'ms-winsoundevent:Notification.Looping.Alarm5',
        'ms-winsoundevent:Notification.Looping.Alarm6',
        'ms-winsoundevent:Notification.Looping.Alarm7',
        'ms-winsoundevent:Notification.Looping.Alarm8',
        'ms-winsoundevent:Notification.Looping.Alarm9',
        'ms-winsoundevent:Notification.Looping.Alarm10',
        'ms-winsoundevent:Notification.Looping.Call',
        'ms-winsoundevent:Notification.Looping.Call2',
        'ms-winsoundevent:Notification.Looping.Call3',
        'ms-winsoundevent:Notification.Looping.Call4',
        'ms-winsoundevent:Notification.Looping.Call5',
        'ms-winsoundevent:Notification.Looping.Call6',
        'ms-winsoundevent:Notification.Looping.Call7',
        'ms-winsoundevent:Notification.Looping.Call8',
        'ms-winsoundevent:Notification.Looping.Call9',
        'ms-winsoundevent:Notification.Looping.Call10',
        'Silent')]
        [string]$AudioSource = 'ms-winsoundevent:Notification.Looping.Alarm3',

        [Parameter()]
        [switch]$ShortDuration,

        [Parameter()]
        [switch]$RequireDismiss #overrides ShortDuration
    )
    DynamicParam {
        # Set the dynamic parameters' name. You probably want to change this.
        $ParameterName = 'Notifier'

        # Create the dictionary
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]

        # Create and set the parameters' attributes. You may also want to change these.
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $false
        $ParameterAttribute.Position = 3

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet. You definitely want to change this. This part populates your set.
        $arrSet = ((Get-NotificationApp).Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($arrSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        return $RuntimeParameterDictionary
    }
    Begin {
        $Notifier = $PsBoundParameters[$ParameterName]
        if ([string]::IsNullOrWhiteSpace($Notifier)) {$Notifier = "Windows.SystemToast.SecurityAndMaintenance"}
        if ([string]::IsNullOrWhiteSpace($Title)) {
            $ttext = $null
        }
        else {
            $ttext = "<text>$Title</text>"
        }

        if ($AudioSource -eq 'Silent') {
            $atext = '<audio silent="true"/>'
        }
        else {
            $atext = '<audio src="' + $AudioSource + '"/>'
        }
        if ($RequireDismiss) {
            $scenario = '<toast scenario="reminder">'
            $actions = @"
        <actions>
            <action arguments="dismiss" content="Dismiss" activationType="system"/>
        </actions>
"@
        }
        else {
            if ($ShortDuration) {$dur = "short"}
            else {$dur = "long"}
            $scenario = '<toast duration="' + $dur + '">'
            $actions = $null
        }

        [xml]$ToastTemplate = @"
            $scenario
                <visual>
                <binding template="ToastGeneric">
                    <text>$Sender</text>
                    $ttext
                    <group>
                        <subgroup>
                            <text hint-style="subtitle" hint-wrap="true">$Message</text>
                        </subgroup>
                    </group>
                </binding>
                </visual>
                $actions
                $atext
            </toast>
"@

        [scriptblock]$ToastScript = {
            Param($ToastTemplate)
            #Load required assemblies
            [void][Windows.UI.Notifications.ToastNotification,Windows.UI.Notifications,ContentType=WindowsRuntime]
            [void][Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom,ContentType=WindowsRuntime]

            #Format XML
            $FinalXML = [Windows.Data.Xml.Dom.XmlDocument]::new()
            $FinalXML.LoadXml($ToastTemplate.OuterXml)

            #Create the Toast
            $Toast = [Windows.UI.Notifications.ToastNotification]::new($FinalXML)

            #Show the Toast message
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($Notifier).show($Toast)
        }
    }
    Process {
        if (![string]::IsNullOrEmpty($ComputerName)) {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock $ToastScript -ArgumentList $ToastTemplate #DevSkim: ignore DS104456
        }
        else {Invoke-Command -ScriptBlock $ToastScript -ArgumentList $ToastTemplate} #DevSkim: ignore DS104456
    }
    End {
        #done
    }
}

$cn = $env:COMPUTERNAME
$PatchFolderPath = "C:\Patches"
$cab = $PatchFolderPath + "\cab"
$ip = Get-InstalledProgram | Select-Object ProgramName,Version,Comment
$hf = (Get-HotFix | Select-Object HotFixID).HotFixID
$Reboot = $false
$cimq = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$wmiq = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue

$dn48path = $PatchFolderPath + "\ndp48-x86-x64-allos-enu.exe"

#$7zip = $PatchFolderPath + "\7zip"
$90meter = $PatchFolderPath + "\90Meter"
$activclient = $PatchFolderPath + "\ActivClient"
$acrobat = $PatchFolderPath + "\Acrobat"
$acroupdate = $PatchFolderPath + "\Acrobat_Update"
$aem = $PatchFolderPath + "\AEM"
$anyconnect = $PatchFolderPath + "\JRSS"
$axway = $PatchFolderPath + "\Axway"
$BigIP = $PatchFolderPath + "\VPN"
$chrome = $PatchFolderPath + "\Chrome"
$dset = $PatchFolderPath + "\DSET"
$edge = $PatchFolderPath + "\Edge"
$encase = $PatchFolderPath + "\Encase"
$firefox = $PatchFolderPath + "\firefox"
$java = $PatchFolderPath + "\Java"
$netbanner = $PatchFolderPath + "\NetBanner"
$onedrive = $PatchFolderPath + "\OneDrive"
$project = $PatchFolderPath + "\Project"
$ssms = $PatchFolderPath + "\SSMS"
$tanium = $PatchFolderPath + "\Tanium"
$teams = $PatchFolderPath + "\Teams"
$titus = $PatchFolderPath + "\Titus"
$transverse = $PatchFolderPath + "\Transverse"
$vESD = $PatchFolderPath + "\vESD"
$visio = $PatchFolderPath + "\visio"
$vlc = $PatchFolderPath + "\vlc"
$vscode = $PatchFolderPath + "\VSCode"
$zoom = $PatchFolderPath + "\Zoom"

$datu = Get-ChildItem -Path $PatchFolderPath | Where-Object {$_.Name -like "CM-*xdat.exe"}
$datun = $datu.Count

if (!(Test-Path $cab)) {
    New-Item -Path $PatchFolderPath -Name cab -ItemType Directory
}
else {
    Remove-Item $cab\* -Recurse -Force
}

#If there are part files, join them together
$parts = $null
$parts = (Get-ChildItem $PatchFolderPath | Where-Object {$_.Attributes -eq "Directory" -and $_.Name -match "Part_"} | Select-Object FullName).FullName
if (!([string]::IsNullOrWhiteSpace($parts))) {
    Write-Output "$cn`: Joining part files."
    foreach ($part in $parts) {
        Join-File $part $PatchFolderPath
    }
}

Start-Sleep 2

#Extract CAB files from .MSU files
$msus = Get-ChildItem -Path $PatchFolderPath | Where-Object {$_.Name -match ".msu"}
if ($msus.Length -ge 1) {
    foreach ($msu in $msus) {
        $name = $msu.Name
        $fname = $msu.FullName
        $nn = $name -replace "1_SSU_windows10.0-","" -replace "2_windows10.0-","" -replace "3_net_windows10.0-","" -replace "windows10.0-","" -replace "windows8.1-","" -replace "windows6.1-","" -replace "windows6.0-",""
        $nn = $nn.Substring(0,9)
        if ($hf -match $nn) {
            #do nothing
        }
        else {
            expand.exe -F:* "$fname" $cab | Out-Null
        }
    }
    Start-Sleep 5
}

#Copy Office updates from individual Office folders to cab folder
$ofcs = $null
$ofcs = @()
$ofi = (Get-ChildItem $PatchFolderPath | Where-Object {$_.Attributes -eq "Directory" -and $_.Name -match "Office"} | Select-Object FullName).FullName
if ($ofi.Length -ge 1) {
    foreach ($of in $ofi) {
        $ofcs += (Get-ChildItem $of | Where-Object {$_.Name -like "*.cab"} | Select-Object FullName).FullName
    }
    foreach ($ofc in $ofcs) {
        if (!([string]::IsNullOrWhiteSpace($ofc))) {
            Copy-Item $ofc $cab -Force
        }
    }
}

#Copy .cab files in PatchFolder to cab folder
$ofi2 = (Get-ChildItem $PatchFolderPath | Where-Object {$_.Name -like "*.cab"} | Select-Object FullName).FullName
if ($ofi2.Length -ge 1) {
    foreach ($ofc2 in $ofi2) {
        Copy-Item $ofc2 $cab -Force
    }
}

#Select only certain updates from the cab folder (ignore the extra files that come with Windows updates)
$cabs = Get-ChildItem -Path $cab | Where-Object {$_.Name -like "Windows*.cab" -or $_.Name -like "ace*.cab" -or $_.Name -like "excel*.cab" -or $_.Name -like "mso*.cab" -or $_.Name -like "graph*.cab" -or $_.Name -like "kb*.cab" -or $_.Name -like "outlook*.cab" -or $_.Name -like "powerpoint*.cab" -or $_.Name -like "word*.cab" -or $_.Name -like "access*.cab" -or $_.Name -like "vbe*.cab"}

$n = $cabs.Length
if ($n -gt 0) {
    $i = 0
    foreach ($obj in $cabs) {
        $i++
        $oname = $obj.FullName
        $obname = $obj.Name
        Write-Output "$cn`: Installing $obname. Patch $i of $n."
        dism.exe /online /add-package /PackagePath:$oname /NoRestart | Out-Null
        Start-Sleep 5
    }
    $Reboot = $true
}


if (Test-Path $dn48path) {
    Write-Output "$cn`: Installing .NET Framework 4.8."
    Start-Process $dn48path -ArgumentList "/q /norestart" -NoNewWindow -Wait
    $Reboot = $true
}

#if (Test-Path $7zip) {
#    Write-Output "$cn`: Installing 7zip."
#    $7i = Get-ChildItem $7zip
#    $7p = $7i.FullName[0]
#    Start-Process $7p -ArgumentList "/S" -NoNewWindow -Wait
#    Start-Sleep 120
#}

if ((Test-Path $90meter) -and $env:USERDNSDOMAIN -like "*.smil.mil") {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "90meter"
    $sv = Get-Content $90meter\SoftwareVersion.txt

    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "90meter*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                #$install = $false #uncomment and remove below lines if stopping at Major.Minor
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    $install = $false
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $90meter\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 330
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if ((Test-Path $activclient) -and $env:USERDNSDOMAIN -notlike "*.smil.mil") {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "ActivClient"
    $sv = Get-Content $activclient\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "ActivClien*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ($sv[0] -gt $ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                $install = $false #uncomment and remove below lines if stopping at Major.Minor
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $activclient\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 330
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $acrobat) {
    $sv = $null
    $ipv = $null
    $install = $false
    $update = $false
    $pn = "Acrobat"
    $sv = Get-Content $acrobat\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Adobe Acrobat*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ($sv[0] -gt $ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $false
                $update = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                #$install = $false #uncomment and remove below lines if stopping at Major.Minor
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $false
                    $update = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    $install = $false
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if adobe is installed already
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true -or $update -eq $true) {
        $rn = ((Get-Date).AddSeconds(300))
        if (!($cimq -like "*Server*" -or $wmiq -like "*Server*")) {
            Send-ToastNotification "Adobe Acrobat installation/update will begin in 5 minutes ($rn.) During this process it may close. Please save all open files." -Title "Adobe Acrobat Install"
            Start-Sleep -Seconds 300
        }
        Write-Output "$cn`: Installing $pn."
        if ($install -eq $true) {
            Start-Process $acrobat\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        }
        if ($update -eq $true) {
            Start-Process $acroupdate\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        }
        Start-Sleep 900
        $Reboot = $true
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $aem) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "AEM"
    $sv = Get-Content $aem\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Designe*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                $install = $false
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $aem\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 360
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if ((Test-Path $anyconnect) -and $env:USERDNSDOMAIN -notlike "*.smil.mil") {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "JRSS"
    $sv = Get-Content $anyconnect\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Cisco AnyConnec*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                #$install = $false #uncomment and remove below lines if stopping at Major.Minor
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    $install = $false
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        if ($cimq -like "*Server*" -or $wmiq -like "*Server*") {
            $rn = ((Get-Date).AddSeconds(300))
            Send-ToastNotification "Cisco AnyConnect installation/update will begin in 5 minutes ($rn.) During this process it may close. If you are using it to connect to VPN, your VPN connection will be disconnected. Please wait at least 5 minutes after it starts to reconnect. Please do not log off or shutdown your computer during this process." -Title "Cisco AnyConnect Install"
            Start-Sleep -Seconds 300
        }
        Write-Output "$cn`: Installing $pn."
        Start-Process $anyconnect\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 300
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $axway) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Axway"
    $sv = Get-Content $axway\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Axway*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                $install = $false
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        if (!($cimq -like "*Server*" -or $wmiq -like "*Server*")) {
            $rn = ((Get-Date).AddSeconds(300))
            Send-ToastNotification "Axway installation/update will begin in 5 minutes ($rn.) During this process it may close. You may need to reboot your computer after it finishes installing" -Title "Axway Install"
            Start-Sleep -Seconds 300
        }
        Write-Output "$cn`: Installing $pn."
        Start-Process $axway\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 400
        $Reboot = $true
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if ((Test-Path $BigIP) -and $env:USERDNSDOMAIN -notlike "*.smil.mil") {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "VPN"
    $sv = Get-Content $BigIP\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "BIG-IP Edg*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    if ([int32]$sv[3] -gt [int32]$ipv[3]) {
                        $install = $true
                    }
                    elseif ([int32]$sv[3] -eq [int32]$ipv[3]) {
                        $install = $false
                    }
                    elseif ([int32]$sv[3] -lt [int32]$ipv[3]) {
                        $install = $false
                    }
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $BigIP\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 300
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $chrome) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Chrome"
    $sv = Get-Content $chrome\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Google Chrom*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    if ([int32]$sv[3] -gt [int32]$ipv[3]) {
                        $install = $true
                    }
                    elseif ([int32]$sv[3] -eq [int32]$ipv[3]) {
                        $install = $false
                    }
                    elseif ([int32]$sv[3] -lt [int32]$ipv[3]) {
                        $install = $false
                    }
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        if (!($cimq -like "*Server*" -or $wmiq -like "*Server*")) {
            $rn = ((Get-Date).AddSeconds(300))
            Send-ToastNotification "Google Chrome installation/update will begin in 5 minutes ($rn.) During this process it may close. Please save all open files. It may take up to 10 minutes for Google Chrome to be reinstalled." -Title "Google Chrome Install"
            Start-Sleep -Seconds 300
        }
        Write-Output "$cn`: Installing $pn."
        Start-Process $chrome\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 360
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if ((Test-Path $dset) -and $env:USERDNSDOMAIN -notlike "*.smil.mil") {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "DSET"
    $sv = Get-Content $dset\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "DSET*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                #$install = $false #uncomment and remove below lines if stopping at Major.Minor
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    $install = $false
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $dset\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $edge) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Edge"
    $sv = Get-Content $edge\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Microsoft Edg*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    if ([int32]$sv[3] -gt [int32]$ipv[3]) {
                        $install = $true
                    }
                    elseif ([int32]$sv[3] -eq [int32]$ipv[3]) {
                        $install = $false
                    }
                    elseif ([int32]$sv[3] -lt [int32]$ipv[3]) {
                        $install = $false
                    }
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        if (!($cimq -like "*Server*" -or $wmiq -like "*Server*")) {
            $rn = ((Get-Date).AddSeconds(300))
            Send-ToastNotification "Microsoft Edge installation/update will begin in 5 minutes ($rn.) During this process it may close. Please save all open files. It may take up to 10 minutes to be reinstalled." -Title "Microsoft Edge Install"
            Start-Sleep -Seconds 300
        }
        Write-Output "$cn`: Installing $pn."
        Start-Process msiexec.exe -ArgumentList "/i $edge\MicrosoftEdgeEnterpriseX64.msi /qn /norestart" -NoNewWindow -Wait
        Start-Sleep 360
        $Reboot = $true
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $encase) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Encase"
    $sv = Get-Content $encase\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Encas*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    if ([int32]$sv[3] -gt [int32]$ipv[3]) {
                        $install = $true
                    }
                    elseif ([int32]$sv[3] -eq [int32]$ipv[3]) {
                        $install = $false
                    }
                    elseif ([int32]$sv[3] -lt [int32]$ipv[3]) {
                        $install = $false
                    }
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $encase\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 300
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $firefox) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Firefox"
    $sv = Get-Content $firefox\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Mozilla Firefo*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                #$install = $false #uncomment and remove below lines if stopping at Major.Minor
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    $install = $false
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if installed already
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        if (!($cimq -like "*Server*" -or $wmiq -like "*Server*")) {
            $rn = ((Get-Date).AddSeconds(300))
            Send-ToastNotification "Mozilla Firefox installation/update will begin in 5 minutes ($rn.) During this process it may close. Please save all open files. It may take up to 10 minutes to be reinstalled" -Title "Firefox Install"
            Start-Sleep -Seconds 300
        }
        Write-Output "$cn`: Installing $pn."
        Start-Process $firefox\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 350
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $java) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Java"
    $sv = Get-Content $java\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Java*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    if ([int32]$sv[3] -gt [int32]$ipv[3]) {
                        $install = $true
                    }
                    elseif ([int32]$sv[3] -eq [int32]$ipv[3]) {
                        $install = $false
                    }
                    elseif ([int32]$sv[3] -lt [int32]$ipv[3]) {
                        $install = $false
                    }
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $java\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 360
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $netbanner) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "NetBanner"
    $sv = Get-Content $netbanner\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Microsoft NetBanne*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                #$install = $false #uncomment and remove below lines if stopping at Major.Minor
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    $install = $false
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $netbanner\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 200
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $onedrive) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "OneDrive"
    $sv = Get-Content $onedrive\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Microsoft OneDriv*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                $install = $false
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        if (!($cimq -like "*Server*" -or $wmiq -like "*Server*")) {
            $rn = ((Get-Date).AddSeconds(300))
            Send-ToastNotification "OneDrive installation/update will begin in 5 minutes ($rn.) During this process it may close. You may need to reboot your computer after it finishes installing" -Title "OneDrive Install"
            Start-Sleep -Seconds 300
        }
        Write-Output "$cn`: Installing $pn."
        Start-Process $onedrive\OneDriveSetup.exe -ArgumentList "/AllUsers /Silent" -NoNewWindow -Wait
        Start-Sleep 400
        $Reboot = $true
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $project) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Project"
    $sv = Get-Content $project\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Microsoft Project*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    if ([int32]$sv[3] -gt [int32]$ipv[3]) {
                        $install = $true
                    }
                    elseif ([int32]$sv[3] -eq [int32]$ipv[3]) {
                        $install = $false
                    }
                    elseif ([int32]$sv[3] -lt [int32]$ipv[3]) {
                        $install = $false
                    }
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $project\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 400
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $ssms) {
    Write-Output "$cn`: Installing SQL Server Management Studio."
    $ssmsexec = $ssms + "\SSMS-Setup-ENU.exe"
    Start-Process $ssmsexec -ArgumentList '/Quiet SSMSInstallRoot="C:\Program Files (x86)\Microsoft SQL Server Management Studio 18" DoNotInstallAzureDataStudio=1' -NoNewWindow -Wait
}

if (Test-Path $tanium) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Tanium"
    $sv = Get-Content $tanium\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Tanium*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    if ([int32]$sv[3] -gt [int32]$ipv[3]) {
                        $install = $true
                    }
                    elseif ([int32]$sv[3] -eq [int32]$ipv[3]) {
                        $install = $false
                    }
                    elseif ([int32]$sv[3] -lt [int32]$ipv[3]) {
                        $install = $false
                    }
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $tanium\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 300
        $Reboot = $true
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $teams) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Teams"
    $sv = Get-Content $teams\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Teams Mac*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                #$install = $false #uncomment and remove below lines if stopping at Major.Minor
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    #$install = $false #uncomment and remove below lines if stopping at Major.Minor.Patch/Revision
                    if ([int32]$sv[3] -gt [int32]$ipv[3]) {
                        $install = $true
                    }
                    elseif ([int32]$sv[3] -eq [int32]$ipv[3]) {
                        $install = $false #stopping at Major.Minor.Build.Revision
                    }
                    elseif ([int32]$sv[3] -lt [int32]$ipv[3]) {
                        $install = $false
                    }
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        if (!($cimq -like "*Server*" -or $wmiq -like "*Server*")) {
            $rn = ((Get-Date).AddSeconds(300))
            Send-ToastNotification "Microsoft Teams installation/update will begin in 5 minutes ($rn.) During this process it may close. Please save all open files. If after 10 minutes it appears to be uninstalled, please log off then log back in" -Title "Microsoft Teams Install"
            Start-Sleep -Seconds 300
        }
        Write-Output "$cn`: Installing $pn."
        Start-Process $teams\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if ((Test-Path $titus) -and $env:USERDNSDOMAIN -like "*.smil.mil") {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Titus"
    $sv = Get-Content $titus\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Titus*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    if ([int32]$sv[3] -gt [int32]$ipv[3]) {
                        $install = $true
                    }
                    elseif ([int32]$sv[3] -eq [int32]$ipv[3]) {
                        $install = $false
                    }
                    elseif ([int32]$sv[3] -lt [int32]$ipv[3]) {
                        $install = $false
                    }
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $titus\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 300
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $transverse) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Transverse"
    $sv = Get-Content $transverse\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "*Transverse*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    if ([int32]$sv[3] -gt [int32]$ipv[3]) {
                        $install = $true
                    }
                    elseif ([int32]$sv[3] -eq [int32]$ipv[3]) {
                        $install = $false
                    }
                    elseif ([int32]$sv[3] -lt [int32]$ipv[3]) {
                        $install = $false
                    }
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $transverse\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 360
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $vESD) {
    $vv = $null
    $vv = Get-Content $vESD\SoftwareVersion.txt
    $ipvv = ($ip | Where-Object {$_.ProgramName -like "USAF vES*"} | Select-Object Version)[0].Version
    if ($vv -match $ipvv) {
        #do nothing Write-Output "$cn`: vESD in patches folder same as installed version. Skipping install..."
    }
    else {
        Write-Output "$cn`: Installing vESD."
        $installer = Get-ChildItem $vESD | Where-Object {$_.Name -like "*.msi"} | Select-Object Name -ExpandProperty Name -Last 1
        $inp = $vESD + "\" + $installer
        $iargs = $inp + " /quiet /norestart"
        Start-Process "c:\Windows\System32\msiexec.exe" -ArgumentList $iargs -NoNewWindow -Wait
        Start-Sleep 300
    }
}

if (Test-Path $visio) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Visio"
    $sv = Get-Content $visio\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Microsoft Visi*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    if ([int32]$sv[3] -gt [int32]$ipv[3]) {
                        $install = $true
                    }
                    elseif ([int32]$sv[3] -eq [int32]$ipv[3]) {
                        $install = $false
                    }
                    elseif ([int32]$sv[3] -lt [int32]$ipv[3]) {
                        $install = $false
                    }
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $visio\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 400
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $vlc) {
    Write-Output "$cn`: Installing VLC."
    $vi = Get-ChildItem $vlc
    $vp = $vi.FullName[0]
    Start-Process $vp -ArgumentList "/L=1033 /S" -NoNewWindow -Wait
    Start-Sleep 120
}

if (Test-Path $vscode) {
    $vsp = "$vscode\VSCodeSetup-x64.exe"
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Teams"
    $sv = Get-Content $vscode\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Microsoft Visual Studio Cod*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                #$install = $false #uncomment and remove below lines if stopping at Major.Minor
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    $install = $false
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        if (!($cimq -like "*Server*" -or $wmiq -like "*Server*")) {
            $rn = ((Get-Date).AddSeconds(300))
            Send-ToastNotification "Visual Studio Code installation/update will begin in 5 minutes ($rn.) During this process it may close. Please save all open files. If after 10 minutes it appears to be uninstalled, please log off then log back in" -Title "Visual Studio Code Install"
            Start-Sleep -Seconds 300
        }
        Write-Output "$cn`: Installing $pn."
        Start-Process $vsp -ArgumentList "/SP- /VERYSILENT /SUPPRESSMSGBOXES /NOCANCEL /NORESTART /CLOSEAPPLICATIONS /NORESTARTAPPLICATIONS /TYPE=full" -NoNewWindow -Wait
        Start-Sleep 300
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $zoom) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Zoom"
    $sv = Get-Content $zoom\SoftwareVersion.txt
    try {
        $ipv = ($ip | Where-Object {$_.ProgramName -like "Zoom*"} -ErrorAction Stop | Select-Object Version)[0].Version

        if (!([string]::IsNullOrWhiteSpace($ipv))) {
            $ipv = $ipv.Split('.')
            $ipv = $ipv.Split(' ')
        }
        else {$install -eq $true}
        $sv = $sv.Split('.')
        $sv = $sv.Split(' ')
    }#try
    catch {
        $install = $true
    }

    #Determine if need to install
    if ($install -eq $false -and (!([string]::IsNullOrWhiteSpace($ipv)))) {
        if ([int32]$sv[0] -gt [int32]$ipv[0]) {
            $install = $true
        }
        elseif ([int32]$sv[0] -eq [int32]$ipv[0]) {
            if ([int32]$sv[1] -gt [int32]$ipv[1]) {
                $install = $true
            }
            elseif ([int32]$sv[1] -eq [int32]$ipv[1]) {
                #$install = $false #uncomment and remove below lines if stopping at Major.Minor
                if ([int32]$sv[2] -gt [int32]$ipv[2]) {
                    $install = $true
                }
                elseif ([int32]$sv[2] -eq [int32]$ipv[2]) {
                    $install = $false
                }
                elseif ([int32]$sv[2] -lt [int32]$ipv[2]) {
                    $install = $false
                }
            }
            elseif ([int32]$sv[1] -lt [int32]$ipv[1]) {
                $install = $false
            }
        }
        elseif ([int32]$sv[0] -lt [int32]$ipv[0]) {
            $install = $false
        }
    }#if already installed
    else {
        $install = $true
    }

    #Install or not
    if ($install -eq $true) {
        if (!($cimq -like "*Server*" -or $wmiq -like "*Server*")) {
            $rn = ((Get-Date).AddSeconds(300))
            Send-ToastNotification "Zoom client installation/update will begin in 5 minutes ($rn.) During this process it may close. Please save all open files. If after 10 minutes it appears to be uninstalled, please log off then log back in" -Title "Zoom Install"
            Start-Sleep -Seconds 300
        }
        Write-Output "$cn`: Installing $pn."
        Start-Process msiexec.exe -ArgumentList "$zoom\ZoomInstallerFull.msi /quiet /norestart" -NoNewWindow -Wait
        Start-Sleep 150
    }
    else {
        #do nothing Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}


if ($datun -ge 1) {
    Write-Output "$cn`: Installing McAfee DAT update."
    foreach ($dat in $datu) {
        Start-Process $dat -ArgumentList "/silent" -NoNewWindow -Wait
    }
}

#####################################
#                                   #
#           Reboot Check            #
#                                   #
#####################################
if ($cimq -like "*Server*" -or $wmiq -like "*Server*") {
    $Reboot = $false
}
if ($Reboot -eq $true) {
    [string]$Time = "0100"
    $hr = $Time.Substring(0,2)
    $mm = $Time.Substring(2)
    $d = 0
    $info = Get-Date
    if ($hr -lt ($info.Hour)) {
        $d = 1
    }
    else {
        if ($mm -le ($info.Minute)) {
            $d = 1
        }
    }
    Send-ToastNotification "Your computer had Windows updates and/or programs installed that require a reboot. Your computer will reboot at 0100." -Title "Reboot Required"
    Start-Sleep -Seconds 30
    shutdown -r -t ([decimal]::round(((Get-Date).AddDays($d).Date.AddHours($hr).AddMinutes($mm) - (Get-Date)).TotalSeconds))
}