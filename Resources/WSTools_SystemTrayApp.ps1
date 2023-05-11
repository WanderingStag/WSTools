Import-Module WSTools
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

# Declare assemblies
Add-Type -AssemblyName PresentationFramework -IgnoreWarnings
[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')    | out-null
[System.Reflection.Assembly]::LoadWithPartialName('presentationframework')   | out-null
[System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')    | out-null
[System.Reflection.Assembly]::LoadWithPartialName('WindowsFormsIntegration') | out-null
[System.Reflection.Assembly]::LoadWithPartialName('System.Xml') | out-null

#Left click on sys tray icon to display this GUI. Right click will show menu.
[xml]$xaml =
@"
<Window
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        WindowStyle="None"
        Height="300"
        Width="200"
        ResizeMode="NoResize"
        ShowInTaskbar="False"
        AllowsTransparency="True"
        Background="Transparent">

    <Border BorderBrush="Transparent" BorderThickness="1" Margin="10,10,10,10">
        <TabControl>
            <TabItem Header="Admin Tools">
                <Grid Background="#FFE5E5E5"/>
            </TabItem>
            <TabItem Header="Sites">
                <Grid Background="#FFE5E5E5"/>
            </TabItem>
            <TabItem Header="VS Code">
                <Grid Background="#FFE5E5E5">
                    <StackPanel HorizontalAlignment="Left" Height="209" Margin="10,10,0,0" VerticalAlignment="Top" Width="151">
                        <Button x:Name="VSCode_ButtonCopySettings" Content="Copy settings to profile"/>
                    </StackPanel>
                </Grid>
            </TabItem>
            <TabItem Header="WSTools">
                <Grid Background="#FFE5E5E5"/>
            </TabItem>
        </TabControl>
    </Border>
</Window>
"@

# GUI to load
$window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))

# XML Declare controls here
$WSRestart = $window.findname("WSRestart")
$WSRestart.Content = "Restart"
$WSExit = $window.findname("WSExit")
$WSExit.Content = "Exit"

# Add an icon to the systray button
$iconBase64      = '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'
$iconBytes       = [Convert]::FromBase64String($iconBase64)
$stream          = New-Object IO.MemoryStream($iconBytes, 0, $iconBytes.Length)
$stream.Write($iconBytes, 0, $iconBytes.Length);
#$iconImage       = [System.Drawing.Image]::FromStream($stream, $true)
$icon       = [System.Drawing.Icon]::FromHandle((New-Object System.Drawing.Bitmap -Argument $stream).GetHIcon())

#$if = "$PSScriptRoot\WSTools.ico"
#$icon = [System.Drawing.Icon]::ExtractAssociatedIcon($if)

# Create object for the systray
$Systray_Tool_Icon = New-Object System.Windows.Forms.NotifyIcon
# Text displayed when you pass the mouse over the systray icon
$Systray_Tool_Icon.Text = "WSTools"
# Systray icon
$Systray_Tool_Icon.Icon = $icon
$Systray_Tool_Icon.Visible = $true

# Admin Tools menu item displayed in the Context menu
$MenuAdmin = New-Object System.Windows.Forms.MenuItem
$MenuAdmin.Text = "Admin Tools"

    #If ADSI Edit installed
    if ((Test-Path "$env:windir\System32\adsiedit.dll") -or (Test-Path "$env:windir\SysWOW64\adsiedit.dll")) {
        $MenuAdmin_ADSI = $MenuAdmin.MenuItems.Add("ADSI")
        $MenuAdmin_ADSI.Add_Click({
            Open-ADSIEdit
        })
    }

    #If AD Sites and Services installed
    if ((Test-Path "$env:windir\System32\dssite.msc") -or (Test-Path "$env:windir\SysWOW64\dssite.msc")) {
        $MenuAdmin_ADSites = $MenuAdmin.MenuItems.Add("AD Sites and Services")
        $MenuAdmin_ADSites.Add_Click({
            dssite.msc
        })
    }

    #If AD Users and Computers installed
    if ((Test-Path "$env:windir\System32\dsa.msc") -or (Test-Path "$env:windir\SysWOW64\dsa.msc")) {
        $MenuAdmin_ADUC = $MenuAdmin.MenuItems.Add("AD Users and Computers")
        $MenuAdmin_ADUC.Add_Click({
            dsa.msc
        })
    }

    #Computer Management
    $MenuAdmin_compmgmt = $MenuAdmin.MenuItems.Add("Computer Management")
    $MenuAdmin_compmgmt.Add_Click({
        compmgmt.msc
    })

    #If DHCP installed
    if ((Test-Path "$env:windir\System32\dhcpmgmt.msc") -or (Test-Path "$env:windir\SysWOW64\dhcpmgmt.msc")) {
        $MenuAdmin_DHCP = $MenuAdmin.MenuItems.Add("DHCP")
        $MenuAdmin_DHCP.Add_Click({
            dhcpmgmt.msc
        })
    }

    #Disc Management
    $MenuAdmin_diskmgmt = $MenuAdmin.MenuItems.Add("Disk Management")
    $MenuAdmin_diskmgmt.Add_Click({
        diskmgmt.msc
    })

    #If DNS installed
    if ((Test-Path "$env:windir\System32\dnsmgmt.msc") -or (Test-Path "$env:windir\SysWOW64\dnsmgmt.msc")) {
        $MenuAdmin_DNS = $MenuAdmin.MenuItems.Add("DNS")
        $MenuAdmin_DNS.Add_Click({
            dnsmgmt.msc
        })
    }

    #If GPO Mgmt installed
    if ((Test-Path "$env:windir\System32\gpmc.msc") -or (Test-Path "$env:windir\SysWOW64\gpmc.msc")) {
        $MenuAdmin_GPMC = $MenuAdmin.MenuItems.Add("Group Policy Management")
        $MenuAdmin_GPMC.Add_Click({
            gpmc.msc
        })
    }

    #If Local Admin Password Solution console installed
    if (Test-Path "$env:ProgramFiles\LAPS\AdmPwd.UI") {
        $MenuAdmin_LAPS = $MenuAdmin.MenuItems.Add("LAPS console")
        $MenuAdmin_LAPS.Add_Click({
            Start-Process 'C:\Program Files\LAPS\AdmPwd.UI'
        })
    }

    #Local Policy Editor
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $MenuAdmin_LPolicy = $MenuAdmin.MenuItems.Add("Local Policy Editor")
        $MenuAdmin_LPolicy.Add_Click({
            gpedit.msc
        })
    }


# Sites menu item displayed in the Context menu
$MenuSites = New-Object System.Windows.Forms.MenuItem
$MenuSites.Text = "Sites"

    #If CM Library config item not blank
    if (!([string]::IsNullOrWhiteSpace(($Global:WSToolsConfig).CMLibrary))) {
        $MenuSites_CMLibrary = $MenuSites.MenuItems.Add("CM Library")
        $MenuSites_CMLibrary.Add_Click({
            Open-CMLibrary
        })
    }

    #If Exchange Admin Console config item not blank
    if (!([string]::IsNullOrWhiteSpace(($Global:WSToolsConfig).EAC))) {
        $MenuSites_EAC = $MenuSites.MenuItems.Add("Exchange Admin Console")
        $MenuSites_EAC.Add_Click({
            Open-EAC
        })
    }

    #If HomeAssistant config item not blank
    if (!([string]::IsNullOrWhiteSpace(($Global:WSToolsConfig).HomeAssistant))) {
        $MenuSites_HomeAssistant = $MenuSites.MenuItems.Add("Home Assistant")
        $MenuSites_HomeAssistant.Add_Click({
            Open-HomeAssistant
        })
    }

    #If iLO config item not blank
    if (!([string]::IsNullOrWhiteSpace(($Global:WSToolsConfig).iLO))) {
        $MenuSites_iLO = $MenuSites.MenuItems.Add("iLO")
        $MenuSites_iLO.Add_Click({
            Open-iLO
        })
    }

    #If LMC config item not blank (aka LexmarkManagementConsole) and print release
    if (!([string]::IsNullOrWhiteSpace(($Global:WSToolsConfig).LMC))) {
        $MenuSites_LMC = $MenuSites.MenuItems.Add("Lexmark Management Console")
        $MenuSites_LMC.Add_Click({
            Open-LexmarkManagementConsole
        })
    }
    if (!([string]::IsNullOrWhiteSpace(($Global:WSToolsConfig).PrintRelease))) {
        $MenuSites_PrintRelease = $MenuSites.MenuItems.Add("Lexmark Print Release")
        $MenuSites_PrintRelease.Add_Click({
            Open-PrintRelease
        })
    }

    #If Remedy config item not blank
    if (!([string]::IsNullOrWhiteSpace(($Global:WSToolsConfig).Remedy))) {
        $MenuSites_EITSM = $MenuSites.MenuItems.Add("EITSM")
        $MenuSites_EITSM.Add_Click({
            Open-EITSM
        })
    }

    #If SDNManagement config item not blank
    if (!([string]::IsNullOrWhiteSpace(($Global:WSToolsConfig).SDNMgmt))) {
        $MenuSites_SDNMgmt = $MenuSites.MenuItems.Add("SDN Management")
        $MenuSites_SDNMgmt.Add_Click({
            Open-SDNMgmt
        })
    }

    #If vCenter config item not blank
    if (!([string]::IsNullOrWhiteSpace(($Global:WSToolsConfig).vCenter))) {
        $MenuSites_vCenter = $MenuSites.MenuItems.Add("vCenter")
        $MenuSites_vCenter.Add_Click({
            Open-vCenter
        })
    }

#Visual Studio Code menu
if (Test-Path "$env:ProgramFiles\Microsoft VS Code\Code.exe") {
    $vsci = $true
    $MenuVSCode = New-Object System.Windows.Forms.MenuItem
    $MenuVSCode.Text = "VS Code"

    if (!([string]::IsNullOrWhiteSpace(($Global:WSToolsConfig).VSCodeSettingsPath))) {
        $MenuVSCode_VSCCSettings = $MenuVSCode.MenuItems.Add("Copy settings to profile")
        $MenuVSCode_VSCCSettings.Add_Click({
            Copy-VSCodeSettingsToProfile
        })
    }

    $MenuVSCode_VSCSnippets = $MenuVSCode.MenuItems.Add("Copy PS snippets to profile")
    $MenuVSCode_VSCSnippets.Add_Click({
        Copy-PowerShellJSON
    })

    $MenuVSCode_VSCESettings = $MenuVSCode.MenuItems.Add("Edit settings")
    $MenuVSCode_VSCESettings.Add_Click({
        code "$env:APPDATA\Code\User\settings.json"
    })

    if (!([string]::IsNullOrWhiteSpace(($Global:WSToolsConfig).VSCodeExtRepo))) {
        $MenuVSCode_VSCExtensions = $MenuVSCode.MenuItems.Add("Update extensions from share")
        $MenuVSCode_VSCExtensions.Add_Click({
            Copy-VSCodeExtensions
        })
    }
}
else {
    $vsci = $false
}

# WSTools menu displayed in the Context menu
$MenuWSTools = New-Object System.Windows.Forms.MenuItem
$MenuWSTools.Text = "WSTools"

    #About
    $MenuWSTools_About = $MenuWSTools.MenuItems.Add("About")
    $MenuWSTools_About.Add_Click({
        $i = Get-WSToolsVersion
        $version = $i.WSToolsVersion.ToString()
        $mdate = $i.Date
        [System.Windows.Forms.MessageBox]::Show("Version: $version`rDate: $mdate")
    })

    #Set preferences
    $MenuWSTools_Preferences = $MenuWSTools.MenuItems.Add("Set preferences")
    $MenuWSTools_Preferences.Add_Click({
        Set-Preferences
    })

    #Set Remediation Values
    $MenuWSTools_Remediation = $MenuWSTools.MenuItems.Add("Set remediation values (admin)")
    $MenuWSTools_Remediation.Add_Click({
        Start-Process powershell.exe -ArgumentList {Set-RemediationValues} -Verb RunAs
    })

    #Server config - only if a DC or Server
    $pt = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object ProductType -ExpandProperty ProductType
    if ('2','3' -contains $pt) {
        $MenuWSTools_ServerConfig = $MenuWSTools.MenuItems.Add("Set server config (admin)")
        $MenuWSTools_ServerConfig.Add_Click({
            Start-Process powershell.exe -ArgumentList {Set-ServerConfig} -Verb RunAs
        })
    }

    #Stop app services
    if (!([string]::IsNullOrWhiteSpace(($Global:WSToolsConfig).AppNames))) {
        $MenuWSTools_StopApps = $MenuWSTools.MenuItems.Add("Stop app services")
        $MenuWSTools_StopApps.Add_Click({
            Stop-AppService
        })
    }

    #Update Visio
    if ((Test-Path ([System.Environment]::GetFolderPath("MyDocuments") + "\My Shapes")) -and (!([string]::IsNullOrWhiteSpace(($Global:WSToolsConfig).Stencils)))) {
        $MenuWSTools_VisioSt = $MenuWSTools.MenuItems.Add("Visio - Update Stencils from share")
        $MenuWSTools_VisioSt.Add_Click({
            Update-VisioStencils
        })
    }

# Restart menu item in the Context menu - This will kill the systray tool and launched it again in 10 seconds
$Menu_Restart_Tool = New-Object System.Windows.Forms.MenuItem
$Menu_Restart_Tool.Text = "Restart GUI"

# Exit menu item in the Context menu - This will close the systray tool
$Menu_Exit = New-Object System.Windows.Forms.MenuItem
$Menu_Exit.Text = "Close"

# Create the context menu for all base menus above
$contextmenu = New-Object System.Windows.Forms.ContextMenu
$Systray_Tool_Icon.ContextMenu = $contextmenu
$Systray_Tool_Icon.contextMenu.MenuItems.AddRange($MenuAdmin)
$Systray_Tool_Icon.contextMenu.MenuItems.AddRange($MenuSites)
if ($vsci) {$Systray_Tool_Icon.contextMenu.MenuItems.AddRange($MenuVSCode)}
$Systray_Tool_Icon.contextMenu.MenuItems.AddRange($MenuWSTools)
#$Systray_Tool_Icon.contextMenu.MenuItems.AddRange($Menu_Restart_Tool)
$Systray_Tool_Icon.contextMenu.MenuItems.AddRange($Menu_Exit)


# Action after clicking on the systray icon - This will display the GUI mentioned above
#$Systray_Tool_Icon.Add_Click({
#    If ($_.Button -eq [Windows.Forms.MouseButtons]::Left) {
#        $window.Left = $([System.Windows.SystemParameters]::WorkArea.Width-$window.Width)
#        $window.Top = $([System.Windows.SystemParameters]::WorkArea.Height-$window.Height)
#        $window.Show()
#        $window.Activate()
#    }
#})


# When Restart the tool is clicked, close everything and kill the PowerShell process then open again the tool
$Menu_Restart_Tool.add_Click({
    Start-Process powershell.exe -ArgumentList "`$host.ui.RawUI.WindowTitle = 'WSTools Taskbar App'; D:\OneDrive\Projects\Scripting\NeedToWorkOn\WSTools_GUI.ps1"

    $Systray_Tool_Icon.Visible = $false
    $window.Close()
    # $window_Config.Close()
    Stop-Process $pid

    $Global:Timer_Status = $timer.Enabled
    If ($Timer_Status -eq $true) {
    $timer.Stop()
    }
})
$WSRestart.add_Click({
    Start-Process powershell.exe -ArgumentList "`$host.ui.RawUI.WindowTitle = 'WSTools Taskbar App'; D:\OneDrive\Projects\Scripting\NeedToWorkOn\WSTools_GUI.ps1"

    $Systray_Tool_Icon.Visible = $false
    $window.Close()
    # $window_Config.Close()
    Stop-Process $pid

    $Global:Timer_Status = $timer.Enabled
    If ($Timer_Status -eq $true) {
    $timer.Stop()
    }
})

# When Exit is clicked, close everything and kill the PowerShell process
$Menu_Exit.add_Click({
    $Systray_Tool_Icon.Visible = $false
    $window.Close()
    # $window_Config.Close()
    Stop-Process $pid

    $Global:Timer_Status = $timer.Enabled
    If ($Timer_Status -eq $true) {
        $timer.Stop()
    }
})
$WSExit.add_Click({
    $Systray_Tool_Icon.Visible = $false
    $window.Close()
    # $window_Config.Close()
    Stop-Process $pid

    $Global:Timer_Status = $timer.Enabled
    If ($Timer_Status -eq $true) {
        $timer.Stop()
    }
})

# Make PowerShell Disappear
$windowcode = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
$asyncwindow = Add-Type -MemberDefinition $windowcode -name Win32ShowWindowAsync -namespace Win32Functions -PassThru
$null = $asyncwindow::ShowWindowAsync((Get-Process -PID $pid).MainWindowHandle, 0)

# Force garbage collection just to start slightly lower RAM usage.
[System.GC]::Collect()

# Create an application context for it to all run within.
# This helps with responsiveness, especially when clicking Exit.
$appContext = New-Object System.Windows.Forms.ApplicationContext
[void][System.Windows.Forms.Application]::Run($appContext)