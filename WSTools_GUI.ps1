# Part used for the restart button
Param
 (
 [String]$Restart
 )
 
If ($Restart -ne "") 
 {
  sleep 10
 }
  
# Declare assemblies 
[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')    | out-null
[System.Reflection.Assembly]::LoadWithPartialName('presentationframework')   | out-null
[System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')    | out-null
[System.Reflection.Assembly]::LoadWithPartialName('WindowsFormsIntegration') | out-null
 
# Example of GUI to display
[xml]$xaml =  
@"
<Window
xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
WindowStyle="None"
Height="600"
Width="400"
ResizeMode="NoResize"
ShowInTaskbar="False"
AllowsTransparency="True"
Background="Transparent"
>
<border  BorderBrush="Black" BorderThickness="1" Margin="10,10,10,10">
 
<grid Name="grid" Background="White">
 <stackpanel HorizontalAlignment="Center" VerticalAlignment="Center">
  <button Name="MyButton" Width="80" Height="20"></button>
 </StackPanel>  
</Grid> 
</Border>
</Window>
"@
 
# GUI to load
$window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
# Declare controls here
$MyButton = $window.findname("MyButton") 
$MyButton.Content = "Button 1"
 
# Add an icon to the systrauy button
$if = "$PSScriptRoot\WSTools.ico"
$icon = [System.Drawing.Icon]::ExtractAssociatedIcon($if)
Start-Sleep 15

# Create object for the systray 
$Systray_Tool_Icon = New-Object System.Windows.Forms.NotifyIcon
# Text displayed when you pass the mouse over the systray icon
$Systray_Tool_Icon.Text = "WSTools"
# Systray icon
$Systray_Tool_Icon.Icon = $icon
$Systray_Tool_Icon.Visible = $true
 
# First menu displayed in the Context menu
$Menu1 = New-Object System.Windows.Forms.MenuItem
$Menu1.Text = "Menu 1"
 
# Second menu displayed in the Context menu
$Menu2 = New-Object System.Windows.Forms.MenuItem
$Menu2.Text = "Menu 2"
 
# Third menu displayed in the Context menu - This will restart kill the systray tool and launched it again in 10 seconds
$Menu_Restart_Tool = New-Object System.Windows.Forms.MenuItem
$Menu_Restart_Tool.Text = "Restart the tool"
 
# Fourth menu displayed in the Context menu - This will close the systray tool
$Menu_Exit = New-Object System.Windows.Forms.MenuItem
$Menu_Exit.Text = "Exit"
 
# Create the context menu for all menus above
$contextmenu = New-Object System.Windows.Forms.ContextMenu
$Systray_Tool_Icon.ContextMenu = $contextmenu
$Systray_Tool_Icon.contextMenu.MenuItems.AddRange($Menu1)
$Systray_Tool_Icon.contextMenu.MenuItems.AddRange($Menu2)
$Systray_Tool_Icon.contextMenu.MenuItems.AddRange($Menu_Restart_Tool)
$Systray_Tool_Icon.contextMenu.MenuItems.AddRange($Menu_Exit)
 
# Create submenu for the menu 1
$Menu1_SubMenu1 = $Menu1.MenuItems.Add("Menu 1 - Submenu 1")
$Menu1_SubMenu2 = $Menu1.MenuItems.Add("Menu 1 - Submenu 2")
 
# Create submenu for the menu 2
$Menu2_SubMenu1 = $Menu2.MenuItems.Add("Menu 2 - Submenu 1")
$Menu2_SubMenu2 = $Menu2.MenuItems.Add("Menu 2 - Submenu 2")
 
 
 
 
# Action after clicking on the systray icon - This will display the GUI mentioned above
$Systray_Tool_Icon.Add_Click({
 If ($_.Button -eq [Windows.Forms.MouseButtons]::Left) {
  $window.Left = $([System.Windows.SystemParameters]::WorkArea.Width-$window.Width)
  $window.Top = $([System.Windows.SystemParameters]::WorkArea.Height-$window.Height)
  $window.Show()
  $window.Activate() 
 }  
})
 
 
# Action after clicking on the Menu 1 - Submenu 1
$Menu1_SubMenu1.Add_Click({ 
 [System.Windows.Forms.MessageBox]::Show("Menu 1 - Submenu 1")
})
 
# Action after clicking on the Menu 1 - Submenu 2
$Menu1_SubMenu2.Add_Click({ 
 [System.Windows.Forms.MessageBox]::Show("Menu 1 - Submenu 2")
})
 
# Action after clicking on the Menu 2 - Submenu 1
$Menu2_SubMenu1.Add_Click({ 
 [System.Windows.Forms.MessageBox]::Show("Menu 2 - Submenu 1")
})
 
# Action after clicking on the Menu 2 - Submenu 2
$Menu2_SubMenu2.Add_Click({ 
 [System.Windows.Forms.MessageBox]::Show("Menu 2 - Submenu 2")
})
 
 
 
# When Restart the tool is clicked, close everything and kill the PowerShell process then open again the tool
$Menu_Restart_Tool.add_Click({
 $Restart = "Yes"
 start-process -WindowStyle hidden powershell.exe ".\WSTools_GUI.ps1 '$Restart'"  
 
 $MDTMonitoring_Icon.Visible = $false
 $window.Close()
 # $window_Config.Close() 
 Stop-Process $pid
  
 $Global:Timer_Status = $timer.Enabled
 If ($Timer_Status -eq $true)
  {
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
 If ($Timer_Status -eq $true)
  {
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