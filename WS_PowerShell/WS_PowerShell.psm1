Function Add-DateTime {
<# 
   .Synopsis 
    This function adds the date and time at current insertion point  
   .Example
    Add-DateTime
    Adds date and time at current insertion point in a PowerShell ISE window 
   .Notes 
    NAME: Add-DateTime
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 19:51:23
    LASTEDIT: 10/26/2017 09:48:00  
    KEYWORDS: Scripting Techniques, Windows PowerShell ISE
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#Requires -Version 2.0 
#> 
    $timeText = @" 
$(Get-Date) 
"@
    $psise.CurrentFile.Editor.InsertText($timeText) 
}


Function Add-DomainCheck {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter ComputerName
    Specifies the computer or computers
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 06/13/2018 14:42:45
    LASTEDIT: 10/04/2018 21:16:04  
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>

    $domainText = @" 
    if (`$env:USERDNSDOMAIN -match "skynet") {
        
    }#if skynet

    elseif (`$env:USERDNSDOMAIN -match "area") {
        
    }#if area

    elseif (`$env:USERDNSDOMAIN -like "*.ogn.*") {
        
    }#if tic

    elseif (`$env:USERDNSDOMAIN -eq "lab.local") {
        
    }#if virtual lab

    elseif (`$env:USERDNSDOMAIN -match ".smil.") {
        
    }#secure
"@
    $psise.CurrentFile.Editor.InsertText($domainText)
}


Function Add-Function {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter PARAMETER
    The parameter does this
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 10/18/2017 13:58:17
    LASTEDIT: 12/20/2019 22:18:43 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#> 
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Browsers,
      
        [Parameter(Mandatory=$false)]
        [Switch]$Object,

        [Parameter(Mandatory=$false)]
        [Switch]$User
    )

if ($Browsers) {
    $browserHelp = @"

   .Parameter Chrome
    Opens the website in Google Chrome
   .Parameter Edge
    Opens the website in Microsoft Edge
   .Parameter Firefox
    Opens the website in Mozilla Firefox
   .Parameter InternetExplorer
    Opens the website in Microsoft Internet Explorer
"@
    $browserText1 = @"
,

        [Parameter(Mandatory=`$false)]
        [Switch]`$Chrome,
      
        [Parameter(Mandatory=`$false)]
        [Switch]`$Edge,
      
        [Parameter(Mandatory=`$false)]
        [Switch]`$Firefox,
        
        [Parameter(Mandatory=`$false)]
        [Switch]`$InternetExplorer
"@

    $browserText2 = @"
    `$URL = "https://......."
    if (`$Chrome) {Start-Process "chrome.exe" `$URL}
    elseif (`$Edge) {Start-Process shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge `$URL}
    elseif (`$Firefox) {Start-Process "firefox.exe" `$URL}
    elseif (`$InternetExplorer) {Start-Process "iexplore.exe" `$URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open(`$URL)
    }
"@
}
else {
    $browserText1 = ""
    $browserText2 = ""
}

if ($Object) {
    $objectText = @"
    New-Object -TypeName PSObject -Property @{
        ComputerName = `$comp
    }#new object
"@
}
else {$objectText = ""}

if ($User) {
    $userHelp = @"

   .Parameter Username
    Specifies the user or users
"@
    $userText1 = @"
,

        [Parameter(Mandatory=`$false, Position=1, ValueFromPipeline=`$true, ValueFromPipelineByPropertyName=`$true)]
        [Alias('User','SamAccountname')]
        [ValidateNotNullOrEmpty()]
        [string[]]`$Username = "`$env:USERNAME"
"@
    $userText2 = @"

    foreach (`$user in `$UserName) {
        
    }
"@
}
else {
    $userHelp = ""
    $userText1 = ""
    $userText2 = ""
}


    $functionText = @"
Function {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter ComputerName
    Specifies the computer or computers$userHelp$browserHelp
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: 
    CREATED: $(Get-Date)
    LASTEDIT: $(Get-Date) 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
   .Link 
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=`$false,
            Position=0,
            ValueFromPipeline = `$true,
            ValueFromPipelineByPropertyName = `$true
        )] 
        [ValidateSet('Info','Error','Warning')]
        [ValidateNotNullOrEmpty()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]`$ComputerName = "`$env:COMPUTERNAME"$userText1$browserText1
    )

    foreach (`$comp in `$ComputerName) {
        
    }
$userText2
$browserText2
$objectText
}
"@

    $psise.CurrentFile.Editor.InsertText($functionText)
}


Function Add-Help {
<# 
   .Synopsis 
    This function adds help at current insertion point  
   .Example
    Add-Help
    Adds comment based help at current insertion point in a PowerShell ISE window 
   .Notes 
    NAME: Add-Help 
    AUTHOR: Skyler Hart
    CREATED: 09/07/2010 17:32:34
    LASTEDIT: 10/04/2018 20:26:05 
    KEYWORDS: Scripting Techniques, Windows PowerShell ISE, Help
    REQUIRES: 
        #Requires -Version 2.0
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#> 
    $helpText = @" 
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter PARAMETER
    The parameter does this
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: 
    CREATED: $(Get-Date)
    LASTEDIT: $(Get-Date) 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
   .Link 
    https://wstools.dev
#> 
"@
    $psise.CurrentFile.Editor.InsertText($helpText) 
}


Function Add-InternetBrowsersBlock {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter PARAMETER
    The parameter does this
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 10/18/2017 12:58:28
    LASTEDIT: 10/18/2017 12:58:28 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#> 
    $browserblockText = @" 
    if (`$Chrome) {Start-Process "chrome.exe" `$URL}
    elseif (`$Edge) {Start-Process shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge `$URL}
    elseif (`$Firefox) {Start-Process "firefox.exe" `$URL}
    elseif (`$InternetExplorer) {Start-Process "iexplore.exe" `$URL}
    else {
        #open in default browser
        (New-Object -com Shell.Application).Open(`$URL)
    }
"@
    $psise.CurrentFile.Editor.InsertText($browserblockText) 
}


Function Add-ParamBlock {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter PARAMETER
    The parameter does this
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 09/27/2017 15:14:53
    LASTEDIT: 12/20/2019 22:15:51 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#> 
    $paramblockText = @" 
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=`$false,
            Position=0,
            ValueFromPipeline = `$true,
            ValueFromPipelineByPropertyName = `$true
        )] 
        [ValidateSet('Info','Error','Warning')]
        [ValidateNotNullOrEmpty()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]`$ComputerName = "`$env:COMPUTERNAME",

        [Parameter()] 
        [Switch]`$Switch
    ) 
"@
    $psise.CurrentFile.Editor.InsertText($paramblockText) 
}


Function Add-ParamInternetBrowser {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter PARAMETER
    The parameter does this
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 10/18/2017 12:55:22
    LASTEDIT: 10/18/2017 14:37:37  
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com 
#>
    $paramIBText = @" 
        [Parameter(Mandatory=`$false)]
        [Switch]`$Chrome,
      
        [Parameter(Mandatory=`$false)]
        [Switch]`$Edge,
      
        [Parameter(Mandatory=`$false)]
        [Switch]`$Firefox,
        
        [Parameter(Mandatory=`$false)]
        [Switch]`$InternetExplorer
"@
    $psise.CurrentFile.Editor.InsertText($paramIBText) 
}


Function Add-ParamSwitchWithOption {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter PARAMETER
    The parameter does this
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 10/23/2017 17:20:36
    LASTEDIT: 12/20/2019 22:14:54 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#> 

    $switchText = @"
,

        [Parameter(Mandatory=`$false)]
        [ValidateSet('Info','Error','Warning')]
        [ValidateNotNullOrEmpty()]
        [Alias('Host','Name','Computer','CN')]
        [string]`$Icon = 'Info'
"@
    $psise.CurrentFile.Editor.InsertText($switchText)
}


Function Add-ProgressBar {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter ComputerName
    Specifies the computer or computers
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 10:53:40
    LASTEDIT: 04/23/2018 10:53:40 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com 
#>
    $objectText = @"
`$i = 0
`$number = `$ComputerName.length
    
#Progress Bar
if (`$number -gt "1") {
    `$i++
    `$amount = (`$i / `$number)
    `$perc1 = `$amount.ToString("P")
    `Write-Progress -activity "Currently doing..." -status "Computer `$i of `$number. Percent complete:  `$perc1" -PercentComplete ((`$i / `$ComputerName.length)  * 100)
}#if length
"@
    $psise.CurrentFile.Editor.InsertText($objectText)
}


Function Add-PSObject {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter PARAMETER
    The parameter does this
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 09/27/2017 17:13:32
    LASTEDIT: 12/21/2019 23:35:03  
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#> 
    [CmdletBinding()]
    Param (
        [Parameter()] 
        [Switch]$CustomObject
    ) 
    
    if ($CustomObject) {
        $objectText = @" 
`$object = [ordered]@{
    'Property1'        = `$null
    'LongPropertyEx'   = `$null
}#pscustom object
[pscustomobject]`$object
#or
[pscustomobject]@{Property1=`$null;LongPropertyEx=`$null}
"@
    }#if custom object
    else {
        $objectText = @" 
New-Object -TypeName PSObject -Property @{
    ComputerName = `$comp
}#new object 
"@
    }#else
    $psise.CurrentFile.Editor.InsertText($objectText) 
}


Function Add-Switch {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter PARAMETER
    The parameter does this
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 07/31/2019 22:17:04
    LASTEDIT: 07/31/2019 22:17:04 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#> 
    $objectText = @"
switch (`$variable) {
    value {`$variable2 = "something"}

    {'value1','value2' -contains `$_} {`$variable2 = "something"}

    {`$anothervariable -match `$variable} {`$variable2 = "something"}
}
"@
    $psise.CurrentFile.Editor.InsertText($objectText)
}


Function Get-Accelerators {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter ComputerName
    Specifies the computer or computers
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 12/21/2019 23:28:57
    LASTEDIT: 12/21/2019 23:28:57 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        Requires -Version 2.0
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>
    [psobject].Assembly.GetType(“System.Management.Automation.TypeAccelerators”)::get | Sort-Object Key
}
New-Alias -Name "Get-TypeAccelerators" -Value Get-Accelerators
New-Alias -Name "accelerators" -Value Get-Accelerators


Function Get-FilePath {  
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter PARAMETER
    The parameter does this
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:05:42
    LASTEDIT: 09/21/2017 13:05:42 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>  
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = "C:\"
    $OpenFileDialog.filter = "All files (*.*)| *.*"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
    $OpenFileDialog.ShowHelp = $true
}


Function Get-FolderPath {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter PARAMETER
    The parameter does this
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:05:51
    LASTEDIT: 09/21/2017 13:05:51 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#> 
    Write-Host "The folder selection window is open. It may be hidden behind windows." -ForegroundColor Yellow
    Add-Type -AssemblyName System.Windows.Forms
    $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    #$FolderBrowser.Description = "Select Folder"
    #$FolderBrowser.ShowNewFolderButton = $false
    #$FolderBrowser.RootFolder = 'MyComputer'
    #to see special folders:  [Enum]::GetNames([System.Environment+SpecialFolder])
    #special folders can be used in the RootFolder section
    #Set-WindowState MINIMIZE
    [void]$FolderBrowser.ShowDialog()
    #Set-WindowState RESTORE
    $FolderBrowser.SelectedPath
}


Function Get-FunctionsInModule {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter PARAMETER
    The parameter does this
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 08/21/2017 13:06:27
    LASTEDIT: 08/21/2017 13:06:27 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#> 
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)] 
        [string]$Module
    )

    $mod = (Get-Module $Module -ListAvailable).ExportedCommands
    $mod.Values.Name | Sort-Object
}


Function Get-Role {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter PARAMETER
    The parameter does this
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 10/20/2017 16:30:43
    LASTEDIT: 10/20/2017 16:30:43 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {$Role = "Admin"}
    else {$Role = "Non-Admin"}
    $Role
}


Function Set-AutoLoadPreference {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter ComputerName
    Specifies the computer or computers
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 02/01/2018 10:23:26
    LASTEDIT: 02/01/2018 10:23:26 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com 
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)] 
        [ValidateSet("All","None")]
        $mode = "All"
    )
    $PSModuleAutoloadingPreference = $mode
}


Function Set-Profile {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter PARAMETER
    The parameter does this
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 21:07:03 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#> 
    #If profile already exists, open for editing
    if (Test-Path $profile) {
        start-process "$env:windir\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe" $profile
    }
    #If it doesn't exist, create it and put default stuff into it
    else {
        $filecontent = '##############################################################
# This file contains the commands to run upon startup of     #
# PowerShell or PowerShell ISE. Dependent on whether you     #
# used the command "Set-Profile" in PowerShell or            #
# PowerShell ISE.                                            #
#                                                            #
# To add additional commands to run at startup just type     #
# them below then save this file. To edit this file in the   #
# future, use the command "Set-Profile"                      #
##############################################################



'

        New-Item $profile -ItemType File -Force -Value $filecontent | Out-Null
        start-sleep 1
        start-process "$env:windir\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe" $profile
    }
}
New-Alias -Name "Edit-Profile" -Value Set-Profile
New-Alias -Name "Profile" -Value Set-Profile


Function Set-Title {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter PARAMETER
    The parameter does this
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:47:14 
    KEYWORDS: 
    REMARKS: 
    REQUIRES: 
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#> 
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)] 
        [string]$titleText
    )

    $Host.UI.RawUI.WindowTitle = $titleText
}
New-Alias -Name "title" -Value Set-Title


Function Start-PowerShell {
<# 
   .Synopsis 
    This does that
   .Description
    This does that
   .Example 
    Example- 
    Example- accomplishes  
   .Parameter ComputerName
    Specifies the computer or computers
   .Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 10/24/2017 14:41:52
    LASTEDIT: 10/24/2017 16:41:21  
    KEYWORDS: 
    REMARKS: 
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [switch]$Console,

        [Parameter(Mandatory=$false)]
        [switch]$ISE,

        [Parameter(Mandatory=$false)]
        [switch]$VSC,

        [Parameter(Mandatory=$false)]
        [switch]$RunAs
    )


    if ($true -notin $Console,$ISE,$VSC) {
        if ($Host.Name -eq 'ConsoleHost') {
            if ($RunAs) {Start-Process "$env:windir\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe" -Verb RunAs}
            else {Start-Process "$env:windir\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe"}
        }
        else {
            if ($RunAs) {Start-Process powershell.exe -Verb RunAs}
            else {Start-Process powershell.exe}
        }
    }
    else {
        if ($Console) {
            if ($RunAs) {Start-Process powershell.exe -Verb RunAs}
            else {Start-Process powershell.exe}
        }
        elseif ($ISE) {
            if ($RunAs) {Start-Process "$env:windir\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe"}
            else {Start-Process "$env:windir\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe"}
        }
        elseif ($VSC) {
            if ($RunAs) {Start-Process "$env:programfiles\Microsoft VS Code\Code.exe"}
            else {Start-Process "$env:programfiles\Microsoft VS Code\Code.exe"}
        }
    }
}
New-Alias -Name "Open-PowerShell" -Value Start-PowerShell


Export-ModuleMember -Alias * -Function *