Function Add-DateTime {
<#
   .Synopsis
    This function adds the date and time at current insertion point.
   .Example
    Add-DateTime
    Adds date and time at current insertion point in a PowerShell ISE window.
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 08/19/2017 19:51:23
    LASTEDIT: 10/26/2017 09:48:00
    KEYWORDS: Scripting Techniques, Windows PowerShell ISE
.LINK
    https://wstools.dev
#Requires -Version 2.0
#>
    $timeText = @"
$(Get-Date)
"@
    $psise.CurrentFile.Editor.InsertText($timeText)
}


Function Add-DomainCheck {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 06/13/2018 14:42:45
    LASTEDIT: 10/04/2018 21:16:04
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
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
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/18/2017 13:58:17
    LASTEDIT: 12/20/2019 22:18:43
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
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
    [PSCustomObject]@{
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
    AUTHOR:
    CREATED: $(Get-Date)
    LASTEDIT: $(Get-Date)
    KEYWORDS:
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
    This function adds help at current insertion point.
   .Example
    Add-Help
    Adds comment based help at current insertion point in a PowerShell ISE window.
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 09/07/2010 17:32:34
    LASTEDIT: 10/04/2018 20:26:05
    KEYWORDS: Scripting Techniques, Windows PowerShell ISE, Help
    REQUIRES:
        #Requires -Version 2.0
.LINK
    https://wstools.dev
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
    AUTHOR:
    CREATED: $(Get-Date)
    LASTEDIT: $(Get-Date)
    KEYWORDS:
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
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/18/2017 12:58:28
    LASTEDIT: 10/18/2017 12:58:28
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wstools.dev
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
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/27/2017 15:14:53
    LASTEDIT: 12/20/2019 22:15:51
    KEYWORDS:
.LINK
    https://wstools.dev
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
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/18/2017 12:55:22
    LASTEDIT: 10/18/2017 14:37:37
    KEYWORDS:
.LINK
    https://wstools.dev
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
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/23/2017 17:20:36
    LASTEDIT: 12/20/2019 22:14:54
    KEYWORDS:
.LINK
    https://wstools.dev
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
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/23/2018 10:53:40
    LASTEDIT: 04/23/2018 10:53:40
    KEYWORDS:
.LINK
    https://wstools.dev
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
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/27/2017 17:13:32
    LASTEDIT: 12/21/2019 23:35:03
    KEYWORDS:
.LINK
    https://wstools.dev
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
[PSCustomObject]@{
    ComputerName = `$comp
}#new object
"@
    }#else
    $psise.CurrentFile.Editor.InsertText($objectText)
}


Function Add-Switch {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 07/31/2019 22:17:04
    LASTEDIT: 07/31/2019 22:17:04
    KEYWORDS:
.LINK
    https://wstools.dev
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



function Convert-AppIconToBase64 {
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
    C:\PS>Convert-AppIconToBase64
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Convert-AppIconToBase64 -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.NOTES
    Author: Skyler Hart
    Created: 2020-11-10 18:57:12
    Last Edit: 2020-11-10 18:57:12
    Keywords:
    Other:
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
            HelpMessage = "Enter the path of the file to extract the icon from. Ex: C:\Temp\app.exe",
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.IO
    $Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($Path)
    $stream = New-Object System.IO.MemoryStream
    $Icon.Save($stream)
    $Bytes = $stream.ToArray()
    $stream.Flush()
    $stream.Dispose()
    $b64 = [convert]::ToBase64String($Bytes)
    $b64
}


function Convert-DatesToDays {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-06-03 08:54:49
    Last Edit: 2021-06-03 09:23:27
    Keywords: date, converter
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [ValidateLength(8,10)]
        [Alias('Day1')]
        [string]$Date1 = (Get-Date -Format "yyyy-MM-dd"),

        [Parameter(
            Mandatory=$false,
            Position=1
        )]
        [ValidateLength(8,10)]
        [Alias('Day2')]
        [string]$Date2 = (Get-Date -Format "yyyy-MM-dd")
    )

    $c1 = $Date1.Length
    if ($c1 -eq 8) {
        $y = $Date1.Substring(0,4)
        $m = $Date1.Substring(4)
        $m = $m.Substring(0,2)
        $d = $Date1.Substring(6)
        $start = (Get-Date -Year $y -Month $m -Day $d)
    }
    elseif ($c1 -eq 10) {
        $y = $Date1.Substring(0,4)
        $m = $Date1.Substring(5)
        $m = $m.Substring(0,2)
        $d = $Date1.Substring(8)
        $start = (Get-Date -Year $y -Month $m -Day $d)
    }

    $c2 = $Date2.Length
    if ($c2 -eq 8) {
        $y = $Date2.Substring(0,4)
        $m = $Date2.Substring(4)
        $m = $m.Substring(0,2)
        $d = $Date2.Substring(6)
        $end = (Get-Date -Year $y -Month $m -Day $d)
    }
    elseif ($c2 -eq 10) {
        $y = $Date2.Substring(0,4)
        $m = $Date2.Substring(5)
        $m = $m.Substring(0,2)
        $d = $Date2.Substring(8)
        $end = (Get-Date -Year $y -Month $m -Day $d)
    }

    $ts = New-TimeSpan -Start $start -End $end
    $ts.Days
}


function Convert-DaysToWorkDay {
<#
.EXAMPLE
    C:\PS>Convert-DaysToWorkDay 1
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Convert-DaysToWorkDay -1
    Another example of how to use this cmdlet.
.NOTES
    Author: Skyler Hart
    Created: 2021-03-04 18:54:31
    Last Edit: 2021-06-20 17:13:33
    Keywords:
.LINK
    https://wstools.dev
.LINK
    https://www.skylerhart.com
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the amount of days you want to convert. Must an a positive or negative integer (Ex: 1 or -1).",
            Mandatory=$true,
            Position=0
        )]
        [int32]$Days,

        [Parameter(
            HelpMessage = "Must be in the format yyyy-MM-dd.",
            Mandatory=$false,
            Position=1
        )]
        [datetime]$StartDay = (Get-Date).Date
    )

    $holidays = ($Global:WSToolsConfig).Holidays.Date

    if ($Days -lt 0) {
        $sub = "sub"
    }
    elseif ($Days -gt 0) {
        $sub = "add"
    }
    else {$sub = "zero"}

    if ($sub -eq "sub") {
        $i = -1
        do {
            $StartDay = $StartDay.AddDays(-1)

            if ($holidays -contains $StartDay) {
                $StartDay = $StartDay.AddDays(-1)
            }

            if ($StartDay.DayOfWeek -match "Sunday") {
                $StartDay = $StartDay.AddDays(-1)
            }

            if ($StartDay.DayOfWeek -match "Saturday") {
                $StartDay = $StartDay.AddDays(-1)
            }

            if ($holidays -contains $StartDay) {
                $StartDay = $StartDay.AddDays(-1)
            }

            $i--
        } until ($i -lt $Days)

        if ($holidays -contains $StartDay) {
            $StartDay = $StartDay.AddDays(-1)
        }

        if ($StartDay.DayOfWeek -match "Sunday") {
            $StartDay = $StartDay.AddDays(-1)
        }

        if ($StartDay.DayOfWeek -match "Saturday") {
            $StartDay = $StartDay.AddDays(-1)
        }

        if ($holidays -contains $StartDay) {
            $StartDay = $StartDay.AddDays(-1)
        }
        $StartDay
    }
    elseif ($sub -eq "add") {
        $i = 1
        do {
            $StartDay = $StartDay.AddDays(1)

            if ($holidays -contains $StartDay) {
                $StartDay = $StartDay.AddDays(1)
            }

            if ($StartDay.DayOfWeek -match "Saturday") {
                $StartDay = $StartDay.AddDays(1)
            }

            if ($StartDay.DayOfWeek -match "Sunday") {
                $StartDay = $StartDay.AddDays(1)
            }

            if ($holidays -contains $StartDay) {
                $StartDay = $StartDay.AddDays(1)
            }

            $i++
        } until ($i -gt $Days)

        if ($holidays -contains $StartDay) {
            $StartDay = $StartDay.AddDays(1)
        }

        if ($StartDay.DayOfWeek -match "Saturday") {
            $StartDay = $StartDay.AddDays(1)
        }

        if ($StartDay.DayOfWeek -match "Sunday") {
            $StartDay = $StartDay.AddDays(1)
        }

        if ($holidays -contains $StartDay) {
            $StartDay = $StartDay.AddDays(1)
        }
        $StartDay
    }
    else {$StartDay}
}


function Convert-ImageToBase64 {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-11-03 22:22:19
    Last Edit: 2020-11-03 22:22:19
    Keywords:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the path of the image you want to convert. Ex: D:\temp\image.jpg",
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$ImagePath
    )

    $b64 = [convert]::ToBase64String((get-content $ImagePath -encoding byte))
    $b64
}
New-Alias -Name "Convert-ICOtoBase64" -Value Convert-ImageToBase64


function Convert-IPtoINT64 () {
    param ($IP)
    $octets = $IP.split(".")
    return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3])
}

function Convert-INT64toIP() {
    param ([int64]$int)
    return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring())
}



Function Get-Accelerator {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 12/21/2019 23:28:57
    LASTEDIT: 12/21/2019 23:28:57
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [psobject].Assembly.GetType(“System.Management.Automation.TypeAccelerators”)::get | Sort-Object Key
}
New-Alias -Name "Get-TypeAccelerators" -Value Get-Accelerators
New-Alias -Name "accelerators" -Value Get-Accelerators


Function Get-FilePath {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:05:42
    LASTEDIT: 09/21/2017 13:05:42
    KEYWORDS:
.LINK
    https://wstools.dev
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
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:05:51
    LASTEDIT: 09/21/2017 13:05:51
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    Write-Output "The folder selection window is open. It may be hidden behind windows."
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
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/21/2017 13:06:27
    LASTEDIT: 08/21/2017 13:06:27
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Module
    )

    $mod = (Get-Module $Module -ListAvailable).ExportedCommands
    $mod.Values.Name | Sort-Object
}


function Get-PowerShellVariable {
<#
.SYNOPSIS
    Will show env: and PowerShell variable active in session.
.DESCRIPTION
    Gets environment variables and the active PowerShell variables in the current session and shows their values.
.PARAMETER Name
    To filter for a specific variable.
.EXAMPLE
    C:\PS>Get-PowerShellVariable
    Example of how to use this cmdlet.
.EXAMPLE
    C:\PS>Get-PowerShellVariable -Name ErrorActionPreference
    Will show what the value is for $ErrorActionPreference.
.EXAMPLE
    C:\PS>Get-PowerShellVariable -Name ErrorActionPreference,OneDriveConsumer
    Will show what the value is for $ErrorActionPreference and $env:OneDriveConsumer.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    variable, environment, system
.NOTES
    Author: Skyler Hart
    Created: 2022-09-22 23:29:51
    Last Edit: 2022-09-22 23:29:51
    Other:
    Requires:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$Name
    )

    $variables = Get-ChildItem Env: | Add-Member -MemberType NoteProperty -Name "VariableType" -Value "`$env:" -PassThru
    $variables += Get-Variable | Add-Member -MemberType NoteProperty -Name "VariableType" -Value "PowerShell" -PassThru

    if (!([string]::IsNullOrWhiteSpace($Name))) {
        $filtered = foreach ($obj in $Name) {
            $variables | Where-Object {$_.Name -match $obj} | Select-Object VariableType,Name,Value
        }
    }
    else {
        $filtered = $variables | Select-Object VariableType,Name,Value
    }

    $filtered | Select-Object | Sort-Object Name
}


Function Get-Role {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/20/2017 16:30:43
    LASTEDIT: 10/20/2017 16:30:43
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {$Role = "Admin"}
    else {$Role = "Non-Admin"}
    $Role
}


Function Set-AutoLoadPreference {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/01/2018 10:23:26
    LASTEDIT: 02/01/2018 10:23:26
    KEYWORDS:
    REQUIRES:
        -Version 2.0 only doesn't apply to Version 3.0 or newer
.LINK
    https://wstools.dev
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
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 21:07:03
    KEYWORDS:
.LINK
    https://wstools.dev
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
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:47:14
    KEYWORDS:
.LINK
    https://wstools.dev
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
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/24/2017 14:41:52
    LASTEDIT: 10/24/2017 16:41:21
    KEYWORDS:
.LINK
    https://wstools.dev
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


#needs Get-NotificationApp
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
        [string]$Sender = " ",

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
        if ([string]::IsNullOrWhiteSpace($Notifier)) {$Notifier = "Windows.SystemToast.NfpAppAcquire"}
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


Function Test-DynamicParameterSwitchCheck {
<#
.SYNOPSIS
    Non-functional. For reference.
.DESCRIPTION
    Shows how to create a function with dynamic parameters (Add and Modify) that only appear if the username parameter is populated and the Enable switch is added.
.COMPONENT
    WSTools
.FUNCTIONALITY
    Example, Reference
.NOTES
    Author: Skyler Hart
    Created: 2022-09-11 01:28:57
    Last Edit: 2022-09-11 01:41:04
    Other:
.LINK
    https://wstools.dev
#>
    Param (
        [Parameter(Mandatory = $false)]
        [Alias('EDIPI','DisplayName')]
        [string[]]$UserName,

        [Parameter(Mandatory = $false)]
        [switch]$Enable

    )
    DynamicParam {
        if (![string]::IsNullOrWhiteSpace($Username) -and $Enable -eq $true) {
            #Parameter
            $parameterAttribute = [System.Management.Automation.ParameterAttribute]@{
                ParameterSetName = "AddingMembers"
                Mandatory = $false
            }

            $attributeCollection = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
            $attributeCollection.Add($parameterAttribute)

            $dynParam1 = [System.Management.Automation.RuntimeDefinedParameter]::new(
                'Add', [switch], $attributeCollection
            )

            $paramDictionary = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
            $paramDictionary.Add('Add', $dynParam1)

            #Parameter2
            $parameterAttribute2 = [System.Management.Automation.ParameterAttribute]@{
                ParameterSetName = "ModifyingMembers"
                Mandatory = $false
            }

            $attributeCollection2 = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
            $attributeCollection2.Add($parameterAttribute2)

            $dynParam2 = [System.Management.Automation.RuntimeDefinedParameter]::new(
                'Modify', [switch], $attributeCollection2
            )

            $paramDictionary.Add('Modify', $dynParam2)
            return $paramDictionary
        }
    }#dynamic
    Process {
        $PSBoundParameters['Add'].IsPresent
    }
}

Export-ModuleMember -Alias * -Function *