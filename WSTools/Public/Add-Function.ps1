function Add-Function {
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
    https://wanderingstag.github.io
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
    elseif (`$Edge) {Start-Process Microsoft-Edge:`$URL}
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
    https://wanderingstag.github.io
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
