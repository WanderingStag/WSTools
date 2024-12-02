function Import-MOF {
<#
.PARAMETER Path
    Specifies the path to the mof file intended to import.
.EXAMPLE
    C:\PS>Import-MOF C:\Example\windows10.mof
    Example of how to use this cmdlet.
.EXAMPLE
    C:\PS>New-WMIFilter 'C:\setup\GPOs\WMIs\Google Chrome\Google Chrome.mof'
    Example of how to use this cmdlet.
.EXAMPLE
    C:\PS>Import-MOF -Path C:\Example\virtualservers.mof
    Another example of how to use this cmdlet but with a parameter or switch.
.NOTES
    Author: Skyler Hart
    Created: 10/27/2017 15:54:18
    Last Edit: 2020-05-08 20:30:19
    Keywords:
    Requires:
        -Module ActiveDirectory
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Import-WMIFilter')]
    Param (
        [Parameter(
            HelpMessage = "Enter the path of the .mof file you want to import. Ex: C:\Example\examplewmi.mof",
            Mandatory=$true,
            Position=0
        )]
        [Alias('mof','Name','File')]
        [string]$Path
    )

    $auth = 'Author = ' + '"' + $env:username + '@' + $env:USERDNSDOMAIN + '"'
    $dom = 'Domain = ' + '"' + $env:USERDNSDOMAIN + '"'
    $content = Get-Content $Path
    $content2 = $content -replace 'Author = \"(.*)\"',"$auth" -replace "",""
    $content2 = $content2 -replace 'Domain = \"(.*)\"',"$dom"
    $content2 > $Path
    mofcomp -N:root\Policy $Path
}
