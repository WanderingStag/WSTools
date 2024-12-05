function Add-DomainCheck {
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
    https://wanderingstag.github.io
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
