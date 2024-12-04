function Find-HiddenGALUser {
    <#
    .Synopsis
        This function gets all users that are hidden from the GAL.

    .Description
        This function gets all users that are hidden from the Global Address List (GAL) in a domain or you can specify an OU to search.

    .Example
        Find-HiddenGALUsers -SearchBase "OU=Test,DC=mydomain,DC=com"
        This function gets all users that are hidden from the GAL in a domain or you can specify an OU to search.

    .Parameter SearchBase
        Specific OU to search. If not included, the entire domain will be searched.

    .Notes
        AUTHOR: Skyler Hart
        CREATED: 2014-01-18 02:50:00
        LASTEDIT: 2022-09-01 22:30:56
        KEYWORDS: Hidden Users, User, Exchange, GAL, Global Address List
        REQUIRES:
            ActiveDirectory

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [string]$SearchBase
    )

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        if (!([string]::IsNullOrWhiteSpace($SearchBase))) {
            Get-ADUser -Filter * -Properties givenName,Surname,SamAccountname,EmailAddress,msExchHideFromAddressLists -SearchBase $SearchBase | Where-Object {$_.msExchHideFromAddressLists -eq "TRUE"} |
            Select-Object givenName,Surname,SamAccountname,EmailAddress,msExchHideFromAddressLists
        }
        else {
            $sb = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
            Get-ADUser -Filter * -Properties givenName,Surname,SamAccountname,EmailAddress,msExchHideFromAddressLists -SearchBase $sb | Where-Object {$_.msExchHideFromAddressLists -eq "TRUE"} |
            Select-Object givenName,Surname,SamAccountname,EmailAddress,msExchHideFromAddressLists
        }
    }
    else {
        Write-Warning "Active Directory module is not installed."
    }
}
