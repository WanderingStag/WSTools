function Get-NonSmartCardRequiredUser {
    <#
    .SYNOPSIS
        Displays users in domain with SmartCardRequired attribute set to false.

    .DESCRIPTION
        Displays all users in the domain with SmartCardRequired attribute on account set to false.

    .PARAMETER ComputerName
        Specifies the name of one or more computers.

    .EXAMPLE
        C:\PS>Get-NonSmartCardRequiredUser
        Example of how to use this cmdlet

    .INPUTS
        None

    .OUTPUTS
        System.Array

    .COMPONENT
        WSTools

    .FUNCTIONALITY
        Active Directory, Smartcard, Smart Card, InTh, Insider Threat

    .NOTES
        Author: Skyler Hart
        Created: 2023-05-02 17:16:53
        Last Edit: 2023-05-02 17:16:53
        Requires:
            -Module ActiveDirectory

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    Param (
        [AllowEmptyString()]
        [Alias('User')]
        [string]$Name
    )

    Begin {
        $ErrorActionPreference = "Stop"
        if ($null -eq (Get-Module -ListAvailable ActiveDir*).Path) {
            throw "Active Directory module not found. Active Directory module is required to run this function."
        }
    }
    Process {
        $users = Get-ADUser -Filter {SmartCardLogonRequired -eq $false} -Properties SmartCardLogonRequired,DisplayName,CanonicalName
    }
    End {
        if ($Name) {
            $users | Where-Object {$_ -match $Name}
        }
        else {$users}
    }
}
