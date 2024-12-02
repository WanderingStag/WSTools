function Get-User {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-04-20 19:51:03
    Last Edit: 2020-04-20 23:14:32
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [ValidateNotNullorEmpty()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(
            Mandatory=$false,
            Position=1
        )]
        [Alias('Username')]
        [string]$User
    )

    foreach ($Comp in $ComputerName) {
        try {
            #Connect to computer and get information on user/users
            if ($null -ne $User) {
                $ui = Get-WmiObject -Class Win32_UserAccount -filter "LocalAccount='True'" -ComputerName $comp -ErrorAction Stop | Select-Object Name,Description,Disabled,Lockout,PasswordChangeable,PasswordExpires,PasswordRequired | Where-Object {$_.Name -match $User}
            }#if user not null
            else {
                $ui = Get-WmiObject -Class Win32_UserAccount -filter "LocalAccount='True'" -ComputerName $comp -ErrorAction Stop | Select-Object Name,Description,Disabled,Lockout,PasswordChangeable,PasswordExpires,PasswordRequired
            }

            ForEach ($u in $ui) {
                [PSCustomObject]@{
                    Computer = $Comp
                    User = $u.Name
                    Description = $u.Description
                    Disabled = $u.Disabled
                    Locked = $u.Lockout
                    PasswordChangeable = $u.PasswordChangeable
                    PasswordExpires = $u.PasswordExpires
                    PasswordRequired = $u.PasswordRequired
                }
            }#foreach u
        }#try
        catch {
            [PSCustomObject]@{
                Computer = $Comp
                User = $null
                Description = $null
                Disabled = $null
                Locked = $null
                PasswordChangeable = $null
                PasswordExpires = $null
                PasswordRequired = $null
            }
        }#catch
    }#foreach comp
}
