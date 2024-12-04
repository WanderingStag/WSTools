function Get-ExchangeLastLoggedOnUser {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:58:33
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
 #Get-ADUser -Filter {EmailAddress -like "*"} -properties * | select EmailAddress | Export-Csv .\users.csv -NoTypeInformation
    $userfile = ".\users.csv"
    $users = "$userfile"

    foreach ($user in $users) {
        Get-MailboxStatistics -Identity $user.EmailAddress |
        Sort-Object DisplayName | Select-Object DisplayName,LastLoggedOnUserAccount,LastLogonTime,LastLogoffTime
    }
}#end get lastloggedonuser
