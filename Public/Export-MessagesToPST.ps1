function Export-MessagesToPST {
<#
   .Synopsis
    This function exports a users mailbox to a pst.
   .Description
    This function exports a users mailbox to a pst.
   .Example
    Export-MessagesToPST -TargetUserAlias joe.snuffy
    Exports joe.snuffy's mailbox to C:\Users\Desktop\joe.snuffy_mailboxyyyyMMddhhmm.pst where yyyyMMddhhmm is
    the date and time the mailbox was exported.
   .Example
    Export-MessagesToPST -TargetUserAlias joe.snuffy -ExportPath "c:\test"
    Exports joe.snuffy's mailbox to C:\test\joe.snuffy_mailboxyyyyMMddhhmm.pst where yyyyMMddhhmm is the date
    and time the mailbox was exported.
   .Parameter TargetUserAlias
    Mandatory parameter. Specify the users alias in Exchange or primary smtp address.
   .Parameter ExportPath
    By default saves to the logged on users desktop. You can specify where to save the pst to.
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 01/19/2014 01:20:00
    LASTEDIT: 2021-10-13 20:39:47
    KEYWORDS: Exchange, Mailbox, PST, export, InTh, Insider Threat
    REQUIRES:
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$TargetUserAlias,

        [Parameter(Mandatory=$false, Position=1)]
        [string]$ExportPath = ([System.Environment]::GetFolderPath("Desktop"))
    )

    $wmiq = Get-WmiObject win32_operatingsystem | Select-Object OSArchitecture
    if ($wmiq -like "*64-bit*") {
        [void][reflection.assembly]::LoadWithPartialName("System.Windows.Forms")
        $ErrorMsg = [System.Windows.Forms.MessageBox]::Show("Error: OS is 64-bit. Unable to Continue`n`nPrerequisites:`n1) Windows 32-bit OS`n2) Exchange 2007/2010/2013 32-bit Management Tools`n3) 32-bit Microsoft Office Suite with Microsoft Outlook`n4) Windows PowerShell v2 or newer","Error - Cannot Continue");
        $ErrorMsg
    }#if wmiq
    else {
        try {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.Admin -ErrorAction Stop}
        catch {Throw "Unable to add Microsoft.Exchange.Management.PowerShell.Admin snapin. Process cancelled."}

        Add-MailboxPermission -Identity "$TargetUserAlias" -User "$env:USERNAME" -AccessRights FullAccess -InheritanceType all -Confirm:$false
        new-item $ExportPath -type Directory -Force
        $LogDate = get-date -f yyyyMMddhhmm
        $FolderPath = $ExportPath + "\" + $TargetUserAlias + "_mailbox" + $LogDate + ".pst"
        Export-Mailbox -Identity "$TargetUserAlias" -PSTFolderPath $FolderPath -Confirm:$false
        Add-MailboxPermission -Identity "$TargetUserAlias" -User "$env:USERNAME" -Deny -AccessRights FullAccess -InheritanceType all -Confirm:$false
        Remove-MailboxPermission -Identity "$TargetUserAlias" -User "$env:USERNAME" -AccessRights FullAccess -InheritanceType all -Confirm:$false
    }#else
}#export messagestopst
