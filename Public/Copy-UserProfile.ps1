function Copy-UserProfile {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 04/06/2020 19:39:42
    LASTEDIT: 04/06/2020 20:10:59
    KEYWORDS:
    REQUIRES:
        -Version 3.0
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            HelpMessage = 'Enter user name. Ex: "1234567890A" without quotes',
            Mandatory=$true,
            Position=0
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('Username','SamAccountName')]
        [string]$User,

        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            Position=1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(HelpMessage = "Enter destination folder path as UNC unless a local path. Ex: E:\ESI\10-001 or \\COMP\e$\ESI\10-001",
            Mandatory=$false
        )]
        [Alias('Dest','DestinationFolder','DestFolder')]
        [string]$Destination = $null
    )
    Begin {
        if ($Destination -eq $null) {
            Write-Output "The destination folder selection window is open. It may be hidden behind windows."
            Add-Type -AssemblyName System.Windows.Forms
            $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
            $FolderBrowser.Description = "Select destination folder for user profile."
            $FolderBrowser.RootFolder = 'MyComputer'
            Set-WindowState MINIMIZE
            [void]$FolderBrowser.ShowDialog()
            Set-WindowState RESTORE
            $Destination = $FolderBrowser.SelectedPath
        }
        $df = $Destination + "\" + $User
    }
    Process {
        foreach ($comp in $ComputerName) {
            robocopy \\$comp\c$\Users\$user $df /mir /mt:3 /xj /r:3 /w:5 /njh /njs
        }
    }
    End {}
}
