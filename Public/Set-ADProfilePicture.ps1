function Set-ADProfilePicture {
<#
.NOTES
    Author: Skyler Hart
    Created: 2017-08-18 20:47:20
    Last Edit: 2022-09-04 12:42:30
    Other:
    Requires:
        -Module ActiveDirectory
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [Alias('User','SamAccountname')]
        [string]$Username
    )

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $OpenFileDialog.initialDirectory = "C:\"
        $OpenFileDialog.filter = "JPG (*.jpg)| *.jpg"
        $OpenFileDialog.ShowDialog() | Out-Null
        $OpenFileDialog.filename
        $OpenFileDialog.ShowHelp = $true
        $ppath = $OpenFileDialog.FileName

        $item = Get-Item $ppath
        if ($item.Length -gt 102400) {Throw "Unable to set $Username's picture. Picture must be less than 100 KB. Also recommend max size of 96 x 96 pixels."}
        else {
            Import-Module activedirectory
            $photo1 = [byte[]](Get-Content $ppath -Encoding byte)
            Set-ADUser $UserName -Replace @{thumbnailPhoto=$photo1}
        }
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}
