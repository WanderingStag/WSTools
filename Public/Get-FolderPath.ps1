function Get-FolderPath {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:05:51
    LASTEDIT: 09/21/2017 13:05:51
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    Write-Output "The folder selection window is open. It may be hidden behind windows."
    Add-Type -AssemblyName System.Windows.Forms
    $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    #$FolderBrowser.Description = "Select Folder"
    #$FolderBrowser.ShowNewFolderButton = $false
    #$FolderBrowser.RootFolder = 'MyComputer'
    #to see special folders:  [Enum]::GetNames([System.Environment+SpecialFolder])
    #special folders can be used in the RootFolder section
    #Set-WindowState MINIMIZE
    [void]$FolderBrowser.ShowDialog()
    #Set-WindowState RESTORE
    $FolderBrowser.SelectedPath
}
