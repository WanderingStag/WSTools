function Get-FilePath {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:05:42
    LASTEDIT: 09/21/2017 13:05:42
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = "C:\"
    $OpenFileDialog.filter = "All files (*.*)| *.*"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
    $OpenFileDialog.ShowHelp = $true
}
