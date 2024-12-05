function Get-DefaultBrowserPath {
    <#
    .NOTES
        Author: Skyler Hart
        Created: Sometime before 2017-08-07
        Last Edit: 2020-08-20 15:09:53

    .LINK
        https://wanderingstag.github.io
    #>
    New-PSDrive -Name HKCR -PSProvider Registry -Root Hkey_Classes_Root | Out-Null
    $BrowserPath = ((Get-ItemProperty 'HKCR:\http\shell\open\command').'(default)').Split('"')[1]
    return $BrowserPath
    Remove-PSDrive -Name HKCR -Force -ErrorAction SilentlyContinue | Out-Null
}
