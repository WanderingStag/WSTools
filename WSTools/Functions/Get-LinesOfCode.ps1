function Get-LinesOfCode {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2021-10-19 19:10:36
        Last Edit: 2021-10-19 19:10:36
        Keywords:
        Other: Excludes blank lines

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the path of the folder you want to count lines of PowerShell and JSON code for",
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    (Get-ChildItem -Path $Path -Recurse | Where-Object {$_.extension -in '.ps1','.psm1','.psd1','.json'} | select-string "^\s*$" -notMatch).Count
}
