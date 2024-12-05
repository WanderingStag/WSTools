function Get-ModuleCommandCount {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2021-10-19 19:50:28
        Last Edit: 2021-10-19 19:50:28
        Keywords:
    .LINK
        https://wanderingstag.github.io
    #>
        [CmdletBinding()]
        param(
            [Parameter(
                HelpMessage = "Enter the name of the module. It must be one that is imported.",
                Mandatory=$true
            )]
            [ValidateNotNullOrEmpty()]
            [Alias('Module')]
            [string]$Name,

            [switch]$Functions
        )

        if ($Functions) {(Get-Command -Module $Name -CommandType Function).Count}
        else {(Get-Command -Module $Name).Count}
    }
