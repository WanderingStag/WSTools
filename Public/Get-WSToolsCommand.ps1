function Get-WSToolsCommand {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 01/31/2018 23:52:54
    LASTEDIT: 01/31/2018 23:52:54
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('WSToolsCommands')]
    param()
    $commands = (Get-Module WSTools | Select-Object ExportedCommands).ExportedCommands
    $commands.Values | Select-Object CommandType,Name,Source
}
