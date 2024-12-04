function Add-ParamBlock {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/27/2017 15:14:53
    LASTEDIT: 12/20/2019 22:15:51
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    $paramblockText = @"
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=`$false,
            Position=0,
            ValueFromPipeline = `$true,
            ValueFromPipelineByPropertyName = `$true
        )]
        [ValidateSet('Info','Error','Warning')]
        [ValidateNotNullOrEmpty()]
        [Alias('Host','Name','Computer','CN')]
        [string[]]`$ComputerName = "`$env:COMPUTERNAME",

        [Parameter()]
        [Switch]`$Switch
    )
"@
    $psise.CurrentFile.Editor.InsertText($paramblockText)
}
