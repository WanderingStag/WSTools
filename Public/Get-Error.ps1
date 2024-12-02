function Get-Error {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2020-04-18 16:42:46
        Last Edit: 2020-04-18 19:08:44

    .LINK
        https://wanderingstag.github.io
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Error')]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [int32]$HowMany
    )

    $Errors = $Global:Error

    if ([string]::IsNullOrWhiteSpace($HowMany)) {
        [int32]$HowMany = $Errors.Count
    }

    $n = $HowMany - 1
    $logs = $Errors[0..$n]

    foreach ($log in $logs) {
        $scriptn = $log.InvocationInfo.ScriptName
        $line = $log.InvocationInfo.ScriptLineNumber
        $char = $log.InvocationInfo.OffsetInline
        $command = $log.InvocationInfo.Line.Trim()
        $exc = $log.Exception.GetType().fullname
        $mes = $log.Exception.message.Trim()
        [PSCustomObject]@{
            Exception = "[$exc]"
            Message = $mes
            Script = $scriptn
            Command = $command
            Line = $line
            Character = $char
        }
    }
}
