function Get-PowerShellVariable {
<#
.SYNOPSIS
    Will show env: and PowerShell variable active in session.
.DESCRIPTION
    Gets environment variables and the active PowerShell variables in the current session and shows their values.
.PARAMETER Name
    To filter for a specific variable.
.EXAMPLE
    C:\PS>Get-PowerShellVariable
    Example of how to use this cmdlet.
.EXAMPLE
    C:\PS>Get-PowerShellVariable -Name ErrorActionPreference
    Will show what the value is for $ErrorActionPreference.
.EXAMPLE
    C:\PS>Get-PowerShellVariable -Name ErrorActionPreference,OneDriveConsumer
    Will show what the value is for $ErrorActionPreference and $env:OneDriveConsumer.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    variable, environment, system
.NOTES
    Author: Skyler Hart
    Created: 2022-09-22 23:29:51
    Last Edit: 2022-09-22 23:29:51
    Other:
    Requires:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$Name
    )

    $variables = Get-ChildItem Env: | Add-Member -MemberType NoteProperty -Name "VariableType" -Value "`$env:" -PassThru
    $variables += Get-Variable | Add-Member -MemberType NoteProperty -Name "VariableType" -Value "PowerShell" -PassThru

    if (!([string]::IsNullOrWhiteSpace($Name))) {
        $filtered = foreach ($obj in $Name) {
            $variables | Where-Object {$_.Name -match $obj} | Select-Object VariableType,Name,Value
        }
    }
    else {
        $filtered = $variables | Select-Object VariableType,Name,Value
    }

    $filtered | Select-Object | Sort-Object Name
}
