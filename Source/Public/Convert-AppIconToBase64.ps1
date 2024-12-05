function Convert-AppIconToBase64 {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Convert-AppIconToBase64
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Convert-AppIconToBase64 -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.NOTES
    Author: Skyler Hart
    Created: 2020-11-10 18:57:12
    Last Edit: 2020-11-10 18:57:12
    Keywords:
    Other:
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the path of the file to extract the icon from. Ex: C:\Temp\app.exe",
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.IO
    $Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($Path)
    $stream = New-Object System.IO.MemoryStream
    $Icon.Save($stream)
    $Bytes = $stream.ToArray()
    $stream.Flush()
    $stream.Dispose()
    $b64 = [convert]::ToBase64String($Bytes)
    $b64
}
