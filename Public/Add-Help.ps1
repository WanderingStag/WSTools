function Add-Help {
<#
   .Synopsis
    This function adds help at current insertion point.
   .Example
    Add-Help
    Adds comment based help at current insertion point in a PowerShell ISE window.
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 09/07/2010 17:32:34
    LASTEDIT: 10/04/2018 20:26:05
    KEYWORDS: Scripting Techniques, Windows PowerShell ISE, Help
    REQUIRES:
        #Requires -Version 2.0
.LINK
    https://wanderingstag.github.io
#>
    $helpText = @"
<#
   .Synopsis
    This does that
   .Description
    This does that
   .Example
    Example-
    Example- accomplishes
   .Parameter PARAMETER
    The parameter does this
   .Notes
    AUTHOR:
    CREATED: $(Get-Date)
    LASTEDIT: $(Get-Date)
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
   .Link
    https://wanderingstag.github.io
#>
"@
    $psise.CurrentFile.Editor.InsertText($helpText)
}
