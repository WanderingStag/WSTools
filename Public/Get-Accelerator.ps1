function Get-Accelerator {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 12/21/2019 23:28:57
    LASTEDIT: 12/21/2019 23:28:57
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Get-TypeAccelerators','accelerators')]
    param()

    [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get | Sort-Object Key
}
