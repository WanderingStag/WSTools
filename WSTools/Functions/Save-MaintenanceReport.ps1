function Save-MaintenanceReport {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-06-16 14:39:04
    Last Edit: 2023-03-22 08:26:11
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
	[CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [int32]$Days = ((Get-Date -Format yyyyMMdd) - ((Get-Date -Format yyyyMMdd).Substring(0,6) + "01"))
    )

    $UHPath = ($Global:WSToolsConfig).UHPath
    $dt = get-date -Format yyyyMMdd
    $sp = $UHPath + "\" + $dt + "_MaintenanceReport.csv"
    $stime = (Get-Date) - (New-TimeSpan -Day $Days)
    $info = Get-ChildItem $UHPath | Where-Object {$_.LastWriteTime -gt $stime -and $_.Name -notlike "*MaintenanceReport.csv"} | Select-Object FullName -ExpandProperty FullName
    $finfo = Import-Csv ($info)
    $finfo | Select-Object Date,ComputerName,KB,Result,Title,Description,Category,ClientApplicationID,SupportUrl | Where-Object {$_.Date -gt $stime} | Sort-Object Date,ComputerName -Descending | Export-Csv $sp -NoTypeInformation
}
