function Get-CommandList {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2021-08-06 23:09:24
        Last Edit: 2021-12-16 21:41:15

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Path','Output','OutputPath','Destination')]
        [string]$ExportPath,

        [switch]$All
    )

    if ($All) {
        $commands = Get-Command * | Select-Object HelpUri,ResolvedCommandName,Definition,Name,CommandType,ModuleName,RemotingCapability,Path,FileVersionInfo
    }
    else {$commands = Get-Command -All | Select-Object HelpUri,ResolvedCommandName,Definition,Name,CommandType,ModuleName,RemotingCapability,Path,FileVersionInfo}
    $commands = $commands | Select-Object HelpUri,ResolvedCommandName,Definition,Name,CommandType,ModuleName,RemotingCapability,Path,FileVersionInfo -Unique
    $slist = Import-Csv $PSScriptRoot\CommandListModules.csv

    $i = 0
    $number = $commands.length
    $info = @()
    $info = foreach ($c in $commands) {
        # Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Generating information for each command." -status "Command $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $commands.length)  * 100)
        }# if length

        $rn = $c.ResolvedCommandName
        if ($c.CommandType -eq "Alias") {
            if ([string]::IsNullOrWhiteSpace($c.ResolvedCommandName)) {
                $rn = $c.Definition
            }
            else {
                $rn = $c.ResolvedCommandName
            }
        }
        $mn = $c.ModuleName
        $sli = $slist | Where-Object {$_.Module -eq $mn}
        if ([string]::IsNullOrWhiteSpace($sli)) {
            [PSCustomObject]@{
                CommandType = ($c.CommandType)
                Name = ($c.Name)
                ResolvedName = $rn
                Path = ($c.Path)
                Description = ($c.FileVersionInfo.FileDescription)
                ModuleName = ($c.ModuleName)
                UsedByOrganization = $null
                RemotingCapability = ($c.RemotingCapability)
                UsedRemotely = $null
                Purpose = $null
                Reference = $null
                HelpUri = ($c.HelpUri)
            }# new object
        }
        else {
            [PSCustomObject]@{
                CommandType = ($c.CommandType)
                Name = ($c.Name)
                ResolvedName = $rn
                Path = ($c.Path)
                Description = ($c.FileVersionInfo.FileDescription)
                ModuleName = ($c.ModuleName)
                UsedByOrganization = ($sli.UsedByOrganization)
                RemotingCapability = ($c.RemotingCapability)
                UsedRemotely = ($sli.Remote)
                Purpose = ($sli.Purpose)
                Reference = ($sli.Reference)
                HelpUri = ($c.HelpUri)
            }# new object
        }
    }

    if ([string]::IsNullOrWhiteSpace($ExportPath)) {
        $info | Select-Object CommandType,Name,ResolvedName,Path,Description,ModuleName,UsedByOrganization,RemotingCapability,UsedRemotely,Purpose,Reference,HelpUri
    }
    else {
        $info | Select-Object CommandType,Name,ResolvedName,Path,Description,ModuleName,UsedByOrganization,RemotingCapability,UsedRemotely,Purpose,Reference,HelpUri | Export-Csv $ExportPath -NoTypeInformation -Force
    }
}
