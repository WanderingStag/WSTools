function Get-DirectoryStat {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2020-08-09 10:07:49
        Last Edit: 2020-08-09 21:35:14

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the path of the folder you want stats on. Ex: C:\Temp or \\computername\c$\temp",
            Mandatory=$true,
            Position=0,
            ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('Dir','Folder','UNC')]
        [string[]]$DirectoryName
    )
    Begin {}
    Process {
        foreach ($Directory in $DirectoryName) {
            $stats = [PSCustomObject]@{
                Directory = $null
                FileCount = 0
                SizeBytes = [long]0
                SizeKB = 0
                SizeMB = 0
                SizeGB = 0
                Over100MB = 0
                Over1GB = 0
                Over5GB = 0
            }
            $stats.Directory = $Directory
            foreach ($d in [system.io.Directory]::EnumerateDirectories($Directory)) {
                foreach ($f in [system.io.Directory]::EnumerateFiles($d)) {
                    $length = (New-Object io.FileInfo $f).Length
                    $stats.FileCount++
                    $stats.SizeBytes += $length
                    if ($length -gt 104857600) {$stats.Over100MB++}
                    if ($length -gt 1073741824) {$stats.Over1GB++}
                    if ($length -gt 5368709120) {$stats.Over5GB++}
                    $stats.SizeKB += ("{0:N2}" -f ($length / 1KB))
                    $stats.SizeMB += ("{0:N2}" -f ($length / 1MB))
                    $stats.SizeGB += ("{0:N2}" -f ($length / 1GB))
                } #foreach file
            }#foreach subfolder get stats
            foreach ($f in [system.io.Directory]::EnumerateFiles($Directory)) {
                $length = (New-Object io.FileInfo $f).Length
                $stats.FileCount++
                $stats.SizeBytes += $length
                if ($length -gt 104857600) {$stats.Over100MB++}
                if ($length -gt 1073741824) {$stats.Over1GB++}
                if ($length -gt 5368709120) {$stats.Over5GB++}
                $stats.SizeKB += ("{0:N2}" -f ($length / 1KB))
                $stats.SizeMB += ("{0:N2}" -f ($length / 1MB))
                $stats.SizeGB += ("{0:N2}" -f ($length / 1GB))
            }#foreach file
            $stats | Select-Object Directory,FileCount,Over100MB,Over1GB,Over5GB,SizeBytes,SizeKB,SizeMB,SizeGB
        }#foreach directory in #directoryname
    }
    End {}
}
