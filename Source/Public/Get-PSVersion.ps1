function Get-PSVersion {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/27/2019 12:35:00
    LASTEDIT: 02/27/2019 12:35:00
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Get-PowerShellVersion')]
    Param (
        [Parameter(HelpMessage = "Enter one or more computer names separated by commas.",
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter()]
        [string[]]$Ignore
    )

    $compinfo = $null
    $compinfo = @()

    $ignorelist = @('tvyx-fs-002p','tvyx-fs-004p','tvyx-cl-001p','tvyx-cl-001v','tvyx-cl-002p','tvyx-cl-002v','tvyx-dc-001v','tvyx-dc-002v','`$tvyx.siem','52TVYX-HBGP-001v','TVYX-VC-001P','tvyx-vmh-001','hqsipfile','tvyxw-lsms','hqceoepo','hqceofile','ceonetapp')
    foreach ($ig in $Ignore) {
        $ignorelist += $ig
    }

    $i = 0
    $number = $ComputerName.length
    $compinfo = foreach ($comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting installed PowerShell version on multiple computers" -status "Computer $i of $number. Currently checking: $comp. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        if ($ignorelist -notmatch $comp) {
            try {
                $info = Get-Item \\$comp\c$\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ErrorAction Stop
                $build = $info.VersionInfo.ProductVersion
                $filebuild = $info.VersionInfo.FileBuildPart
                $osinfo = Get-OperatingSystem $comp -ErrorAction Stop
                $os = $osinfo.OS

                if ($build -like "6.0*") {$ver = "1"}
                elseif ($build -like "6.1*") {$ver = "2"}
                elseif ($build -like "6.2*") {$ver = "3"}
                elseif ($build -like "6.3*") {$ver = "4"}
                elseif ($build -like "10.*") {
                    if ($filebuild -lt "14300") {$ver = "50"}
                    elseif ($filebuild -ge "14300") {$ver = "51"}
                }
                else {$ver = "Build $build"}

                if ($os -match "2008" -and $os -notmatch "2008 R2") {$maxver = "3"}
                elseif ($os -match "2008 R2") {$maxver = "51"}
                elseif ($os -match "2012 R2") {$maxver = "51"}
                elseif ($os -match "2016" -or $os -match "2019" -or $os -match "Windows 10" -or $os -match "Windows 11") {$maxver = "7"}

                if ($ver -lt $maxver) {$status = "Outdated"}
                elseif ($ver -ge $maxver) {$status = "Current"}
                else {$ver = "NA"}

                [PSCustomObject]@{
                    ComputerName = $comp
                    InstalledPowerShellVersion = $ver
                    Status = $status
                    HighestSupportedVersion = $maxver
                    OS = $os
                }#new object
            }
            catch {
                [PSCustomObject]@{
                    ComputerName = $comp
                    InstalledPowerShellVersion = "Unable to connect"
                    Status = "NA"
                    HighestSupportedVersion = "NA"
                    OS = "NA"
                }#new object
            }
        }
    }
    $compinfo
}
