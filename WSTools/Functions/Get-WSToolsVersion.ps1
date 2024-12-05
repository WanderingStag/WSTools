function Get-WSToolsVersion {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/09/2018 00:23:25
    LASTEDIT: 02/14/2018 11:05:37
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('WSToolsVersion')]
    Param (
        [Parameter(Mandatory=$false)]
        [Switch]$Remote,

        [Parameter(Mandatory=$false)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName
    )

    if ($Remote) {
        foreach ($comp in $ComputerName) {
            $path = "\\$comp\c$\Program Files\WindowsPowerShell\Modules\WSTools\WSTools.psd1"
            try {
                $info = Test-ModuleManifest $path
                $ver = $info.Version
            }
            catch {
                $ver = "NA"
            }

            try {
                $info2 = Get-Item $path
                $i2 = $info2.LastWriteTime
            }
            catch {
                $i2 = "NA"
            }

            $version = [PSCustomObject]@{
                ComputerName = $comp
                WSToolsVersion = $ver
                Date = $i2
                Path = $path
            }#new object
            $version | Select-Object ComputerName,WSToolsVersion,Date,Path
        }
    }
    else {
        $path = "$PSScriptRoot\WSTools.psd1"
        try {
            $info = Test-ModuleManifest $path
            $ver = $info.Version
        }
        catch {
            $ver = "NA"
        }

        try {
            $info2 = Get-Item $path
            $i2 = $info2.LastWriteTime
        }
        catch {
            $i2 = "NA"
        }
        $cn = $env:COMPUTERNAME

        $version = [PSCustomObject]@{
            ComputerName = $cn
            WSToolsVersion = $ver
            Date = $i2
            Path = $path
        }#new object
        $version | Select-Object ComputerName,WSToolsVersion,Date,Path
    }
}
