function Test-NetworkSpeed {
<#
.SYNOPSIS
    Test network file transfer speeds, upload and download.
.DESCRIPTION
    Will test the file transfer speed of a generated file and provide you with the speed in Mbps (Megabit) and MBps (Megabyte) for uploads and downloads to a SMB file share.
.PARAMETER FileSize
    Specifies the file size of the file to be generated and transferred. Enter in the format xxKB, xxMB, or xxGB.
.PARAMETER LocalPath
    Specifies the path to the local folder where a file will be generated and where a file will be copied to.
.PARAMETER RemotePath
    Specifies the path to the remote folder where a file will be generated and where a file will be copied to.
.EXAMPLE
    C:\PS>Test-NetworkSpeed
    Example of how to use this cmdlet using the configured values in the WSTools config.ps1 file.
.EXAMPLE
    C:\PS>Test-NetworkSpeed -FileSize 500KB
    Another example of how to use this cmdlet but with the FileSize parameter. This example will generate 500 Kilobyte files to transfer.
.EXAMPLE
    C:\PS>Test-NetworkSpeed -FileSize 100MB
    Another example of how to use this cmdlet but with the FileSize parameter. This example will generate 100 Megabyte files to transfer.
.EXAMPLE
    C:\PS>Test-NetworkSpeed -FileSize 1GB
    Another example of how to use this cmdlet but with the FileSize parameter. This example will generate 1 Gigabyte files to transfer.
.EXAMPLE
    C:\PS>Test-NetworkSpeed -LocalPath C:\Transfer
    Another example of how to use this cmdlet but with the local path parameter.
.EXAMPLE
    C:\PS>Test-NetworkSpeed -LocalPath D:\Temp -RemotePath \\server1.wstools.dev\Transfer
    Another example of how to use this cmdlet but with the local and remote path parameters.
.INPUTS
    System.String, System.Int64
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    Network, troubleshooting, speedtest, test
.NOTES
    Author: Skyler Hart
    Created: 2022-06-24 18:21:40
    Last Edit: 2022-06-24 18:21:40
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [string]$LocalPath,

        [Parameter(
            Mandatory=$false
        )]
        [string]$RemotePath,

        [Parameter(
            Mandatory=$false
        )]
        [int64]$FileSize
    )

    Begin {
        Write-Verbose "$(Get-Date): Start Network Speed Test"
        $config = $Global:WSToolsConfig
        $filename = (Get-Date -Format yyyyMMddHHmmssms) + "_testfile"

        if ([string]::IsNullOrWhiteSpace($FileSize)) {
            $FileSize = $config.NSFileSize
        }
        Write-Verbose "$(Get-Date): File size is: $FileSize"

        if ([string]::IsNullOrWhiteSpace($LocalPath)) {
            $LocalPath = $config.NSLocal
            $LocalFile = $LocalPath + "\" + $filename + "_upload.dat"
        }
        else {
            $LocalFile = $LocalPath + "\" + $filename + "_upload.dat"
        }
        Write-Verbose "$(Get-Date): LocalPath is: $LocalPath"
        Write-Verbose "$(Get-Date): LocalFile is: $LocalFile"

        if ([string]::IsNullOrWhiteSpace($RemotePath)) {
            $RemotePath = $config.NSRemote
            $RemoteFile = $RemotePath + "\" + $filename + "_download.dat"
        }
        else {
            $RemoteFile = $RemotePath + "\" + $filename + "_download.dat"
        }

        $LocalDownFile = $LocalPath + "\" + $filename + "_download.dat"
        $RemoteUpFile = $RemotePath + "\" + $filename + "_upload.dat"

        Write-Verbose "$(Get-Date): RemotePath is: $RemotePath"
        Write-Verbose "$(Get-Date): RemoteFile is: $RemoteFile"

        try {
            Write-Verbose "$(Get-Date): Create local file"
            $writelocalfile = new-object System.IO.FileStream $LocalFile, Create, ReadWrite
            $writelocalfile.SetLength($FileSize)
            $writelocalfile.Close()

            $UpSize = Get-Item $LocalFile | Measure-Object -Property Length -Sum | Select-Object -ExpandProperty Sum
        }
        catch {
            Write-Warning "Unable to create local file at $LocalFile"
            Write-Warning "Error: $($Error[0])"
            break
        }

        try {
            Write-Verbose "$(Get-Date): Create remote file"
            $writeremotefile = new-object System.IO.FileStream $RemoteFile, Create, ReadWrite
            $writeremotefile.SetLength($FileSize)
            $writeremotefile.Close()

            $DownSize = Get-Item $RemoteFile | Measure-Object -Property Length -Sum | Select-Object -ExpandProperty Sum
        }
        catch {
            Write-Warning "Unable to create remote file at $RemoteFile"
            Write-Warning "Error: $($Error[0])"
            break
        }
    }
    Process {
        Write-Verbose "$(Get-Date): Beginning Upload Test"
        try {
            $UploadTest = Measure-Command {
                Copy-Item $LocalFile $RemotePath -ErrorAction Stop
            }
            $UStatus = "Complete"
        }
        catch {
            Write-Warning "Error during upload test: $($Error[0])"
            $UStatus = "Error"
            $UpMbps = 0
            $UploadTest = New-TimeSpan -Days 0
        }
        $UploadSeconds = $UploadTest.TotalSeconds
        Write-Verbose "$(Get-Date): File upload took: $UploadSeconds"

        Write-Verbose "$(Get-Date): Beginning Download Test"
        try {
            $DownloadTest = Measure-Command {
                Copy-Item $RemoteFile $LocalPath -ErrorAction Stop
            }
            $DStatus = "Complete"
        }
        catch {
            Write-Warning "Error during download test: $($Error[0])"
            $DStatus = "Error"
            $DownMbps = 0
            $DownloadTest = New-TimeSpan -Days 0
        }
        $DownloadSeconds = $DownloadTest.TotalSeconds
        Write-Verbose "$(Get-Date): File upload took: $DownloadSeconds"

        Write-Verbose "$(Get-Date): Removing generated files."
        Remove-Item $LocalFile -Force -ErrorAction SilentlyContinue
        Remove-Item $RemoteFile -Force -ErrorAction SilentlyContinue
        Remove-Item $LocalDownFile -Force -ErrorAction SilentlyContinue
        Remove-Item $RemoteUpFile -Force -ErrorAction SilentlyContinue

        Write-Verbose "$(Get-Date): Calculating speeds"
        $UpMbps = [Math]::Round((($UpSize * 8) / $UploadSeconds) / 1048576,2)
        $UpMB = [Math]::Round((($UpSize) / $UploadSeconds) / 1024 / 1024,2)
        $DownMbps = [Math]::Round((($DownSize * 8) / $DownloadSeconds) / 1048576,2)
        $DownMB = [Math]::Round((($DownSize) / $DownloadSeconds) / 1024 / 1024,2)

        Write-Verbose "$(Get-Date): Generating results"
        [PSCustomObject]@{
            FileSizeMB = ([Math]::Round($UpSize/1024/1024,2))
            DownloadStatus = $DStatus
            DownloadSeconds = $DownloadSeconds
            DownMbps = $DownMbps
            DownMBperSecond = $DownMB
            UploadStatus = $UStatus
            UploadSeconds = $UploadSeconds
            UpMbps = $UpMbps
            UpMBperSecond = $UpMB
        }#new object
    }
}
