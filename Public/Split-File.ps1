function Split-File {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 04/30/2019 13:18:22
    LASTEDIT: 2021-12-17 21:13:05
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter the path of the file you want to split.",
            Mandatory=$true,
            Position=0
        )]
        [Alias('Source','InputLocation','SourceFile')]
        [string]$Path,

        [Parameter(HelpMessage = "Enter the path of where you want the part files placed.",
            Mandatory=$false,
            Position=1
        )]
        [Alias('OutputLocation','Output','DestinationPath','Destination')]
        [string]$DestinationFolder,

        [Parameter(HelpMessage = "Enter the size you want the part files to be. Can be bytes or you can specify a size. Ex: 100MB",
            Mandatory=$false,
            Position=2
        )]
        [Alias('Size','Newsize')]
        [int]$PartFileSize = 10MB
    )

    $FilePath = [IO.Path]::GetDirectoryName($Path)
    if (([string]::IsNullOrWhiteSpace($DestinationFolder)) -and $FilePath -ne "") {$FilePath = $FilePath + "\"}
    elseif ($null -ne $DestinationFolder -and $DestinationFolder -ne "") {
        $FilePath = $DestinationFolder + "\"
    }
    $FileName = [IO.Path]::GetFileNameWithoutExtension($Path)
    $Extension = [IO.Path]::GetExtension($Path)
    $Part = "_Part"

    if (!(Test-Path $FilePath)) {
        New-Item -Path $FilePath -ItemType Directory
    }

    $ReadObj = New-Object System.IO.BinaryReader([System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read))
	[Byte[]]$Buffer = New-Object Byte[] $PartFileSize
	[int]$BytesRead = 0

    $N = 1
    Write-Output "Saving part files to $FilePath"
    while (($BytesRead = $ReadObj.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
        $NewName = "{0}{1}{2}{3,2:00}{4}" -f ($FilePath,$FileName,$Part,$N,$Extension)
        $WriteObj = New-Object System.IO.BinaryWriter([System.IO.File]::Create($NewName))
        $WriteObj.Write($Buffer, 0, $BytesRead)
        $WriteObj.Close()
        $N++
    }
    $ReadObj.Close()
}
