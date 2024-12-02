function Clear-ImproperProfileCopy {
    <#
    .Synopsis
        Clears Application Data folder that was improperly copied which happens when copy and pasting a profile.

    .Description
        Copies nested Application Data folders to a higher level (by default to C:\f2) and deletes them.

    .Example
        Clear-ImproperProfileCopy -Source \\fileserver\example\user -Destination E:\f2
        Clears nested Application Data folders from \\fileserver\example\user. Uses E:\f2 as the folder for
        clearing.

    .Example
        Clear-ImproperProfileCopy E:\temp\Profile E:\f2
        Clears nested Application Data folders from E:\temp\Profile. Uses E:\f2 as the folder for clearing.

    .Parameter Source
        Specifies the folder that contains the Application Data folder causing issues.

    .Parameter Destination
        Specifies the folder that is used to copy the nested folders to and deletes them.

    .Notes
        AUTHOR: Skyler Hart
        CREATED: 06/11/2016 20:37:14
        LASTEDIT: 2020-04-15 21:54:21
        KEYWORDS: user, profile, app data, application data, cleanup, clear, improper

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Source,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$Destination
    )

    if (!($Destination)) {
        New-Item $Destination -ItemType Directory
        $cd = $true
    }
    else {
        $cd = $false
    }

    $folder1 = $Source + "\Application Data"
    $folder2 = $Destination + "\Application Data"
    $folder3 = $Source + "Application Data\Application Data\Application Data\Application Data"
    $folder4 = $Destination + "\Application Data\Application Data\Application Data\Application Data"

    $i = 0
    do {
        Move-Item -Path $folder3 -Destination $f2
        start-sleep 1
        Remove-Item -Path $folder1 -Recurse -Force
        Remove-Item -Path $folder2 -Recurse -Force
        Move-Item -Path $folder4 -Destination $f1
        start-sleep 1
        Remove-Item -Path $folder2 -Recurse -Force
        Remove-Item -Path $folder1 -Recurse -Force
        Start-Sleep 1
        $i++
        Write-Output "Completed Pass $i"
    }
    until (!(Test-Path $folder3))

    if ($cd) {
        Remove-Item -Path $Destination -Recurse -Force
    }
}
