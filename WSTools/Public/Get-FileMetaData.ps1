function Get-FileMetaData {
    <#
    .Synopsis
        This function gets file metadata and returns it as a custom PS Object.

    .Description
        This function gets file metadata using the Shell.Application object and
        returns a custom PSObject object that can be sorted, filtered or otherwise
        manipulated.

    .Example
        Get-FileMetaData -Path "e:\music"
        Gets file metadata for all files in the e:\music directory

    .Example
        Get-FileMetaData -Path (gci e:\music -Recurse -Directory).FullName
        This example uses the Get-ChildItem cmdlet to do a recursive lookup of
        all directories in the e:\music folder and then it goes through and gets
        all of the file metada for all the files in the directories and in the
        subdirectories.

    .Example
        Get-FileMetaData -Path "c:\fso","E:\music\Big Boi"
        Gets file metadata from files in both the c:\fso directory and the
        e:\music\big boi directory.

    .Example
        $meta = Get-FileMetaData -Path "E:\music"
        This example gets file metadata from all files in the root of the
        e:\music directory and stores the returned custom objects in a $meta
        variable for later processing and manipulation.

    .Parameter Path
        The path that is parsed for files

    .Notes
        NAME:  Get-FileMetaData
        AUTHOR: ed wilson, msft
        Edited By: Skyler Hart
        Original: 01/24/2014 14:08:24
        Last Edit: 2021-12-19 18:54:58
        KEYWORDS: Storage, Files, Metadata

    .Link
        https://devblogs.microsoft.com/scripting/
    #Requires -Version 2.0
    #>
    Param([string[]]$Path)
    foreach($sFolder in $Path) {
        $ItemInfo = Get-Item $sFolder | Select-Object *
        if ($ItemInfo.Mode -like "d-*") {
            $ItemType = "Directory"
            $FolderPath = $sFolder
        }
        else {
            $ItemType = "File"
            $FolderPath = $ItemInfo.DirectoryName
            $FileName = $ItemInfo.Name
        }
        $a = 0
        $objShell = New-Object -ComObject Shell.Application
        $objFolder = $objShell.namespace($FolderPath)
        $Metadata = foreach ($File in $objFolder.items()) {
            $FileMetaData = New-Object PSCustomObject
            for ($a ; $a  -le 266; $a++) {
                if($objFolder.getDetailsOf($File, $a)) {
                    $hash += @{$($objFolder.getDetailsOf($objFolder.items, $a)) = $($objFolder.getDetailsOf($File, $a))}
                    $FileMetaData | Add-Member $hash
                    $hash.clear()
                } #end if
            } #end for
            $a=0
            $FileMetaData
        } #end foreach $file
        if ($ItemType -eq "File") {
            $Metadata | Where-Object {$_.FileName -eq $FileName}
        }
        else {
            $Metadata
        }
    } #end foreach $sfolder
}
