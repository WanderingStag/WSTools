function Get-BitLockerStatus {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2020-04-22 22:10:27
        Last Edit: 2020-04-22 22:10:27
        Keywords: BitLocker, Local, Remote, manage, manage-bde, bde
        Requires:
            -RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$false
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $overall = @()
    foreach ($Comp in $ComputerName) {
        $i = 0
        try {
            $ErrorActionPreference = "Stop"
            $bi = manage-bde.exe -ComputerName $Comp -status

            # Get Drives
            $drives = @()
            $d = $bi | Select-String -Pattern 'Volume '
            $drives += $d | ForEach-Object {
                $_.ToString().Trim().Substring(0,8) -replace "Volume ",""
            }# foreach drive

            # Get Size
            $size = @()
            $si = $bi | Select-String -Pattern 'Size'
            $size += $si | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach size

            # Get BitLocker Version
            $ver = @()
            $v = $bi | Select-String -Pattern 'BitLocker Version'
            $ver += $v | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach version

            # Get Status
            $status = @()
            $s = $bi | Select-String -Pattern 'Conversion Status'
            $status += $s | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach status

            # Get Percent Encrypted
            $per = @()
            $p = $bi | Select-String -Pattern 'Percentage Encrypt'
            $per += $p | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach percentage

            # Get Encryption Method
            $em = @()
            $e = $bi | Select-String -Pattern 'Encryption Method'
            $em += $e | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach encryption method

            # Get Protection Status
            $ps = @()
            $pi = $bi | Select-String -Pattern 'Protection Status'
            $ps += $pi | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach pro status

            # Get Lock Status
            $ls = @()
            $li = $bi | Select-String -Pattern 'Lock Status'
            $ls += $li | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach Lock Status

            # Get ID Field
            $id = @()
            $ii = $bi | Select-String -Pattern 'Identification Field'
            $id += $ii | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach ID

            # Get Key Protectors
            $key = @()
            $k = $bi | Select-String -Pattern 'Key Protect'
            $key += $k | ForEach-Object {
                $_.ToString().Trim().Substring(22)
            }# foreach
        }# try
        catch {
            Write-Output "Unable to connect to $Comp"
            $status = "Insuffiect permissions or unable to connect"
        }

        $num = $drives.Length
        do {
            $overall += [PSCustomObject]@{
                ComputerName = $Comp
                Drive = $drives[$i]
                Size = $size[$i]
                BitLockerVersion = $ver[$i]
                Status = $status[$i]
                PercentEncrypted = $per[$i]
                EncryptionMethod = $em[$i]
                ProtectionStatus = $ps[$i]
                LockStatus = $ls[$i]
                ID_Field = $id[$i]
                KeyProtectors = $key[$i]
            }
            $i++
        }#do
        while ($i -lt $num)
    }# foreach comp
    $overall | Select-Object ComputerName,Drive,Size,BitLockerVersion,Status,PercentEncrypted,EncryptionMethod,ProtectionStatus,LockStatus,ID_Field,KeyProtectors | Sort-Object ComputerName,Drive
}
