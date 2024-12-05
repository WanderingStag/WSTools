function Get-CertificateInventory {
    <#
    .NOTES
        Author: Skyler Hart
        Created: 2021-11-18 22:44:53
        Last Edit: 2021-11-18 22:44:53
        Keywords:

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [Alias('Get-CertInv','Get-CertInfo')]
    param()

    $cpath = @('Cert:\LocalMachine\My','Cert:\LocalMachine\Remote Desktop')

    $os = (Get-WmiObject Win32_OperatingSystem).ProductType

    if ($os -eq 1) {$type = "Workstation"}
    elseif (($os -eq 2) -or ($os -eq 3)) {$type = "Server"}

    $certinfo = foreach ($cp in $cpath) {
        Get-ChildItem $cp | Select-Object *
    }

    $certs = foreach ($cert in $certinfo) {
        $cp = $cert.PSParentPath -replace "Microsoft.PowerShell.Security\\Certificate\:\:",""

        if (($cert.Subject) -eq ($cert.Issuer)) {$ss = $true}
        else {$ss = $false}

        $daystoexpire = (New-TimeSpan -Start (get-date) -End ($cert.NotAfter)).Days

        [PSCustomObject]@{
            ComputerName = ($env:computername)
            ProductType = $type
            Subject = ($cert.Subject)
            Issuer = ($cert.Issuer)
            Location = $cp
            SelfSigned = $ss
            ValidFrom = ($cert.NotBefore)
            ValidTo = ($cert.NotAfter)
            DaysToExpiration = $daystoexpire
            SerialNumber = ($cert.SerialNumber)
            Thumbprint = ($cert.Thumbprint)
        }# new object
    }
    $certs | Select-Object ComputerName,ProductType,Location,Subject,Issuer,SelfSigned,ValidFrom,ValidTo,DaysToExpiration,SerialNumber,Thumbprint | Sort-Object Subject
}
