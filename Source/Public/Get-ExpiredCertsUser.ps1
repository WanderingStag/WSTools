function Get-ExpiredCertsUser {
    <#
    .Notes
        AUTHOR: Skyler Hart
        CREATED: 10/04/2018 21:08:39
        LASTEDIT: 10/04/2018 21:09:34

    .LINK
        https://wanderingstag.github.io
    #>
    $cd = Get-Date
    $certs = Get-ChildItem -Path Cert:\CurrentUser -Recurse | Select-Object *

    $excerts = $null
    $excerts = @()

    foreach ($cer in $certs) {
        if ($null -ne $cer.NotAfter -and $cer.NotAfter -lt $cd) {
            $excerts += ($cer | Where-Object {$_.PSParentPath -notlike "*Root"} | Select-Object FriendlyName,SubjectName,NotBefore,NotAfter,SerialNumber,EnhancedKeyUsageList,DnsNameList,Issuer,Thumbprint,PSParentPath)
        }
    }
}
