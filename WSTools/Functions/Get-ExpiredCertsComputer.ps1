function Get-ExpiredCertsComputer {
    <#
    .Notes
        AUTHOR: Skyler Hart
        CREATED: 10/04/2018 20:46:38
        LASTEDIT: 10/04/2018 21:08:31

    .LINK
        https://wanderingstag.github.io
    #>
    $cd = Get-Date
    $certs = Get-ChildItem -Path Cert:\LocalMachine -Recurse | Select-Object *

    $excerts = $null
    $excerts = @()

    foreach ($cer in $certs) {
        if ($null -ne $cer.NotAfter -and $cer.NotAfter -lt $cd) {
            $excerts += ($cer | Where-Object {$_.PSParentPath -notlike "*Root"} | Select-Object FriendlyName,SubjectName,NotBefore,NotAfter,SerialNumber,EnhancedKeyUsageList,DnsNameList,Issuer,Thumbprint,PSParentPath)
        }
    }
}
