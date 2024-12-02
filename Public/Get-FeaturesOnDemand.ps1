function Get-FeaturesOnDemand {
    <#
    .Notes
        AUTHOR: Skyler Hart
        CREATED: 09/25/2019 14:13:50
        LASTEDIT: 2020-08-31 21:44:37
        REQUIRES:
            Requires -RunAsAdministrator

    .LINK
        https://wanderingstag.github.io
    #>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {$Role = 'Admin'}
    else {$Role = 'User'}

    if ($Role -eq "Admin") {
        $info = (dism /online /get-capabilities | Where-Object {$_ -like "Capability Identity*" -or $_ -like "State*"})
        $idents = ($info | Where-Object {$_ -like "Capa*"}).Split(' : ') | Where-Object {$_ -ne "Capability" -and $_ -ne "Identity" -and $_ -ne $null -and $_ -ne ""}
        $state = $info | Where-Object {$_ -like "State*"}
        $state = $state -replace "State : "

        foreach ($ident in $idents) {
            $state2 = $state[$i]
            [PSCustomObject]@{
                CapabilityIdentity = $ident
                State = $state2
            }
        }
    }#if admin
    else {
        Write-Error "Not admin. Please run PowerShell as admin."
    }
}
