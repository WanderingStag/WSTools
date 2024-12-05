function Restart-KDC {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 02:45:00
    LASTEDIT: 2022-09-04 12:38:21
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN','ComputerName')]
        [string]$DC = "$env:COMPUTERNAME",
        [Switch]$All
    )
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        if (!($All)) {
            Write-Output "Restarting KDC service on $DC"
            try {Restart-Service -inputobject $(Get-Service -ComputerName $DC -Name kdc) -Force}
            catch {Throw "Unable to connect to $DC or failed to restart service."}
        }#if not all
        elseif ($All) {
            $AllDCs = (Get-ADForest).Domains | ForEach-Object {Get-ADDomainController -Filter * -Server $_}
            foreach ($Srv in $AllDCs) {
                $SrvName = $Srv.HostName
                Write-Output "Restarting KDC service on $SrvName"
                try {Restart-Service -inputobject $(Get-Service -ComputerName $SrvName -Name kdc) -Force}
                catch {Throw "Unable to connect to $DC or failed to restart service."}
            }#foreach dc
        }#elseif
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}
