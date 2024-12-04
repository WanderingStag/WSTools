function Restart-DNS {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/08/2017 17:23:43
    LASTEDIT: 2022-09-04 12:35:59
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
            Write-Output "Restarting DNS service on $DC"
            try {Restart-Service -inputobject $(Get-Service -ComputerName $DC -Name DNS) -Force}
            catch {Throw "Unable to connect to $DC or failed to restart service."}
        }#if not all
        elseif ($All) {
            $AllDCs = (Get-ADForest).Domains | ForEach-Object {Get-ADDomainController -Filter * -Server $_}
            foreach ($Srv in $AllDCs) {
                $SrvName = $Srv.HostName
                Write-Output "Restarting DNS service on $SrvName"
                try {Restart-Service -inputobject $(Get-Service -ComputerName $SrvName -Name DNS) -Force}
                catch {Throw "Unable to connect to $DC or failed to restart service."}
            }#foreach dc
        }#elseif
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}
