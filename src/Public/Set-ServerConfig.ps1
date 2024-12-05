function Set-ServerConfig {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-10-24 20:09:27
    Last Edit: 2020-10-24 20:09:27
    Keywords:
    Requires:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    $sc = $Global:WSToolsConfig

    $netadapter = Get-NetAdapter
    foreach ($na in $netadapter) {
        $ia = $na.Name

        #DHCP
        if ($sc.SCDHCP -eq $true) {
            $na | Set-NetIPInterface -Dhcp Enabled
        }
        else {
            $na | Set-NetIPInterface -Dhcp Disabled
        }

        #IPv6
        if ($sc.SCIPv6 -eq $true) {
            Enable-NetAdapterBinding -InterfaceAlias $ia -ComponentID ms_tcpip6
        }
        else {
            Disable-NetAdapterBinding -InterfaceAlias $ia -ComponentID ms_tcpip6
        }

        #Link-Layer Topology Discovery Responder
        if ($sc.SCllrspndr -eq $true) {
            Enable-NetAdapterBinding -InterfaceAlias $ia -ComponentID ms_rspndr
        }
        else {
            Disable-NetAdapterBinding -InterfaceAlias $ia -ComponentID ms_rspndr
        }

        #Link-Layer Topology Discovery Mapper I/O
        if ($sc.SClltdio -eq $true) {
            Enable-NetAdapterBinding -InterfaceAlias $ia -ComponentID ms_lltdio
        }
        else {
            Disable-NetAdapterBinding -InterfaceAlias $ia -ComponentID ms_lltdio
        }

        #Offloading
        if ($sc.SCOffload -eq $true) {
            Set-NetAdapterAdvancedProperty -Name $ia -DisplayName "*Offloa*" -DisplayValue "Enabled"
        }
        else {
            Set-NetAdapterAdvancedProperty -Name $ia -DisplayName "*Offloa*" -DisplayValue "Disabled"
        }
    }#foreach network adapter

    #NetBIOS
    $NICS = Get-WmiObject Win32_NetworkAdapterConfiguration
    $nb = $sc.SCNetBios
    foreach ($NIC in $NICS) {
        $NIC.settcpipnetbios($nb)
    }

    #RDP
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value ($sc.SCRDP)

    #Server Manager
    if ($sc.SCServerMgr -eq $true) {
        Get-ScheduledTask -TaskName ServerManager | Enable-ScheduledTask
    }
    else {
        Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask
    }

    #WINS
    $wdns = $sc.SCWDNS
    $lmh = $sc.SCLMHost
    $nicClass = Get-WmiObject -list Win32_NetworkAdapterConfiguration
    $nicClass.enablewins($wdns,$lmh)
}
