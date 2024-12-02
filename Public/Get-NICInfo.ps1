# Working for the most part
# add search base filter so that you can search a specific OU or OUs
# Get-NICInfo (Get-Content .\computers.txt) | where {$_.DHCPEnabled -eq $false} | select Computer,DHCPEnabled,IPv4
# Get-ADComputer -Filter * | foreach {get-nicinfo $_.name | select Name,DHCPEnabled,IPv4} | Export-Csv .\nic.csv -NoTypeInformation
# Get-ADComputer -Filter * -SearchBase "OU=test,DC=testdomain,DC=com" | foreach {Get-NICInfo $_.name}
# Add check for autoipv6
# Put subnet check under IP check so can move autoipv6 subnet
function Get-NICInfo {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 09/21/2017 13:06:33
    LASTEDIT: 09/21/2017 13:06:33
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $i = 0
    $number = $ComputerName.length

    foreach ($Comp in $ComputerName) {
        Clear-Variable -Name ints,int,intname,mac,DHCPEnabled,DHCPServer,ipv6DHCPServer,dhsraddr,IPv4,ipv42,ipv6auto,IPv6,IPv62,`
            subnet,subnet2,ipv6subnet,ipv6subnet2,gateway,gateway2,ipv6gateway,ipv6gateway2,dns1,dns2,dns3,ipv6dns1,ipv6dns2,`
            ipv6dns3,ipv6auto,autosub -ErrorAction SilentlyContinue | Out-Null

        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting NIC info on computers. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        try {
            $wmio = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $Comp -ErrorAction Stop
            $wwhr = (($wmio) | Where-Object {$_.IPEnabled -eq $true -and $null -ne $_.IPAddress})
            $ints = ($wwhr | Select-Object -property *)

            if ($null -ne $ints) {
                foreach ($int in $ints) {
                    Clear-Variable -Name MAC,intname,DHCPEnabled,DHCPServer,dhsraddr,ipv6DHCPServer,IPv4,ipv42,ipv6auto,IPv6,`
                        IPv62,subnet,subnet2,ipv6subnet,ipv6subnet2,gateway,gateway2,ipv6gateway,ipv6gateway2,dns1,dns2,dns3,`
                        ipv6dns1,ipv6dns2,ipv6dns3,ipv6auto,autosub,ipv4addrs,ipv6addrs,ipv6addrauto,ipv4subnets,ipv6subnets,`
                        ipv4gateways,ipv6gateways,ipv4dhcpsrvs,ipv6dhcpsrvs,ipv4dnssrvs -ErrorAction SilentlyContinue | Out-Null

                    #Get interface Desscription
                    $intname = $int.Description

                    #Figure out if Static or DHCP
                    if ($int.DHCPEnabled -eq $False) {$DHCPEnabled = "False"}#if int static
                    else {$DHCPEnabled = "True"}#else int dhcp

                    #Get IP addresses
                    foreach ($ipaddr in $int.IPAddress) {
                        if ($ipaddr -match "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv4addrs += $ipaddr}#if ipv4addrs
                        if ($ipaddr -notmatch "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" -and $ipaddr -notlike "fe80*") {[string[]]$ipv6addrs += $ipaddr}#if ipv6addrs
                        if ($ipaddr -notmatch "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" -and $ipaddr -like "fe80*") {[string[]]$ipv6addrauto += $ipaddr}#if auto ipv6addr
                    }#foreach ipaddr
                    if ($null -ne $ipv4addrs) {
                        $IPv4 = $ipv4addrs[0]
                        $IPv42 = $ipv4addrs[1]}#if ipv4 not null
                    if (null -ne $$ipv6addrs) {
                        $IPv6 = $ipv6addrs[0]
                        $IPv62 = $ipv6addrs[1]}#if ipv6 not null
                    if ($null -ne $ipv6addrauto) {
                        $ipv6auto = $ipv6addrauto[0]}#if ipv6 auto not null

                    #Get subnet addresses
                    foreach ($subaddr in $int.IPSubnet) {
                        if ($subaddr -match "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv4subnets += $subaddr}#if ipv4addrs
                        if ($subaddr -match "[0-9]{1,2}" -and $subaddr -notmatch "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv6subnets += $subaddr}#if ipv6addrs
                    }#foreach subnet
                    if ($null -ne $ipv4subnets) {
                        $subnet = $ipv4subnets[0]
                        $subnet2 = $ipv4subnets[1]}#if ipv4 not null
                    if ($null -ne $ipv6subnets) {
                        if ($null -ne $ipv6addrauto) {
                            $autosub = $ipv6subnets[0]
                            $ipv6subnet = $ipv6subnets[1]
                            $ipv6subnet2 = $ipv6subnets[2]
                        }#if there is an auto assigned ipv6 address
                        else {
                            $ipv6subnet = $ipv6subnets[0]
                            $ipv6subnet2 = $ipv6subnets[1]
                        }#else there is no auto assigned IPv6 address
                    }#if ipv6 not null

                    #Get Gateway addresses
                    foreach ($gwaddr in $int.DefaultIPGateway) {
                        if ($gwaddr -match "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv4gateways += $gwaddr}#if ipv4addrs
                        if ($gwaddr -notmatch "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv6gateways += $gwaddr}#if ipv6addrs
                    }#foreach gateway
                    if ($null -ne $ipv4gateways) {
                        $gateway = $ipv4gateways[0]
                        $gateway2 = $ipv4gateways[1]}#if ipv4 not null
                    if ($null -ne $ipv6gateways) {
                        $ipv6gateway = $ipv6gateways[0]
                        $ipv6gateway2 = $ipv6gateways[1]}#if ipv6 not null

                    #Get DHCPServers
                    foreach ($dhsraddr in $int.DHCPServer) {
                        if ($dhsraddr -match "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv4dhcpsrvs += $dhsraddr}#if ipv4addrs
                        if ($dhsraddr -notmatch "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv6dhcpsrvs += $dhsraddr}#if ipv6addrs
                    }#foreach dhcp server
                    if ($null -ne $ipv4dhcpsrvs) {$DHCPServer = $ipv4dhcpsrvs[0]}#if ipv4 not null
                    if ($null -ne $ipv6dhcpsrvs) {$ipv6DHCPServer = $ipv6dhcpsrvs[0]}#if ipv6 not null

                    #Get MAC address
                    $MAC = $int.MACAddress

                    #Get DNS servers
                    foreach ($dnssraddr in $int.DNSServerSearchOrder) {
                        if ($dnssraddr -match "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv4dnssrvs += $dnssraddr}#if ipv4addrs
                        #if ($dnssraddr -notmatch "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") {[string[]]$ipv6dnssrvs += $dnssraddr}#if ipv6addrs
                    }#foreach dns server
                    $dns1 = $ipv4dnssrvs[0]
                    $dns2 = $ipv4dnssrvs[1]
                    $dns3 = $ipv4dnssrvs[2]
                    #$ipv6dns1 = $ipv6dnssrvs[0]
                    #$ipv6dns2 = $ipv6dnssrvs[1]
                    #$ipv6dns3 = $ipv6dnssrvs[2]

                    #Create Objects
                    [PSCustomObject]@{
                        Name = $Comp
                        Interface = $intname
                        MACAddress = $mac
                        DHCPEnabled = $DHCPEnabled
                        DHCPServer = $DHCPServer
                        IPv6DHCPServer = $ipv6DHCPServer
                        IPv4 = $IPv4
                        IPv4_2 = $ipv42
                        IPv6 = $IPv6
                        IPv6_2 = $IPv62
                        Subnet = $subnet
                        Subnet2 = $subnet2
                        IPv6Subnet = $ipv6subnet
                        IPv6Subnet2 = $ipv6subnet2
                        IPv4Gateway = $gateway
                        IPv4Gateway2 = $gateway2
                        IPv6Gateway = $ipv6gateway
                        IPv6Gateway2 = $ipv6gateway2
                        AutoIPv6 = $ipv6auto
                        AutoIPv6Subnet = $autosub
                        DNSServer1 = $dns1
                        DNSServer2 = $dns2
                        DNSServer3 = $dns3
                        #IPv6DNSServer1 = $ipv6dns1
                        #IPv6DNSServer2 = $ipv6dns2
                        #Pv6DNSServer3 = $ipv6dns3
                    }#new object
                }#foreach interface
            }#if ints not null
        }#try

        catch {
            [PSCustomObject]@{
                Name = $Comp
                Interface = "Comm Error"
                MACAddress = $mac
                DHCPEnabled = $DHCPEnabled
                DHCPServer = $DHCPServer
                IPv6DHCPServer = $ipv6DHCPServer
                IPv4 = $IPv4
                IPv4_2 = $ipv42
                IPv6 = $IPv6
                IPv6_2 = $IPv62
                Subnet = $subnet
                Subnet2 = $subnet2
                IPv6Subnet = $ipv6subnet
                IPv6Subnet2 = $ipv6subnet2
                IPv4Gateway = $gateway
                IPv4Gateway2 = $gateway2
                IPv6Gateway = $ipv6gateway
                IPv6Gateway2 = $ipv6gateway2
                AutoIPv6 = $ipv6auto
                AutoIPv6Subnet = $autosub
                DNSServer1 = $dns1
                DNSServer2 = $dns2
                DNSServer3 = $dns3
                #IPv6DNSServer1 = $ipv6dns1
                #IPv6DNSServer2 = $ipv6dns2
                #Pv6DNSServer3 = $ipv6dns3
            }#new object
        }#catch
    }#foreach computer
}
