function Get-IPrange {
    <#
    .SYNOPSIS
        Lists IPs within a range, subnet, or CIDR block.

    .DESCRIPTION
        Lists IPs within a range, subnet, or CIDR block.

    .PARAMETER CIDR
        Specifies what CIDR block notation you want to list IPs from.

    .PARAMETER End
        The ending IP in a range.

    .PARAMETER IP
        An IP from the subnet mask or CIDR block you want a range for.

    .PARAMETER Start
        Specifies a path to one or more locations.

    .PARAMETER Subnet
        The subnet mask you want a range for.

    .EXAMPLE
        C:\PS>Get-IPrange -ip 192.168.0.3 -subnet 255.255.255.192
        Will show all IPs within the 192.168.0.0 space with a subnet mask of 255.255.255.192 (CIDR 26.)

    .EXAMPLE
        C:\PS>Get-IPrange -PARAMETER
        Another example of how to use this cmdlet but with a parameter or switch.

    .NOTES
        Author: Skyler Hart
        Created: Sometime before 8/7/2017
        Last Edit: 2020-08-20 09:11:46

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('IPv4','Address','IPv4Address')]
        [string]$IP,

        [Parameter(
            Mandatory=$false
        )]
        [Alias('Notation','Block')]
        [string]$CIDR,

        [Parameter(
            Mandatory=$false
        )]
        [Alias('Mask')]
        [string]$Subnet,

        [Parameter(
            Mandatory=$false
        )]
        [string]$Start,

        [Parameter(
            Mandatory=$false
        )]
        [string]$End
    )


    if ($IP) {$ipaddr = [Net.IPAddress]::Parse($IP)}
    if ($CIDR) {$maskaddr = [Net.IPAddress]::Parse((Convert-INT64toIP -int ([convert]::ToInt64(("1"*$CIDR+"0"*(32-$CIDR)),2)))) }
    if ($Subnet) {$maskaddr = [Net.IPAddress]::Parse($Subnet)}
    if ($IP) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)}
    if ($IP) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))}

    if ($IP) {
        $startaddr = Convert-IPtoINT64 -IP $networkaddr.ipaddresstostring
        $endaddr = Convert-IPtoINT64 -IP $broadcastaddr.ipaddresstostring
    } else {
        $startaddr = Convert-IPtoINT64 -IP $start
        $endaddr = Convert-IPtoINT64 -IP $end
    }

    for ($i = $startaddr; $i -le $endaddr; $i++) {
        Convert-INT64toIP -int $i
    }
}
