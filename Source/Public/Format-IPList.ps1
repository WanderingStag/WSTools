function Format-IPList {
    <#
    .SYNOPSIS
        Takes a list of IP addresses and sorts them.

    .DESCRIPTION
        This function takes a list of IP addresses and sorts them in the appropriate order.

    .PARAMETER IPs
        Used to specify the IP addresses that you wish to sort.

    .EXAMPLE
        Format-IPList -IPs 127.0.0.5, 127.0.0.100, 10.0.1.5, 10.0.1.1, 10.0.1.100
        Sorts the given list of IP addresses in the correct order.

    .EXAMPLE
        Sort-IPs 127.0.0.5, 127.0.0.100, 10.0.1.5, 10.0.1.1, 10.0.1.100
        Uses the alias Sort-IPs to sort the list of IP addresses.

    .NOTES
        AUTHOR: Skyler Hart
        CREATED: 2023-10-11 10:58:24
        LASTEDIT: 2024-11-27 13:00:00

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [Alias('Sort-IPList','Sort-IPs')]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias('IPAddresses')]
        [System.Net.IPAddress[]]$IPs
    )

    Process {
        $IPs | Sort-Object {
            $_.GetAddressBytes() -as [System.Collections.IComparer]
        }
    }
}
