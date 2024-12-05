function Test-MTU {
<#
.SYNOPSIS
    Finds the MTU size for packets to a remote computer.
.DESCRIPTION
    Will find the point where packets don't fragment (MTU) to a remote source, which defaults to the computers logon server if an address isn't specified.
.PARAMETER RemoteAddress
    Specifies the name or IP of one or more remote computers.
.PARAMETER BufferSizeMax
    Allows you to specify the highest MTU to test.
.EXAMPLE
    C:\PS>Test-MTU
    Example of how to use this cmdlet.
.EXAMPLE
    C:\PS>Test-MTU www.wanderingstag.com
    Shows how to test the MTU to the website www.wanderingstag.com.
.EXAMPLE
    C:\PS>Test-MTU COMP1,www.wanderingstag.com
    Shows how to test the MTU to the computer COMP1 and the website www.wanderingstag.com.
.EXAMPLE
    C:\PS>Test-MTU COMP1 1272
    Shows how to test the MTU to the computer COMP1, the max buffer size (MTU) will start at 1272.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    Maximum Transmission Unit, MTU, network, connectivity, troubleshooting
.NOTES
    Author: Skyler Hart
    Created: 2022-11-22 21:27:58
    Last Edit: 2022-11-22 23:06:11
    Other:
    Requires:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [Alias('Host', 'Name', 'Computer', 'ComputerName', 'TestAddress')]
        [string[]]$RemoteAddress,

        #Set BufferSizeMax to the largest MTU you want to test (1500 normally or up to 9000 if using Jumbo Frames)
        [Parameter(Mandatory=$false)]
        [int]$BufferSizeMax = 1500
    )

    if ([string]::IsNullOrWhiteSpace($RemoteAddress)) {
        Write-Verbose "Test Address not specified. Setting to logon server."
        $RemoteAddress = ($env:LOGONSERVER).Replace('\\','') + "." + $env:USERDNSDOMAIN
    }
    Write-Verbose "RemoteAddress: $TestAddress"
    Write-Verbose "BufferSizeMax: $BufferSizeMax"

    foreach ($TestAddress in $RemoteAddress) {
        $LastMinBuffer=$BufferSizeMin
        $LastMaxBuffer=$BufferSizeMax
        $MaxFound=$false
        $GoodMTU = @()
        $BadMTU = @()

        #Calculate first MTU test, halfway between zero and BufferSizeMax
        [int]$BufferSize = ($BufferSizeMax - 0) / 2
        while ($MaxFound -eq $false){
            try{
                $Response = ping $TestAddress -n 1 -f -l $BufferSize
                #if MTU is too big, ping will return: Packet needs to be fragmented but DF set.
                if ($Response -like "*fragmented*") {throw}
                if ($LastMinBuffer -eq $BufferSize) {
                    #test values have converged onto the highest working MTU, stop here and report value
                    $MaxFound = $true
                    break
                }
                else {
                    #it worked at this size, make buffer bigger
                    Write-Verbose "Found good MTU: $BufferSize"
                    $GoodMTU += $BufferSize
                    $LastMinBuffer = $BufferSize
                    $BufferSize = $BufferSize + (($LastMaxBuffer - $LastMinBuffer) / 2)
                }
            }
            catch {
                #it didn't work at this size, make buffer smaller
                Write-Verbose "Found bad MTU: $BufferSize"
                $BadMTU += $BufferSize
                $LastMaxBuffer = $BufferSize
                #if we're getting close, just subtract 1
                if(($LastMaxBuffer - $LastMinBuffer) -le 3){
                    $BufferSize = $BufferSize - 1
                } else {
                    $BufferSize = $LastMinBuffer + (($LastMaxBuffer - $LastMinBuffer) / 2)
                }
            }
        }

        Write-Verbose "Good MTUs: $GoodMTU"
        Write-Verbose "Bad MTUs: $BadMTU"
        Write-Verbose "Recommended MTU: $BufferSize"

        if ($BufferSize -le 1472) {
            $BufferSize = $BufferSize+28
        }

        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            GoodMTUs = $GoodMTU -join ","
            BadMTUs = $BadMTU -join ","
            MTUwithBuffer = $BufferSize
            TestAddress = $TestAddress
        }#new object
    }
}
