function Test-ResponseTime {
<#
.SYNOPSIS
    Finds the response time of a remote computer.
.DESCRIPTION
    Will find average, minimum, and maximum response times (from four pings) of a remote computer, which defaults to the computers logon server if an address is not specified.

.PARAMETER RemoteAddress
    Specifies the name of one or more remote computers.
.PARAMETER ThrottleLimit
    Allows you to specify the most remote computers that will be tested at a time, defaults to 5.
.EXAMPLE
    C:\PS>Test-ResponseTime
    Example of how to use this cmdlet.
.EXAMPLE
    C:\PS>Test-ResponseTime www.wanderingstag.com
    Shows how to test the response time to the website www.wanderingstag.com.
.EXAMPLE
    C:\PS>Test-ResponseTime COMP1,www.wanderingstag.com
    Shows how to test the response time to the computer COMP1 and the website www.wanderingstag.com.
.EXAMPLE
    C:\PS>Test-MTU COMP1,COMP2,COMP3,www.wanderingstag.com -ThrottleLimit 2
    Shows how to test the response times to multiple computers, the test will be performed against two of the computers at a time.
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.COMPONENT
    WSTools
.FUNCTIONALITY
    Response time, ping, network, connectivity, troubleshooting
.NOTES
    Author: Skyler Hart
    Created: 2023-02-01 22:51:01
    Last Edit: 2023-02-01 22:51:01
    Other:
    Requires:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param (
        [Parameter()]
        [Alias('Host','Name','Computer','ComputerName','TestAddress')]
        [string[]] $RemoteAddress,

        [int32] $ThrottleLimit = 5
    )

    if ([string]::IsNullOrWhiteSpace($RemoteAddress)) {
        Write-Verbose "Test Address not specified. Setting to logon server."
        $RemoteAddress = ($env:LOGONSERVER).Replace('\\','') + "." + $env:USERDNSDOMAIN
    }
    Write-Verbose "RemoteAddress: $RemoteAddress"

    Write-Verbose "Testing connections"
    $responses = Test-Connection -ComputerName $RemoteAddress -ThrottleLimit $ThrottleLimit
    Write-Verbose "Responses: $responses"

    $testaddresses = $responses | Select-Object -ExpandProperty Address -Unique

    if (($testaddresses.Count) -le 1) {
        $j = $responses | Where-Object {$_.Address -eq $testaddresses[0]}
        $measuredinfo = $responses.ResponseTime | Measure-Object -Average -Maximum -Minimum
        [PSCustomObject]@{
            ComputerName = ($responses[0].PSComputerName)
            TestAddress = ($responses[0].Address)
            ResponseTime = ($measuredinfo | Select-Object -ExpandProperty Average)
            Minimum = ($measuredinfo | Select-Object -ExpandProperty Minimum)
            Maximum = ($measuredinfo | Select-Object -ExpandProperty Maximum)
        }#new object
    }
    else {
        for ($i = 0; $i -lt $testaddresses.Length; $i++) {
            $j = $responses | Where-Object {$_.Address -eq $testaddresses[$i]}
            $measuredinfo = $j.ResponseTime | Measure-Object -Average -Maximum -Minimum
            [PSCustomObject]@{
                ComputerName = ($j[0].PSComputerName)
                TestAddress = $testaddresses[$i]
                ResponseTime = ($measuredinfo | Select-Object -ExpandProperty Average)
                Minimum = ($measuredinfo | Select-Object -ExpandProperty Minimum)
                Maximum = ($measuredinfo | Select-Object -ExpandProperty Maximum)
            }#new object
        }
    }
}
