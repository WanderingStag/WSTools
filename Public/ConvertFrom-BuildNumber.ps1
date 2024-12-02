function ConvertFrom-BuildNumber {
    <#
    .SYNOPSIS
        Converts a Microsoft Build number to a version number.

    .DESCRIPTION
        Takes a build number for Windows 8/Server 2012 or newer and converts it to a version number and Operatiing System.

    .PARAMETER Build
        Specifies the number of the Microsoft Build.

    .EXAMPLE
        C:\PS>ConvertFrom-BuildNumber 20348
        Example of how to use this cmdlet. This example will return Windows Server 2022.

    .INPUTS
        System.Int32

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .COMPONENT
        WSTools

    .FUNCTIONALITY
        Microsoft, Build, Version, conversion

    .NOTES
        Author: Skyler Hart
        Created: 2023-09-22 12:04:10
        Last Edit: 2023-09-22 12:21:16
        Other:

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [Alias('ConvertFrom-MicrosoftBuildNumber')]
    param(
        [Parameter(
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [int32[]] $Build
    )

    Process {
        foreach ($BuildNumber in $Build) {
            if ($BuildNumber -eq 9200) {
                [PSCustomObject]@{
                    OS = "Windows 8 or Windows Server 2012"
                    Build = $BuildNumber
                    Version ="6.2"
                }
            }
            elseif ($BuildNumber -eq 9600) {
                [PSCustomObject]@{
                    OS = "Windows 8.1 or Windows Server 2012 R2"
                    Build = $BuildNumber
                    Version ="6.3"
                }
            }
            elseif ($BuildNumber -eq 14393) {
                [PSCustomObject]@{
                    OS = "Windows 10 or Windows Server 2016"
                    Build = $BuildNumber
                    Version ="1607"
                }
            }
            elseif ($BuildNumber -eq 15063) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="1703"
                }
            }
            elseif ($BuildNumber -eq 16299) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="1709"
                }
            }
            elseif ($BuildNumber -eq 17134) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="1803"
                }
            }
            elseif ($BuildNumber -eq 17763) {
                [PSCustomObject]@{
                    OS = "Windows 10 or Windows Server 2019"
                    Build = $BuildNumber
                    Version ="1809"
                }
            }
            elseif ($BuildNumber -eq 18362) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="1903"
                }
            }
            elseif ($BuildNumber -eq 18363) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="1909"
                }
            }
            elseif ($BuildNumber -eq 19041) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="2004"
                }
            }
            elseif ($BuildNumber -eq 19042) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="20H2 (2009)"
                }
            }
            elseif ($BuildNumber -eq 19043) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="21H1 (2103)"
                }
            }
            elseif ($BuildNumber -eq 19044) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="21H2 (2109)"
                }
            }
            elseif ($BuildNumber -eq 22000) {
                [PSCustomObject]@{
                    OS = "Windows 11"
                    Build = $BuildNumber
                    Version ="21H2 (2109)"
                }
            }
            elseif ($BuildNumber -eq 20348) {
                [PSCustomObject]@{
                    OS = "Windows Server 2022"
                    Build = $BuildNumber
                    Version ="21H2 (2109)"
                }
            }
            elseif ($BuildNumber -eq 19045) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="22H2 (2209)"
                }
            }
            elseif ($BuildNumber -eq 19046) {
                [PSCustomObject]@{
                    OS = "Windows 10"
                    Build = $BuildNumber
                    Version ="23H2 (2309)"
                }
            }
            elseif ($BuildNumber -eq 22621) {
                [PSCustomObject]@{
                    OS = "Windows 11"
                    Build = $BuildNumber
                    Version ="22H2 (2209)"
                }
            }
            elseif ($BuildNumber -eq 22631) {
                [PSCustomObject]@{
                    OS = "Windows 11"
                    Build = $BuildNumber
                    Version ="23H2 (2309)"
                }
            }
            elseif ($BuildNumber -eq 26100) {
                [PSCustomObject]@{
                    OS = "Windows 11"
                    Build = $BuildNumber
                    Version ="24H2 (2409)"
                }
            }
        }
    }
}
