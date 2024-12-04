function Convert-ImageToBase64 {
<#
.NOTES
    Author: Skyler Hart
    Created: 2020-11-03 22:22:19
    Last Edit: 2020-11-03 22:22:19
    Keywords:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Convert-ICOtoBase64')]
    param(
        [Parameter(
            HelpMessage = "Enter the path of the image you want to convert. Ex: D:\temp\image.jpg",
            Mandatory=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$ImagePath
    )

    $b64 = [convert]::ToBase64String((get-content $ImagePath -encoding byte))
    $b64
}
