function Find-SID {
    <#
    .Synopsis
        This function finds what Active Directory object the specified SID belongs to.

    .Description
        This function finds what Active Directory object the specified SID belongs to.

    .Example
        Find-SID "S-1-5-21-1454471165-1004335555-1606985555-5555"
        Finds what Active Directory object the specified SID belongs to.

    .Parameter SID
        Mandatory parameter. Specify the SID you want to search for.

    .Notes
        AUTHOR: Skyler Hart
        CREATED: 2014-01-19 01:45:00
        LASTEDIT: 08/15/2018 22:47:26
        KEYWORDS: SID

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$true,
            Position=0
        )]
        [string]$SID
    )
    $objSID = New-Object System.Security.Principal.SecurityIdentifier `
        ("$SID")
    $obj = $objSID.Translate( [System.Security.Principal.NTAccount])
    $obj.Value
}
