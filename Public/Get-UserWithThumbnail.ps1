function Get-UserWithThumbnail {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 10/03/2014 14:18:42
    LASTEDIT: 2022-09-04 11:56:28
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
.LINK
    https://wanderingstag.github.io
#>
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Write-Output "Getting OU names . . ."
        $ous = (Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Select-Object DistinguishedName).DistinguishedName

        Write-Output "Getting Users . . ."
        $users = foreach ($ouname in $ous) {
            Get-ADUser -Filter * -Properties thumbnailPhoto -SearchBase "$ouname" -SearchScope OneLevel | Where-Object {!([string]::IsNullOrWhiteSpace($_.thumbnailPhoto))} | Select-Object Name,UserPrincipalName,thumbnailPhoto
        }

        $users | Select-Object Name,UserPrincipalName,thumbnailPhoto
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}
