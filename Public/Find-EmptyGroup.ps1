function Find-EmptyGroup {
    <#
    .Synopsis
        This function will show empty groups.

    .Description
        This function will show empty groups in your domain.

    .Example
        Find-EmptyGroups -SearchBase "OU=test,dc=yourdomain,dc=com"
        This function searches the test OU under the yourdomain.com domain and saves a csv with empty groups to c:\test\emptygroups.csv.

    .Parameter SearchBase
        Specific OU to search. If not included, the entire domain will be searched.

    .Notes
        AUTHOR: Skyler Hart
        CREATED: 2014-01-18 11:50:00
        LASTEDIT: 2022-09-01 21:59:13
        KEYWORDS: Groups, empty groups, group management
        REQUIRES:
            ActiveDirectory

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
      [string]$SearchBase
     )

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        if (!([string]::IsNullOrWhiteSpace($SearchBase))) {
            Get-ADGroup -Filter * -Properties CN,GroupScope,GroupCategory,ManagedBy,SamAccountName,whenCreated,CanonicalName,Members -SearchBase $SearchBase | Where-Object {-Not $_.Members} |
            Select-Object CN,GroupScope,GroupCategory,ManagedBy,SamAccountName,whenCreated,CanonicalName
        }
        else {
            $sb = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
            Get-ADGroup -Filter * -Properties CN,GroupScope,GroupCategory,ManagedBy,SamAccountName,whenCreated,CanonicalName,Members -SearchBase $sb | Where-Object {-Not $_.Members} |
            Select-Object CN,GroupScope,GroupCategory,ManagedBy,SamAccountName,whenCreated,CanonicalName
        }
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run Find-EmptyGroup."
    }
}
