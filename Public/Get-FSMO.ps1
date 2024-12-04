function Get-FSMO {
    <#
    .Notes
        AUTHOR: Skyler Hart
        CREATED: Sometime before 2017-08-07
        LASTEDIT: 2022-09-01 22:47:51
        KEYWORDS:

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    [Alias('fsmo')]
    Param (
        [Parameter()]
        [Switch]$netdom
    )
    if (!$netdom) {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            $RoleHolders = Get-ADDomainController -Filter * | Select-Object Name,OperationMasterRoles
            $RoleHolderInfo = foreach ($RoleHolder in $RoleHolders) {
                $Comp = $RoleHolder.Name
                $Roles = $RoleHolder.OperationMasterRoles
                $Roles = $Roles -join ", "
                [PSCustomObject]@{
                    ComputerName = $Comp
                    Roles = $Roles
                }#new object
            }
            $RoleHolderInfo
        }
        else {
            netdom /query FSMO
        }
    }
    else {
        netdom /query FSMO
    }
}
