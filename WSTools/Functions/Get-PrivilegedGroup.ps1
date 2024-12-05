function Get-PrivilegedGroup {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 03/05/2019 14:56:27
    LASTEDIT: 2022-09-04 00:41:10
    KEYWORDS:
    REQUIRES:
        -Modules ActiveDirectory
.Link
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Switch]$GetParentGroups
    )
    $config = $Global:WSToolsConfig
    $agroups = $config.PrivGroups

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Write-Verbose "Getting groups listed in config file"
        $PrivGroupsCoded = foreach ($ag in $agroups) {
            Get-ADGroup $ag -Properties MemberOf | Add-Member -NotePropertyName Why -NotePropertyValue ParentInScript -Force -PassThru
        }
        $pgccount = $PrivGroupsCoded.Count
        Write-Verbose "Priv Groups in config: $pgccount"

        if ($GetParentGroups) {
            Write-Verbose "Getting Parent Groups"
            $ParentGroups = @()
            $groups = $PrivGroupsCoded.MemberOf | Select-Object -Unique
            $NewGroupsAdded = $true

            while ($NewGroupsAdded) {
                $NewGroupsAdded = $false
                $holdinglist = @()
                foreach ($group in $groups) {
                    Write-Verbose "Checking $group"
                    [array]$new_groups = Get-ADPrincipalGroupMembership $group | ForEach-Object {$_.distinguishedName}
                    if ($new_groups.Length -ge 1) {
                        $NewGroupsAdded = $true
                        foreach ($new in $new_groups) {
                            $holdinglist += $new
                        }
                    }
                    else {
                        $holdinglist += $group
                    }
                }
                [array]$groups = $holdinglist
                $ParentGroups += $groups | Where-Object {$_ -like "CN=*"} | Sort-Object | Select-Object -Unique
                if ($NewGroupsAdded) {
                    Write-Verbose "Starting re-check"
                }
            }

            $parentgroupscount = $ParentGroups.Count
            Write-Verbose "Parent groups: $parentgroupscount"

            $bgroups = $ParentGroups | Select-Object -Unique
            $PrivGroupsCoded = foreach ($group in $bgroups) {
                Write-Verbose "Getting AD info of parent group: $group"
                Get-ADGroup $group | Add-Member -NotePropertyName Why -NotePropertyValue Parent -Force -PassThru
            }
            $pgccount = $PrivGroupsCoded.Count
            Write-Verbose "Priv Groups after getting parent: $pgccount"
        }

        Write-Verbose "Getting sub groups"
        $subgroups = foreach ($group in $PrivGroupsCoded) {
            Get-ADGroupMember $group | Select-Object * | Where-Object {$_.objectClass -eq "group"} | Select-Object -ExpandProperty Name
        }
        $subgroups = $subgroups | Sort-Object | Select-Object -Unique
        $PrivSubGroups = @()
        $PrivSubGroups += foreach ($group in $subgroups) {
            Get-ADGroup $group | Select-Object -ExpandProperty distinguishedName
        }
        $NewGroupsAdded = $true
        while ($NewGroupsAdded) {
            $NewGroupsAdded = $false
            $holdinglist = @()
            foreach ($group in $subgroups) {
                Write-Verbose "Checking subgroup $group"
                [array]$new_groups = Get-ADGroupMember $group | Where-Object {$_.objectClass -eq "group"} | Select-Object -ExpandProperty Name
                if ($new_groups.Length -ge 1) {
                    $NewGroupsAdded = $true
                    foreach ($new in $new_groups) {
                        $holdinglist += $new
                    }
                }
                else {
                    $holdinglist += $group
                }
            }
            [array]$subgroups = $holdinglist
            $PrivSubGroups += $subgroups | Sort-Object | Select-Object -Unique
            if ($NewGroupsAdded) {
                Write-Verbose "Starting re-check"
            }
        }
        $PrivSubGroups = $PrivSubGroups | Sort-Object | Select-Object -Unique
        Write-Verbose "Getting AD info of each subgroup"
        $PrivGroupsSub = foreach ($group in $PrivSubGroups) {
            if ($PrivGroupsCoded -notmatch $group) {
                Write-Verbose " - Getting AD info of $group"
                Get-ADGroup $group | Add-Member -NotePropertyName Why -NotePropertyValue "Subgroup" -Force -PassThru
            }
        }
        $pgscount = $PrivGroupsSub.Count
        Write-Verbose "Sub Groups: $pgscount"

        Write-Verbose "Combining info"
        $AllGroups = @()
        $AllGroups += $PrivGroupsCoded
        $AllGroups += $PrivGroupsSub
        $AllGroups | Select-Object Name,Why,GroupScope,GroupCategory,DistinguishedName -Unique
    }
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}
