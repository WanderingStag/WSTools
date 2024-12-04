function Update-BrokenInheritance {
<#
.SYNOPSIS
    Finds and fixes users with broken inheritance.
.DESCRIPTION
    Will search Active Directory for users that do not have permissions inheritance enabled and then fix the inheritance.
.PARAMETER Identity
    Specify a user to fix the inheritance on. Can use sAMAccountName or distinguishedName. If no user is specified it will find all users with broken inheritance.
.PARAMETER SearchBase
    Specify the OU to search using the distinguishedName of the OU. If not specified it searches the whole domain.
.EXAMPLE
    C:\PS>Update-BrokenInheritance -Identity "CN=Joe Snuffy,CN=Users,DC=wstools,DC=dev"
    Will fix the broken inheritance on the user Joe Snuffy.
.EXAMPLE
    C:\PS>Update-BrokenInheritance -SearchBase "CN=Users,DC=wstools,DC=dev"
    Will fix the broken inheritance on all users in the Users OU.
.INPUTS
    System.String
.OUTPUTS
    System.String
.COMPONENT
    WSTools
.FUNCTIONALITY
    Permissions, Inheritance, Active Directory
.NOTES
    Author: Skyler Hart
    Created: Sometime before 2017-08-07
    Last Edit: 2022-09-05 23:40:29
    Other:
    Requires:
        -Module ActiveDirectory
.LINK
    https://wanderingstag.github.io
#>
    Param (
        [Parameter(
            HelpMessage="Enter the distinguishedName of the OU that you want to search",
            Mandatory=$false
        )]
    	[string]$SearchBase = (Get-ADDomain).DistinguishedName,

        [Parameter(
            HelpMessage="Enter User ID (sAMAccountName or distinguishedName)",
            Mandatory=$false
        )]
		[string]$Identity
	)

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        #Start Directory Searcher
        If (!($Identity)) {
	        $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$SearchBase","(&(objectcategory=user)(objectclass=user))")
    	}
        Else {
            Write-Output "Searching for User $($Identity)"
    	    If ($Identity -like "CN=*") {
                $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Identity")
	        }
            Else {
                $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$SearchBase","(&(objectcategory=user)(objectclass=user)(samaccountname=$($Identity)))")
	        }
        }

        #Find All Matching Users
        $Users = $DirectorySearcher.FindAll()

        Foreach ($obj in $users) {
            #Set 'objBefore' to the current object so we can track any changes
            $objBefore = $obj.GetDirectoryEntry()

            #Check to see if user has Inheritance Disabled; $True is inheritance disabled, $False is inheritance enabled
            If ($objBefore.psBase.ObjectSecurity.AreAccessRulesProtected -eq $True) {
                Write-Output "User: $($objBefore.sAMAccountName) Inheritance is disabled: $($objBefore.psBase.ObjectSecurity.AreAccessRulesProtected) ; adminSDHolder: $($objBefore.Properties.AdminCount)"
                $objBeforeACL = $($objBefore.psBase.ObjectSecurity.AreAccessRulesProtected)

                #Fix inheritance
                Write-Output "Updating $($objBefore.sAMAccountName)."
                $objBefore.psbase.ObjectSecurity.SetAccessRuleProtection($false,$true)
                $objBefore.psbase.CommitChanges()

                #Set 'objAfter' so we can see the updated change
                $objAfter = $obj.GetDirectoryEntry()
                $objAfterACL = $($objAfter.psBase.ObjectSecurity.AreAccessRulesProtected)
            }
            Else {
                #User has inheritance enabled, so do nothing
            }
        }
    }#if ad module exists
    else {
        Write-Warning "Active Directory module is not installed and is required to run this command."
    }
}
