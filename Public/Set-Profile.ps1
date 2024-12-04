function Set-Profile {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 21:07:03
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Edit-Profile','Profile')]
    param()

    #If profile already exists, open for editing
    if (Test-Path $profile) {
        start-process "$env:windir\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe" $profile
    }
    #If it doesn't exist, create it and put default stuff into it
    else {
        $filecontent = '##############################################################
# This file contains the commands to run upon startup of     #
# PowerShell or PowerShell ISE. Dependent on whether you     #
# used the command "Set-Profile" in PowerShell or            #
# PowerShell ISE.                                            #
#                                                            #
# To add additional commands to run at startup just type     #
# them below then save this file. To edit this file in the   #
# future, use the command "Set-Profile"                      #
##############################################################



'

        New-Item $profile -ItemType File -Force -Value $filecontent | Out-Null
        start-sleep 1
        start-process "$env:windir\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe" $profile
    }
}
