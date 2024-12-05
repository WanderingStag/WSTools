function Open-WindowsUpdateLog {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 05/03/2016 20:06:39
    LASTEDIT: 08/07/2018 15:53:00
    KEYWORDS:
    REQUIRES:
.LINK
    https://wanderingstag.github.io
#>
<#--
Found on the Configuration Manager Client computer, by default, in %windir%.

WindowsUpdate.log
Provides information about when the Windows Update Agent connects to the WSUS server and retrieves the
software updates for compliance assessment and whether there are updates to the agent components.
--#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Continues querying system(s)."
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","Cancels the command."
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

    $title = "Alert!"
    $message = "This command doesn't work on Windows 10 or newer computers. Do you want to continue running it?"
    $result = $host.ui.PromptForChoice($title, $message, $options, 1)
    switch ($result) {
        0 {
            Write-Output "Yes"
        }
        1 {
            Write-Output "No"
        }
    }

    if ($result -eq 0) {
        foreach ($comp in $ComputerName) {
            try {
                notepad \\$comp\c$\Windows\WindowsUpdate.log
            }
            catch {
                Throw "Unable to connect to $comp"
            }
        }
    }#if yes then continue
    else {
        #do nothing
    }
}
