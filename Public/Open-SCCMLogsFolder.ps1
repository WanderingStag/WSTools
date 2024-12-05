function Open-SCCMLogsFolder {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 2020-09-28 09:25:48
    KEYWORDS:
    REQUIRES:
        -RunAsAdministrator on remote computers
.LINK
    https://wanderingstag.github.io
#>
<#--
CAS.log
Provides information about the process of downloading software updates to the local cache and cache management.

CIAgent.log
Provides information about processing configuration items, including software updates.

LocationServices.log
Provides information about the location of the WSUS server when a scan is initiated on the client.

PatchDownloader.log
Provides information about the process for downloading software updates from the update source to the download destination on the site server.

Note
On 64-bit operating systems and on 32-bit operating systems without Configuration Manager 2007 installed, PatchDownloader.log is created in the server logs directory. On 32-bit operating systems, if the Configuration Manager 2007 client is installed, and on the synchronization host computer for the Inventory Tool for Microsoft Updates, PatchDownloader.log is created in the client logs directory.

PolicyAgent.log
Provides information about the process for downloading, compiling, and deleting policies on client computers.

PolicyEvaluator
Provides information about the process for evaluating policies on client computers, including policies from software updates.

RebootCoordinator.log
Provides information about the process for coordinating system restarts on client computers after software update installations.

ScanAgent.log
Provides information about the scan requests for software updates, what tool is requested for the scan, the WSUS location, and so on.

ScanWrapper
Provides information about the prerequisite checks and the scan process initialization for the Inventory Tool for Microsoft Updates on Systems Management Server (SMS) 2003 clients.

SdmAgent.log
Provides information about the process for verifying and decompressing packages that contain configuration item information for software updates.

ServiceWindowManager.log
Provides information about the process for evaluating configured maintenance windows.

smscliUI.log
Provides information about the Configuration Manager Control Panel user interactions, such as initiating an Software Updates Scan Cycle from the Configuration Manager Properties dialog box, opening the Program Download Monitor, and so on.

SmsWusHandler
Provides information about the scan process for the Inventory Tool for Microsoft Updates on SMS 2003 client computers.

StateMessage.log
Provides information about when software updates state messages are created and sent to the management point.

UpdatesDeployment.log
Provides information about the deployment on the client, including software update activation, evaluation, and enforcement. Verbose logging shows additional information about the interaction with the client user interface.

UpdatesHandler.log
Provides information about software update compliance scanning, and the download and installation of software updates on the client.

UpdatesStore.log
Provides information about the compliance status for the software updates that were assessed during the compliance scan cycle.

WUAHandler.log
Provides information about when the Windows Update Agent on the client searches for software updates.

WUSSyncXML.log
Provides information about the Inventory Tool for Microsoft Updates synchronization process.
This log is only on the client computer configured as the synchronization host for the Inventory Tool for Microsoft Updates.
--#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    foreach ($comp in $ComputerName) {
        if (Test-Path \\$comp\c$\Windows\CCM\Logs) {
            explorer \\$comp\c$\Windows\CCM\Logs
        }
        else {
            try {
                $wmiq = Get-WmiObject win32_operatingsystem -ComputerName $comp -ErrorAction Stop | Select-Object OSArchitecture
                if ($wmiq -like "*64-bit*") {
                    explorer \\$comp\c$\Windows\SysWOW64\CCM\Logs
                }
                else {
                    explorer \\$comp\c$\Windows\System32\CCM\Logs
                }
            }#try
            catch {
                Throw "Unable to connect to $comp"
            }
        }
    }#foreach computer
}
