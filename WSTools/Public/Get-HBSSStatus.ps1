# Working. To Do:
# Get-HBSSStatus (Get-Content .\computers.txt) | Format-Table -AutoSize
# Get-HBSSStatus (Get-Content .\computers.txt) | Export-Csv .\hbssstatus.csv -NoTypeInformation
function Get-HBSSStatus {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 08/18/2017 21:11:01
    LASTEDIT: 09/25/2019 14:42:42
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    #Set variables needed for overall script
    $i = 0
    $number = $ComputerName.length
    $64keyname = 'SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion'
    $64hbsskey = 'SOFTWARE\\Wow6432Node\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\VIRUSCAN8800'
    $64hipskey = 'SOFTWARE\\Wow6432Node\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\HOSTIPS_8000'
    $64epokey = 'SOFTWARE\\Wow6432Node\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\EPOAGENT3000'
    $32hbsskey = 'SOFTWARE\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\VIRUSCAN8800'
    $32hipskey = 'SOFTWARE\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\HOSTIPS_8000'
    $32epokey = 'SOFTWARE\\Network Associates\\ePolicy Orchestrator\\Application Plugins\\EPOAGENT3000'
    $version = $host.Version.Major
    $hname = $host.Name
    $datdaysold = "4" #specific number of days old the DAT can be
    $EngineVersion = "5900*" #has to be a generic version such as 5700* or 5800*
    $PatchesInstalled = "12" #specific number of patches that should be installed
    $AntiVirusVersion = "8.8*" #has to be a generic version such as 8.8* or 8.9* or even 9.1*
    $HBSSFrameworkVersion = "5.6.1.308" #specific framework version that is required

    $64enskey = 'SOFTWARE\WOW6432Node\Network Associates\TVD\Shared Components\Framework'

    #For each computer, check HBSS
    foreach ($comp in $ComputerName) {
        #Set variables required per computer
        Clear-Variable value2,reg,reg2,reg3,key,key2,key3,datdateval,DATVersionval,DATVersion,engversionval,hotfixverval,versval,hipsverval,frameworkverval,outdated,engoutdated,hfoutdated,avoutdated,fwoutdated,ePOServers | Out-Null

        #Progress Bar... Computers checked
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Getting HBSS status. Currently checking $comp" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#progress bar

        #Make sure running at least PowerShell v3
        if ($version -gt "2" -or $hname -like "ServerRemote*") {
            #64-bit test
            try {
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                $key = $reg.OpenSubKey($64keyname)
                $value2 = $key.GetValue('CurrentVersion')
            }
            catch {$value2 = $null}

#region 64-bit tasks
            if ($null -ne $value2) {
                #Get HBSS values (not ENS)
                try {
                    $reg2 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                    $key2 = $reg2.OpenSubkey($64hbsskey)
                    $datdateval = $key2.GetValue('DatDate')
                    $DATVersionval = $key2.GetValue('DATVersion')
                    $engversionval = $key2.GetValue('EngineVersion')
                    $hotfixverval = $key2.GetValue('HotFixVersions')
                    $versval = $key2.GetValue('Version')

                    #Check registry for HIPS values
                    try {
                        $reg3 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                        $key3 = $reg3.OpenSubkey($64hipskey)
                        $hipsverval = $key3.GetValue('Version')
                    }
                    catch {
                        $hipsverval = "Not Installed"
                    }

                    #Check registry for HBSS Framework values
                    try {
                        $reg4 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                        $key4 = $reg4.OpenSubkey($64epokey)
                        $frameworkverval = $key4.GetValue('Version')
                        $type = "HBSS"
                        $type | Out-Null
                    }
                    catch {
                        $frameworkverval = "Not Installed"
                        $type = $null
                    }
                }
                catch {
                    $datdateval = $null
                    $DATVersionval = $null
                    $engversionval = $null
                    $hotfixverval = $null
                    $versval = $null
                    $type = $null
                }
                #Get ENS values
            }#if 64-bit
#endregion 64bit tasks


#region 32-bit tasks
            if ($null -eq $value2) {
                #See if HBSS has been installed
                #if (Test-Path "$psdpath\Program Files\Common Files\McAfee\Engine\OldEngine\config.dat") {$hbssstatus = "Yes"}
                #else {$hbssstatus = "No"}


                #Check registry for Virus Scan values
                try {
                    $reg2 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                    $key2 = $reg2.OpenSubkey($32hbsskey)
                    $datdateval = $key2.GetValue('DatDate')
                    $DATVersionval = $key2.GetValue('DATVersion')
                    $engversionval = $key2.GetValue('EngineVersion')
                    $hotfixverval = $key2.GetValue('HotFixVersions')
                    $versval = $key2.GetValue('Version')
                }
                catch {
                    $datdateval = $null
                    $DATVersionval = $null
                    $engversionval = $null
                    $hotfixverval = $null
                    $versval = $null
                }


                #Check registry for HIPS values
                try {
                    $reg3 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                    $key3 = $reg3.OpenSubkey($32hipskey)
                    $hipsverval = $key3.GetValue('Version')
                }
                catch {
                    $hipsverval = "Not Installed"
                }


                #Check registry for HBSS Framework values
                try {
                    $reg4 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                    $key4 = $reg4.OpenSubkey($32epokey)
                    $frameworkverval = $key4.GetValue('Version')
                }
                catch {
                    $frameworkverval = "Not Installed"
                }

            }
#endregion 32bit tasks

            #Perform check to see if DAT is out of date
            if ($null -eq $datdateval) {$datdateval = "20000101"}
            $today = get-date -f yyyyMMdd
            $daysold = $today - $datdateval
            if ($daysold -gt $datdaysold) {$outdated = "Yes"}
            else {$outdated = "No"}

            #Perform check to see if Engine is out of date
            if ($engversionval -notlike $EngineVersion) {$engoutdated = "Yes"}
            else {$engoutdated = "No"}

            #Peform check to see if patches are needed
            if ($hotfixverval -ne $PatchesInstalled) {$hfoutdated = "Yes"}
            else {$hfoutdated = "No"}

            #Perform check to see if Antivirus version 8.8
            if ($versval -notlike $AntiVirusVersion) {$avoutdated = "Yes"}
            else {$avoutdated = "No"}

            #Perform check to see if HBSS Framework is up-to-date
            if ($frameworkverval -eq $HBSSFrameworkVersion) {$fwoutdated = "No"}
            else {$fwoutdated = "Yes"}

            #Take the extra 0's off the end of the DAT version
            if ($null -eq $DatVersionval) {$DatVersionval = "0000.0000"}
            $DATVersion = $DATVersionval.substring(0,4)

            #Create the object data
            [PSCustomObject]@{
                Computer = "$comp"
                DatDate = "$datdateval"
                DatVersion = "$DATVersion"
                DATOutdated = "$outdated"
                EngineVersion = "$engversionval"
                EngineOutdated = "$engoutdated"
                PatchesInstalled = "$hotfixverval"
                PatchesNeeded = "$hfoutdated"
                McAfeeVersion = "$versval"
                McAfeeOutdated = "$avoutdated"
                HIPSVersion = "$hipsverval"
                HBSS_Framework = "$frameworkverval"
                HBSSOutdated = "$fwoutdated"

            } | Select-Object Computer,DatDate,DatVersion,DATOutdated,EngineVersion,EngineOutdated,PatchesInstalled,PatchesNeeded,McAfeeVersion,McAfeeOutdated,HIPSVersion,HBSS_Framework,HBSSOutdated
        }#if host version gt 2
        else {
            Write-Output "  PowerShell must be at least version 3. Current version:  $version  `n  Click OK to continue.  "
            [void][reflection.assembly]::LoadWithPartialName("System.Windows.Forms")
            [System.Windows.Forms.MessageBox]::Show("                               Error:`n`nPowerShell must be at least version 3.`n`nCurrent version is:  $version");
        }#else host version
    }#foreach computer
}#get hbssstatus
