Function Get-InstalledPrograms {
<#
.Synopsis
Generates a list of installed programs on a computer
    
.DESCRIPTION
This function generates a list by querying the registry and returning the installed programs of a local or remote computer.
    
.NOTES   
Name: Get-RemoteProgram
Author: Jaap Brasser
Version: 1.2.1
DateCreated: 2013-08-23
DateUpdated: 2015-02-28
DateLastUpdatedBySkylerHart: 08/29/2019 11:41:59 
Blog: https://www.jaapbrasser.com
    
.LINK
https://www.jaapbrasser.com
    
.PARAMETER ComputerName
The computer to which connectivity will be checked
    
.PARAMETER Property
Additional values to be loaded from the registry. Can contain a string or an array of string that will be attempted to retrieve from the registry for each program entry
    
.EXAMPLE
Get-RemoteProgram
    
Description:
Will generate a list of installed programs on local machine
    
.EXAMPLE
Get-RemoteProgram -ComputerName server01,server02
    
Description:
Will generate a list of installed programs on server01 and server02
    
.EXAMPLE
Get-RemoteProgram -ComputerName Server01 -Property DisplayVersion,VersionMajor
    
.EXAMPLE
'server01','server02' | Get-RemoteProgram -Property Uninstallstring
#>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Alias('Host','Name','DNSHostName','Computer')]
        [string[]]$ComputerName = $env:COMPUTERNAME,
        [Parameter(Position=1)]
        [string[]]$Property 
    )
    
    begin {
        $RegistryLocation = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
                            'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'
        $HashProperty = @{}
        $SelectProperty = @('ComputerName','Installed','ProgramName','Version','Uninstall','Comment')
        if ($Property) {
            $SelectProperty += $Property
        }
    }
    
    process {
        foreach ($Computer in $ComputerName) {
            $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer)
            $installed = @()
            foreach ($CurrentReg in $RegistryLocation) {
                if ($RegBase) {
                    $CurrentRegKey = $RegBase.OpenSubKey($CurrentReg)
                    if ($CurrentRegKey) {
                        $CurrentRegKey.GetSubKeyNames() | ForEach-Object {
                            if ($Property) {
                                foreach ($CurrentProperty in $Property) {
                                    $HashProperty.$CurrentProperty = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue($CurrentProperty)
                                }
                            }
                            $HashProperty.ComputerName = $Computer
                            $HashProperty.ProgramName = ($DisplayName = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('DisplayName'))
                            $HashProperty.Version = ($DisplayVersion = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('DisplayVersion'))
                            $HashProperty.Installed = ($InstallDate = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('InstallDate'))
                            $HashProperty.Uninstall = ($UninstallString = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('UninstallString'))
                            $HashProperty.Comment = ($Comments = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('Comments'))
                            if ($DisplayName -and ($DisplayName -notmatch "Update for" -and $DisplayName -notmatch " Security Update for" -and $DisplayName -notmatch "Hotfix for" -and $DisplayName -notlike "Windows Setup Remediations*" `
                                -and $DisplayName -notlike "Outils de v*" -and $DisplayName -notlike "Intel(R) Processor*" -and $DisplayName -notlike "Intel(R) Chipset*" -and $DisplayName -notlike "herramientas de corr*" `
                                -and $DisplayName -notlike "Dell Touchpa*" -and $DisplayName -notmatch "Crystal Reports" -and $DisplayName -notmatch "Catalyst Control" -and $DisplayName -notlike "AMD *" -and $DisplayName -notlike "Microsoft * MUI*" `
                                -and $DisplayName -notlike "Microsoft Visual C* Redist*" -and $DisplayName -notlike "Vulkan Run Time Libraries*" -and $DisplayName -notlike "Microsoft Visual C* Minimum*" -and $DisplayName -notlike "Microsoft Visual C* Additional*")) {
                                $installed += New-Object -TypeName PSCustomObject -Property $HashProperty |
                                Select-Object -Property $SelectProperty
                            }
                            $DisplayVersion | Out-Null
                            $InstallDate | Out-Null
                            $UninstallString | Out-Null
                            $Comments | Out-Null
                        }
                    }
                }
            }
            $installed | Select-Object $SelectProperty | Sort-Object ProgramName
        }
    }
}

Function Join-File {
<# 
.Synopsis 
    This does that
.Description
    This does that
.Example 
    Example- 
    Example- accomplishes  
.Parameter ComputerName
    Specifies the computer or computers
.Notes 
    NAME: FUNCTIONNAME 
    AUTHOR: Skyler Hart
    CREATED: 04/30/2019 14:52:40
    LASTEDIT: 04/30/2019 17:17:50   
.Link 
    https://www.skylerhart.com
    https://www.wanderingstag.com
#>
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter the path of the folder with the part files you want to join.",
            Mandatory=$true,
            Position=0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Source','InputLocation','SourceFolder')]
        [string]$Path,
    
        [Parameter(HelpMessage = "Enter the path where you want the joined file placed.",
            Mandatory=$false,
            Position=1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('OutputLocation','Output','DestinationPath','Destination')]
        [string]$DestinationFolder
    )
    
    $og = (Get-Location).Path
    $objs = Get-ChildItem $Path | Where-Object {$_.Name -like "*_Part*"}
    
    $myobjs = @()
    foreach ($obj in $objs) {
        $ext = $obj.Extension
        $name = $obj.Name
        $num = $name -replace "[\s\S]*.*(_Part)","" -replace $ext,""
        $fn = $obj.FullName
        $dp = $obj.Directory.FullName
    
        $myobjs += New-Object -TypeName PSObject -Property @{
            FullName = $fn
            Name = $name
            Extension = $ext
            Num = [int]$num
            Directory = $dp
        }#new object 
    }
    
    $sobj = $myobjs | Sort-Object Num | Select-Object FullName,Name,Extension,Directory
    
    $fo = $sobj[0]
    $fon = $fo.Name
    $fon = $fon -replace "_Part01",""
    $fd = $fo.Directory
    if ($DestinationFolder -eq "") {
        $fop = $fd + "\" + $fon
        Set-Location $fd
    }
    else {
        $fop = $DestinationFolder + "\" + $fon
        if (!(Test-Path $DestinationFolder)) {
         New-Item -Path $DestinationFolder -ItemType Directory
        }
        Set-Location $DestinationFolder
    }
    
    $WriteObj = New-Object System.IO.BinaryWriter([System.IO.File]::Create($fop))
    
    if ($host.Version.Major -ge 3) {
        $sobj.FullName | ForEach-Object {
            Write-Host "Appending $_ to $fop"
            $ReadObj = New-Object System.IO.BinaryReader([System.IO.File]::Open($_, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read))
    
            $WriteObj.BaseStream.Position = $WriteObj.BaseStream.Length
            $ReadObj.BaseStream.CopyTo($WriteObj.BaseStream)
            $WriteObj.BaseStream.Flush()
    
            $ReadObj.Close()
        }
    }
    else {
        [Byte[]]$Buffer = New-Object Byte[] 100MB
    
        $sobj.FullName | ForEach-Object {
            Write-Host "Appending $_ to $fop"
            $ReadObj = New-Object System.IO.BinaryReader([System.IO.File]::Open($_, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read))
    
            while ($ReadObj.BaseStream.Position -lt $ReadObj.BaseStream.Length) {
                $ReadBytes = $ReadObj.Read($Buffer, 0, $Buffer.Length)
                $WriteObj.Write($Buffer, 0, $ReadBytes)
            }
    
            $ReadObj.Close()
        }
    }
    
    $WriteObj.Close()
    Set-Location $og
}

$comp = $env:COMPUTERNAME
$cn = $env:COMPUTERNAME
$PatchFolderPath = "C:\Patches"
$cab = $PatchFolderPath + "\cab"
$ip = Get-InstalledPrograms | Select-Object ProgramName,Version,Comment
$hf = (Get-HotFix | Select-Object HotFixID).HotFixID

#$scripts = Get-ChildItem -Path $PatchFolderPath | Where-Object {$_.Name -match ".ps1" -and $_.Name -notmatch "Install.ps1" -and $_.Name -notmatch "InstallRemote.ps1"}

$dn472path = $PatchFolderPath + "\NDP472-KB4054530-x86-x64-AllOS-ENU.exe"
$dn48path = $PatchFolderPath + "\ndp48-x86-x64-allos-enu.exe"
$patch2 = $PatchFolderPath + "\Patch2\Setup.exe"
$patch4 = $PatchFolderPath + "\Patch4\Setup.exe"
$patch11 = $PatchFolderPath + "\Patch11\Setup.exe"

$7zip = $PatchFolderPath + "\7zip"
$90meter = $PatchFolderPath + "\90Meter"
$activclient = $PatchFolderPath + "\ActivClient"
$acrobat = $PatchFolderPath + "\Acrobat"
$axway = $PatchFolderPath + "\Axway"
$chrome = $PatchFolderPath + "\Chrome"
$dset = $PatchFolderPath + "\DSET"
$firefox = $PatchFolderPath + "\firefox"
$flash = $PatchFolderPath + "\Flash"
$java = $PatchFolderPath + "\Java"
#$shockwave = $PatchFolderPath + "\Shockwave"
$silverlight = $PatchFolderPath + "\Silverlight"
$tanium = $PatchFolderPath + "\Tanium"
$teams = $PatchFolderPath + "\Teams"
$titus = $PatchFolderPath + "\Titus"
$vlc = $PatchFolderPath + "\vlc"

$onedrive = $PatchFolderPath + "\OneDriveSetup.exe"

$datu = Get-ChildItem -Path $PatchFolderPath | Where-Object {$_.Name -like "CM-*xdat.exe"}
$datun = $datu.Count

if (!(Test-Path $cab)) {
    New-Item -Path $PatchFolderPath -Name cab -ItemType Directory
}
else {
    Remove-Item $cab\* -Recurse -Force
}

#If there are part files, join them together
$parts = (Get-ChildItem $PatchFolderPath | Where-Object {$_.Attributes -eq "Directory" -and $_.Name -match "Part_"} | Select-Object FullName).FullName
foreach ($part in $parts) {
    Join-File $part $PatchFolderPath
}

Start-Sleep 2

#Extract CAB files from .MSU files
$msus = Get-ChildItem -Path $PatchFolderPath | Where-Object {$_.Name -match ".msu"}
foreach ($msu in $msus) {
    $name = $msu.Name
    $fname = $msu.FullName
    $nn = $name -replace "1_SSU_windows10.0-","" -replace "2_windows10.0-","" -replace "3_net_windows10.0-","" -replace "windows10.0-","" -replace "windows8.1-","" -replace "windows6.1-","" -replace "windows6.0-",""
    $nn = $nn.Substring(0,9)
    if ($hf -match $nn) {
        Write-Host "$cn`: Patch $nn already installed. Skipping..."
    }
    else {
        expand.exe -F:* "$fname" $cab | Out-Null
    }
}

Start-Sleep 5

#Copy Office updates from individual Office folders to cab folder
$ofcs = $null
$ofcs = @()
$ofi = (Get-ChildItem $PatchFolderPath | Where-Object {$_.Attributes -eq "Directory" -and $_.Name -match "Office"} | Select-Object FullName).FullName
foreach ($of in $ofi) {
    $ofcs += (Get-ChildItem $of | Where-Object {$_.Name -like "*.cab"} | Select-Object FullName).FullName
}
foreach ($ofc in $ofcs) {
    if ($null -ne $ofc -and $ofc -ne "") {
        Copy-Item $ofc $cab -Force
    }
}

#Copy .cab files in PatchFolder to cab folder
$ofi2 = (Get-ChildItem $PatchFolderPath | Where-Object {$_.Name -like "*.cab"} | Select-Object FullName).FullName
foreach ($ofc2 in $ofi2) {
    Copy-Item $ofc2 $cab -Force
}

#Ingore the extra files that come with Windows updates
$cabs = Get-ChildItem -Path $cab | Where-Object {$_.Name -like "Windows*.cab" -or $_.Name -like "ace*.cab" -or $_.Name -like "excel*.cab" -or $_.Name -like "mso*.cab" -or $_.Name -like "graph*.cab" -or $_.Name -like "kb*.cab" -or $_.Name -like "outlook*.cab" -or $_.Name -like "powerpoint*.cab" -or $_.Name -like "word*.cab" -or $_.Name -like "access*.cab"}


$n = $cabs.Length
$i = 0
foreach ($obj in $cabs) {
    $i++
    $oname = $obj.FullName
    $obname = $obj.Name
    Write-Host "$cn`: Installing $obname. Patch $i of $n."
    dism.exe /online /add-package /PackagePath:$oname /NoRestart | Out-Null
    Start-Sleep 5
}

if (Test-Path $dn472path) {
    Write-Host "$cn`: Installing .NET Framework 4.7.2."
    Start-Process $dn472path -ArgumentList "/q /norestart" -NoNewWindow -Wait
}

if (Test-Path $dn48path) {
    Write-Host "$cn`: Installing .NET Framework 4.8."
    Start-Process $dn48path -ArgumentList "/q /norestart" -NoNewWindow -Wait
}

if (Test-Path $7zip) {
    Write-Host "$cn`: Installing 7zip."
    $7i = Get-ChildItem $7zip
    $7p = $7i.FullName[0]
    Start-Process $7p -ArgumentList "/S" -NoNewWindow -Wait
    Start-Sleep 120
}

if (Test-Path $90meter) {
    $ip9 = ($ip | Where-Object {$_.ProgramName -like "90meter*"} | Select-Object Version,Comment)[0]
    $ip9c = ($ip9 | Select-Object Comment).Comment
    if ($ip9c -eq " -- SDC SIPR - 90Meter Smart Card Manager - 190712") {
        Write-Host "$cn`: 90Meter in patches folder same as installed version. Skipping install..."
    }
    else {
        Write-Host "$cn`: Uninstalling old 90Meter"
        Get-WmiObject -Class Win32_Product -Filter "Name LIKE '90Meter%'" | Remove-WmiObject
        Start-Sleep 30
        Start-Process C:\windows\System32\msiexec.exe -ArgumentList "/uninstall {54C965FF-E457-4993-A083-61B9A6AEFEC1} /quiet /norestart" -NoNewWindow -Wait
        Start-Sleep 30
        Write-Host "$cn`: Installing 90meter."
        Start-Process c:\Patches\90Meter\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
}

if (Test-Path $activclient) {
    $inac = $null
    $inac = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%ActivClient%'"
    if ($null -ne $inac -and $inac -ne "") {
        Write-Host "$cn`: Uninstalling old version of ActivClient."
        Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%ActivClient%'" | Remove-WmiObject
        Start-Sleep 150
    }
    Write-Host "$cn`: Installing ActivClient."
    Start-Process c:\Patches\ActivClient\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
    Start-Sleep 150
}

if (Test-Path $acrobat) {
    $sv = $null
    $sv = Get-Content $acrobat\SoftwareVersion.txt
    $ipa = ($ip | Where-Object {$_.ProgramName -like "Adobe Acrobat*"} | Select-Object Version)[0].Version
    if ($sv -match $ipa) {
        Write-Host "$cn`: Adobe Acrobat in patches folder same as installed version. Skipping install..."
    }
    else {
        Write-Host "$cn`: Installing Adobe Acrobat."
        Start-Process c:\Patches\Acrobat\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 200
    }
}

if (Test-Path $axway) {
    Write-Host "$cn`: Installing Axway."
    Start-Process c:\Patches\Axway\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
    Start-Sleep 150
}

if (Test-Path $chrome) {
    $sv = $null
    $sv = Get-Content $chrome\SoftwareVersion.txt
    $ipc = ($ip | Where-Object {$_.ProgramName -like "Google Chrom*"} | Select-Object Version)[0].Version
    if ($sv -match $ipc) {
        Write-Host "$cn`: Google Chrome in patches folder same as installed version. Skipping install..."
    }
    else {
        $inchrome = $null
        $inchrome = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Chrome%'"
        if ($null -ne $inchrome -and $inchrome -ne "") {
            Write-Host "$cn`: Uninstalling old version of Chrome."
            Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Chrome%'" | Remove-WmiObject
            Start-Sleep 150
        }
        Write-Host "$cn`: Installing Chrome."
        Start-Process c:\Patches\Chrome\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
}

if (Test-Path $dset) {
    $sv = $null
    $sv = Get-Content $dset\SoftwareVersion.txt
    $ipd = ($ip | Where-Object {$_.ProgramName -like "DSET*"} | Select-Object Version)[0].Version
    if ($sv -match $ipd) {
        Write-Host "$cn`: DSET in patches folder same as installed version. Skipping install..."
    }
    else {
        Write-Host "$cn`: Installing DSET."
        Start-Process c:\Patches\DSET\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
}

if (Test-Path $firefox) {
    $inff = $null
    $sv = Get-Content $firefox\SoftwareVersion.txt
    $inff = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Firefox%'"
    if ($inff -eq "") {$inff = "0.0.0.0.0.0"}
    $ipff = ($inff | Select-Object Version)[0].Version
    
    if ($sv -match $ipff) {
        Write-Host "$cn`: Firefox in patches folder same as installed version. Skipping install..."
    }
    else {
        if ($null -ne $inff -and $inff -ne "") {
            Write-Host "$cn`: Uninstalling old versions of Firefox."
            Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files\Mozilla Firefox\uninstall\helper.exe" -ms' -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Seconds 10
            Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files (x86)\Mozilla Firefox\uninstall\helper.exe" -ms' -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Seconds 30
            Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Firefox%'" | Remove-WmiObject
            Start-Sleep 60
        }
        Write-Host "$cn`: Installing Firefox."
        $ffi = Get-ChildItem $firefox | Where-Object {$_.Name -like "firef*.exe"}
        if ($ffi.count -eq 1) {
            $ffp = $ffi.FullName
        }
        else {
            $ffp = $ffi.FullName[0]
        }
        Start-Process $ffp -ArgumentList "-ms" -NoNewWindow -Wait
        Start-Sleep 150
        Write-Host "$cn`: Uninstalling Firefox Maintenance Service."
        Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files (x86)\Mozilla Maintenance Service\uninstall.exe" /S' -ErrorAction SilentlyContinue | Out-Null
        Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Mozilla Maintenance%'"| Remove-WmiObject
        Start-Sleep 30
    }#else firefox same as installed
}

if (Test-Path $flash) {
    $sv = $null
    $sv = Get-Content $flash\SoftwareVersion.txt
    $ipf = ($ip | Where-Object {$_.ProgramName -like "Adobe Flash Player*"} | Select-Object Version)[0].Version
    if ($sv -match $ipf) {
        Write-Host "$cn`: Flash in patches folder same as installed version. Skipping install..."
    }
    else {
        Write-Host "$cn`: Installing Flash."
        Start-Process c:\Patches\Flash\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
}

if (Test-Path $java) {
    $sv = $null
    $sv = Get-Content $java\SoftwareVersion.txt
    $ipj = ($ip | Where-Object {$_.ProgramName -like "Java*"} | Select-Object Version)[0].Version
    if ($sv -match $ipj) {
        Write-Host "$cn`: Java in patches folder same as installed version. Skipping install..."
    }
    else {
        $inja = $null
        $inja = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Java%'"
        if ($null -ne $inja -and $inja -ne "") {
            Write-Host "$cn`: Uninstalling old version of Java."
            Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Java%'" | Remove-WmiObject
            Start-Sleep 450
        }
        Write-Host "$cn`: Installing Java."
        Start-Process c:\Patches\Java\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 400
    }
}

if (Test-Path $onedrive) {
    Start-Process $onedrive -ArgumentList "/AllUsers /Silent" -NoNewWindow -Wait
}

#if (Test-Path $shockwave) {
#    $sv = $null
#    $sv = gc $shockwave\SoftwareVersion.txt
#    $ips = ($ip | where {$_.ProgramName -like "Adobe Shockwave*"} | select Version)[0].Version
#    if ($sv -match $ips) {
#        Write-Host "$cn`: Shockwave in patches folder same as installed version. Skipping install..."
#    }
#    else {
#        Write-Host "$cn`: Installing Shockwave."
#        Start-Process c:\Patches\Shockwave\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
#        Start-Sleep 150
#    }
#}

if (Test-Path $silverlight) {
    $slv = $null
    $slv = Get-Content $silverlight\SoftwareVersion.txt
    $ips = ($ip | Where-Object {$_.ProgramName -like "Microsoft Silverligh*"} | Select-Object Version)[0].Version
    if ($slv -match $ips) {
        Write-Host "$cn`: Silverlight in patches folder same as installed version. Skipping install..."
    }
    else {
        Write-Host "$cn`: Installing Silverlight."
        Start-Process c:\Patches\Silverlight\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
}

if (Test-Path $tanium) {
    $tav = $null
    $tav = Get-Content $tanium\SoftwareVersion.txt
    $ipta = ($ip | Where-Object {$_.ProgramName -like "Tanium Cli*"} | Select-Object Version)[0].Version
    if ($tav -match $ipta) {
        Write-Host "$cn`: Tanium in patches folder same as installed version. Skipping install..."
    }
    else {
        Write-Host "$cn`: Installing Tanium."
        Start-Process c:\Patches\Tanium\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
}

if (Test-Path $teams) {
    $tev = $null
    $tev = Get-Content $teams\SoftwareVersion.txt
    $ipt = ($ip | Where-Object {$_.ProgramName -like "Teams Mach*"} | Select-Object Version)[0].Version
    if ($tev -match $ipt) {
        Write-Host "$cn`: Teams in patches folder same as installed version. Skipping install..."
    }
    else {
        Write-Host "$cn`: Installing Teams."
        Start-Process c:\Patches\Teams\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
}

if (Test-Path $titus) {
    Write-Host "$cn`: Installing Titus."
    Start-Process c:\Patches\Titus\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
    Start-Sleep 150
}

if (Test-Path $vlc) {
    Write-Host "$cn`: Installing VLC."
    $vi = Get-ChildItem $vlc
    $vp = $vi.FullName[0]
    Start-Process $vp -ArgumentList "/L=1033 /S" -NoNewWindow -Wait
    Start-Sleep 120
}

if (Test-Path $patch2) {
    Write-Host "$cn`: Installing McAfee Patch 2."
    Start-Process $patch2 -ArgumentList "/quiet /norestart" -NoNewWindow -Wait
    Start-Sleep -Seconds 30
}

if (Test-Path $patch4) {
    Write-Host "$cn`: Installing McAfee Patch 4."
    Start-Process $patch4 -ArgumentList "/quiet /norestart" -NoNewWindow -Wait
    Start-Sleep -Seconds 30
}
    
if (Test-Path $patch11) {
    Write-Host "$cn`: Installing McAfee Patch 11."
    Start-Process $patch11 -ArgumentList "/quiet /norestart" -NoNewWindow -Wait
    Start-Sleep -Seconds 30
}

if ($datun -ge 1) {
    Write-Host "$cn`: Installing McAfee DAT update."
    foreach ($dat in $datu) {
        Start-Process $dat -ArgumentList "/silent" -NoNewWindow -Wait
    }
}