Function Get-InstalledProgram {
<#
.SYNOPSIS
    Displays installed programs on a computer.
.DESCRIPTION
    Displays a list of installed programs on a local or remote computer by querying the registry.
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Get-InstalledProgram
    Shows the installed programs on the local computer.
.EXAMPLE
    C:\PS>Get-InstalledProgram -ComputerName COMPUTER1
    Shows the installed programs on the remote computer COMPUTER1.
.EXAMPLE
    C:\PS>Get-InstalledProgram -ComputerName COMPUTER1,COMPUTER2
    Shows the installed programs on the remote computers COMPUTER1 and COMPUTER2.
.EXAMPLE
    C:\PS>Get-InstalledProgram (gc C:\Temp\computers.txt)
    Shows the installed programs on the remote computers listed in the computers.txt file (each computer name on a new line.)
.EXAMPLE
    C:\PS>Get-InstalledProgram COMPUTER1 -Property InstallSource
    Shows the installed programs on the remote computer COMPUTER1 and also shows the additional property InstallSource from the registry.
.EXAMPLE
    C:\PS>Get-InstalledProgram COMPUTER1,COMPUTER2 -Property InstallSource,Comments
    Shows the installed programs on the remote computers COMPUTER1 and COMPUTER2. Also shows the additional properties InstallSource and Comments from the registry.
.NOTES
    Author: Skyler Hart
    Created: Sometime prior to 2017-08
    Last Edit: 2020-08-19 23:03:32
    Keywords:
.LINK
    https://wstools.dev
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
    Begin {
        $RegistryLocation = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
                            'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'
        $HashProperty = @{}
        $SelectProperty = @('ComputerName','Installed','ProgramName','Version','Uninstall','Comment')
        if ($Property) {
            $SelectProperty += $Property
        }
    }#begin
    Process {
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
                        }#foreach object
                    }#if currentregkey
                }#if regbase
            }#foreach registry entry in registry location
            $installed | Select-Object $SelectProperty | Sort-Object ProgramName
        }#foreach computer
    }#process
}

Function Join-File {
<#
    .Notes
    AUTHOR: Skyler Hart
    CREATED: 04/30/2019 14:52:40
    LASTEDIT: 04/30/2019 17:17:50
    KEYWORDS:
.LINK
    https://wstools.dev
#>
    [CmdletBinding()]
    Param (
        [Parameter(HelpMessage = "Enter the path of the folder with the part files you want to join.",
            Mandatory=$true,
            Position=0
        )]
        [Alias('Source','InputLocation','SourceFolder')]
        [string]$Path,

        [Parameter(
            Mandatory=$false,
            Position=1
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
            Write-Output "Appending $_ to $fop"
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
            Write-Output "Appending $_ to $fop"
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
$ip = Get-InstalledProgram | Select-Object ProgramName,Version,Comment
$hf = (Get-HotFix | Select-Object HotFixID).HotFixID

#$scripts = Get-ChildItem -Path $PatchFolderPath | Where-Object {$_.Name -match ".ps1" -and $_.Name -notmatch "Install.ps1" -and $_.Name -notmatch "InstallRemote.ps1"}

$dn48path = $PatchFolderPath + "\ndp48-x86-x64-allos-enu.exe"
$patch2 = $PatchFolderPath + "\Patch2\Setup.exe"
$patch4 = $PatchFolderPath + "\Patch4\Setup.exe"
$patch11 = $PatchFolderPath + "\Patch11\Setup.exe"
$patch15 = $PatchFolderPath + "\Patch15\Setup.exe"

#$7zip = $PatchFolderPath + "\7zip"
$90meter = $PatchFolderPath + "\90Meter"
$activclient = $PatchFolderPath + "\ActivClient"
$acrobat = $PatchFolderPath + "\Acrobat"
$axway = $PatchFolderPath + "\Axway"
$chrome = $PatchFolderPath + "\Chrome"
$dset = $PatchFolderPath + "\DSET"
$firefox = $PatchFolderPath + "\firefox"
#$flash = $PatchFolderPath + "\Flash"
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
        Write-Output "$cn`: Patch $nn already installed. Skipping..."
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
$cabs = Get-ChildItem -Path $cab | Where-Object {$_.Name -like "Windows*.cab" -or $_.Name -like "ace*.cab" -or $_.Name -like "excel*.cab" -or $_.Name -like "mso*.cab" -or $_.Name -like "graph*.cab" -or $_.Name -like "kb*.cab" -or $_.Name -like "outlook*.cab" -or $_.Name -like "powerpoint*.cab" -or $_.Name -like "word*.cab" -or $_.Name -like "access*.cab" -or $_.Name -like "vbe*.cab"}


$n = $cabs.Length
$i = 0
foreach ($obj in $cabs) {
    $i++
    $oname = $obj.FullName
    $obname = $obj.Name
    Write-Output "$cn`: Installing $obname. Patch $i of $n."
    dism.exe /online /add-package /PackagePath:$oname /NoRestart | Out-Null
    Start-Sleep 5
}

if (Test-Path $dn48path) {
    Write-Output "$cn`: Installing .NET Framework 4.8."
    Start-Process $dn48path -ArgumentList "/q /norestart" -NoNewWindow -Wait
}

#if (Test-Path $7zip) {
#    Write-Output "$cn`: Installing 7zip."
#    $7i = Get-ChildItem $7zip
#    $7p = $7i.FullName[0]
#    Start-Process $7p -ArgumentList "/S" -NoNewWindow -Wait
#    Start-Sleep 120
#}

if (Test-Path $90meter -and $env:USERDNSDOMAIN -like "*.smil.mil") {
    $ip9 = ($ip | Where-Object {$_.ProgramName -like "90meter*"} | Select-Object Version,Comment)[0]
    $ip9c = ($ip9 | Select-Object Comment).Comment
    if ($ip9c -eq " -- SDC SIPR - 90Meter Smart Card Manager - 190712") {
        Write-Output "$cn`: 90Meter in patches folder same as installed version. Skipping install..."
    }
    else {
        Write-Output "$cn`: Uninstalling old 90Meter"
        Get-WmiObject -Class Win32_Product -Filter "Name LIKE '90Meter%'" | Remove-WmiObject
        Start-Sleep 30
        Start-Process C:\windows\System32\msiexec.exe -ArgumentList "/uninstall {54C965FF-E457-4993-A083-61B9A6AEFEC1} /quiet /norestart" -NoNewWindow -Wait
        Start-Sleep 30
        Write-Output "$cn`: Installing 90meter."
        Start-Process c:\Patches\90Meter\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
}

if (Test-Path $activclient -and $env:USERDNSDOMAIN -notlike "*.smil.mil") {
    $inac = $null
    $inac = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%ActivClient%'"
    if ($null -ne $inac -and $inac -ne "") {
        Write-Output "$cn`: Uninstalling old version of ActivClient."
        Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%ActivClient%'" | Remove-WmiObject
        Start-Sleep 150
    }
    Write-Output "$cn`: Installing ActivClient."
    Start-Process c:\Patches\ActivClient\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
    Start-Sleep 150
}

if (Test-Path $acrobat) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Acrobat"
    $sv = Get-Content $acrobat\SoftwareVersion.txt
    $ipv = ($ip | Where-Object {$_.ProgramName -like "Adobe Acrobat*"} | Select-Object Version)[0].Version

    $ipv = $ipv.Split('.')
    $ipv = $ipv.Split(' ')
    $sv = $sv.Split('.')
    $sv = $sv.Split(' ')

    #Determine if need to install
    if ($sv[0] -gt $ipv[0]) {
        $install = $true
    }
    elseif ($sv[0] -eq $ipv[0]) {
        if ($sv[1] -gt $ipv[1]) {
            $install = $true
        }
        elseif ($sv[1] -eq $ipv[1]) {
            #$install = $false #uncomment and remove below lines if stopping at Major.Minor
            if ($sv[2] -gt $ipv[2]) {
                $install = $true
            }
            elseif ($sv[2] -eq $ipv[2]) {
                $install = $false
            }
            elseif ($sv[2] -lt $ipv[2]) {
                $install = $false
            }
        }
        elseif ($sv[1] -lt $ipv[1]) {
            $install = $false
        }
    }
    elseif ($sv[0] -lt $ipv[0]) {
        $install = $false
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $acrobat\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 600
    }
    else {
        Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $axway) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Axway"
    $sv = Get-Content $axway\SoftwareVersion.txt
    $ipv = ($ip | Where-Object {$_.ProgramName -like "Axway*"} | Select-Object Version)[0].Version

    $ipv = $ipv.Split('.')
    $ipv = $ipv.Split(' ')
    $sv = $sv.Split('.')
    $sv = $sv.Split(' ')

    #Determine if need to install
    if ($sv[0] -gt $ipv[0]) {
        $install = $true
    }
    elseif ($sv[0] -eq $ipv[0]) {
        if ($sv[1] -gt $ipv[1]) {
            $install = $true
        }
        elseif ($sv[1] -eq $ipv[1]) {
            $install = $false
        }
        elseif ($sv[1] -lt $ipv[1]) {
            $install = $false
        }
    }
    elseif ($sv[0] -lt $ipv[0]) {
        $install = $false
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $axway\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
    else {
        Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $chrome) {
    $sv = $null
    $sv = Get-Content $chrome\SoftwareVersion.txt
    $ipc = ($ip | Where-Object {$_.ProgramName -like "Google Chrom*"} | Select-Object Version)[0].Version
    if ($sv -match $ipc) {
        Write-Output "$cn`: Google Chrome in patches folder same as installed version. Skipping install..."
    }
    else {
        $inchrome = $null
        $inchrome = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Chrome%'"
        if ($null -ne $inchrome -and $inchrome -ne "") {
            Write-Output "$cn`: Uninstalling old version of Chrome."
            Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Chrome%'" | Remove-WmiObject
            Start-Sleep 150
        }
        Write-Output "$cn`: Installing Chrome."
        Start-Process c:\Patches\Chrome\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
}

if (Test-Path $dset -and $env:USERDNSDOMAIN -notlike "*.smil.mil") {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "DSET"
    $sv = Get-Content $dset\SoftwareVersion.txt
    $ipv = ($ip | Where-Object {$_.ProgramName -like "DSET*"} | Select-Object Version)[0].Version

    $ipv = $ipv.Split('.')
    $ipv = $ipv.Split(' ')
    $sv = $sv.Split('.')
    $sv = $sv.Split(' ')

    #Determine if need to install
    if ($sv[0] -gt $ipv[0]) {
        $install = $true
    }
    elseif ($sv[0] -eq $ipv[0]) {
        if ($sv[1] -gt $ipv[1]) {
            $install = $true
        }
        elseif ($sv[1] -eq $ipv[1]) {
            #$install = $false #uncomment and remove below lines if stopping at Major.Minor
            if ($sv[2] -gt $ipv[2]) {
                $install = $true
            }
            elseif ($sv[2] -eq $ipv[2]) {
                $install = $false
            }
            elseif ($sv[2] -lt $ipv[2]) {
                $install = $false
            }
        }
        elseif ($sv[1] -lt $ipv[1]) {
            $install = $false
        }
    }
    elseif ($sv[0] -lt $ipv[0]) {
        $install = $false
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $dset\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
    else {
        Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $firefox) {
    $inff = $null
    $sv = Get-Content $firefox\SoftwareVersion.txt
    $inff = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Firefox%'"
    if ($inff -eq "") {$inff = "0.0.0.0.0.0"}
    $ipff = ($inff | Select-Object Version)[0].Version

    if ($sv -match $ipff) {
        Write-Output "$cn`: Firefox in patches folder same as installed version. Skipping install..."
    }
    else {
        if ($null -ne $inff -and $inff -ne "") {
            Write-Output "$cn`: Uninstalling old versions of Firefox."
            Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files\Mozilla Firefox\uninstall\helper.exe" -ms' -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Seconds 10
            Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files (x86)\Mozilla Firefox\uninstall\helper.exe" -ms' -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Seconds 30
            Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Firefox%'" | Remove-WmiObject
            Start-Sleep 200
        }
        Write-Output "$cn`: Installing Firefox."
        Start-Process c:\Patches\Flash\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 350
        #$ffi = Get-ChildItem $firefox | Where-Object {$_.Name -like "firef*.exe"}
        #if ($ffi.count -eq 1) {
        #    $ffp = $ffi.FullName
        #}
        #else {
        #    $ffp = $ffi.FullName[0]
        #}
        #Start-Process $ffp -ArgumentList "-ms" -NoNewWindow -Wait
        #Start-Sleep 150
        #Write-Output "$cn`: Uninstalling Firefox Maintenance Service."
        #Invoke-WMIMethod -Class Win32_Process -ComputerName $comp -Name Create -ArgumentList 'cmd /c "C:\Program Files (x86)\Mozilla Maintenance Service\uninstall.exe" /S' -ErrorAction SilentlyContinue | Out-Null
        #Get-WmiObject -Class Win32_Product -Filter "Name LIKE 'Mozilla Maintenance%'"| Remove-WmiObject
        #Start-Sleep 30
    }#else firefox same as installed
}

if (Test-Path $java) {
    $sv = $null
    $sv = Get-Content $java\SoftwareVersion.txt
    $ipj = ($ip | Where-Object {$_.ProgramName -like "Java*"} | Select-Object Version)[0].Version
    if ($sv -match $ipj) {
        Write-Output "$cn`: Java in patches folder same as installed version. Skipping install..."
    }
    else {
        $inja = $null
        $inja = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Java%'"
        if ($null -ne $inja -and $inja -ne "") {
            Write-Output "$cn`: Uninstalling old version of Java."
            Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Java%'" | Remove-WmiObject
            Start-Sleep 450
        }
        Write-Output "$cn`: Installing Java."
        Start-Process c:\Patches\Java\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 400
    }
}

if (Test-Path $onedrive) {
    Start-Process $onedrive -ArgumentList "/AllUsers /Silent" -NoNewWindow -Wait
}

if (Test-Path $silverlight) {
    $slv = $null
    $slv = Get-Content $silverlight\SoftwareVersion.txt
    $ips = ($ip | Where-Object {$_.ProgramName -like "Microsoft Silverligh*"} | Select-Object Version)[0].Version
    if ($slv -match $ips) {
        Write-Output "$cn`: Silverlight in patches folder same as installed version. Skipping install..."
    }
    else {
        Write-Output "$cn`: Installing Silverlight."
        Start-Process c:\Patches\Silverlight\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
}

if (Test-Path $tanium) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Tanium"
    $sv = Get-Content $tanium\SoftwareVersion.txt
    $ipv = ($ip | Where-Object {$_.ProgramName -like "Tanium*"} | Select-Object Version)[0].Version

    $ipv = $ipv.Split('.')
    $ipv = $ipv.Split(' ')
    $sv = $sv.Split('.')
    $sv = $sv.Split(' ')

    #Determine if need to install
    if ($sv[0] -gt $ipv[0]) {
        $install = $true
    }
    elseif ($sv[0] -eq $ipv[0]) {
        if ($sv[1] -gt $ipv[1]) {
            $install = $true
        }
        elseif ($sv[1] -eq $ipv[1]) {
            if ($sv[2] -gt $ipv[2]) {
                $install = $true
            }
            elseif ($sv[2] -eq $ipv[2]) {
                if ($sv[3] -gt $ipv[3]) {
                    $install = $true
                }
                elseif ($sv[3] -eq $ipv[3]) {
                    $install = $false
                }
                elseif ($sv[3] -lt $ipv[3]) {
                    $install = $false
                }
            }
            elseif ($sv[2] -lt $ipv[2]) {
                $install = $false
            }
        }
        elseif ($sv[1] -lt $ipv[1]) {
            $install = $false
        }
    }
    elseif ($sv[0] -lt $ipv[0]) {
        $install = $false
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $tanium\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
    else {
        Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $teams) {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Teams"
    $sv = Get-Content $teams\SoftwareVersion.txt
    $ipv = ($ip | Where-Object {$_.ProgramName -like "Teams Mach*"} | Select-Object Version)[0].Version

    $ipv = $ipv.Split('.')
    $ipv = $ipv.Split(' ')
    $sv = $sv.Split('.')
    $sv = $sv.Split(' ')

    #Determine if need to install
    if ($sv[0] -gt $ipv[0]) {
        $install = $true
    }
    elseif ($sv[0] -eq $ipv[0]) {
        if ($sv[1] -gt $ipv[1]) {
            $install = $true
        }
        elseif ($sv[1] -eq $ipv[1]) {
            #$install = $false #uncomment and remove below lines if stopping at Major.Minor
            if ($sv[2] -gt $ipv[2]) {
                $install = $true
            }
            elseif ($sv[2] -eq $ipv[2]) {
                #$install = $false #uncomment and remove below lines if stopping at Major.Minor.Patch/Revision
                if ($sv[3] -gt $ipv[3]) {
                    $install = $true
                }
                elseif ($sv[3] -eq $ipv[3]) {
                    $install = $false #stopping at Major.Minor.Build.Revision
                }
                elseif ($sv[3] -lt $ipv[3]) {
                    $install = $false
                }
            }
            elseif ($sv[2] -lt $ipv[2]) {
                $install = $false
            }
        }
        elseif ($sv[1] -lt $ipv[1]) {
            $install = $false
        }
    }
    elseif ($sv[0] -lt $ipv[0]) {
        $install = $false
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $teams\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
    else {
        Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $titus -and $env:USERDNSDOMAIN -like "*.smil.mil") {
    $sv = $null
    $ipv = $null
    $install = $false
    $pn = "Titus"
    $sv = Get-Content $titus\SoftwareVersion.txt
    $ipv = ($ip | Where-Object {$_.ProgramName -like "Titus*"} | Select-Object Version)[0].Version

    $ipv = $ipv.Split('.')
    $ipv = $ipv.Split(' ')
    $sv = $sv.Split('.')
    $sv = $sv.Split(' ')

    #Determine if need to install
    if ($sv[0] -gt $ipv[0]) {
        $install = $true
    }
    elseif ($sv[0] -eq $ipv[0]) {
        if ($sv[1] -gt $ipv[1]) {
            $install = $true
        }
        elseif ($sv[1] -eq $ipv[1]) {
            if ($sv[2] -gt $ipv[2]) {
                $install = $true
            }
            elseif ($sv[2] -eq $ipv[2]) {
                if ($sv[3] -gt $ipv[3]) {
                    $install = $true
                }
                elseif ($sv[3] -eq $ipv[3]) {
                    $install = $false
                }
                elseif ($sv[3] -lt $ipv[3]) {
                    $install = $false
                }
            }
            elseif ($sv[2] -lt $ipv[2]) {
                $install = $false
            }
        }
        elseif ($sv[1] -lt $ipv[1]) {
            $install = $false
        }
    }
    elseif ($sv[0] -lt $ipv[0]) {
        $install = $false
    }

    #Install or not
    if ($install -eq $true) {
        Write-Output "$cn`: Installing $pn."
        Start-Process $titus\Deploy-application.exe -ArgumentList "-DeployMode 'NonInteractive'" -NoNewWindow -Wait
        Start-Sleep 150
    }
    else {
        Write-Output "$cn`: $pn same as installed version or older. Skipping..."
    }
}

if (Test-Path $vlc) {
    Write-Output "$cn`: Installing VLC."
    $vi = Get-ChildItem $vlc
    $vp = $vi.FullName[0]
    Start-Process $vp -ArgumentList "/L=1033 /S" -NoNewWindow -Wait
    Start-Sleep 120
}

if (Test-Path $patch2) {
    Write-Output "$cn`: Installing McAfee Patch 2."
    Start-Process $patch2 -ArgumentList "/quiet /norestart" -NoNewWindow -Wait
    Start-Sleep -Seconds 30
}

if (Test-Path $patch4) {
    Write-Output "$cn`: Installing McAfee Patch 4."
    Start-Process $patch4 -ArgumentList "/quiet /norestart" -NoNewWindow -Wait
    Start-Sleep -Seconds 30
}

if (Test-Path $patch11) {
    Write-Output "$cn`: Installing McAfee Patch 11."
    Start-Process $patch11 -ArgumentList "/quiet /norestart" -NoNewWindow -Wait
    Start-Sleep -Seconds 30
}

if (Test-Path $patch15) {
    Write-Output "$cn`: Installing McAfee Patch 15."
    Start-Process $patch15 -ArgumentList "/quiet /norestart" -NoNewWindow -Wait
    Start-Sleep -Seconds 30
}

if ($datun -ge 1) {
    Write-Output "$cn`: Installing McAfee DAT update."
    foreach ($dat in $datu) {
        Start-Process $dat -ArgumentList "/silent" -NoNewWindow -Wait
    }
}