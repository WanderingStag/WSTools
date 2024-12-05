function Set-SMBv1Fix {
<#
   .Synopsis
    Enables SMB v1.
   .Description
    Turns SMBv1 on. While this fix action turns SMBv1 on, group policy can turn SMBv1 off, which is counted on.
   .Example
    Set-SMBv1Fix COMP1
    Sets the fix action on COMP1. After the fix action is applied, COMP1 will need to be rebooted.
   .Example
    Set-SMBv1Fix
    Sets the fix action on the local computer. After the fix action is applied, the local computer will need to be rebooted.
   .Parameter ComputerName
    Specifies the computer or computers
   .Notes
    AUTHOR: Skyler Hart
    CREATED: 12/18/2018 09:36:43
    LASTEDIT: 12/18/2018 10:25:19
    KEYWORDS: fix action, fix, SMB, SMBv1
    REQUIRES:
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory=$false,
            Position=0
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME"
    )

    $ValueName = "SMB1"
    $Valuedata = 1
    $i = 0
    $number = $ComputerName.length

    foreach ($comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Setting SMBv1 registry fix" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        Invoke-Command -ComputerName $comp -ScriptBlock {Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart} #DevSkim: ignore DS104456

        #([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters') #DevSkim: ignore DS106863
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',$true) #DevSkim: ignore DS106863
        $SubKey.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::DWORD)
    }
}
