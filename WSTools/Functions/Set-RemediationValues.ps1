function Set-RemediationValues {
<#
.Notes
    AUTHOR: Skyler Hart
    CREATED: 02/08/2018 22:10:17
    LASTEDIT: 2023-11-17 16:58:54
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -RunAsAdministrator
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

    $v1 = 'iexplore.exe'
    $v2 = 'SchUseStrongCrypto'
    $v3 = 'Enabled'
    $v4 = 'DisabledByDefault'
    $v5 = 'FeatureSettingsOverride'
    $v6 = 'FeatureSettingsOverrideMask'
    $v7 = 'SMB1'

    #PrintNightmare
    $v8 = 'NoWarningNoElevationOnInstall'
    $v9 = 'UpdatePromptSettings'
    $v10 = 'RestrictDriverInstallationToAdministrators'

    # EnableCertPadding
    $CertPadding = 'EnableCertPaddingCheck'

    $d0 = 0
    $d1 = 1
    $d3 = 3
    $d72 = 72 #change to 8264 for systems without hyper-threading
    #value for enabling SCHANNEL things
    #4294967295

    $i = 0
    $number = $ComputerName.length
    foreach ($comp in $ComputerName) {
        #Progress Bar
        if ($number -gt "1") {
            $i++
            $amount = ($i / $number)
            $perc1 = $amount.ToString("P")
            Write-Progress -activity "Setting remediation values" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
        }#if length

        #regionInternetExplorer
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING',$true)
        $SubKey.SetValue($v1, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING',$true)
        $SubKey.SetValue($v1, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX',$true)
        $SubKey.SetValue($v1, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX',$true)
        $SubKey.SetValue($v1, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionNETFramework
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\.NETFramework\v2.0.50727')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\.NETFramework\v2.0.50727',$true)
        $SubKey.SetValue($v2, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727',$true)
        $SubKey.SetValue($v2, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\.NETFramework\v4.0.30319')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\.NETFramework\v4.0.30319',$true)
        $SubKey.SetValue($v2, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319',$true)
        $SubKey.SetValue($v2, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionSCHANNELProtocols
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols')

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client',$true)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client',$true)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client',$true)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client',$true)
        $SubKey.SetValue($v3, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client',$true)
        $SubKey.SetValue($v4, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client',$true)
        $SubKey.SetValue($v3, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client',$true)
        $SubKey.SetValue($v4, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server',$true)
        $SubKey.SetValue($v3, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)
        $SubKey.SetValue($v4, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client',$true)
        $SubKey.SetValue($v3, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client',$true)
        $SubKey.SetValue($v4, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionSCHANNELCiphers
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/56')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/56',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168')  #DevSkim: ignore DS106863
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168',$true) #DevSkim: ignore DS106863
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56')  #DevSkim: ignore DS106863
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56',$true) #DevSkim: ignore DS106863
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionSCHANNELHashes
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA',$true)
        #$SubKey.SetValue($v3, 4294967295, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #Known Microsoft bug causes this to error out

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5')  #DevSkim: ignore DS126858
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5',$true) #DevSkim: ignore DS126858
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionSCHANNELKeyExchangeAlgorithms
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms')
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS',$true)
        #$SubKey.SetValue($v3, 4294967295, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #Known Microsoft bug causes this to error out

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman',$true)
        $SubKey.SetValue($v3, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #For local computer, properly set SHA and PKCS
        if ($comp -eq $env:COMPUTERNAME) {
            $filepath = $PSScriptRoot.Substring(0,($PSScriptRoot.Length-15)) + "\SHAandPKCS.reg"
            reg import $filepath
        }

        #regionSessionManager
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',$true)
        $SubKey.SetValue($v5, $d72, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',$true)
        $SubKey.SetValue($v6, $d3, [Microsoft.Win32.RegistryValueKind]::DWORD)
        #endregion

        #regionSMB
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',$true)
        $SubKey.SetValue($v7, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        if ($comp -eq $env:COMPUTERNAME) {
            $os = (Get-OperatingSystem).OS
            if ($os -match "2008" -or $os -match "Windows 7") {
                #Disable SMB1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 –Force
                sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
                sc.exe config mrxsmb10 start= disabled
                Start-Sleep 3

                #Enable SMB2
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 1 –Force
                sc.exe config lanmanworkstation depend= bowser/mrxsmb10/mrxsmb20/nsi
                sc.exe config mrxsmb20 start= auto
            }
            else {
                #Disable SMB1
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
                Start-Sleep 3

                #Enable SMB2
                Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
            }
        }
        #endregion

        # PrintNightmare
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',$true)
        $SubKey.SetValue($v8, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',$true)
        $SubKey.SetValue($v9, $d0, [Microsoft.Win32.RegistryValueKind]::DWORD)

        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',$true)
        $SubKey.SetValue($v10, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        # Enable Cert Padding Check
        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Microsoft\Cryptography\Wintrust\Config')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Microsoft\Cryptography\Wintrust\Config',$true)
        $SubKey.SetValue($CertPadding, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)).CreateSubKey('SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config')
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $comp)
        $SubKey = $BaseKey.OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config',$true)
        $SubKey.SetValue($CertPadding, $d1, [Microsoft.Win32.RegistryValueKind]::DWORD)

        # Network Level Authentication
        Set-NLA -ComputerName $comp
    }#foreach computer
}
