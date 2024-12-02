#referenced in Send-ToastNotification
function Get-NotificationApp {
<#
.NOTES
    Author: Skyler Hart
    Created: 2021-07-14 23:42:57
    Last Edit: 2021-07-16 01:57:31
    Keywords:
    Requires:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('Get-ToastNotifierApp','Get-ToastNotificationApp')]
    param()

    $info = @()
    $HKCR = Get-PSDrive -Name HKCR -ErrorAction SilentlyContinue
    if (!($HKCR)) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root Hkey_Classes_Root -Scope Script | Out-Null
    }

    $AppRegPath = "HKCR:\AppUserModelId"
    $apps = Get-ChildItem $AppRegPath | Where-Object {$_.Name -notmatch "Andromeda_cw5n1h2txyewy!App" -and $_.Name -notmatch "Microsoft.Windows.Defender" -and `
        $_.Name -notlike "*Windows.Defender" -and $_.Name -notmatch "DeviceManagementTokenRenewalRequired" -and $_.Name -notmatch "Messaging.SystemAlertNotification" -and `
        $_.Name -notmatch "Windows.SystemToast.Suggested" -and $_.Name -notmatch "Windows.SystemToast.WindowsTip"
    }

    $info = foreach ($app in $apps) {
        $name = $app.Name -replace "HKEY_CLASSES_ROOT\\AppUserModelId\\",""
        $apppath = $AppRegPath + "\" + $name
        $dn = Get-ItemProperty -Path $apppath -Name DisplayName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue

        if ($name -eq 'Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge') {$dn = "Microsoft Edge"}
        elseif ($name -eq 'Microsoft.Office.OUTLOOK.EXE.15') {$dn = "Outlook"}
        #elseif ($name -eq "Microsoft.Office.OUTLOOK.EXE.16") {$dn = "Microsoft.Office.OUTLOOK.EXE.16"}
        elseif ($name -eq "Microsoft.Windows.ControlPanel") {$dn = "Control Panel"}
        elseif ($name -eq "Microsoft.Windows.Explorer") {$dn = "File Explorer"}
        elseif ($name -eq "Microsoft.Windows.InputSwitchToastHandler") {$dn = "Input Switch Notification"}
        elseif ($name -eq "Microsoft.Windows.LanguageComponentsInstaller") {$dn = "Language settings"}
        elseif ($name -eq "Microsoft.Windows.ParentalControls") {$dn = "Microsoft family features"}
        elseif ($name -eq "Windows.ActionCenter.QuietHours") {$dn = "Focus assist"}
        elseif ($name -eq "Windows.Defender.MpUxDlp") {$dn = "Data Loss Prevention"}
        elseif ($name -eq "Windows.Defender.SecurityCenter") {$dn = "Windows Security"}
        elseif ($name -eq "Windows.System.AppInitiatedDownload") {$dn = "Automatic file downloads"}
        elseif ($name -eq "Windows.System.Audio") {$dn = "Volume Warning"}
        elseif ($name -eq "Windows.System.Continuum") {$dn = "Tablet mode"}
        elseif ($name -eq "Windows.System.MiracastReceiver") {$dn = "Connect"}
        elseif ($name -eq "Windows.System.NearShareExperienceReceive") {$dn = "Nearby sharing"}
        elseif ($name -eq "Windows.System.ShareExperience") {$dn = "Nearby sharing"}
        elseif ($name -eq "Windows.SystemToast.AudioTroubleshooter") {$dn = "Audio"}
        elseif ($name -eq "Windows.SystemToast.AutoPlay") {$dn = "AutoPlay"}
        elseif ($name -eq "Windows.SystemToast.BackgroundAccess") {$dn = "Battery saver"}
        elseif ($name -eq "Windows.SystemToast.BackupReminder") {$dn = "Backup settings"}
        elseif ($name -eq "Windows.SystemToast.BdeUnlock") {$dn = "BitLocker Drive Encryption"}
        elseif ($name -eq "Windows.SystemToast.BitLockerPolicyRefresh") {$dn = "Device Encryption"}
        elseif ($name -eq "Windows.SystemToast.Bthprops") {$dn = "Add a device"}
        elseif ($name -eq "Windows.SystemToast.BthQuickPair") {$dn = "Bluetooth"}
        elseif ($name -eq "Windows.SystemToast.Calling") {$dn = "Incoming call"}
        elseif ($name -eq "Windows.SystemToast.Calling.SystemAlertNotification") {$dn = "Alert"}
        elseif ($name -eq "Windows.SystemToast.CloudExperienceHostLauncher") {$dn = "Device Setup"}
        elseif ($name -eq "Windows.SystemToast.CloudExperienceHostLauncherCustom") {$dn = "Device Setup"}
        elseif ($name -eq "Windows.SystemToast.Compat") {$dn = "Compatibility Assistant"}
        #elseif ($name -eq "Windows.SystemToast.DeviceConsent") {$dn = ""}
        elseif ($name -eq "Windows.SystemToast.DeviceEnrollmentActivity") {$dn = "Device Management Enrollment Service"}
        elseif ($name -eq "Windows.SystemToast.DeviceManagement") {$dn = "Work or School Account"}
        elseif ($name -eq "Windows.SystemToast.Devices") {$dn = "Devices"}
        elseif ($name -eq "Windows.SystemToast.DisplaySettings") {$dn = "Display Settings"}
        elseif ($name -eq "Windows.SystemToast.EnterpriseDataProtection") {$dn = "Windows Information Protection"}
        elseif ($name -eq "Windows.SystemToast.Explorer") {$dn = "File Explorer"}
        elseif ($name -eq "Windows.SystemToast.FodHelper") {$dn = "Optional Features"}
        elseif ($name -eq "Windows.SystemToast.HelloFace") {$dn = "Windows Hello"}
        elseif ($name -eq "Windows.SystemToast.LocationManager") {$dn = "Location"}
        elseif ($name -eq "Windows.SystemToast.LowDisk") {$dn = "Storage settings"}
        elseif ($name -eq "Windows.SystemToast.MobilityExperience") {$dn = "Continue from your phone"}
        elseif ($name -eq "Windows.SystemToast.NfpAppAcquire") {$dn = "System Notification"}
        elseif ($name -eq "Windows.SystemToast.NfpAppLaunch") {$dn = "Tap and start"}
        elseif ($name -eq "Windows.SystemToast.NfpDevicePairing") {$dn = "Tap and setup"}
        elseif ($name -eq "Windows.SystemToast.NfpReceiveContent") {$dn = "Tap and send"}
        elseif ($name -eq "Windows.SystemToast.Print.Notification") {$dn = "Print Notification"}
        elseif ($name -eq "Windows.SystemToast.RasToastNotifier") {$dn = "VPN"}
        elseif ($name -eq "Windows.SystemToast.SecurityAndMaintenance") {$dn = "Security and Maintenance"}
        elseif ($name -eq "Windows.SystemToast.SecurityCenter") {$dn = "Security and Maintenance"}
        elseif ($name -eq "Windows.SystemToast.SEManagement") {$dn = "Payment"}
        elseif ($name -eq "Windows.SystemToast.ServiceInitiatedHealing.Notification" ) {$dn = "Service Initiated Healing"}
        elseif ($name -eq "Windows.SystemToast.Share") {$dn = "Share"}
        elseif ($name -eq "Windows.SystemToast.SoftLanding") {$dn = "Tips"}
        elseif ($name -eq "Windows.SystemToast.SpeechServices") {$dn = "Microsoft Speech Recognition"}
        elseif ($name -eq "Windows.SystemToast.StorSvc") {$dn = "Storage settings"}
        elseif ($name -eq "Windows.SystemToast.Usb.Notification") {$dn = "USB"}
        elseif ($name -eq "Windows.SystemToast.WiFiNetworkManager") {$dn = "Wireless"}
        elseif ($name -eq "Windows.SystemToast.WindowsUpdate.Notification") {$dn = "Windows Update"}
        elseif ($name -eq "Windows.SystemToast.Winlogon") {$dn = "Windows logon reminder"}
        elseif ($name -eq "Windows.SystemToast.Wwansvc") {$dn = "Cellular"}
        elseif ([string]::IsNullOrWhiteSpace($dn)) {$dn = "unknown"}

        $zname = $dn + " (" + $name + ")"
        [PSCustomObject]@{
            Name = $name
            DisplayName = $dn
            zName = $zname
        }#new object
    }

    $info
    #Remove-PSDrive -Name HKCR -Force
}
