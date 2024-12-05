function Show-BalloonTip {
<#
   .Notes
    AUTHOR: Skyler Hart
    CREATED: Sometime before 2017-08-07
    LASTEDIT: 08/18/2017 20:47:33
    KEYWORDS:
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    [Alias('tip')]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Text,

        [Parameter(Mandatory=$true)]
        [string]$Title,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Info','Error','Warning')]
        [string]$Icon = 'Info',

        [Parameter(Mandatory=$false)]
        [int32]$Timeout = 30000
    )

    Add-Type -AssemblyName System.Windows.Forms
    If ($null -eq $PopUp)  {$PopUp = New-Object System.Windows.Forms.NotifyIcon}
    $Path = Get-Process -Id $PID | Select-Object -ExpandProperty Path
    $PopUp.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($Path)
    $PopUp.BalloonTipIcon = $Icon
    $PopUp.BalloonTipText = $Text
    $PopUp.BalloonTipTitle = $Title
    $PopUp.Visible = $true
    $PopUp.ShowBalloonTip($Timeout)
}
