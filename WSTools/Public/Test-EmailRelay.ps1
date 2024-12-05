function Test-EmailRelay {
    <#
       .Notes
        AUTHOR: Skyler Hart
        CREATED: 08/18/2017 20:40:04
        LASTEDIT: 2021-10-12 22:09:30
        KEYWORDS: E-mail, email, relay, smtp
        REMARKS: On secure networks, port 25 has to be open
.LINK
    https://wanderingstag.github.io
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidGlobalVars",
        "",
        Justification = "Have tried other methods and they do not work consistently."
    )]
    [CmdletBinding()]
    [Alias('Test-SMTPRelay','Test-MailRelay')]
    Param (
        [Parameter(
            Mandatory=$true,
            Position=0,
            HelpMessage="Enter e-mail address of recipient")]
        [string]$Recipient
    )

    $config = $Global:WSToolsConfig
    $from = $config.Sender
    $smtpserver = $config.SMTPServer
    $port = $config.SMTPPort

    $date = Get-Date
    $subject = "Test from $env:COMPUTERNAME $date"

    send-mailmessage -To $Recipient -From $from -Subject $subject -Body "Testing relay of SMTP messages.`nFrom: $from `nTo: $Recipient `n`nPlease delete this message." -smtpserver $smtpserver -Port $port
}
