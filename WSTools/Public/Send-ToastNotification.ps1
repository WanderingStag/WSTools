#needs Get-NotificationApp
function Send-ToastNotification {
<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.PARAMETER ComputerName
    Specifies the name of one or more computers.
.PARAMETER Path
    Specifies a path to one or more locations.
.EXAMPLE
    C:\PS>Send-ToastNotification
    Example of how to use this cmdlet
.EXAMPLE
    C:\PS>Send-ToastNotification -PARAMETER
    Another example of how to use this cmdlet but with a parameter or switch.
.NOTES
    Author: Skyler Hart
    Created: 2020-11-08 14:57:29
    Last Edit: 2021-07-16 23:08:42
    Requires:
        -Module ActiveDirectory
        -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    param(
        [Parameter(
            HelpMessage = "Enter the message to send.",
            Mandatory=$true,
            Position=0
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(
            HelpMessage = "Enter the name of the sender.",
            Mandatory=$false,
            Position=1
        )]
        [string]$Sender = " ",

        [Parameter(
            Mandatory=$false,
            Position=2
        )]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName,

        [Parameter(
            Mandatory=$false
        )]
        [string]$Title,

        [Parameter(Mandatory=$false)]
        [ValidateSet('ms-winsoundevent:Notification.Default',
        'ms-winsoundevent:Notification.IM',
        'ms-winsoundevent:Notification.Mail',
        'ms-winsoundevent:Notification.Reminder',
        'ms-winsoundevent:Notification.SMS',
        'ms-winsoundevent:Notification.Looping.Alarm',
        'ms-winsoundevent:Notification.Looping.Alarm2',
        'ms-winsoundevent:Notification.Looping.Alarm3',
        'ms-winsoundevent:Notification.Looping.Alarm4',
        'ms-winsoundevent:Notification.Looping.Alarm5',
        'ms-winsoundevent:Notification.Looping.Alarm6',
        'ms-winsoundevent:Notification.Looping.Alarm7',
        'ms-winsoundevent:Notification.Looping.Alarm8',
        'ms-winsoundevent:Notification.Looping.Alarm9',
        'ms-winsoundevent:Notification.Looping.Alarm10',
        'ms-winsoundevent:Notification.Looping.Call',
        'ms-winsoundevent:Notification.Looping.Call2',
        'ms-winsoundevent:Notification.Looping.Call3',
        'ms-winsoundevent:Notification.Looping.Call4',
        'ms-winsoundevent:Notification.Looping.Call5',
        'ms-winsoundevent:Notification.Looping.Call6',
        'ms-winsoundevent:Notification.Looping.Call7',
        'ms-winsoundevent:Notification.Looping.Call8',
        'ms-winsoundevent:Notification.Looping.Call9',
        'ms-winsoundevent:Notification.Looping.Call10',
        'Silent')]
        [string]$AudioSource = 'ms-winsoundevent:Notification.Looping.Alarm3',

        [Parameter()]
        [switch]$ShortDuration,

        [Parameter()]
        [switch]$RequireDismiss #overrides ShortDuration
    )
    DynamicParam {
        # Set the dynamic parameters' name. You probably want to change this.
        $ParameterName = 'Notifier'

        # Create the dictionary
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]

        # Create and set the parameters' attributes. You may also want to change these.
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $false
        $ParameterAttribute.Position = 3

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet. You definitely want to change this. This part populates your set.
        $arrSet = ((Get-NotificationApp).Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($arrSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        return $RuntimeParameterDictionary
    }
    Begin {
        $Notifier = $PsBoundParameters[$ParameterName]
        if ([string]::IsNullOrWhiteSpace($Notifier)) {$Notifier = "Windows.SystemToast.NfpAppAcquire"}
        if ([string]::IsNullOrWhiteSpace($Title)) {
            $ttext = $null
        }
        else {
            $ttext = "<text>$Title</text>"
        }

        if ($AudioSource -eq 'Silent') {
            $atext = '<audio silent="true"/>'
        }
        else {
            $atext = '<audio src="' + $AudioSource + '"/>'
        }
        if ($RequireDismiss) {
            $scenario = '<toast scenario="reminder">'
            $actions = @"
        <actions>
            <action arguments="dismiss" content="Dismiss" activationType="system"/>
        </actions>
"@
        }
        else {
            if ($ShortDuration) {$dur = "short"}
            else {$dur = "long"}
            $scenario = '<toast duration="' + $dur + '">'
            $actions = $null
        }

        [xml]$ToastTemplate = @"
            $scenario
                <visual>
                <binding template="ToastGeneric">
                    <text>$Sender</text>
                    $ttext
                    <group>
                        <subgroup>
                            <text hint-style="subtitle" hint-wrap="true">$Message</text>
                        </subgroup>
                    </group>
                </binding>
                </visual>
                $actions
                $atext
            </toast>
"@

        [scriptblock]$ToastScript = {
            Param($ToastTemplate)
            #Load required assemblies
            [void][Windows.UI.Notifications.ToastNotification,Windows.UI.Notifications,ContentType=WindowsRuntime]
            [void][Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom,ContentType=WindowsRuntime]

            #Format XML
            $FinalXML = [Windows.Data.Xml.Dom.XmlDocument]::new()
            $FinalXML.LoadXml($ToastTemplate.OuterXml)

            #Create the Toast
            $Toast = [Windows.UI.Notifications.ToastNotification]::new($FinalXML)

            #Show the Toast message
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($Notifier).show($Toast)
        }
    }
    Process {
        if (![string]::IsNullOrEmpty($ComputerName)) {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock $ToastScript -ArgumentList $ToastTemplate #DevSkim: ignore DS104456
        }
        else {Invoke-Command -ScriptBlock $ToastScript -ArgumentList $ToastTemplate} #DevSkim: ignore DS104456
    }
    End {
        #done
    }
}
