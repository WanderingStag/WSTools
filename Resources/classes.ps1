Class WSTools {
	#Properties
	[datetime]$LastUpdate
	[string]$Version
	[string]$ScriptRoot
	[object]$Config

	#Methods
	hidden Init () {
        $root = $PSScriptRoot.Substring(0,($PSScriptRoot.Length-10))
		$this.ScriptRoot = $root
		$this.Config = $Global:WSToolsConfig
		$this.Version = (Test-ModuleManifest $root\WSTools.psd1).Version
		$this.LastUpdate = (Get-Item $root\WSTools.psd1).LastWriteTime
	}

	AddConfigItem ($Name, $Value) {
		$this.Config = $this.Config | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -PassThru
	}

	SaveUserConfig () {
		$ModuleConfig = "$PSScriptRoot\Config.ps1"

		$items = $Global:WSToolsConfig | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name

		$filetextstart = @"
`$Global:WSToolsUserConfig = [PSCustomObject]@{
"@

		$filetextend = @"

}
"@

		$filetext = foreach ($i in $items) {
    		$Type = ($Global:WSToolsConfig.$i).GetType() | Select-Object -ExpandProperty Name
			$Value = $Global:WSToolsConfig.$i

			if (($ModuleConfig.$i -ne $Global:WSToolsConfig.$i) -and $Type -eq "String") {
				@"

	$i = "$Value"
"@
			}
			elseif ($Type -eq "Int32") {
				@"

	$i = $Value
"@
			}
			elseif ($Type -eq "Boolean") {
				@"

	$i = `$$Value
"@
			}
			elseif ($Type -match "Object") {
				$Value = $Value -join "','"
				@"

	$i = @('$Value')
"@
			}
		}#file text

		$content = $filetextstart + $filetext + $filetextend
		$UserPowerShell = split-path $Global:Profile.CurrentUserCurrentHost

		if (!(Test-Path $UserPowerShell)) {
			New-Item -Path $UserPowerShell -ItemType Directory
		}

		if (!(Test-Path $UserPowerShell\WSToolsConfig.ps1)) {
			Set-Content -Path $UserPowerShell\WSToolsConfig.ps1 -Value $content
		}
		else {
			$overwrite = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
			$cancel = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
			$options = [System.Management.Automation.Host.ChoiceDescription[]]($overwrite, $cancel)

			$title = 'User config exists'
			$message = 'User configuration file already exists. Overwrite it?'
			$result = $Global:Host.ui.PromptForChoice($title, $message, $options, 0)

			switch ($result) {
				0 {Set-Content -Path $UserPowerShell\WSToolsConfig.ps1 -Value $content}
				1 {Write-Host 'Cancelled'}
			}
		}
	}#save user config

	Update () {
		Update-WSTools
	}

	#Constructors
	WSTools () {
		$this.Init()
	}
}

$Global:WSTools = [WSTools]::new()