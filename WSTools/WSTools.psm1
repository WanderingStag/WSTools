#Requires -Version 3
# Get public and private function definition files.
$Functions = @( Get-ChildItem -Path $PSScriptRoot\Functions\*.ps1 -Recurse -ErrorAction SilentlyContinue )

# Dot source the files
Foreach ($import in @($Functions)) {
    Try {
        . $import.fullname
    }
    Catch {
        Write-Error -Message "Failed to import function $($import.fullname): $_"
    }
}

Export-ModuleMember -Function $Functions.Basename
