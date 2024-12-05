Describe "WSTools Module" {
    It "Should import without errors" {
        Import-Module WSTools -ErrorAction Stop
    }
    It "Should have expected functions" {
        (Get-Command -Module WSTools).Name | Should -Contain "Get-WSToolsVersion"
    }
}
