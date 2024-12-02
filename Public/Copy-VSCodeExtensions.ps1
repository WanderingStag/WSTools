function Copy-VSCodeExtensions {
    <#
    .SYNOPSIS
        Copies Visual Studio Code extensions from a specified repository to the user's local VSCode extensions directory.

    .DESCRIPTION
        This function copies all VSCode extensions from a defined repository to the user's local extensions directory, maintaining mirror consistency using robocopy.

    .PARAMETER RepoPath
        Specifies the path to the repository that contains the VSCode extensions. This path should be pre-configured in the WSTools configuration.

    .EXAMPLE
        Copy-VSCodeExtensions
        Copies VSCode extensions from the configured repository to the user's local extensions directory.

    .NOTES
        AUTHOR: Skyler Hart
        CREATED: 2021-11-01 23:18:30
        LASTEDIT: 2024-11-27 13:00:00

    .LINK
        https://wanderingstag.github.io
    #>
    [CmdletBinding()]
    param ()

    $repo = ($Global:WSToolsConfig).VSCodeExtRepo
    $dst = "$env:USERPROFILE\.vscode\extensions"

    if (-not (Test-Path -Path $dst)) {
        New-Item -Path $dst -ItemType Directory -Force | Out-Null
    }

    robocopy $repo $dst /mir /mt:4 /r:4 /w:15 /njh /njs
}
