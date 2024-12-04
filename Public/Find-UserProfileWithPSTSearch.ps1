function Find-UserProfileWithPSTSearch {
<#
.Notes
    AUTHOR: Skyler Hart
    LASTEDIT: 08/18/2017 20:58:26
    KEYWORDS:
    REQUIRES:
        #Requires -Version 3.0
        #Requires -Modules ActiveDirectory
        #Requires -PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
        #Requires -RunAsAdministrator
.LINK
    https://wanderingstag.github.io
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Host','Name','Computer','CN')]
        [string[]]$ComputerName = "$env:COMPUTERNAME",

        [Parameter(Mandatory=$false, Position=1)]
        [Alias('User','SamAccountname')]
        [string[]]$Username = "$env:USERNAME"
    )

    $i = 0

    foreach ($Comp in $ComputerName) {
            #Progress Bar
            $length = $ComputerName.length
            $i++
            if ($length -gt "1") {
                $number = $ComputerName.length
                $amount = ($i / $number)
                $perc1 = $amount.ToString("P")
                Write-Progress -activity "Getting profile status on computers" -status "Computer $i of $number. Percent complete:  $perc1" -PercentComplete (($i / $ComputerName.length)  * 100)
            }#if length
        $compath = "\\" + $Comp + "\c$"
        try {
            New-PSDrive -Name ProfCk -PSProvider FileSystem -root "$compath" -ErrorAction Stop | Out-Null

            foreach ($User in $Username) {
                try {
                    $modtime = $null
                    $usrpath = "ProfCk:\Users\$User"
                    if (Test-Path -Path $usrpath -ErrorAction Stop) {
                        $modtime = Get-Item $usrpath | ForEach-Object {$_.LastWriteTime}

                        #Check for pst's
                        $pstck = (Get-ChildItem $usrpath -recurse -filter *.pst | Select-Object Name,LastWriteTime,LastAccessTime,Directory)
                        if ($null -ne $pstck) {
                            foreach ($pst in $pstck) {
                                $pstname = ($pst).Name
                                $pstlwt = ($pst).LastWriteTime
                                $pstlat = ($pst).LastAccessTime
                                $pstdir = ($pst).Directory.FullName

                                [PSCustomObject]@{
                                    Name = $Comp
                                    Status = "Online"
                                    User = $User
                                    Profile = "Yes"
                                    ProfileModifiedTime = $modtime
                                    PST = "Yes"
                                    PSTName = $pstname
                                    PSTLastWriteTime = $pstlwt
                                    PSTLastAccessTime = $pstlat
                                    PSTDirectory = $pstdir
                                } | Select-Object Name,Status,User,Profile,ProfileModifiedTime,PST,PSTName,PSTLastWriteTime,PSTLastAccessTime,PSTDirectory
                            }#foreach pst
                        }#if pstck not null
                        else {
                            [PSCustomObject]@{
                                Name = $Comp
                                Status = "Online"
                                User = $User
                                Profile = "Yes"
                                ProfileModifiedTime = $modtime
                                PST = "No"
                                PSTName = $null
                                PSTLastWriteTime = $null
                                PSTLastAccessTime = $null
                                PSTDirectory = $null
                            } | Select-Object Name,Status,User,Profile,ProfileModifiedTime,PST,PSTName,PSTLastWriteTime,PSTLastAccessTime,PSTDirectory
                        }#else pstck is null
                    }#if user profile exists on computer
                    else {
                        [PSCustomObject]@{
                            Name = $Comp
                            Status = "Online"
                            User = $User
                            Profile = "No"
                            ProfileModifiedTime = $null
                            PST = $null
                            PSTName = $null
                            PSTLastWriteTime = $null
                            PSTLastAccessTime = $null
                            PSTDirectory = $null
                        } | Select-Object Name,Status,User,Profile,ProfileModifiedTime,PST,PSTName,PSTLastWriteTime,PSTLastAccessTime,PSTDirectory
                    }#else no profile
                }#try
                Catch [System.UnauthorizedAccessException] {
                    [PSCustomObject]@{
                        Name = $Comp
                        Status = "Access Denied"
                        User = $user
                        Profile = "Possible"
                        ProfileModifiedTime = $null
                        PST = $null
                        PSTName = $null
                        PSTLastWriteTime = $null
                        PSTLastAccessTime = $null
                        PSTDirectory = $null
                    } | Select-Object Name,Status,User,Profile,ProfileModifiedTime,PST,PSTName,PSTLastWriteTime,PSTLastAccessTime,PSTDirectory
                }#catch access denied
            }#foreach user
            Remove-PSDrive -Name ProfCk -ErrorAction SilentlyContinue -Force | Out-Null
        }#try new psdrive
        Catch {
            [PSCustomObject]@{
                Name = $Comp
                Status = "Comm Error"
                User = $null
                Profile = $null
                ProfileModifiedTime = $null
                PST = $null
                PSTName = $null
                PSTLastWriteTime = $null
                PSTLastAccessTime = $null
                PSTDirectory = $null
            } | Select-Object Name,Status,User,Profile,ProfileModifiedTime,PST,PSTName,PSTLastWriteTime,PSTLastAccessTime,PSTDirectory
        }#catch new psdrive
    }#foreach computer
}#find userprofilewithpstsearch
