# WSTools

![WSTools Logo](https://github.com/WanderingStag/WSTools/blob/master/WSTools_PowerShell_Module.png)

## Issues

Please **_[Open an issue](https://github.com/WanderingStag/WSTools/issues "WSTools Issues")_** if there are any problems or requests.

## Introduction

Are we Windows System Tools? Windows Security Tools? Windows Server Tools? Yes and no. WSTools are all those things and more. Whatever you decide you want to call WSTools is up to you! However, officially, we are Wandering Stag Tools (WSTools). WSTools was written for System Administrators, Help Desk Technicians, and other Network Operations personnel to automate tasks and provide valuable tools. As of May 2023 there are over 330 functions in this module. Some functionality includes:

- Active Directory functions, reports, and shortcuts allowing for easier domain management and awareness
- Computer/Server Management
  - Install/uninstall software
  - Remediation tasks such as disabling vulnerable SCHANNEL settings
  - Set network and system settings
  - Reports
- PowerShell snippets in PowerShell ISE and VS Code for easier coding
- Conversions such as image files to base64, int64 to/from IP, uint16 to string

## Download, Install, and Configuration

### Prerequisites

1. **PowerShell:** version 2 for most functions but some individual functions require version 3 or version 5. Some plans have been made to add some functions that require version 7. Check your version of PowerShell by entering the following command: **`$host`**
Then look at the _`Version`_ attribute.
2. **Active Directory PowerShell module:** Not needed for everything but is necessary for 30+ functions.
3. **NetIQ DRA PowerShell REST Extensions:** Not needed for many functions at the moment but there are plans to add more.
4. **Local Admin Password Solution (LAPS):** Actual module name: AdmPwd.PS. There are a handful of functions that require the full install of LAPS to get the module and not just the basic install. However, if you are not using LAPS on your network then there are no worries.
5. **Microsoft.Exchange.Management.PowerShell.Admin PSSnapin:** Required for the very few Exchange server related functions.

### Download

> Intended only for Windows computers at this time. Some functions may work on other OS's though.

#### From GitHub

1. Click on the Green Code button with the down arrow.
2. Select Download ZIP.
3. Change the name of the file from WSTools-master.zip to WSTools.zip.

### Install

1. Uncompress the WSTools.zip file.
2. Make available globally or just for single user.

#### Global

Copy the WSTools folder to **C:\Program Files\WindowsPowerShell\Modules**
> Requires admin rights.

#### User only

Copy the WSTools folder to **C:\Users\\_\<USERNAME>_\Documents\WindowsPowerShell\Modules**
> If the folder already exists or you get a message saying _"The destination has # files with the same names."_ you can either delete the folder that already exists _(prefered)_ or you can _Replace the files in the destination_

### Initial changes to make after copying to computer

General Configuration

1. Open PowerShell (after WSTools has been added to one of the locations above)
2. Type **```Set-WSToolsConfig```** and then press `Enter`. In the file that opens you will need to update the values so they work on your network.
    > Recommend copying this file (config.ps1) to another location after you modify it so if you download a newer version of WSTools you can just paste the config file back unless there are changes in the config file.

Remote installation of .msu files and a select few other things:

1. Open WSTools Module Path then edit InstallRemote.ps1
    > Typically _C:\Program Files\WindowsPowerShell\Modules\WSTools_ or _C:\Users\\<USERNAME\>\Documents\WindowsPowerShell\Modules\WSTools_
2. On Line 1 of InstallRemote.ps1 change the value of $PatchFolderPath to the directory on remote computers you store windows updates. This is predefined as "C:\Patches".

## Visual Studio Code setup

For adding the Visual Studio Code PowerShell Snippets do the following:

1. Open PowerShell (after WSTools has been added to one of the locations above)
2. Type the following command:
    **```Set-PowerShellJSON```**

**_or_**

1. Open the WSTools folder
    > Typically _C:\Program Files\WindowsPowerShell\Modules\WSTools_ or _C:\Users\\<USERNAME\>\Documents\WindowsPowerShell\Modules\WSTools_).
2. Cut and paste powershell.json to **%AppData%\Roaming\Code\User\Snippets** directory.

**_or_**

1. Open powershell.json (located in the WSTools module folder) and copy the text then in VSCode Command Palette (Ctrl + Shift + P)
2. Type **Snippet** and select **Preferences: Configure User Snippets**.
3. Type **PowerShell** then press **Enter**.
4. Select **powershell.json**.
5. Paste the copied text between the { } brackets and save the file.

get more open commands here: <https://sysadminstricks.com/tricks/most-useful-microsoft-management-console-snap-in-control-files-msc-files.html>
