# Install and Configuration of WSTools

## Download WSTools

> Intended only for Windows computers.

1. On the left side, hover over the **Repos** menu item and then select **Files**
2. On the right side next to the Clone button, click on the **More actions** (three dots) button and select **Download as Zip**

## After downloading  to computer

1. Uncompress the WSTools.zip file.
2. Make available globally or just for single user.

### Global

Copy the WSTools folder to **C:\Program Files\WindowsPowerShell\Modules**
> Requires admin rights.
  
### User only
  
Copy the WSTools folder to **C:\Users\\_USERNAME_\Documents\WindowsPowerShell\Modules**
> If the folder already exists or you get a message saying _"The destination has # files with the same names."_ you can either delete the folder that already exists *(prefered)* or you can *Replace the files in the destination*

## Initial changes to make after copying to computer

General Configuration

1. Open PowerShell (after WSTools has been added to one of the locations above)
2. Type the following command and then press Enter. In the file that opens you will need to update the values so they work on your network.
**Set-WSToolsConfig**
    > Recommend copying this file (config.ps1) to another location so if you download a newer version of WSTools you can just paste the config file back unless there are changes in the config file.

Remote installation of .msu files and a select few other things:

1. Open WSTools Module Path (typically _C:\Program Files\WindowsPowerShell\Modules\WSTools_ or _C:\Users\USERNAME\Documents\WindowsPowerShell\Modules\WSTools_) then edit InstallRemote.ps1.
2. On Line 221 of InstallRemote.ps1 change the value of $PatchFolderPath to the directory on remote computers you store windows updates. This is predefined as "C:\Patches".

## Visual Studio Code setup

For adding the Visual Studio Code PowerShell Snippets do the following:

1. Open PowerShell (after WSTools has been added to one of the locations above)
2. Type the following command
**Set-PowerShellJSON**

**_or_**

1. Open the WSTools folder (typically _C:\Program Files\WindowsPowerShell\Modules\WSTools_ or _C:\Users\USERNAME\Documents\WindowsPowerShell\Modules\WSTools_).
2. Cut and paste powershell.json to **%AppData%\Roaming\Code\User\Snippets** directory.

**_or_**

1. Open powershell.json (located in the WSTools module folder) and copy the text then in VSCode Command Palette (Ctrl + Shift + P)  
2. Type **Snippet** and select **Preferences: Configure User Snippets**.
3. Type **PowerShell** then press **Enter**.
4. Select **powershell.json**.
5. Paste the copied text between the { } brackets and save the file.
