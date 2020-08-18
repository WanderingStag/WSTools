# Install and Configuration of WSTools

## After downloading or copying to computer

1. Uncompress the wstools-master file.
2. Rename the uncompressed folder from wstools-master to WSTools.
3. Make available globally or just for single user.
    ### Global  
    Copy the WSTools folder to **C:\Program Files\WindowsPowerShell\Modules**
    > Requires admin rights.
    ### User only  
    Copy the WSTools folder to **C:\Users\\_USERNAME_\Documents\WindowsPowerShell\Modules**
> If the folder already exists or you get a message saying _"The destination has # files with the same names."_ you can either delete the folder that already exists *(prefered)* or you can *Replace the files in the destination*

## Initial changes to make after copying to computer

Remote installation of .msu files and a select few other things:  
1. Open WSTools Module Path (typically _C:\Program Files\WindowsPowerShell\Modules\WSTools_ or _C:\Users\USERNAME\Documents\WindowsPowerShell\Modules\WSTools_) then edit InstallRemote.ps1.
2. On Line 230 of InstallRemote.ps1 change the value of $PatchFolderPath to the directory on remote computers you store windows updates. This is predefined as "C:\Patches".

## Visual Studio Code setup

For adding the Visual Studio Code PowerShell Snippets do the following:  
1. Open the WSTools folder (typically _C:\Program Files\WindowsPowerShell\Modules\WSTools_ or _C:\Users\USERNAME\Documents\WindowsPowerShell\Modules\WSTools_).
2. Cut and paste powershell.json to **%AppData%\Roaming\Code\User\Snippets** directory.

**_or_**

Open powershell.json (located in the WSTools module folder) and copy the text then in VSCode Command Palette (Ctrl + Shift + P)  
1. Type **Snippet** and select **Preferences: Configure User Snippets**.
2. Type **PowerShell** then press **Enter**.
3. Select **powershell.json**.
4. Paste the copied text between the { } brackets and save the file.
