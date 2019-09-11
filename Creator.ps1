

REM Variable enteries
Set Citrix="C:\Program Files\Citrix\Virtual Desktop  Agent\VDA.exe"
Set CitrixPVS="C:\Program Files\Citrix\Provisioning Services\StatusTray.exe"
set test="C:\bdlog.txt"
Set FSLOGIX="c:\Program Files\FSLigix\Apps\frx.exe"
Set Ivanti="C:\Program Files\AppSense\environment Manager\Agent\ENUser.exe"
Set VMware="C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"

REM ##### Create bare Seal Script Folder ####
MD C:\Seal 
Copy NUL > c:\Seal\SealScript.PS1

Echo "EEC Services Seal Script" >> C:\Seal\sealscript.ps1

If exist %test% (echo hellow >> "c:\UserGuidePDF\test.txt") Else ( REM File doesnt exist )
	Pause