

REM Variable enteries
Set Citrix="C:\Program Files\Citrix\Virtual Desktop  Agent\VDA.exe"
Set CitrixPVS="C:\Program Files\Citrix\Provisioning Services\StatusTray.exe"
set test="C:\bdlog.txt"
Set FSLOGIX="c:\Program Files\FSLigix\Apps\frx.exe"
Set Ivanti="C:\Program Files\AppSense\environment Manager\Agent\ENUser.exe"
Set VMware="C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
Set Systrack="C:\Program Files (x86)\Systrack\LsiAgent\LSiAgent.exe"

REM OS version check
$os = Get-CimInstance Win32_OperatingSystem | Select -expand Caption



REM ##### Create bare Seal Script Folder ####
MD C:\Seal 
Copy NUL > c:\Seal\SealScript.PS1
REM ##### Citrix Gneralisation Phase #####
Echo "EEC Services Seal Script" >> C:\Seal\sealscript.ps1

If exist %test% (echo hellow >> "c:\UserGuidePDF\test.txt") Else ( REM File doesnt exist )


REM ##### Scan for Systrack Agent #####
if Exist %Systrack% (
Echo "Net Stop LsiAgent"
Echo "REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\Deploy" /v SystemName /f"
Echo "REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\Deploy" /v SystemName /t REG_SZ"
Echo "REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\Deploy" /v MasterSystem /f"
Echo "REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\Deploy" /v MasterSystem /t REG_SZ"
Echo "REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\LsiAgent\Settings" /f"
Echo "REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\LsiAgent\Settings""
Echo "del "D:\SystrackDB\*.*" /q /s"
Echo "RMDIR "D:\SystrackDB\" /s /q"
Echo "MKDIR "D:\SystrackDB\""
) >> C:\Seal\SealScript.ps1


REM ##### VMware Tools cleanup #####
IF EXIST %VMware% (Echo "RD "C:\Programdata\Microsoft\Windows\start Menu\Programs\VMware" /S /Q"
) >> C:\Seal\SealScript.PS1


REM ##### insert general seal up script options #####

Echo "powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" >> c:\Seal\Sealscript.ps1
Echo "powershell.exe -noprofile -executionpolicy bypass -command "wevtutil el | Foreach-Object {wevtutil cl "$_"}"" >> c:\Seal\SealScript.ps1
Echo "##### Pagefile settings #####" >> c:\Seal\SealScript
Echo "wmic pagefileset where name="C:\\pagefile.sys" delete" >> c:\Seal\SealScript
Echo "wmic pagefileset create name="D:\pagefile.sys"" >> c:\Seal\SealScript
Echo "wmic pagefileset where name="D:\\pagefile.sys" set InitialSize=512,MaximumSize=8096" >> c:\Seal\SealScript
	
##### OS Specific Generalisations for Server 2016 #####
:Server2016

##### OS Specific Generalisations for Server 2019 #####
:Server2019 

##### OS Specific Generalisations for Windows 10 #####
:Windows10

	
	Pause
	
	
	
	##### Sample Scriptlets #####
	##### powershell set variable #####
	# $variable = "location" #
	##### powershell check location exists #####
	# test-path -path $variable # 
	##### Capture OS Version #####
	# Get-CimInstance Win32_OperatingSystem | select -expand Caption  # 
	