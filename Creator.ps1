

##### Variable enteries #####
##### Enter execution path here #####


$SealFolder = "C:\Seal"
$SealFile = "SealScript.ps1"
$CompanyName = "EEC Services"

$Citrix = "C:\bdlog.txt"
$CitrixVDA = "C:\Program files\Citrix\Virtual Desktop Agent\BrokerAgent.exe"
$CitrixPVS = "C:\Program files\Citrix\Provisioning Services\StatusTray.exe"
$WEM = "C:\Program Files (x86)\Norskale\Norskale Agent Host\VUEMUIAgent.exe"
$test = "C:\bdlog.txt"
$FSLOGIX = "C:\Program Files\FSLogix\Apps\frx.exe"
$Ivanti = "C:\Program Files\Appsense\Environment Manager\Agent\EMUser.exe"
$VMware = "C:\Program files\VMware\VMware Tools\vmtoolsd.exe"
$Systrack = "C:\Program Files (x86)\SysTrack\LSiAgent\LsiAgent.exe"
$SymantecEP = "C:\bdlog.txt"
$TrendOS = "C:\bdlog.txt"
$MCafeeEP = "C:\bdlog.txt"
$SCCM = "C:\Windows\System32\smss.exe"
$SophosEP = "C:\BDlog.txt"
$UberAgent = "C:\BDLOg.txt"

##### OS version check #####
$os = Get-CimInstance Win32_OperatingSystem | Select -expand Caption



##### Create bare Seal Script Folder and File ####
New-Item -path $SealFolder -ItemType Directory
New-Item -path $SealFolder\$SealFile



##### Generalisation Phase #####
Echo "$CompanyName Seal Script" >> $SealFolder\$SealFile
Add-Content -path $SealFolder\$SealFile -value ""
Echo "$PSScriptRoot" >> $Sealfolder\$SealFile

################################################
##########Citrix Stack Generalisation###########
################################################

##### Citrix provisioning Services actions #####
If (test-path "$CitrixPVS") {
Echo '##### Citrix Provisioning Services Generalisation #####' >> $SealFolder\$SealFile
Echo 'REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters /V DisableTaskOffload /t REG_DWORD /d 0x1 /f' >> $SealFolder\$SealFile
Echo 'Del "C:\Program Data\Citrix\Provisioning Services\Log\*.* /F/Q"' >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""
If (Test-Path "$CitrixVDA") {
Echo '##### Citrix VDA Generalisation #####' >> $SealFolder\$SealFile
Echo 'del "C:\Windows\System32\LogFiles\UserProfileManager\*.log"' >> $SealFolder\$SealFile
Echo 'del "C:\Windows\System32\LogFiles\UserProfileManager\*.bak"' >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""

If (Test-Path "$FSLogix") {
Echo '##### FSLogix Generalisation #####' >> $SealFolder\$SealFile
Echo 'del "C:\Program Files\FSLogix\Apps\Logs\*.log"' >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""


################################################
##########Monitoring Tool Generalisation########
################################################

##### Scan for Systrack Agent #####
if (test-path "$Systrack") {
Echo '##### LakeSide Systrack Generalisation #####' >> $SealFolder\$SealFile
Echo "Net Stop LsiAgent" >> $SealFolder\$SealFile
Echo 'REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\Deploy" /v SystemName /f' >> $SealFolder\$SealFile
Echo 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\Deploy" /v SystemName /t REG_SZ' >> $SealFolder\$SealFile
Echo 'REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\Deploy" /v MasterSystem /f' >> $SealFolder\$SealFile
Echo 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\Deploy" /v MasterSystem /t REG_SZ' >> $SealFolder\$SealFile
Echo 'REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\LsiAgent\Settings" /f' >> $SealFolder\$SealFile
Echo 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\LsiAgent\Settings"' >> $SealFolder\$SealFile
Echo 'del D:\SystrackDB\*.* /q /s' >> $SealFolder\$SealFile
Echo 'RMDIR D:\SystrackDB\ /s /q' >> $SealFolder\$SealFile
Echo 'MKDIR D:\SystrackDB\' >> $SealFolder\$SealFile
 }
Add-Content -path $SealFolder\$SealFile -value ""

if (test-path "$UberAgent") {
Echo '##### UberAgent Generalisation #####' >> $SealFolder\$SealFile
Echo "Net Stop uberAgent" >> $SealFolder\$SealFile
Echo 'REG DELETE “HKLM\SOFTWARE\vast limits\uberAgent” /f /reg:64' >> $SealFolder\$SealFile

 }
Add-Content -path $SealFolder\$SealFile -value ""

##### VMware Tools cleanup #####
IF (Test-Path "$VMware") {
Echo '##### Remove VMware Tools Menu Icon #####' >> $SealFolder\$SealFile
Echo 'RD "C:\Programdata\Microsoft\Windows\start Menu\Programs\VMware" /S /Q' >> $SealFolder\$SealFile }
Add-Content -path $SealFolder\$SealFile -value ""

##### Ivanti Sealup Actions #####
IF (test-path "$Ivanti") {
Echo '##### Ivanti Generalisation #####' >> $SealFolder\$SealFile
Echo 'CD "C:\Program Files\AppSense\Management Center\Communications Agent\"' >> $SealFolder\$SealFile
Echo './CCACMD.exe /Imageprep' >> $SealFolder\$SealFile
Echo 'sc.exe config "AppSense Client Communications Agent" start=disabled' >> $SealFolder\$SealFile
Echo 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\CtxHook" /V "ExcludedImageNames" /t REG_SZ /d "AMAgent.exe,Cca.exe,WatchdogAgent.exe,WatchdogAgent64.exe,EMAgent.exe,EMAgentAssist.exe,EMNotify.exe,EmCoreService.exe,EmExit.exe,EmLoggedOnUser.exe,EmSystem.exe,EmUser.exe,EmUserLogoff.exe,PmAgent.exe,PmAgentAssist.exe" /f' >> $SealFolder\$SealFile
Echo 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Citrix\CtxHook" /V "ExcludedImageNames" /t REG_SZ /d "AMAgent.exe,Cca.exe,WatchdogAgent.exe,WatchdogAgent64.exe,EMAgent.exe,EMAgentAssist.exe,EMNotify.exe,EmCoreService.exe,EmExit.exe,EmLoggedOnUser.exe,EmSystem.exe,EmUser.exe,EmUserLogoff.exe,PmAgent.exe,PmAgentAssist.exe" /f' >> $SealFolder\$SealFile
Echo 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Citrix\CtxHook64" /V "ExcludedImageNames" /t REG_SZ /d "AMAgent.exe,Cca.exe,WatchdogAgent.exe,WatchdogAgent64.exe,EMAgent.exe,EMAgentAssist.exe,EMNotify.exe,EmCoreService.exe,EmExit.exe,EmLoggedOnUser.exe,EmSystem.exe,EmUser.exe,EmUserLogoff.exe,PmAgent.exe,PmAgentAssist.exe" /f' >> $SealFolder\$SealFile

}
Add-Content -path $SealFolder\$SealFile -value ""

##### Citrix WEM Sealup Actions #####
IF (test-path "$WEM") {
Echo '##### Citrix WEM Generalisation #####' >> $SealFolder\$SealFile
Echo 'Net Stop "Citrix WEM Agent Host Service"' >> $SealFolder\$SealFile
Echo '"del %PROGRAMFILES(X86)%\Norskale\Norskale Agent Host\*.log /Q"' >> $SealFolder\$SealFile
Echo 'del c:\trace\*.svclog /Q' >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""


################################################
##########Antivirus Generalisation##############
################################################


##### Symantec Endpoint Protection #####
IF (Test-Path "$SymantecEP") {
Copy "$PSScriptRoot\Content\ClientSideClonePrepTool.exe" $SealFolder  
Echo '##### Symantec Endpoint Protection Generalisation #####' >> $SealFolder\$SealFile
Echo '"C:\Program Files (x86)\Symantec\Symantec Endpoint Protection\smc.exe" -stop' >> $SealFolder\$SealFile
Echo '"ClientSideClonePrepTool.exe"' >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""

##### Mcafee Agent 5.x #####
IF (Test-Path "$McafeeEP") {
Echo '##### Mcafee Agent Generalisation #####' >> $SealFolder\$SealFile
Echo '"C:\Program Files\McAfee\Agent\maconfig -enforce -noguid"' >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""

##### Sophos Endpoint Agent #####
IF (Test-Path "$SophosEP") {
Echo '##### Symantec Endpoint Protection Generalisation #####' >> $SealFolder\$SealFile
Echo 'Net Stop "Sophos Autoupdate Service"' >> $SealFolder\$SealFile
Echo '"ClientSideClonePrepTool.exe"' >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""

##### Trend OfficeScan #####
IF (Test-Path "$TrendOS") {
Copy "$PSScriptRoot\Content\ImgSetup.exe" $SealFolder  
Echo '##### Trend OfficeScan Generalisation #####' >> $SealFolder\$SealFile
Echo "$SealFolder\ImgSetup.exe" >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""

##### Default user logon image #####
Copy $PSScriptRoot\Content\user-192.png $SealFolder 
Echo "#####Setting default user logon image#####" >> $SealFolder\$SealFile
Echo "Copy $SealFolder\User-192.png 'C:\programdata\Microsoft\User Account Pictures\'" >> $SealFolder\$SealFile
Add-Content -path $SealFolder\$SealFile -value ""

##### insert general seal up script options #####
Echo '##### Final General Actions #####' >> $SealFolder\$SealFile
Echo "wevtutil el | Foreach-Object {wevtutil cl "$_"}" >> $SealFolder\$SealFile
Add-Content -path $SealFolder\$SealFile -value ""
Echo '##### Pagefile settings #####' >> $SealFolder\$SealFile
Echo 'wmic pagefileset where name="C:\\pagefile.sys" delete' >> $SealFolder\$SealFile
Echo 'wmic pagefileset create name="D:\pagefile.sys"' >> $SealFolder\$SealFile
Echo 'wmic pagefileset where name="D:\\pagefile.sys" set InitialSize=512,MaximumSize=8096' >> $SealFolder\$SealFile
Echo 'Echo defragmenting the C Drive' >> $SealFolder\$SealFile
Echo "defrag c: /v" >> $SealFolder\$SealFile
Add-Content -path $SealFolder\$SealFile -value ""
	
##### OS Specific Generalisations for Server 2016 #####
IF ($OS -eq "Microsoft Windows Server 2016") {
Echo "##### Setting High Performance Mode #####" >> $SealFolder\$SealFile
Echo 'powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' >> $SealFolder\$SealFile

}

##### OS Specific Generalisations for Server 2019 #####
IF ($OS -eq "Microsoft Windows Server 2019") {
Echo "##### Setting High Performance Mode #####" >> $SealFolder\$SealFile
Echo 'powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' >> $SealFolder\$SealFile

}

##### OS Specific Generalisations for Windows 10 #####
IF ($OS -eq "Microsoft Windows 10 Pro" -or "Microsoft Windos 10 Enterprise" -or "Microsoft Windows 10 Home") {
Echo "##### Setting High Performance Mode #####" >> $SealFolder\$SealFile
Echo 'powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""

##### Shutdown the image #####
Echo "##### Shutting down the Image #####" >> $SealFolder\$SealFile
Echo "Shutdown -s -t 60" >> $SealFolder\$SealFile

Pause
	
	
	
	##### Sample Scriptlets #####
	##### powershell set variable #####
	# $variable = "location" #
	##### powershell check location exists #####
	# If (test-path "$CitrixPVS") {Echo "REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters /V DisableTaskOffload /t REG_DWORD /d 0x1 /f" >> $SealFolder\$SealFile} # 
	##### Capture OS Version #####
	# Get-CimInstance Win32_OperatingSystem | select -expand Caption  # 
	##### Powershell output to seal script #####
	#write-output "test2" | Out-file -filepath $sealloc -append #
	