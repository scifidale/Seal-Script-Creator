

##### Variable enteries #####


$SealFolder = "C:\Seal"
$SealFile = "SealScript.ps1"

$Citrix = "C:\bdlog.txt"
$CitrixVDA = "C:\bdlog.txt"
$CitrixPVS = "C:\bdlog.txt"
$test = "C:\bdlog.txt"
$FSLOGIX = "C:\bdlog.txt"
$Ivanti = "C:\bdlog.txt"
$VMware = "C:\bdlog.txt"
$Systrack = "C:\bdlog.txt"

##### OS version check #####
$os = Get-CimInstance Win32_OperatingSystem | Select -expand Caption



##### Create bare Seal Script Folder ####
New-Item -path $SealFolder -ItemType Directory
New-Item -path $SealFolder\$SealFile


##### Citrix Generalisation Phase #####
Echo "EEC Services Seal Script" >> $SealFolder\$SealFile
Add-Content -path $SealFolder\$SealFile -value ""


##### Citrix provisioning Services actions #####
If (test-path "$CitrixPVS") {
Echo 'REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters /V DisableTaskOffload /t REG_DWORD /d 0x1 /f' >> $SealFolder\$SealFile
Echo 'Del "C:\Program Data\Citrix\Provisioning Services\Log\*.* /F/Q"' >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""
If (Test-Path "$CitrixVDA") {
Echo 'del "C:\Windows\System32\LogFiles\UserProfileManager\*.log"' >> $SealFolder\$SealFile
Echo 'del "C:\Windows\System32\LogFiles\UserProfileManager\*.bak"' >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""

##### Scan for Systrack Agent #####
if (test-path "$Systrack") {
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

##### VMware Tools cleanup #####
IF (Test-Path "$VMware") {Echo 'RD "C:\Programdata\Microsoft\Windows\start Menu\Programs\VMware" /S /Q' >> $SealFolder\$SealFile }
Add-Content -path $SealFolder\$SealFile -value ""

##### Ivanti Sealup Actions #####
IF (test-path "$Ivanti") {
Echo '"C:\Program Files\AppSense\Management Center\Communications Agent\CcaCmd.exe" /imageprep' >> $SealFolder\$SealFile
Echo 'sc config "AppSense Client Communications Agent" start=disabled' >> $SealFolder\$SealFile
Echo 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\CtxHook" /V "ExcludedImageNames" /t REG_SZ /d "AMAgent.exe,Cca.exe,WatchdogAgent.exe,WatchdogAgent64.exe,EMAgent.exe,EMAgentAssist.exe,EMNotify.exe,EmCoreService.exe,EmExit.exe,EmLoggedOnUser.exe,EmSystem.exe,EmUser.exe,EmUserLogoff.exe,PmAgent.exe,PmAgentAssist.exe" /f' >> $SealFolder\$SealFile
Echo 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Citrix\CtxHook" /V "ExcludedImageNames" /t REG_SZ /d "AMAgent.exe,Cca.exe,WatchdogAgent.exe,WatchdogAgent64.exe,EMAgent.exe,EMAgentAssist.exe,EMNotify.exe,EmCoreService.exe,EmExit.exe,EmLoggedOnUser.exe,EmSystem.exe,EmUser.exe,EmUserLogoff.exe,PmAgent.exe,PmAgentAssist.exe" /f' >> $SealFolder\$SealFile
Echo 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Citrix\CtxHook64" /V "ExcludedImageNames" /t REG_SZ /d "AMAgent.exe,Cca.exe,WatchdogAgent.exe,WatchdogAgent64.exe,EMAgent.exe,EMAgentAssist.exe,EMNotify.exe,EmCoreService.exe,EmExit.exe,EmLoggedOnUser.exe,EmSystem.exe,EmUser.exe,EmUserLogoff.exe,PmAgent.exe,PmAgentAssist.exe" /f' >> $SealFolder\$SealFile

}
Add-Content -path $SealFolder\$SealFile -value ""

##### Symantec Endpoint Protection #####
IF (Test-Path "$SymantecEP") {
Echo '"C:\Program Files (x86)\Symantec\Symantec Endpoint Protection\smc.exe" -stop' >> $SealFolder\$SealFile
Echo '"$SealFolder\$SealFile\ClientSideClonePrepTool.exe' >> $SealFolder\SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""
##### insert general seal up script options #####

Echo 'powershell.exe -noprofile -executionpolicy bypass -command "wevtutil el | Foreach-Object {wevtutil cl "$_"}"' >> $SealFolder\$SealFile
Echo '##### Pagefile settings #####' >> $SealFolder\$SealFile
Echo 'wmic pagefileset where name="C:\\pagefile.sys" delete' >> $SealFolder\$SealFile
Echo 'wmic pagefileset create name="D:\pagefile.sys"' >> $SealFolder\$SealFile
Echo 'wmic pagefileset where name="D:\\pagefile.sys" set InitialSize=512,MaximumSize=8096' >> $SealFolder\$SealFile
Add-Content -path $SealFolder\$SealFile -value ""
	
##### OS Specific Generalisations for Server 2016 #####
IF ($OS -eq "Microsoft Windows Server 2016") {

}

##### OS Specific Generalisations for Server 2019 #####
IF ($OS -eq "Microsoft Windows Server 2019") {

}

##### OS Specific Generalisations for Windows 10 #####
IF ($OS -eq "Microsoft Windows 10 Home") {
Echo 'powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' >> $SealFolder\$SealFile
}

	

	
	
	
	##### Sample Scriptlets #####
	##### powershell set variable #####
	# $variable = "location" #
	##### powershell check location exists #####
	# If (test-path "$CitrixPVS") {Echo "REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters /V DisableTaskOffload /t REG_DWORD /d 0x1 /f" >> $SealFolder\$SealFile} # 
	##### Capture OS Version #####
	# Get-CimInstance Win32_OperatingSystem | select -expand Caption  # 
	##### Powershell output to seal script #####
	#write-output "test2" | Out-file -filepath $sealloc -append #
	