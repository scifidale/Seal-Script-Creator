

##### Variable enteries #####
##### Custom Variables here, change paths as required #####
$SealFolder = "C:\Seal"
$SealFile = "SealScript.ps1"
$CompanyName = "Company"
$EventLog = "D:\EventLogs"


##### DO not change #####
If((Get-CimInStance Win32_OperatingSystem).OSArchitecture -eq "64-Bit") {$pFiles = "C:\Program Files"} Else {$pFiles = "C:\Program Files (x86)"}

$CitrixVDA = "$pFiles\Citrix\Virtual Desktop Agent\BrokerAgent.exe"
$CitrixPVS = "$pFiles\Citrix\Provisioning Services\StatusTray.exe"
$WEM = "C:\Program Files (x86)\Norskale\Norskale Agent Host\VUEMUIAgent.exe"
$FSLOGIX = "$pFiles\FSLogix\Apps\frx.exe"
$Ivanti = "$pFiles\Appsense\Environment Manager\Agent\EMUser.exe"
$VMware = "$pFiles\VMware\VMware Tools\vmtoolsd.exe"
$Systrack = "C:\Program Files (x86)\SysTrack\LSiAgent\LsiAgent.exe"
$SymantecEP = "C:\Program Files (x86)\Symantec\Symantec Endpoint Protection\smc.exe"
$TrendOS = "C:\Program Files (x86)\Trend Micro\OfficeScan"
$MCafeeEP = "C:\Program Files (x86)\McAfee\Common Framework\masvc.exe"
$KasperskyEP = "C:\Program Files (x86)\Kaspersky Lab\Endpoint Agent"
$SCCM = "C:\Windows\System32\smss.exe"
$SophosEP = "C:\Program Files\Sophos\Sophos Endpoint Agent\ManagementAgentNT.exe"
$UberAgent = "$pFiles\vast limits\uberAgent\uberAgent.exe"

##### OS version check #####
$os = Get-CimInstance Win32_OperatingSystem | Select -expand Caption



##### Create bare Seal Script Folder and File ####
New-Item -path $SealFolder -ItemType Directory
New-Item -path $SealFolder\$SealFile



##### Generalisation Phase #####
Echo "# $CompanyName Seal Script" >> $SealFolder\$SealFile
Add-Content -path $SealFolder\$SealFile -value ""
# Echo "# $PSScriptRoot" >> $Sealfolder\$SealFile#

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

##### Citrix VDA UPM Generalisation #####
If (Test-Path "$CitrixVDA") {
Echo '##### Citrix VDA Generalisation #####' >> $SealFolder\$SealFile
Echo 'del "C:\Windows\System32\LogFiles\UserProfileManager\*.log"' >> $SealFolder\$SealFile
Echo 'del "C:\Windows\System32\LogFiles\UserProfileManager\*.bak"' >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""

################################################
##########FSLogix Generalisation################
################################################

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
Echo 'REG DELETE "HKLM\SOFTWARE\vast limits\uberAgent" /f /reg:64' >> $SealFolder\$SealFile

 }
Add-Content -path $SealFolder\$SealFile -value ""

##### VMware Tools cleanup #####
IF (Test-Path "$VMware") {
Echo '##### Remove VMware Tools Menu Icon #####' >> $SealFolder\$SealFile
Echo 'CMD /c RD "C:\Programdata\Microsoft\Windows\start Menu\Programs\VMware" /S /Q' >> $SealFolder\$SealFile }
Add-Content -path $SealFolder\$SealFile -value ""

################################################
########Policy & Profile Tool Generalisation####
################################################

##### Ivanti Sealup Actions #####
IF (test-path "$Ivanti") {
Echo '##### Ivanti Generalisation #####' >> $SealFolder\$SealFile
Echo 'CD "C:\Program Files\AppSense\Management Center\Communications Agent\"' >> $SealFolder\$SealFile
Echo './CCACMD.exe /Imageprep' >> $SealFolder\$SealFile
Echo 'sc.exe config "AppSense Client Communications Agent" start=disabled' >> $SealFolder\$SealFile
Echo 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\CtxHook" /V "ExcludedImageNames" /t REG_SZ /d "AMAgent.exe,Cca.exe,WatchdogAgent.exe,WatchdogAgent64.exe,EMAgent.exe,EMAgentAssist.exe,EMNotify.exe,EmCoreService.exe,EmExit.exe,EmLoggedOnUser.exe,EmSystem.exe,EmUser.exe,EmUserLogoff.exe,PmAgent.exe,PmAgentAssist.exe" /f' >> $SealFolder\$SealFile
Echo 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Citrix\CtxHook" /V "ExcludedImageNames" /t REG_SZ /d "AMAgent.exe,Cca.exe,WatchdogAgent.exe,WatchdogAgent64.exe,EMAgent.exe,EMAgentAssist.exe,EMNotify.exe,EmCoreService.exe,EmExit.exe,EmLoggedOnUser.exe,EmSystem.exe,EmUser.exe,EmUserLogoff.exe,PmAgent.exe,PmAgentAssist.exe" /f' >> $SealFolder\$SealFile
Echo 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Citrix\CtxHook64" /V "ExcludedImageNames" /t REG_SZ /d "AMAgent.exe,Cca.exe,WatchdogAgent.exe,WatchdogAgent64.exe,EMAgent.exe,EMAgentAssist.exe,EMNotify.exe,EmCoreService.exe,EmExit.exe,EmLoggedOnUser.exe,EmSystem.exe,EmUser.exe,EmUserLogoff.exe,PmAgent.exe,PmAgentAssist.exe" /f' >> $SealFolder\$SealFile
Echo 'wevtutil sl Appsense /lfn:$EventLog\Appsense.evtx' >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""

##### Citrix WEM Sealup Actions #####
IF (test-path "$WEM") {
Echo '##### Citrix WEM Generalisation #####' >> $SealFolder\$SealFile
Echo 'Net Stop "Citrix WEM Agent Host Service"' >> $SealFolder\$SealFile
Echo 'del "%PROGRAMFILES(X86)%\Norskale\Norskale Agent Host\*.log" /Q' >> $SealFolder\$SealFile
Echo 'del c:\trace\*.svclog /Q' >> $SealFolder\$SealFile
Echo 'wevtutil sl "WEM Agent Service" /lfn:$EventLog\WEMService.evtx' >> $SealFolder\$SealFile
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
Echo '"C:\Program Files\McAfee\Agent\maconfig.exe -enforce -noguid"' >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""

##### Sophos Endpoint Agent #####
IF (Test-Path "$SophosEP") {
Echo '##### Sophos Endpoint Protection Generalisation #####' >> $SealFolder\$SealFile
Echo 'Net Stop "Sophos Agent"' >> $SealFolder\$SealFile
Echo 'SC Config "Sophos MCS" start=delayed-auto' >> $SealFolder\$SealFile
Echo 'Net Stop "Sophos Managed Threat Response"' >> $SealFolder\$SealFile
Echo 'Del "C:\ProgramData\Sophos\Management Communications System\Endpoint\Persist\Credentials.txt"' >> $SealFolder\$SealFile
Echo 'Del "C:\ProgramData\Sophos\Management Communications System\Endpoint\Persist\EndpointIdentity.txt"' >> $SealFolder\$SealFile
Echo 'Del /Q "C:\ProgramData\Sophos\Management Communications System\Endpoint\Persist\*.xml"' >> $SealFolder\$SealFile
Echo 'Del /Q "C:\ProgramData\Sophos\Management Communications System\Endpoint\Cache\*.status"' >> $SealFolder\$SealFile
Echo 'Del "C:\ProgramData\Sophos\AutoUpdate\data\machine_id.txt"' >> $SealFolder\$SealFile
Echo 'Del "C:\ProgramData\Sophos\Managed Threat Response\data\osquery.db"' >> $SealFolder\$SealFile
Echo 'Del "C:\ProgramData\Sophos\Managed Threat Response\config\policy.xml"' >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""

##### Trend OfficeScan #####
IF (Test-Path "$TrendOS") {
Copy "$PSScriptRoot\Content\ImgSetup.exe" $SealFolder  
Echo '##### Trend OfficeScan Generalisation #####' >> $SealFolder\$SealFile
Echo '##### Please Obtain ImgSetup.exe from Trend Management Server #####' >> $SealFolder\$SealFile
Echo "$SealFolder\ImgSetup.exe" >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""

##### Kaspersky Endpoint  #####
IF (Test-Path "$KasperskyEP") {
Echo '##### Kaspersky Endpoint Agent Generalisation #####' >> $SealFolder\$SealFile
Echo "wevtutil sl `'Kaspersky-Security-Sensor Diagnostics/Operational`' `"/lfn:$EventLog\KasperskySensor.evtx`"" >> $SealFolder\$SealFile
Echo "wevtutil sl `"Kaspersky-Security-Soyuz/Product /lfn:$EventLog\KasperskySoyuz.evtx`"" >> $SealFolder\$SealFile
}
Add-Content -path $SealFolder\$SealFile -value ""


################################################
##########Visual Actions #######################
################################################

##### Default user logon image #####
Copy $PSScriptRoot\Content\user-192.png $SealFolder 
Echo "#####Setting default user logon image#####" >> $SealFolder\$SealFile
Echo "Copy $SealFolder\User-192.png 'C:\programdata\Microsoft\User Account Pictures\'" >> $SealFolder\$SealFile
Add-Content -path $SealFolder\$SealFile -value ""


################################################
##########.NET Framework Actions ###############
################################################


##### .NET Framework update #####
Echo "##### Updating .Net Framework #####" >> $SealFolder\$SealFile
$netversiontest = get-childitem -path c:\windows\microsoft.net\framework -file -recurse | select-object -property directory,name | where Name -eq "ngen.exe" | select-object -property directory -last 1 | ft -hidetableheaders |  Out-String -stream
Echo "CD$netversiontest" >> $SealFolder\$SealFile
Echo ".\ngen.exe update" >> $SealFolder\$SealFile

Add-Content -path $SealFolder\$SealFile -value ""

$netversiontestx64 = get-childitem -path c:\windows\microsoft.net\framework64 -file -recurse | select-object -property directory,name | where Name -eq "ngen.exe" | select-object -property directory -last 1 | ft -hidetableheaders |  Out-String -stream
Echo "CD$netversiontestx64" >> $SealFolder\$SealFile
Echo ".\ngen.exe update" >> $SealFolder\$SealFile

Add-Content -path $SealFolder\$SealFile -value ""

################################################
##########Tidy up Actions #####################
################################################

##### insert general seal up script options #####
Echo "##### Final General Actions #####" >> $SealFolder\$SealFile
Echo 'wevtutil el | Foreach-Object {wevtutil cl `"$_`"}' >> $SealFolder\$SealFile
Echo "wevtutil sl Application /lfn:$EventLog\Application.evtx" >> $SealFolder\$SealFile
Echo "wevtutil sl System /lfn:$EventLog\System.evtx" >> $SealFolder\$SealFile
Echo "wevtutil sl Setup /lfn:$EventLog\Setup.evtx" >> $SealFolder\$SealFile
Add-Content -path $SealFolder\$SealFile -value ""
Echo '##### Pagefile settings #####' >> $SealFolder\$SealFile
Echo 'wmic pagefileset delete' >> $SealFolder\$SealFile
Echo 'wmic pagefileset create name="D:\pagefile.sys"' >> $SealFolder\$SealFile
Echo 'wmic pagefileset where name=`"D:\\pagefile.sys`" set InitialSize=512,MaximumSize=8096' >> $SealFolder\$SealFile
Add-Content -path $SealFolder\$SealFile -value ""
Echo '##### Echo defragmenting the C Drive #####' >> $SealFolder\$SealFile
Echo "defrag c: /v" >> $SealFolder\$SealFile
Echo "Ipconfig /flushdns" >> $SealFolder\$SealFile
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


	