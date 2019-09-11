@ECHO OFF

ECHO ------------------------MDW VDI GENERALISATION SCRIPT -------------------------

REM VERSION HISTORY
REM VERSION 1.0 INITIAL CREATION

ECHO ------------------------MDW VDI GENERALISATION SCRIPT------------
ECHO V1.0

ECHO ----------------List software versions to Seal\versions.txt--------------
Del c:\seal\versions.txt
ECHO ----- Windows Version -----
ver >> C:\Seal\versions.txt

ECHO -------------Running Windows customisations-----------
Copy C:\Seal\User-192.png "C:\programdata\Microsoft\User Account Pictures\"
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Graphics" /V "SetDisplayRequiredMode" /t "REG_DWORD" /d "0x0" /f
Copy c:\Seal\Teams.lnk "C:\Users\All Users\Microsoft\Windows\Start Menu\"

RD "C:\Programdata\Microsoft\Windows\start Menu\Programs\VMware" /S /Q

REM --Disable Windows indexing on D:\--
rem powershell.exe -executionpolicy Bypass -nologo -noninteractive -noprofile -command "Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter='D:'" | Set-CimInstance -Property @{IndexingEnabled=$false}"
powershell.exe -executionpolicy Bypass -nologo -noninteractive -noprofile -command C:\Seal\Customisations.ps1
powercfg -devicedisablewake "vmxnet3 ethernet adapter"

REM --Disable NetBios-- 
rem $regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
rem Get-ChildItem $regkey |foreach { Set-ItemProperty -Path $regkey\$($_.pschildname) -Name NetbiosOptions -Value 2 -Verbose}
rem powershell.exe -executionpolicy Bypass -nologo -noninteractive -noprofile -command C:\Seal\DisableNetbios.ps1

REM --Removes default Fax printer--
rem Remove-Printer Fax

REM --Import scheduled tasks - must run command with elevated admin rights to import tasks
REM schtasks /create /xml C:\seal\1_user_logon.xml /TN 1_user_logon
schtasks /create /xml "C:\seal\App-V Publishing Refresh.xml" /TN "Microsoft\AppV\Publishing\App-V Publishing Refresh"
schtasks /create /xml "C:\seal\App-V Publishing Refresh - login.xml" /TN "Microsoft\AppV\Publishing\App-V Publishing Refresh - login"

REM --Configures ICMP block for Infosec requirements--
netsh advfirewall firewall add rule name="Block Type 13 ICMP V4" protocol=icmpv4:13,any dir=in action=block


REM ----- Move SC Content to MDT sequence ----


REM Bitlocker remove users service start 
sc.exe sdset BDESVC D:(A;;CCDCLCSWRPWPDTLORCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLORCWDWO;;;BA)(A;;CCLCSWLORC;;;BU)(A;;CCLCSWLORC;;;AU)S:(AU;FA;CCDCLCSWRPWPDTLOSDRCWDWO;;;WD)


REM Windows Mobile Hotspot Service icssvc
sc.exe sdset icssvc D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;LC;;;WD)(A;;CCLCSWLOCRRC;;;S-1-15-2-155514346-2573954481-755741238-1654018636-1233331829-3075935687-2861478708)

REM Device setup manager (Deny BU builtin\users service start permissions)
sc.exe sdset dsmsvc D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(D;;RP;;;BU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)


REM Data sharing Service (Deny WD everyone service start)
D:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;LC;;;WD)(A;;LCRP;;;AC)

REM Delivery Optimisation (Deny AU authenticated users service start)
sc.exe sdset dosvc D:(A;;CCLCSWLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;DCRC;;;S-1-5-80-3055155277-3816794035-3994065555-2874236192-2193176987)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)



Echo ----- FSLogix Version -----
"c:\Program Files\FSLogix\Apps\frx.exe" version >> C:\Seal\versions.txt

Echo ----- .Net Optimisations -----
Sleep 5
c:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe update
c:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe update




REM -------------------APPSENSE GENERALISATION STARTING------------------------

ECHO -------APPSENSE GENERALISATION STARTING----------

"C:\Program Files\AppSense\Management Center\Communications Agent\CcaCmd.exe" /imageprep


REM -------------------APPSENSE REGISTRY KEYS ADDED---------------------------------
REM More details found at  https://community.ivanti.com/docs/DOC-45273 

ECHO -------APPSENSE REGISTRY KEYS ADDING----------

sc config "AppSense Client Communications Agent" start=disabled

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\CtxHook" /V "ExcludedImageNames" /t REG_SZ /d "AMAgent.exe,Cca.exe,WatchdogAgent.exe,WatchdogAgent64.exe,EMAgent.exe,EMAgentAssist.exe,EMNotify.exe,EmCoreService.exe,EmExit.exe,EmLoggedOnUser.exe,EmSystem.exe,EmUser.exe,EmUserLogoff.exe,PmAgent.exe,PmAgentAssist.exe" /f

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Citrix\CtxHook" /V "ExcludedImageNames" /t REG_SZ /d "AMAgent.exe,Cca.exe,WatchdogAgent.exe,WatchdogAgent64.exe,EMAgent.exe,EMAgentAssist.exe,EMNotify.exe,EmCoreService.exe,EmExit.exe,EmLoggedOnUser.exe,EmSystem.exe,EmUser.exe,EmUserLogoff.exe,PmAgent.exe,PmAgentAssist.exe" /f

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Citrix\CtxHook64" /V "ExcludedImageNames" /t REG_SZ /d "AMAgent.exe,Cca.exe,WatchdogAgent.exe,WatchdogAgent64.exe,EMAgent.exe,EMAgentAssist.exe,EMNotify.exe,EmCoreService.exe,EmExit.exe,EmLoggedOnUser.exe,EmSystem.exe,EmUser.exe,EmUserLogoff.exe,PmAgent.exe,PmAgentAssist.exe" /f

ECHO ---------------PVS OPTIMISATION-------------
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters" /V "DisableTaskOffload" /t "REG_DWORD" /d "0x1" /f

 
REM -------------------MS OFFICE LICENSE ACTIVATION--------------------------------
ECHO -------MS OFFICE LICENSE ACTIVATION----------

REM --------------------SYMANTEC GENERALISATION------------------------------------
REM Password is required for below
ECHO ----------------SYMANTEC GENERALISATION--------
"C:\Program Files (x86)\Symantec\Symantec Endpoint Protection\smc.exe" -stop

"C:\Seal\"ClientSideClonePrepTool.exe

REM PAUSE
REM ---------------------CITRIX GENERALISATION------------------------------------

ECHO -----------------CITRIX GENERALISATION--------
del "C:\Windows\System32\LogFiles\UserProfileManager\*.log"
del "C:\Windows\System32\LogFiles\UserProfileManager\*.bak"

REM ---------------------SYSTRACK GENERALISATION--------------------------------------
ECHO --------------------SYSTRACK GENERALISATION-----------------------------
net stop LsiAgent
net stop SnowInventoryAgent5
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\Deploy" /v SystemName /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\Deploy" /v SystemName /t REG_SZ
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\Deploy" /v MasterSystem /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\Deploy" /v MasterSystem /t REG_SZ
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\LsiAgent\Settings" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\LsiAgent\Settings"
del "D:\SystrackDB\*.*" /q /s
rmdir "D:\SystrackDB\" /s /q
mkdir "D:\SystrackDB\"
del "C:\Program Files\inventoryclient\data"
del "C:\program files\sis now software\inventory\agent\data"
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Lakeside Software\LsiAgent\HookThread" /V "FilteredApps" /t REG_SZ /d "AMAgent.exe,AMAgentAssist.exe,AMMessageAssist.exe,Cca.exe,WatchdogAgent.exe,WatchdogAgent64.exe,EMAgent.exe,EMAgentAssist.exe,EMNotify.exe,EmCoreService.exe,EmExit.exe,EmLoggedOnUser.exe,EmSystem.exe,EmUser.exe,EmUserLogoff.exe,EmVirtualizationHost.exe,PmAgent.exe,PmAgentAssist.exe,ccSvcHst.exe,lsiuser.exe" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /V "AppInit_DLLs" /t REG_SZ /d "" /f

REM ---------------------FINAL WINDOWS SEAL---------------------------------------
ECHO --------------------FINAL WINDOWS SEAL---------------------

cd C:\Seal
ipconfig /flushdns
powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powershell.exe -noprofile -executionpolicy bypass -command add-appxpackage -DisableDevelopmentmode -register 'C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2017.37071.16410.0_x64__8wekyb3d8bbwe\AppxManifest.xml'
powershell.exe -noprofile -executionpolicy bypass -command "wevtutil el | Foreach-Object {wevtutil cl "$_"}"

wmic pagefileset where name="C:\\pagefile.sys" delete
wmic pagefileset create name="D:\pagefile.sys"
wmic pagefileset where name="D:\\pagefile.sys" set InitialSize=512,MaximumSize=8096

REM -----------------------SCRIPT COMPLETE-------------------------------------------
ECHO ----------------------SCRIPT COMPLETE--------------------------------------------------------
