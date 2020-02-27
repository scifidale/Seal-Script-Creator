# Seal-Script-Creator
README

The seal script creator is currently in Alpha stage, script actions will be changed and updated frequently.
The seal script creator consists of a single powershell script that searches for executables commonly 
associated with software installed within a non-persistent environment and creates and appends a SealScript.PS1/CMD
file with the common generalisation and cleanup tasks performed on as master image before final shutdown.
There are also sections that detect which operating system the script is being executed on so OS specific 
actions can be applied to the script. 

Thi script is never intended to be a complete sealup script however will provide a basic start and framework 
which to build on when deployed via a task sequence in tools such as Microsoft MDT etc. 


For initial deployment please customise the below variables within the script. Company Name should always be customised
however $SealFolder and $SealFile will rarely need changing. 

$SealFolder = "C:\Seal"
$SealFile = "SealScript.ps1"
$CompanyName = "Company"
$EventLog = "D:\EventLogs"

Contents
Creator.ps1 -- Seal script creator 
SealScript.CMD -- example script created by Creator.ps1
README -- This document 


Release Radar 
Beta v0.1 CURRENT	
Initial release of the seal script creator including sealscript actions for the following items: 
Citrix VDA 
Citrix PVS Tools
Citrix WEM 
Microsoft FSLogix 
Ivanti Environment Management
VMware Tools 
Lakesie Systrack 
Symantec Endpoint Protection 
Trend OS 
Macfee Endpoint Protection 
Kaspersky Endpoint Protection 
Microsoft SCCM 
Sophos Antivirus 
UberAgent 
General Operating system sealup actions


Date 03/01/2020 
Author Dale Scriven

