# Seal-Script-Creator
README

The seal script creator is currently in Alpha stage, script actions will be changed and updated frequently.
The seal script creator consists of a single powershell script that searches for executables commonly 
associated with software installed within a non-persistent environment and creates and appends a SealScript.CMD
file with the common generalisation and cleanup tasks performed on as master image before final shutdown.
There are also sections that detect which operating system the script is being executed on so OS specific 
actions can be applied to the script. 

Thi script is never intended to be a complete sealup script however will provide a basic start and framework 
which to build on when deployed via a task sequence in tools such as Microsoft MDT etc. 

Contents
Creator.ps1 -- Seal script creator 
SealScript.CMD -- example script created by Creator.ps1
README -- This document 

Date 03/01/2020 
Author Dale Scriven
