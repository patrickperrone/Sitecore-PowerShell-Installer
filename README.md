Sitecore-PowerShell-Installer
=============================
The Sitecore-PowerShell-Installer script enables you to install Production-ready Sitecore instances from the command-line.

### Features of the Project
- Install Sitecore with or without the databases.
- Scrip sanity checks SQL and input validation prior to making any changes
- Write output to the screen and to a log file.
- Fine-grained control of the application pool identity (built-in or domain account)
- Assign recommended file system permissions on web server.
- Add application pool identity to recommended local groups on web server.
- Create user mappings for login in SQL.
- Install database files on any valid path or UNC
- SQL Login used during install doesn't have to be the same account executing the script.
- May specifiy a host name and port used for MongoDB
- May supply a Solr base address
- Choose to use SQL as a session state server
- Many CD-hardening options

### Requirements
- SQL logins must exist prior to running script
- SQL login used for install must either have the sysadmin or both the dbcreator and securityadmin roles
- Must have a valid Sitecore .zip file

### How To Use
1. Download script, config file, and .zip for desired Sitecore version
2. Edit config file
3. Run Powershell as Administrator and invoke ```install.ps1```

This script was inspired by Alex Shyba's script: https://github.com/Sitecore/PowerShell-Script-Library
