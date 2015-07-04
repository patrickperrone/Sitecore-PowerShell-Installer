$scriptDir = Split-Path (Resolve-Path $myInvocation.MyCommand.Path)

function Write-Message([xml]$config, [string]$message, [string]$messageColor, [bool]$logOnly=$FALSE)
{
    $installPath = Join-path $config.InstallSettings.WebServer.SitecoreInstallRoot -ChildPath $config.InstallSettings.WebServer.SitecoreInstallFolder
    $logFileName = $config.InstallSettings.LogFileName
    $logPath = Join-path $installPath -ChildPath $logFileName

    # Write message to log file
    if (!([string]::IsNullOrEmpty($logFileName)))
    {
        Add-Content $logPath $message
    }

    # Write message to screen
    if (!($logOnly))
    {
        Write-Host $message -ForegroundColor $messageColor;
    }
}

function Read-InstallConfigFile
{
    [xml]$Config = Get-Content ($scriptDir + "\install.config")
    return $Config
}

function Get-ConfigOption([xml]$config, [string]$optionName)
{
    $shouldInstall = $FALSE
    $nodeValue = $config.InstallSettings.SelectSingleNode($optionName).InnerText
    if (!([string]::IsNullOrEmpty($nodeValue)))
    {
        $shouldInstall = [System.Convert]::ToBoolean($nodeValue)
    }
    return $shouldInstall
}

function Get-SqlLoginAccountForDataAccess([xml]$config)
{
    # Top priority is Application Pool Identity
    if (Get-ConfigOption $config "WebServer/UseWindowsAuthenticationForSqlDataAccess")
    {
        return $config.InstallSettings.WebServer.AppPoolIdentity
    }

    # Next, use the SQL login for data access if it exists
    if (!([string]::IsNullOrEmpty($config.InstallSettings.Database.SqlLoginForDataAccess)))
    {
        return $config.InstallSettings.Database.SqlLoginForDataAccess
    }

    # Finally, use the Sql login for install, but only if it is not a domain account
    $split = $config.InstallSettings.Database.SqlLoginForInstall.Split("\")
    if ($split.Count -lt 2)
    {
        return $config.InstallSettings.Database.SqlLoginForInstall
    }

    return $null
}

function Confirm-SqlLoginConfiguration([xml]$config)
{
    $login = Get-SqlLoginAccountForDataAccess $config
    if ($login -eq $null)
    {
        return $FALSE
    }

    return $TRUE
}

function Get-SqlServerSmo([xml]$config)
{
    $sqlServerName = $config.InstallSettings.Database.SqlServerName
    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | Out-Null 
    $sqlServerSmo = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server $sqlServerName

    # Set authentication to use login from config
    $split = $config.InstallSettings.Database.SqlLoginForInstall.Split("\")
    if ($split.Count -eq 2)
    {
        # Use Windows authentication
        $sqlServerSmo.ConnectionContext.LoginSecure = $TRUE
        $sqlServerSmo.ConnectionContext.ConnectAsUser = $TRUE 
		$sqlServerSmo.ConnectionContext.ConnectAsUserName  = $split[1]
		$sqlServerSmo.ConnectionContext.ConnectAsUserPassword = $config.InstallSettings.Database.SqlLoginForInstallPassword
    }
    else
    {
        # Use SQL authentication
        $sqlServerSmo.ConnectionContext.LoginSecure = $FALSE
        $sqlServerSmo.ConnectionContext.set_Login($config.InstallSettings.Database.SqlLoginForInstall)
        $password = ConvertTo-SecureString $config.InstallSettings.Database.SqlLoginForInstallPassword -AsPlainText -Force 
        $sqlServerSmo.ConnectionContext.set_SecurePassword($password)
    }

    return $sqlServerSmo
}

function Confirm-MemberOfRole([string]$memberName, [string]$roleName, [Microsoft.SqlServer.Management.Smo.Server]$sqlServerSmo)
{
    $roleMembers = $sqlServerSmo.Roles[$roleName].EnumServerRoleMembers()
    if ($roleMembers |  Where-Object { $memberName -contains $_ })
    {
        return $TRUE
    }
    else
    {
        $FALSE
    }
}

function Confirm-SqlConnectionAndRoles([xml]$config)
{
    [Microsoft.SqlServer.Management.Smo.Server]$sqlServerSmo = Get-SqlServerSmo $config

    try
    {
        # Validate SQL connection can be established
        $sqlServerSmo.ConnectionContext.Connect()

        # Validate server roles for install login: must be sysadmin or dbcreator and securityadmin
        $memberName = $config.InstallSettings.Database.SqlLoginForInstall
        $isSysAdmin = Confirm-MemberOfRole $memberName "sysadmin" $sqlServerSmo
        $isDbCreator = Confirm-MemberOfRole $memberName "dbcreator" $sqlServerSmo
        $isSecurityAdmin = Confirm-MemberOfRole $memberName "securityadmin" $sqlServerSmo
        if (!$isSysAdmin -and !($isDbCreator -and $isSecurityAdmin))
        {
            Write-Host "$memberName doesn't have required server roles in SQL" -ForegroundColor Red
            return $FALSE
        }

        # Validate data access login exists
        $loginName = Get-SqlLoginAccountForDataAccess $config
        if ($sqlServerSmo.Logins[$loginName] -eq $null)
        {
            Write-Host "Could not find a login called $loginName on SQL server" -ForegroundColor Red
            return $FALSE
        }

        return $TRUE
    }
    catch [Exception]
    {
        Write-Host  $_.Exception -ForegroundColor Red
        return $FALSE
    }
}

function Confirm-ConfigurationSettings([xml]$config)
{
    if ([string]::IsNullOrEmpty($config.InstallSettings.SitecoreZipPath))
    {
        Write-Host "SitecoreZipPath cannot be null or empty" -ForegroundColor Red
        return $FALSE
    }

    if ([string]::IsNullOrEmpty($config.InstallSettings.WebServer.LicenseFilePath))
    {
        Write-Host "LicenseFilePath cannot be null or empty" -ForegroundColor Red
        return $FALSE
    }

    if ([string]::IsNullOrEmpty($config.InstallSettings.WebServer.SitecoreInstallRoot))
    {
        Write-Host "SitecoreInstallRoot cannot be null or empty" -ForegroundColor Red
        return $FALSE
    }

    if ([string]::IsNullOrEmpty($config.InstallSettings.WebServer.SitecoreInstallFolder))
    {
        Write-Host "SitecoreInstallFolder cannot be null or empty" -ForegroundColor Red
        return $FALSE
    }

    if ([string]::IsNullOrEmpty($config.InstallSettings.WebServer.IISWebSiteName))
    {
        Write-Host "IISWebSiteName cannot be null or empty" -ForegroundColor Red
        return $FALSE
    }

    if ([string]::IsNullOrEmpty($config.InstallSettings.WebServer.DefaultRuntimeVersion))
    {
        Write-Host "DefaultRuntimeVersion cannot be null or empty" -ForegroundColor Red
        return $FALSE
    }

    $sessionStateProvider = $config.InstallSettings.WebServer.SessionStateProvider
    if ($sessionStateProvider.ToLower() -eq "mongo")
    {
        Write-Host "Mongo is not currently supported by installer for SessionStateProvider" -ForegroundColor Red
        return $FALSE
    }
    elseif ($sessionStateProvider.ToLower() -ne "inproc" -and $sessionStateProvider.ToLower() -ne "mssql")
    {
        Write-Host "SessionStateProvider selection is not recognized" -ForegroundColor Red
        return $FALSE
    }

    if ([string]::IsNullOrEmpty($config.InstallSettings.WebServer.AppPoolIdentity))
    {
        Write-Host "AppPoolIdentity cannot be null or empty" -ForegroundColor Red
        return $FALSE
    }
    elseif ($config.InstallSettings.WebServer.AppPoolIdentity -ne "ApplicationPoolIdentity" -and $config.InstallSettings.WebServer.AppPoolIdentity -ne "NetworkService")
    {
        # Validate that input is in the form <domain>\<username>
        $split = $config.InstallSettings.WebServer.AppPoolIdentity.Split("\")
        if ([string]::IsNullOrEmpty($split[0]) -or [string]::IsNullOrEmpty($split[1]))
        {
            Write-Host "AppPoolIdentity must be of the form <domain>\<username>" -ForegroundColor Red
            return $FALSE
        }

        # Validate that we have a password
        if ([string]::IsNullOrEmpty($config.InstallSettings.WebServer.AppPoolIdentityPassword))
        {
            Write-Host "AppPoolIdentityPassword cannot be null or empty" -ForegroundColor Red
            return $FALSE
        }
    }
    else
    {
        # Using a built-in account, ensure it will not be used for SQL login
        if (Get-ConfigOption $config "WebServer/UseWindowsAuthenticationForSqlDataAccess")
        {
            Write-Host "Must use a domain account for application pool identity when also using Windows authentication for SQL login" -ForegroundColor Red
            return $FALSE
        }
    }

    if ([string]::IsNullOrEmpty($config.InstallSettings.WebServer.IISHostName))
    {
        Write-Host "IISHostName cannot be null or empty" -ForegroundColor Red
        return $FALSE
    }

    if ([string]::IsNullOrEmpty($config.InstallSettings.Database.SqlServerName))
    {
        Write-Host "SqlServerName cannot be null or empty" -ForegroundColor Red
        return $FALSE
    }

    if ([string]::IsNullOrEmpty($config.InstallSettings.Database.SqlLoginForInstall))
    {
        Write-Host "SqlLoginForInstall cannot be null or empty" -ForegroundColor Red
        return $FALSE
    }
    else
    {
        $split = $config.InstallSettings.Database.SqlLoginForInstall.Split("\")
        if ($split.Count -eq 2)
        {
            # Validate that input is in the form <domain>\<username>
            if ([string]::IsNullOrEmpty($split[0]) -or [string]::IsNullOrEmpty($split[1]))
            {
                Write-Host "SqlLoginForInstall must be of the form <domain>\<username>" -ForegroundColor Red
                return $FALSE
            }
        }
    }

    if ([string]::IsNullOrEmpty($config.InstallSettings.Database.SqlLoginForInstallPassword))
    {
        Write-Host "SqlLoginForInstallPassword cannot be null or empty" -ForegroundColor Red
        return $FALSE
    }

    if (!([string]::IsNullOrEmpty($config.InstallSettings.Database.SqlLoginForDataAccess)))
    {
        if ([string]::IsNullOrEmpty($config.InstallSettings.Database.SqlLoginForDataAccessPassword))
        {
            Write-Host "SqlLoginForDataAccessPassword cannot be null or empty" -ForegroundColor Red
            return $FALSE
        }

        # Validate that login is not a domain account
        $split = $config.InstallSettings.Database.SqlLoginForDataAccess.Split("\")
        if ($split.Count -eq 2)
        {
            Write-Host "SqlLoginForDataAccess cannot be a domain account" -ForegroundColor Red
            return $FALSE
        }
    }
    
    $isValidLoginConfiguration = Confirm-SqlLoginConfiguration $config
    if (!$isValidLoginConfiguration)
    {
        Write-Host "The specified combination of accounts will not produce a valid SQL login for data access." -ForegroundColor Red
        return $FALSE
    }

    $isSqlConnectionValid = Confirm-SqlConnectionAndRoles $config
    if(!$isSqlConnectionValid)
    {
        Write-Host "A problem has been detected with the SQL connection." -ForegroundColor Red
        return $FALSE
    }

    return $TRUE
}

function Find-FolderInZipFile($items, [string]$folderName)
{
    foreach($item in $items)
    {
        if ($item.GetFolder -ne $Null)
        {
            Find-FolderInZipFile $item.GetFolder.items() $folderName
        }
        if ($item.name -Like $folderName)
        {
            return $item
        } 
    } 
}

function Get-DatabaseInstallFolderPath([xml]$config, [string]$installPath)
{
    # Determine the install root for db files
    if ([string]::IsNullOrEmpty($config.InstallSettings.Database.DatabaseInstallRoot))
    {
        $dbInstallPath = $installPath
    }
    else
    {
        $dbInstallPath = $config.InstallSettings.Database.DatabaseInstallRoot
    }

    # Determine database folder name
    $defaultDbFolderName = "Databases"
    if ([string]::IsNullOrEmpty($config.InstallSettings.Database.DatabaseInstallFolderName))
    {
        $dbFolderName = $defaultDbFolderName
    }
    else
    {
        $dbFolderName = $config.InstallSettings.Database.DatabaseInstallFolderName
    }

    $dbFolderPath = Join-path $dbInstallPath -ChildPath $dbFolderName
    return $dbFolderPath
}

function Copy-DatabaseFiles([xml]$config, [string]$zipPath, [string]$installPath)
{
    $dbFolderPath =  Get-DatabaseInstallFolderPath $config $installPath

    Write-Message $config "Extracting database files from $zipPath to $dbFolderPath" "White"

    # Copy Databases folder
    if (Test-Path $dbFolderPath)
    {
        Write-Message $config "$dbFolderPath already exists, skipping extraction" "Yellow"
    }
    else
    {
        # Create Database directory
        New-Item $dbFolderPath -type directory -force | Out-Null

        $item = Find-FolderInZipFile $shell.NameSpace($zipPath).Items() "Databases"
        foreach($childItem in $shell.NameSpace($item.Path).Items())
        {
            $shell.NameSpace($dbFolderPath).CopyHere($childItem)

            # Rename Analytics database files to Reporting
            if ($childItem.Name -eq "Sitecore.Analytics.ldf")
            {
                Rename-Item "$dbFolderPath\Sitecore.Analytics.ldf" "Sitecore.Reporting.ldf"
            }

            if ($childItem.Name -eq "Sitecore.Analytics.mdf")
            {
                Rename-Item "$dbFolderPath\Sitecore.Analytics.mdf" "Sitecore.Reporting.mdf"
            }

        }
        Write-Message $config "Database files copied." "White"
    }
}

function Copy-SitecoreFiles([xml]$config)
{
    Write-Message $config "`nCopying Sitecore files..." "Green"

    $zipPath = $config.InstallSettings.SitecoreZipPath
    $installPath = Join-Path $config.InstallSettings.WebServer.SitecoreInstallRoot -ChildPath $config.InstallSettings.WebServer.SitecoreInstallFolder

    $shell = New-Object -com shell.application

    Write-Message $config "Extracting files from $zipPath to $installPath" "White"

    # Copy Data folder
    $folderName = "Data"
    $folderPath = Join-Path $installPath -ChildPath $folderName
    if (Test-Path $folderPath)
    {
        Write-Message $config "$folderPath already exists, skipping extraction" "Yellow"
    }
    else
    {
        $item = Find-FolderInZipFile $shell.NameSpace($zipPath).Items() $folderName
        $shell.NameSpace($installPath).CopyHere($item)
        Write-Message $config "$folderName folder copied." "White"
    }

    # Copy Website folder
    $folderName = "Website"
    $folderPath = Join-Path $installPath -ChildPath $folderName
    if (Test-Path $folderPath)
    {
        Write-Message $config "$folderPath already exists, skipping extraction" "Yellow"
    }
    else
    {
        $item = Find-FolderInZipFile $shell.NameSpace($zipPath).Items() $folderName
        $shell.NameSpace($installPath).CopyHere($item)
        Write-Message $config "$folderName folder copied." "White"
    }

    if (Get-ConfigOption $config "Database/InstallDatabase")
    {
        Copy-DatabaseFiles $config $zipPath $installPath
    }
    else
    {
        Write-Message $config "Skipping database file extraction: InstallDatabase option is false" "White"
    }
    
    $licenseInstallPath = Join-Path $installPath -ChildPath "Data\license.xml"
    Copy-Item -Path $config.InstallSettings.WebServer.LicenseFilePath -Destination $licenseInstallPath

    Write-Message $config "File copying done!" "White"
}

function Get-DatabaseNames
{
    $databaseNames = @("Core", "Master", "Web", "Sessions", "Reporting")
    return $databaseNames
}

function Attach-SitecoreDatabase([xml]$config, [string]$databaseName, [Microsoft.SqlServer.Management.Smo.Server]$sqlServerSmo)
{
    $fullDatabaseName = $config.InstallSettings.Database.DatabaseNamePrefix + $databaseName

    if (!(Get-ConfigOption $config "Database/InstallDatabase"))
    {
        Write-Message $config "Skipping database attach: InstallDatabase option is false" "White"
        return $fullDatabaseName
    }

    if ($sqlServerSmo.databases[$fullDatabaseName] -eq $null)
    {
        $message = "Attaching database $fullDatabaseName to " + $sqlServerSmo.Name
        Write-Message $config $message "White"

        $installPath = Join-path $config.InstallSettings.WebServer.SitecoreInstallRoot -ChildPath $config.InstallSettings.WebServer.SitecoreInstallFolder
        $dbFolderPath = Get-DatabaseInstallFolderPath $config $installPath

        # Get paths of the data and log file
        $dataFilePath = Join-path $dbFolderPath -ChildPath "Sitecore.$databaseName.mdf";
        $logFilePath = Join-Path $dbFolderPath -ChildPath "Sitecore.$databaseName.ldf";

        $files = New-Object System.Collections.Specialized.StringCollection 
        $files.Add($dataFilePath) | Out-Null; 
        $files.Add($logFilePath) | Out-Null;

        # Try attaching
        try
        {
            $sqlServerSmo.AttachDatabase($fullDatabaseName, $files)
        }
        catch
        {
            Write-Message $config $_.Exception "Red"
        }
    }
    else
    {
        $message = "Database $fullDatabaseName already exists on " + $sqlServerSmo.Name
        Write-Message $config $message "Yellow"
    }

    return $fullDatabaseName
}

function Set-DatabaseRoles([xml]$config, [string]$databaseName, [Microsoft.SqlServer.Management.Smo.Server]$sqlServerSmo)
{
    $loginName = Get-SqlLoginAccountForDataAccess $config

    # Add database mapping
    $database = $sqlServerSmo.Databases[$databaseName]
    if ($database.Users[$loginName])
    {
        Write-Message $config "Dropping user from $database" "Yellow"
        $database.Users[$loginName].Drop()
    }
    $dbUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.User -ArgumentList $database, $loginName
    $dbUser.Login = $loginName
    $dbUser.Create()

    $basicRoles = @("db_datareader", "db_datawriter", "public")
    $extendedRoles = @("aspnet_Membership_BasicAccess", "aspnet_Membership_FullAccess", "aspnet_Membership_ReportingAccess",
                    "aspnet_Profile_BasicAccess", "aspnet_Profile_FullAccess", "aspnet_Profile_ReportingAccess",
                    "aspnet_Roles_BasicAccess", "aspnet_Roles_FullAccess", "aspnet_Roles_ReportingAccess")

    $roles = $basicRoles
    if ($databaseName.ToLower().EndsWith("_core"))
    {
        $roles += $extendedRoles   
    }

    # Assign database roles user
    foreach ($roleName in $roles)
    {
        Write-Message $config "Adding $roleName role for $loginName on $database" "White"
        $dbrole = $database.Roles[$roleName]
        $dbrole.AddMember($loginName)
        $dbrole.Alter | Out-Null
    }
}

function Grant-DatabasePermissions([xml]$config, [string]$databaseName, [Microsoft.SqlServer.Management.Smo.Server]$sqlServerSmo)
{
    $loginName = Get-SqlLoginAccountForDataAccess $config

    $database = $sqlServerSmo.Databases[$databaseName]
    $permset = New-Object Microsoft.SqlServer.Management.Smo.DatabasePermissionSet 
    $permset.Execute = $true
    $database.Grant($permset, $loginName)
    $database.Alter();

    Write-Message $config "Granted Execute permission to $loginName on $database" "White"
}

function Initialize-SitecoreDatabases([xml]$config)
{
    Write-Message $config "`nInitializing Sitecore Databases..." "Green"

    [Microsoft.SqlServer.Management.Smo.Server]$sqlServerSmo = Get-SqlServerSmo $config

    foreach ($dbname in Get-DatabaseNames)
    {
        $fullDatabaseName = Attach-SitecoreDatabase $config $dbname $sqlServerSmo
        Set-DatabaseRoles $config $fullDatabaseName $sqlServerSmo
        Grant-DatabasePermissions $config $fullDatabaseName $sqlServerSmo
    }

    Write-Message $config "Database initialization complete!" "White"
}

function Set-ApplicationPoolIdentity([xml]$config, $pool)
{
    $pool.processModel.userName = $config.InstallSettings.WebServer.AppPoolIdentity
    
    if ($config.InstallSettings.WebServer.AppPoolIdentity -ne "ApplicationPoolIdentity" -and $config.InstallSettings.WebServer.AppPoolIdentity -ne "NetworkService")
    {
        # Using a service account
        $pool.processModel.password = $config.InstallSettings.WebServer.AppPoolIdentityPassword
        # Set identity type for a "SpecificUser"
        $pool.processModel.identityType = 3
    }

    $pool | Set-Item

    Write-Message $config "Identity of application pool is $pool.processModel.userName" "White"
}

function Add-IpRestrictionsToTarget([xml]$config, [string]$target, [string]$iisSiteName)
{
    $pspath = "IIS:\"
    $filter = "/system.webserver/security/ipSecurity"
    $propertyName = "allowUnlisted"
    $propertyValue =  "false"
    $location = $iisSiteName + "/" + $target
 
    Set-WebConfigurationProperty -PSPath $pspath -Filter $filter -Name $propertyName -Value $propertyValue -Location $location

    Write-Message $config "Denying all unspecified clients for $target" "White"

    $whiteList = $config.InstallSettings.WebServer.IPWhiteList
    foreach ($ip in $whiteList.IP)
    {
        Add-WebConfiguration -pspath $pspath -filter $filter -value @{ipAddress=$ip;allowed="true"} -Location $location
        Write-Message $config "$ip added to IP whitelist for $target" "White"
    }
}

function Set-IpRestrictions([xml]$config, [string]$iisSiteName)
{
    $targetItems = @("sitecore/admin", "sitecore/shell", "sitecore/login", "sitecore/default.aspx")
    foreach ($target in $targetItems)
    {
        Add-IpRestrictionsToTarget $config $target $iisSiteName
    }
}

function Initialize-WebSite([xml]$config)
{
    Write-Message $config "`nInitializing site in IIS..." "Green"

    $siteName = $config.InstallSettings.WebServer.IISWebSiteName

    # Setup application pool
    $appPoolName = $siteName + "AppPool"
    if(Test-Path IIS:\AppPools\$appPoolName)
    {
        Write-Message $config "Application pool named $appPoolName already exists" "Yellow"
    }
    else
    {
        Write-Message $config "Provisioning new application pool in IIS - $appPoolName" "White"
        New-WebAppPool -Name $appPoolName -force | Out-Null

        $pool = Get-Item IIS:\AppPools\$appPoolName
        Set-ApplicationPoolIdentity $config $pool
        $pool.managedRuntimeVersion = $config.InstallSettings.WebServer.DefaultRuntimeVersion
        $pool.processModel.loadUserProfile = $TRUE
        $pool.processModel.maxProcesses = 1
        $pool | Set-Item
    }

    # Create IIS site
    $iisSiteName = $sitename
    if(Test-Path IIS:\Sites\$iisSiteName)
    {
        Write-Message $config  "A site named $iisSiteName already exists in IIS" "Yellow"
    }
    else
    {
        Write-Message $config "Provisioning new IIS site name $iisSiteName" "White"
        $hostName = $config.InstallSettings.WebServer.IISHostName
        $installPath = Join-Path $config.InstallSettings.WebServer.SitecoreInstallRoot -ChildPath $config.InstallSettings.WebServer.SitecoreInstallFolder
        $sitePath = Join-Path $installPath -ChildPath "Website"
        New-Website –Name $iisSiteName –Port 80 –HostHeader $hostname –PhysicalPath $sitePath -ApplicationPool $appPoolName -force | Out-Null

        # Add hostname to hosts file
        Write-Message $config "Add $hostName to hosts file" "White"
        $hostsPath = "$env:windir\System32\drivers\etc\hosts"
        Add-Content $hostsPath "`n127.0.0.1 $hostName"
    }

    Write-Message $config "IIS site initialization complete!" "White"

    return $iisSiteName
}

function Get-BaseConnectionString([xml]$config)
{
    $sqlServerName = $config.InstallSettings.Database.SqlServerName
    
    if (Get-ConfigOption $config "WebServer/UseWindowsAuthenticationForSqlDataAccess")
    {
        $baseConnectionString = "Server=$sqlServerName;Trusted_Connection=Yes;Database="
    }
    else
    {
        if ([string]::IsNullOrEmpty($config.InstallSettings.Database.SqlLoginForDataAccess))
        {
            $loginName = $config.InstallSettings.Database.SqlLoginForInstall
            $loginPassword = $config.InstallSettings.Database.SqlLoginForInstallPassword
        }
        else
        {
            $loginName = $config.InstallSettings.Database.SqlLoginForDataAccess
            $loginPassword = $config.InstallSettings.Database.SqlLoginForDataAccessPassword
        }

        $baseConnectionString = "user id=$loginName;password=$loginPassword;Data Source=$sqlServerName;Database="
    }

    return $baseConnectionString
}

function Copy-SwitchMasterToWeb([xml]$config, [string]$installPath)
{
    $folderPath = Join-path $installPath -ChildPath "Website\App_Config\Include\zzzMustBeLast"
    New-Item $folderPath -type directory -force | Out-Null

    $destination = Join-path $folderPath -ChildPath "SwitchMasterToWeb.config"
    $source = Join-path $installPath -ChildPath "Website\App_Config\Include\SwitchMasterToWeb.config.example"

    Copy-Item $source $destination
    
    Write-Message $config "Saved SwitchMasterToWeb.config to $folderPath" "White"
}

function Set-ConfigurationFiles([xml]$config)
{
    Write-Message $config "`nWriting changes to config files..." "Green"

    $installPath = Join-path $config.InstallSettings.WebServer.SitecoreInstallRoot -ChildPath $config.InstallSettings.WebServer.SitecoreInstallFolder

    # Edit web.config
    $webConfigPath = Join-Path $installPath -ChildPath "Website\web.config"
    $webconfig = [xml](Get-Content $webConfigPath)
    $currentDate = (Get-Date).ToString("yyyyMMdd_hh-mm-s")
    $backup = $webConfigPath + "__$currentDate"
    Write-Message $config "Backing up Web.config" "White"
    $webconfig.Save($backup)

    $dataFolderPath = Join-Path $installPath -ChildPath "Data"
    $webconfig.configuration.SelectSingleNode("sitecore/sc.variable[@name='dataFolder']").SetAttribute("value", $dataFolderPath)

    # Modify sessionState element
    if ($config.InstallSettings.WebServer.SessionStateProvider.ToLower() -eq "mssql")
    {
        $webconfig.configuration.SelectSingleNode("system.web/sessionState").SetAttribute("mode", "Custom")
        $webconfig.configuration.SelectSingleNode("system.web/sessionState").SetAttribute("customProvider", "mssql")
        Write-Message $config "Changing session state provider to MSSQL" "White"
    }

    Write-Message $config "Saving changes to Web.config" "White"
    $webconfig.Save($webConfigPath)


    # Edit connectionStrings.config
    $connectionStringsPath = Join-Path $installPath -ChildPath "Website\App_Config\ConnectionStrings.config"
    $connectionStringsConfig = [xml](Get-Content $connectionStringsPath)
    $backup = $connectionStringsPath + "__$currentDate"
    Write-Message $config "Backing up ConnectionStrings.config" "White"
    $connectionStringsConfig.Save($backup)

    $baseConnectionString = Get-BaseConnectionString $config
    foreach ($databaseName in Get-DatabaseNames)
    {
        $dbname = $databaseName.ToLower()
        $fullDatabaseName = $config.InstallSettings.Database.DatabaseNamePrefix + $databaseName
        $connectionString = $baseConnectionString + $fullDatabaseName + ";"

        $node = $connectionStringsConfig.SelectSingleNode("connectionStrings/add[@name='$dbname']")
        if ($node -ne $null)
        {
            $node.SetAttribute("connectionString", $connectionString);
        }
    }

    # Optionally add a session connection string
    if ($config.InstallSettings.WebServer.SessionStateProvider.ToLower() -eq "mssql")
    {
        $sessionElement = $connectionStringsConfig.CreateElement("add")

        $sessionAttr = $connectionStringsConfig.CreateAttribute("name")
        $sessionAttr.Value = "session"
        $sessionElement.Attributes.Append($sessionAttr) | Out-Null

        $sessionAttr = $connectionStringsConfig.CreateAttribute("connectionString")
        $sessionAttr.Value = $baseConnectionString + $config.InstallSettings.Database.DatabaseNamePrefix + "Sessions;"
        $sessionElement.Attributes.Append($sessionAttr) | Out-Null

        $connectionStringsConfig.DocumentElement.AppendChild($sessionElement) | Out-Null
        Write-Message $config "Addedd a session connection string" "White"
    }

    # Modify Mongo connection strings
    if (!([string]::IsNullOrEmpty($config.InstallSettings.WebServer.MongoDb.HostName)))
    {
        $mongoNodes = $connectionStringsConfig.SelectNodes("connectionStrings/add[contains(@connectionString, 'mongodb://')]")
        foreach ($node in $mongoNodes)
        {
            $url = [System.Uri]($node.connectionString)

            $builder = New-Object System.UriBuilder
            $builder.Scheme = $url.Scheme
            $builder.Host = $config.InstallSettings.WebServer.MongoDb.HostName
            if (!([string]::IsNullOrEmpty($config.InstallSettings.WebServer.MongoDb.Port)))
            {
                $builder.Port = $config.InstallSettings.WebServer.MongoDb.Port
            }
            $builder.Path = $url.AbsolutePath

            $node.SetAttribute("connectionString", $builder.ToString())
        }

        Write-Message $config "Changing host name for MongoDb connection strings" "White"
    }

    # Comment out connection strings not needed by CD server
    if (Get-ConfigOption $config "WebServer/CDServerSettings/DeactivateConnectionStrings")
    {
        $node = $connectionStringsConfig.SelectSingleNode("connectionStrings/add[@name='master']")
        $node.ParentNode.InnerXml = $node.ParentNode.InnerXml.Replace($node.OuterXml, $node.OuterXml.Insert(0, "<!--").Insert($node.OuterXml.Length+4, "-->"))

        $node = $connectionStringsConfig.SelectSingleNode("connectionStrings/add[@name='tracking.history']")
        $node.ParentNode.InnerXml = $node.ParentNode.InnerXml.Replace($node.OuterXml, $node.OuterXml.Insert(0, "<!--").Insert($node.OuterXml.Length+4, "-->"))

        $node = $connectionStringsConfig.SelectSingleNode("connectionStrings/add[@name='reporting']")
        $node.ParentNode.InnerXml = $node.ParentNode.InnerXml.Replace($node.OuterXml, $node.OuterXml.Insert(0, "<!--").Insert($node.OuterXml.Length+4, "-->"))

        Write-Message $config "Commenting out connection strings not need on CD server" "White"

        Copy-SwitchMasterToWeb $config $installPath
    }

    Write-Message $config "Saving ConnectionStrings.config" "White"
    $connectionStringsConfig.Save($connectionStringsPath)


    # Edit Sitecore.ContentSearch.Solr.DefaultIndexConfiguration.config.example
    if (!([string]::IsNullOrEmpty($config.InstallSettings.WebServer.Solr.ServiceBaseAddress)))
    {
        $solrConfigPath = Join-Path $installPath -ChildPath "Website\App_Config\Include\Sitecore.ContentSearch.Solr.DefaultIndexConfiguration.config.example"
        $solrConfig = [xml](Get-Content $solrConfigPath)
        $backup = $solrConfigPath + "__$currentDate"
        Write-Message $config "Backing up Sitecore.ContentSearch.Solr.DefaultIndexConfiguration.config.example" "White"
        $solrConfig.Save($backup)

        $solrConfig.configuration.SelectSingleNode("sitecore/settings/setting[@name='ContentSearch.Solr.ServiceBaseAddress']").SetAttribute("value", $config.InstallSettings.WebServer.Solr.ServiceBaseAddress)
        Write-Message $config "Changing Solr ServiceBaseAddress" "White"

        Write-Message $config "Saving Sitecore.ContentSearch.Solr.DefaultIndexConfiguration.config.example" "White"
        $solrConfig.Save($solrConfigPath)
    }

    Write-Message $config "Modifying config files complete!" "White"
}

function Set-AclForFolder([string]$userName, [string]$permission, [string]$folderPath)
{
    $acl = Get-Acl $folderPath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($userName, $permission, "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl $folderPath $acl
    Write-Message $config "Added $userName to ACL ($permission) for $folderPath" "White"
}

function Confirm-IsUserMemberOfLocalGroup([string]$groupName, [string]$userName)
{
    $group =[ADSI]"WinNT://$env:COMPUTERNAME/$groupName,group" 
    $members = @($group.psbase.Invoke("Members")) 

    foreach ($member in $members)
    {
        $memberName = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
        if ($memberName -eq $userName)
        {
            return $TRUE
        }
    }

    return $FALSE
}

function Add-AppPoolIdentityToLocalGroup([xml]$config, [string]$groupName, [string]$iisSiteName)
{
    if ($config.InstallSettings.WebServer.AppPoolIdentity -eq "ApplicationPoolIdentity")
    {
        $domain = "IIS APPPOOL"
        $site = Get-Website -Name $iisSiteName
        $userName = $site.applicationPool
    }
    elseif ($config.InstallSettings.WebServer.AppPoolIdentity -eq "NetworkService")
    {
        $domain = "NT AUTHORITY"
        $userName = "Network Service"
    }
    else
    {
        $split = $config.InstallSettings.WebServer.AppPoolIdentity.split("\")
        $domain = $split[0]
        $userName = $split[1]
    }

    if (Confirm-IsUserMemberOfLocalGroup $groupName $userName)
    {
        Write-Message $config "$userName is already a member of $groupName" "White"
    }
    else
    {
        $group = [ADSI]"WinNT://$env:COMPUTERNAME/$groupName,group"
        $group.Add("WinNT://$domain/$userName,user")
        Write-Message $config "$userName added a member of $groupName" "White"
    }
}

function Set-FileSystemPermissions([xml]$config, [string]$iisSiteName)
{
    $installPath = Join-path $config.InstallSettings.WebServer.SitecoreInstallRoot -ChildPath $config.InstallSettings.WebServer.SitecoreInstallFolder

    # Get app pool from site name
    $site = Get-Website -Name $iisSiteName
    $appPoolName = $site.applicationPool
    $pool = Get-Item IIS:\AppPools\$appPoolName

    # Set ACLs for "Website"
    $folderPath = Join-Path $installPath -ChildPath "Website"
    Set-AclForFolder $pool.processModel.userName "Modify" $folderPath
    Set-AclForFolder "IUSR" "Read" $folderPath

    # Set ACLs for "Data"
    $folderPath = Join-Path $installPath -ChildPath "Data"
    Set-AclForFolder $pool.processModel.userName "Modify" $folderPath
}

function Get-FilesToDisableOnCDServer([xml]$config)
{
    $installPath = Join-path $config.InstallSettings.WebServer.SitecoreInstallRoot -ChildPath $config.InstallSettings.WebServer.SitecoreInstallFolder
    $webrootPath = Join-Path $installPath -ChildPath "Website"

    $files = @("App_Config\Include\Sitecore.Analytics.Automation.TimeoutProcessing.config",
               "App_Config\Include\Sitecore.Analytics.Processing.Aggregation.Services.config",
               "App_Config\Include\Sitecore.Analytics.Processing.Services.config",
               "App_Config\Include\Sitecore.Analytics.Reporting.config",
               "App_Config\Include\Sitecore.Processing.config",
               "App_Config\Include\Sitecore.Marketing.Definitions.MarketingAssets.Repositories.Lucene.Index.Master.config",
               "App_Config\Include\Sitecore.Marketing.Client.config",
               "App_Config\Include\Sitecore.ContentSearch.Lucene.Index.Master.config",
               "App_Config\Include\Sitecore.PathAnalyzer.Client.config",
               "App_Config\Include\Sitecore.PathAnalyzer.config",
               "App_Config\Include\Sitecore.PathAnalyzer.Processing.config",
               "App_Config\Include\Sitecore.PathAnalyzer.RemoteClient.config",
               "App_Config\Include\Sitecore.PathAnalyzer.Services.config",
               "App_Config\Include\Sitecore.PathAnalyzer.Services.RemoteServer.config",
               "bin\Sitecore.PathAnalyzer.dll",
               "bin\Sitecore.PathAnalyzer.Client.dll",
               "bin\Sitecore.PathAnalyzer.Services.dll",
               "bin\Sitecore.SequenceAnalyzer.dll",
               "App_Config\Include\ExperienceAnalytics\Sitecore.ExperienceAnalytics.Aggregation.config",
               "App_Config\Include\ExperienceAnalytics\Sitecore.ExperienceAnalytics.Client.config",
               "App_Config\Include\ExperienceAnalytics\Sitecore.ExperienceAnalytics.Reduce.config",
               "App_Config\Include\ExperienceAnalytics\Sitecore.ExperienceAnalytics.StorageProviders.config",
               "App_Config\Include\ExperienceAnalytics\Sitecore.ExperienceAnalytics.WebAPI.config",
               "bin\Sitecore.ExperienceAnalytics.dll",
               "App_Config\Include\ExperienceProfile\Sitecore.ExperienceProfile.config",
               "App_Config\Include\ExperienceProfile\Sitecore.ExperienceProfile.Reporting.config",
               "App_Config\Include\ExperienceProfile\Sitecore.ExperienceProfile.Client.config",
               "App_Config\Include\Sitecore.Xdb.Remote.Client.MarketingAssets.config",
               "App_Config\Include\Sitecore.Xdb.Remote.Server.MarketingAssets.config",
               "App_Config\Include\Sitecore.Xdb.Remote.Client.config",
               "App_Config\Include\Sitecore.Xdb.Remote.Server.config")

    return $files | % { Join-Path $webrootPath -ChildPath $_ }
}

function Disable-FilesForCDServer([xml]$config)
{
    Write-Message $config "Disabling files not needed on CD server." "White"
    foreach ($file in Get-FilesToDisableOnCDServer $config)
    {        
        if (Test-Path $file)
        {
            $fileName = Split-Path $file -leaf
            $newName = $fileName + ".disabled"
            Rename-Item -Path $file -NewName $newName
            Write-Message $config "Disabled: $file" "White" $TRUE
        }
        else
        {
            Write-Message $config "File not found on server: $file" "White" $TRUE
        }
    }
}

function Block-AnonymousUsers([xml]$config, [string]$iisSiteName)
{
    Write-Message $config "Blocking anonymous access to sensitive folders on CD server." "White"
    $filter = "/system.WebServer/security/authentication/anonymousAuthentication"
    $folderList = @("/App_Config", "/sitecore/admin", "/sitecore/debug", "/sitecore/shell/WebService")
    foreach ($folder in $folderList)
    {
        Set-WebConfigurationProperty -Filter $filter -PSPath IIS:\ -Name enabled -Location "$iisSiteName$folder" -Value false
        Write-Message $config "Blocked folder: $folder" "White" $TRUE
    }
}

function Revoke-ExecutePermission([xml]$config, [string]$iisSiteName)
{
    Write-Message $config "Denying execute permission on the /upload and /temp folders." "White"
    Set-WebConfigurationProperty /system.WebServer/handlers "IIS:\sites\$iisSiteName\upload" -Name accessPolicy -value "Read"
    Set-WebConfigurationProperty /system.WebServer/handlers "IIS:\sites\$iisSiteName\temp" -Name accessPolicy -value "Read"
}

function Apply-SecuritySettings([xml]$config, [string]$iisSiteName)
{
    Write-Message $config "`nApplying recommended security settings..." "Green"
    
    Set-FileSystemPermissions $config $iisSiteName

    Add-AppPoolIdentityToLocalGroup $config "IIS_IUSRS" $iisSiteName
    Add-AppPoolIdentityToLocalGroup $config "Performance Monitor Users" $iisSiteName

    if (Get-ConfigOption $config "WebServer/CDServerSettings/ApplyIPWhitelist")
    {
        Set-IpRestrictions $config $iisSiteName
    }

    if (Get-ConfigOption $config "WebServer/CDServerSettings/DisableFilesNotNeededForCD")
    {
        Disable-FilesForCDServer $config
    }

    if (Get-ConfigOption $config "WebServer/CDServerSettings/PreventAnonymousAccess")
    {
        Block-AnonymousUsers $config $iisSiteName
    }

    if (Get-ConfigOption $config "WebServer/CDServerSettings/DenyExecutePermission")
    {
        Revoke-ExecutePermission $config $iisSiteName
    }

    Write-Message $config "Security settings complete!" "White"
}

function Start-Browser([string]$siteUrl)
{
    Write-Host "`nLaunching site in browser: $siteUrl"
    $ie = new-object -comobject "InternetExplorer.Application" 
    $ie.visible = $true
    $ie.navigate($siteUrl)
}

function Install-SitecoreApplication
{
    [xml]$config = Read-InstallConfigFile
    if ($config -eq $null)
    {
        return
    }

    $configIsValid = Confirm-ConfigurationSettings $config
    if (!$configIsValid)
    {
        Write-Host "Aborting install: config.xml file has a bad setting." -ForegroundColor Red
        return
    }

    # Create install directory
    $installPath = Join-Path $config.InstallSettings.WebServer.SitecoreInstallRoot -ChildPath $config.InstallSettings.WebServer.SitecoreInstallFolder
    if (!(Test-Path $installPath))
    {
        New-Item $installPath -type directory -force | Out-Null
    }

    $date = Get-Date
    $message = "Starting install - $date" 
    Write-Message $config $message "Green"

    $loginName = $config.InstallSettings.Database.SqlLoginForInstall
    Write-Message $config "Using $loginName as the SQL login during installation" "White"
    $loginName = Get-SqlLoginAccountForDataAccess $config
    Write-Message $config "Using $loginName as the SQL login for data access" "White"

    Copy-SitecoreFiles $config

    Set-ConfigurationFiles $config

    $iisSiteName = Initialize-WebSite $config

    Apply-SecuritySettings $config $iisSiteName

    Initialize-SitecoreDatabases $config

    $date = Get-Date
    $message = "`nInstall finished - $date"
    Write-Message $config $message "Green"

    $siteUrl = "http://" + $config.InstallSettings.WebServer.IISHostName
    Start-Browser $siteUrl
}

Install-SitecoreApplication
