# Specify a path to the .config file if you do not wish to put the .config file
# in the same directory as the script
param([string]$ConfigPath = "C:\Users\pperrone\Desktop\install.sandbox.patrick.config")

$scriptDir = Split-Path (Resolve-Path $myInvocation.MyCommand.Path)
$configSettings = $null
# Assume there is no host console available until we can read the config file.
$hostScreenAvailable = $FALSE

#region Utility Functions
function Write-Message([string]$Message, [string]$MessageColor="White", [bool]$WriteToLogOnly=$FALSE, [bool]$WriteToLog=$FALSE, [bool]$HostConsoleAvailable=$FALSE)
{
    if (!([string]::IsNullOrEmpty($script:configSettings.WebServer.SitecoreLogPath)) -and $WriteToLog)
    {
        # Write message to log file
        Add-Content $script:configSettings.WebServer.SitecoreLogPath $Message
    }

    if (!$WriteToLogOnly)
    {
        if ($HostConsoleAvailable)
        {
            # Write message to screen
            Write-Host $Message -ForegroundColor $MessageColor
        }
        else
        {
            # Write message to output stream
            Write-Verbose $Message
        }
    }
}

function Remove-BackupFiles([System.Collections.Generic.List[string]]$backupFiles)
{
    Write-Message "`nDeleting backed up files..." "Green" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    foreach ($file in $backupFiles)
    {
        Remove-Item $file
    }
    Write-Message "Removed back ups!" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
}

function Read-InstallConfigFile([string]$configPath)
{
    if ([string]::IsNullOrEmpty($configPath))
    {
        [xml]$configXml = Get-Content ($scriptDir + "\install.config")
    }
    else
    {
        if (Test-Path $configPath)
        {
            [xml]$configXml = Get-Content ($configPath)
        }
        else
        {
            Write-Message "Could not find configuration file at specified path: $configPath" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        }
    }

    return $configXml
}

function Get-ConfigOption([xml]$config, [string]$optionName, [bool]$isAttribute=$FALSE)
{
    $optionValue = $FALSE

    if ($isAttribute)
    {
        $attributeName = Split-Path -Leaf $optionName
        $optionName = Split-Path $optionName
        $optionName = $optionName.Replace("\", "//")
        $node = $config.InstallSettings.SelectSingleNode($optionName)

        if ($node -ne $null)
        {
            $attributeValue = $node.GetAttribute($attributeName).Trim()
            if (!([string]::IsNullOrEmpty($attributeValue)))
            {
                $optionValue = [System.Convert]::ToBoolean($attributeValue)
            }
        }
    }
    else
    {
        $nodeValue = $config.InstallSettings.SelectSingleNode($optionName).InnerText.Trim()
        if (!([string]::IsNullOrEmpty($nodeValue)))
        {
            $optionValue = [System.Convert]::ToBoolean($nodeValue)
        }
    }

    return $optionValue
}

function Find-MediaRequestConfig
{
    $mediaRequestConfig = "Website/App_Config/Include/Sitecore.Media.RequestProtection.config"
    $mediaRequestConfigPath = Join-Path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath $mediaRequestConfig
    if(Test-Path $mediaRequestConfigPath -PathType Leaf)
    {
        return $mediaRequestConfigPath
    }
    
    return $null
}

function Get-SqlLoginAccountForDataAccess
{
    # Top priority is Application Pool Identity
    if ($script:configSettings.Database.UseWindowsAuthenticationForSqlDataAccess)
    {
        return $script:configSettings.WebServer.AppPoolIdentity
    }

    # Next, use the SQL login for data access if it exists
    if (!([string]::IsNullOrEmpty($script:configSettings.Database.SqlLoginForDataAccess)))
    {
        return $script:configSettings.Database.SqlLoginForDataAccess
    }

    # Finally, use the Sql login for install, but only if it is not a domain account
    $split = $script:configSettings.Database.SqlLoginForInstall.Split("\")
    if ($split.Count -lt 2)
    {
        return $script:configSettings.Database.SqlLoginForInstall
    }
    else
    {
        Write-Message "The SqlLoginForInstall is a domain account and SqlLoginForDataAccess is undefined. You must supply a value for SqlLoginForDataAccess." "Yellow" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
    }

    return $null
}

function Get-SqlServerSmo
{
    $sqlServerName = $script:configSettings.Database.SqlServerName
    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | Out-Null 
    $sqlServerSmo = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server $sqlServerName

    # Set authentication to use login from config
    $split = $script:configSettings.Database.SqlLoginForInstall.Split("\")
    if ($split.Count -eq 2)
    {
        # Use Windows authentication
        $sqlServerSmo.ConnectionContext.LoginSecure = $TRUE
        $sqlServerSmo.ConnectionContext.ConnectAsUser = $TRUE 
        $sqlServerSmo.ConnectionContext.ConnectAsUserName  = $split[1]
        $sqlServerSmo.ConnectionContext.ConnectAsUserPassword = $script:configSettings.Database.SqlLoginForInstallPassword
    }
    else
    {
        # Use SQL authentication
        $sqlServerSmo.ConnectionContext.LoginSecure = $FALSE
        $sqlServerSmo.ConnectionContext.set_Login($script:configSettings.Database.SqlLoginForInstall)
        $password = ConvertTo-SecureString $script:configSettings.Database.SqlLoginForInstallPassword -AsPlainText -Force 
        $sqlServerSmo.ConnectionContext.set_SecurePassword($password)
    }

    return $sqlServerSmo
}

function Get-DatabaseInstallFolderPath
{
    [CmdletBinding()]
    param
    (
        [parameter(Position=0, Mandatory=$true)]
        [ValidateSet("DataFiles", "LogFiles")]
        [string]$FileType,
        [parameter(Mandatory=$false)]
        [switch]$LocalPath
    )
    process
    {
        $dbFilePath = $script:configSettings.Database.DatabaseInstallPath.DataFiles
        if($FileType -eq "LogFiles")
        {
            $dbFilePath = $script:configSettings.Database.DatabaseInstallPath.LogFiles
        }

        if ($LocalPath)
        {
            return $dbFilePath.Local
        }

        # Return the Local path if the Unc path does not exist
        if ([string]::IsNullOrEmpty($dbFilePath.Unc))
        {
            return $dbFilePath.Local
        }

        return $dbFilePath.Unc
    }
}

function Get-AspNetRegIisPath
{
    return (Join-Path $env:windir -ChildPath "Microsoft.NET\Framework64\v4.0.30319\aspnet_regiis.exe")
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

function Get-SitecoreVersion
{
    [CmdletBinding()]
    param
    (
        [parameter(Position=0)]
        [switch]$GetFromZip,
        [parameter(Position=1)]
        [switch]$GetFullVersion
    )
    process
    {
        # Returns the version of the Sitecore.Kernel.dll
        $installPath = Join-Path $script:configSettings.WebServer.SitecoreInstallRoot -ChildPath $script:configSettings.WebServer.SitecoreInstallFolder
        $webrootPath = Join-Path $installPath -ChildPath "Website"
        $kernelPath = Join-Path $webrootPath -ChildPath "bin\Sitecore.Kernel.dll"

        if ($GetFromZip)
        {
            if (!(Test-Path $installPath))
            {
                New-Item $installPath -type directory -force | Out-Null
            }

            $zipPath = $script:configSettings.SitecoreZipPath
            $shell = New-Object -com shell.application
            $item = Find-FolderInZipFile $shell.NameSpace($zipPath).Items() "bin"
            $kernelItem = $shell.NameSpace($item.Path).Items() | Where {$_.Name -match "Sitecore.Kernel.dll"}
            $shell.NameSpace($installPath).CopyHere($kernelItem) | Out-Null
            $path = Join-Path $installPath -ChildPath $kernelItem.Name
            $fullVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path).FileVersion
            Remove-Item $path
        }
        else
        {
            $fullVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($kernelPath).FileVersion
        }

        $versionInfo = $fullVersion
        if (!$GetFullVersion)
        {
            $verArr = $fullVersion.Split(".")
            $versionInfo = "{0}.{1}" -f $verArr[0],$verArr[1]
        }

        return $versionInfo
    }
}

function Get-BaseConnectionString
{
    $sqlServerName = $script:configSettings.Database.SqlServerName
    
    if ($script:configSettings.Database.UseWindowsAuthenticationForSqlDataAccess)
    {
        $baseConnectionString = "Server=$sqlServerName;Trusted_Connection=Yes;Database="
    }
    else
    {
        if ([string]::IsNullOrEmpty($script:configSettings.Database.SqlLoginForDataAccess))
        {
            $loginName = $script:configSettings.Database.SqlLoginForInstall
            $loginPassword = $script:configSettings.Database.SqlLoginForInstallPassword
        }
        else
        {
            $loginName = $script:configSettings.Database.SqlLoginForDataAccess
            $loginPassword = $script:configSettings.Database.SqlLoginForDataAccessPassword
        }

        $baseConnectionString = "user id=$loginName;password=$loginPassword;Data Source=$sqlServerName;Database="
    }

    return $baseConnectionString
}

function Get-SubstituteDatabaseFileName($currentFileName, $dbName)
{
    $extension = [System.IO.Path]::GetExtension($currentFileName)
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($currentFileName)
    $prefix = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
    return "$prefix.$dbName$extension"
}

function Set-AclForFolder([string]$userName, [string]$permission, [string]$folderPath)
{
    $acl = Get-Acl $folderPath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($userName, $permission, "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl $folderPath $acl
    Write-Message "Added $userName to ACL ($permission) for $folderPath" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
}

function Test-IsUserMemberOfLocalGroup([string]$groupName, [string]$userName)
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

function New-SitecoreConfigurationCsvFile($excelPath)
{
    # Creates a csv with 'dummy' header, we do this to guarantee that 
    # we can create the csv file without requiring the first row to be
    # populated.
    Import-Excel $excelPath -DataOnly -NoHeader `
        | Where-Object { $_.'P1' -ne "GENERAL CONFIGURATION"  } `
        | Export-Csv -Path $script:configSettings.ConfigurationFilesCsvPath -NoTypeInformation

    # Remove top line from csv file
    (Get-Content $script:configSettings.ConfigurationFilesCsvPath | Select-Object -Skip 1) | Set-Content $script:configSettings.ConfigurationFilesCsvPath
}

function Get-SitecoreConfigurationFiles
{
    [CmdletBinding()]
    param
    (
        [parameter(Position=0, Mandatory=$true)]
        [ValidateSet("CM", "CD", "Processing")]
        [string]$ServerRole,
        [parameter(Position=1, Mandatory=$true)]
        [ValidateSet("Enable", "Disable")]
        [string]$ConfigFilter
    )
    process
    {
        $files = @()

        $roleName = "Content Management (CM)"
        if ($ServerRole -eq "CD")
        {
            $roleName = "Content Delivery (CD)"
        }
        elseif ($ServerRole -eq "Processing")
        {
            $roleName = "Processing"
        }

        Import-Csv $script:configSettings.ConfigurationFilesCsvPath `
        | Where-Object `
            {
                $_.$($roleName).Trim() -eq $ConfigFilter `
                -and !($_.'Search Provider Used'.Contains("Solr")) `
                -and !($_.'Search Provider Used'.Contains("Azure")) `
                -and !($_.'Config file name'.Trim().EndsWith(".Oracle")) `
            } `
        | ForEach-Object `
            {
                $fileName = $_.'Config file name'.Trim()

                if (!$fileName.EndsWith(".config"))
                {
                    $fileName = [IO.Path]::GetFileNameWithoutExtension($fileName)
                }

                $files += (Join-Path $_.'File Path'.Trim() -ChildPath $fileName)
            }

        return $files
    }
}

function Remove-ChildXmlComments([System.XML.XMLElement]$node)
{
    foreach($child in $node.ChildNodes)
    {
        if ($child.NodeType -eq [System.Xml.XmlNodeType]::Comment)
        {
            $child.ParentNode.RemoveChild($child) | Out-Null
        }
    }
    return $node
}

function Add-CalculatedPropertiesToConfigurationSettings
{
    # WebServer.SitecoreInstallPath
    $sitecoreInstallPath = Join-Path $script:configSettings.WebServer.SitecoreInstallRoot -ChildPath $script:configSettings.WebServer.SitecoreInstallFolder
    $script:configSettings.WebServer | Add-Member -MemberType NoteProperty -Name SitecoreInstallPath -Value $sitecoreInstallPath

    # WebServer.SitecoreLogPath
    $sitecoreLogPath = ""
    if (!([string]::IsNullOrEmpty($script:configSettings.LogFileName)))
    {
        $sitecoreLogPath = Join-path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath $script:configSettings.LogFileName
    }
    $script:configSettings.WebServer | Add-Member -MemberType NoteProperty -Name SitecoreLogPath -Value $sitecoreLogPath

    # Database.BaseConnectionString
    $script:configSettings.Database | Add-Member -MemberType NoteProperty -Name BaseConnectionString -Value (Get-BaseConnectionString)

    # ConfigurationFilesCsvPath
    $script:configSettings | Add-Member -MemberType NoteProperty -Name ConfigurationFilesCsvPath -Value (Join-Path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath "configFiles.csv")

    if ($script:configSettings.Database.DatabaseInstallPath.LogFiles.Local -eq $null)
    {
       $script:configSettings.Database.DatabaseInstallPath.LogFiles.Local = $script:configSettings.Database.DatabaseInstallPath.DataFiles.Local 
       $script:configSettings.Database.DatabaseInstallPath.LogFiles.Unc = $script:configSettings.Database.DatabaseInstallPath.DataFiles.unc 
    }
}

function New-ConfigSettings([xml]$config)
{
    #region WebServer

    #region IISBindings
    $iisbindings = New-Object 'System.Collections.Generic.List[PSObject]'
    foreach ($binding in ($config.InstallSettings.WebServer.IISBindings.Binding))
    {
        $b = New-Object -TypeName PSObject

        $ip = $binding.IP
        if (!([string]::IsNullOrEmpty($ip)))
        {
            $ip = $ip.Trim()
        }
        [int]$port = $binding.Port
        $hostheader = $binding.HostHeader
        if (!([string]::IsNullOrEmpty($hostheader)))
        {
            $hostheader = $hostheader.Trim()
        }
        [bool]$addToHostsFile = [System.Convert]::ToBoolean($binding.AddToHostsFile)

        $b | Add-Member -MemberType NoteProperty -Name IP -Value $ip
        $b | Add-Member -MemberType NoteProperty -Name Port -Value $port
        $b | Add-Member -MemberType NoteProperty -Name HostHeader -Value $hostheader        
        $b | Add-Member -MemberType NoteProperty -Name AddToHostsFile -Value $addToHostsFile

        $iisBindings.Add($b)
    }
    #endregion

    #region Analytics
    $analytics = New-Object -TypeName PSObject

    $clusterName = $config.InstallSettings.WebServer.Analytics.ClusterName
    if (!([string]::IsNullOrEmpty($clusterName)))
    {
        $clusterName = $clusterName.Trim()
    }
    $hostName = $config.InstallSettings.WebServer.Analytics.HostName
    if (!([string]::IsNullOrEmpty($hostName)))
    {
        $hostName = $hostName.Trim()
    }

    $analytics | Add-Member -MemberType NoteProperty -Name ClusterName -Value $clusterName
    $analytics | Add-Member -MemberType NoteProperty -Name HostName -Value $hostName
    #endregion

    #region CMServerSettings
    $parallel = New-Object -TypeName PSObject
    [int]$growthsize = $config.InstallSettings.WebServer.CMServerSettings.Publishing.Parallel.WebDatabaseAutoGrowthInMB
    [int]$degrees = $config.InstallSettings.WebServer.CMServerSettings.Publishing.Parallel.MaxDegreesOfParallelism
    $parallel | Add-Member -MemberType NoteProperty -Name Enabled -Value (Get-ConfigOption $config "WebServer/CMServerSettings/Publishing/Parallel/enabled" $TRUE)
    $parallel | Add-Member -MemberType NoteProperty -Name WebDatabaseAutoGrowthInMB -Value $growthsize
    $parallel | Add-Member -MemberType NoteProperty -Name MaxDegreesOfParallelism -Value $degrees

    $publishing = New-Object -TypeName PSObject
    $publishingInstance = $config.InstallSettings.WebServer.CMServerSettings.Publishing.PublishingInstance
    if (!([string]::IsNullOrEmpty($publishingInstance)))
    {
        $publishingInstance = $publishingInstance.Trim()
    }
    $appPoolIdleTimeout = $config.InstallSettings.WebServer.CMServerSettings.Publishing.AppPoolIdleTimeout
    if (!([string]::IsNullOrEmpty($appPoolIdleTimeout)))
    {
        $appPoolIdleTimeout = $appPoolIdleTimeout.Trim()
    }
    $publishing | Add-Member -MemberType NoteProperty -Name Enabled -Value (Get-ConfigOption $config "WebServer/CMServerSettings/Publishing/enabled" $TRUE)
    $publishing | Add-Member -MemberType NoteProperty -Name PublishingInstance -Value $publishingInstance
    $publishing | Add-Member -MemberType NoteProperty -Name ApplicationInitializationEnabled -Value (Get-ConfigOption $config "WebServer/CMServerSettings/Publishing/ApplicationInitializationEnabled" $FALSE)
    $publishing | Add-Member -MemberType NoteProperty -Name AppPoolIdleTimeout -Value $appPoolIdleTimeout
    $publishing | Add-Member -MemberType NoteProperty -Name DisableScheduledTaskExecution -Value (Get-ConfigOption $config "WebServer/CMServerSettings/Publishing/DisableScheduledTaskExecution")
    $publishing | Add-Member -MemberType NoteProperty -Name Parallel -Value $parallel

    $processing = New-Object -TypeName PSObject
    $processing | Add-Member -MemberType NoteProperty -Name Enabled -Value (Get-ConfigOption $config "WebServer/CMServerSettings/Processing/enabled" $TRUE)
    $processing | Add-Member -MemberType NoteProperty -Name ApplyIPWhitelist -Value (Get-ConfigOption $config "WebServer/CMServerSettings/Processing/ApplyIPWhitelist")
    $processing | Add-Member -MemberType NoteProperty -Name DeactivateConnectionStrings -Value (Get-ConfigOption $config "WebServer/CMServerSettings/Processing/DeactivateConnectionStrings")
    $processing | Add-Member -MemberType NoteProperty -Name ConfigureFilesForProcessing -Value (Get-ConfigOption $config "WebServer/CMServerSettings/Processing/ConfigureFilesForProcessing")
    $processing | Add-Member -MemberType NoteProperty -Name PreventAnonymousAccess -Value (Get-ConfigOption $config "WebServer/CMServerSettings/Processing/PreventAnonymousAccess")

    $cmServerSettings = New-Object -TypeName PSObject
    $adminPassword = $config.InstallSettings.WebServer.CMServerSettings.DefaultSitecoreAdminPassword
    if (!([string]::IsNullOrEmpty($adminPassword)))
    {
        $adminPassword = $adminPassword.Trim()
    }
    $cmServerSettings | Add-Member -MemberType NoteProperty -Name AddTelerikEncryptionKey -Value $FALSE
    $telerikEncryptionKey = $config.InstallSettings.WebServer.CMServerSettings.TelerikEncryptionKey
    if (!([string]::IsNullOrEmpty($telerikEncryptionKey)))
    {
        $telerikEncryptionKey = $telerikEncryptionKey.Trim()
        $cmServerSettings.AddTelerikEncryptionKey = $TRUE
    }
    $cmServerSettings | Add-Member -MemberType NoteProperty -Name TelerikEncryptionKey -Value $telerikEncryptionKey
    $cmServerSettings | Add-Member -MemberType NoteProperty -Name Enabled -Value (Get-ConfigOption $config "WebServer/CMServerSettings/enabled" $TRUE)
    $cmServerSettings | Add-Member -MemberType NoteProperty -Name DefaultSitecoreAdminPassword -Value $adminPassword
    $cmServerSettings | Add-Member -MemberType NoteProperty -Name Publishing -Value $publishing
    $cmServerSettings | Add-Member -MemberType NoteProperty -Name Processing -Value $processing
    #endregion

    #region CDServerSettings
    $cdServerSettings = New-Object -TypeName PSObject
    $cdServerSettings | Add-Member -MemberType NoteProperty -Name Enabled -Value (Get-ConfigOption $config "WebServer/CDServerSettings/enabled" $TRUE)
    $cdServerSettings | Add-Member -MemberType NoteProperty -Name ApplyIPWhitelist -Value (Get-ConfigOption $config "WebServer/CDServerSettings/ApplyIPWhitelist")
    $cdServerSettings | Add-Member -MemberType NoteProperty -Name DeactivateConnectionStrings -Value (Get-ConfigOption $config "WebServer/CDServerSettings/DeactivateConnectionStrings")
    $cdServerSettings | Add-Member -MemberType NoteProperty -Name ConfigureFilesForCD -Value (Get-ConfigOption $config "WebServer/CDServerSettings/ConfigureFilesForCD")
    $cdServerSettings | Add-Member -MemberType NoteProperty -Name PreventAnonymousAccess -Value (Get-ConfigOption $config "WebServer/CDServerSettings/PreventAnonymousAccess")
    $cdServerSettings | Add-Member -MemberType NoteProperty -Name DenyExecutePermission -Value (Get-ConfigOption $config "WebServer/CDServerSettings/DenyExecutePermission")
    $cdServerSettings | Add-Member -MemberType NoteProperty -Name DisableUploadWatcher -Value (Get-ConfigOption $config "WebServer/CDServerSettings/DisableUploadWatcher")
    $cdServerSettings | Add-Member -MemberType NoteProperty -Name DisableExperienceAnalyticsAssemblies -Value (Get-ConfigOption $config "WebServer/CDServerSettings/DisableExperienceAnalyticsAssemblies")
    $cdServerSettings | Add-Member -MemberType NoteProperty -Name RemovePhantomJs -Value (Get-ConfigOption $config "WebServer/CDServerSettings/RemovePhantomJs")
    $cdServerSettings | Add-Member -MemberType NoteProperty -Name DisableTelerikControls -Value (Get-ConfigOption $config "WebServer/CDServerSettings/DisableTelerikControls")
    #endregion

    #region MediaRequestProtection
    $mediaRequestProtection = New-Object -TypeName PSObject
    
    $sharedSecret = ""
    if (!([string]::IsNullOrEmpty($config.InstallSettings.WebServer.MediaRequestProtection.SharedSecret)))
    {
        $sharedSecret = $config.InstallSettings.WebServer.MediaRequestProtection.SharedSecret.Trim()
    }
    $mediaRequestLogging = ""
    if (!([string]::IsNullOrEmpty($config.InstallSettings.WebServer.MediaRequestProtection.LoggingEnabled)))
    {
        $mediaRequestLogging = Get-ConfigOption $config "WebServer/MediaRequestProtection/LoggingEnabled"
    }
    $mediaRequestProtection | Add-Member -MemberType NoteProperty -Name SharedSecret -Value $sharedSecret
    $mediaRequestProtection | Add-Member -MemberType NoteProperty -Name LoggingEnabled -Value $mediaRequestLogging
    #endregion

    #region IPWhiteList
    $ipWhiteList = New-Object 'System.Collections.Generic.List[string]'
    foreach ($ip in ($config.InstallSettings.WebServer.IPWhiteList.IP))
    {
        $ipValue = $ip
        if (!([string]::IsNullOrEmpty($ipValue)))
        {
            $ipValue = $ipValue.Trim()
        }

        $ipWhiteList.Add($ipValue)
    }

    #endregion

    #region SessionStateProvider
    $sessionStateProvider = New-Object -TypeName PSObject

    $private = $config.InstallSettings.WebServer.SessionStateProvider.Private
    if (!([string]::IsNullOrEmpty($private)))
    {
        $private = $private.Trim()
    }
    $shared = $config.InstallSettings.WebServer.SessionStateProvider.Shared
    if (!([string]::IsNullOrEmpty($shared)))
    {
        $shared = $shared.Trim()
    }

    $sessionStateProvider | Add-Member -MemberType NoteProperty -Name Private -Value $private
    $sessionStateProvider | Add-Member -MemberType NoteProperty -Name Shared -Value $shared
    #endregion

    #region Solr
    $solr = New-Object -TypeName PSObject

    $serviceBaseAddress = $config.InstallSettings.WebServer.Solr.ServiceBaseAddress
    if (!([string]::IsNullOrEmpty($serviceBaseAddress)))
    {
        $serviceBaseAddress = $serviceBaseAddress.Trim()
    }

    $solr | Add-Member -MemberType NoteProperty -Name ServiceBaseAddress -Value $serviceBaseAddress
    #endregion

    #region AzureConfig
    $azure = New-Object -TypeName PSObject

    $serverAddress = $config.InstallSettings.Database.SqlServerName
    if (!([string]::IsNullOrEmpty($serverAddress)))
    {
        $serverAddress = $serverAddress.Trim()
    }

    $sqlPackageDir = $config.InstallSettings.Database.Azure.SQLPackagePath
    $sqlEdition = $config.InstallSettings.Database.Azure.SQLEdition
    $sqlSize = $config.InstallSettings.Database.Azure.SQLMaxSize
    $sqlObjective = $config.InstallSettings.Database.Azure.SQLServiceObjective
    $sqlResourceGroup = $config.Installsettings.Database.Azure.SQLResourceGroup

    $azure | Add-Member -MemberType NoteProperty -Name ServerAddress -Value $serverAddress
    $azure | Add-Member -MemberType NoteProperty -Name SqlPackagePath -Value $sqlPackageDir
    $azure | Add-Member -MemberType NoteProperty -Name Edition -Value $sqlEdition
    $azure | Add-Member -MemberType NoteProperty -Name MaxSize -Value $sqlSize
    $azure | Add-Member -MemberType NoteProperty -Name ServiceObjective -Value $sqlObjective
    $azure | Add-Member -MemberType NoteProperty -Name ResourceGroup -Value $sqlResourceGroup

    
    #endregion

    #region MongoDb
    $credentials = New-Object -TypeName PSObject
    $username = $config.InstallSettings.WebServer.MongoDb.Credentials.Username
    if (!([string]::IsNullOrEmpty($username)))
    {
        $username = $username.Trim()
    }
    $password = $config.InstallSettings.WebServer.MongoDb.Credentials.Password
    if (!([string]::IsNullOrEmpty($password)))
    {
        $password = $password.Trim()
    }
    $credentials | Add-Member -MemberType NoteProperty -Name Username -Value $username
    $credentials | Add-Member -MemberType NoteProperty -Name Password -Value $password

    $hosts = New-Object 'System.Collections.Generic.List[PSObject]'
    foreach ($mongohost in ($config.InstallSettings.WebServer.MongoDb.Hosts.Host))
    {
        $h = New-Object -TypeName PSObject

        $hostname = $mongohost.HostName
        if (!([string]::IsNullOrEmpty($hostname)))
        {
            $hostname = $hostname.Trim()
        }
        [int]$port = $mongohost.Port

        $h | Add-Member -MemberType NoteProperty -Name HostName -Value $hostname
        $h | Add-Member -MemberType NoteProperty -Name Port -Value $port

        $hosts.Add($h)
    }

    $mongodb = New-Object -TypeName PSObject
    $options = $config.InstallSettings.WebServer.MongoDb.Options
    if (!([string]::IsNullOrEmpty($options)))
    {
        $options = $options.Trim()
    }
    $mongodb | Add-Member -MemberType NoteProperty -Name Enabled -Value (Get-ConfigOption $config "WebServer/MongoDb/enabled" $TRUE)
    $mongodb | Add-Member -MemberType NoteProperty -Name Credentials -Value $credentials
    $mongodb | Add-Member -MemberType NoteProperty -Name Hosts -Value $hosts
    $mongodb | Add-Member -MemberType NoteProperty -Name Options -Value $options
    #endregion

    $webserver = New-Object -TypeName PSObject

    $licenseFilePath = $config.InstallSettings.WebServer.LicenseFilePath
    if (!([string]::IsNullOrEmpty($licenseFilePath)))
    {
        $licenseFilePath = $licenseFilePath.Trim()
    }
    $sitecoreInstallRoot = $config.InstallSettings.WebServer.SitecoreInstallRoot
    if (!([string]::IsNullOrEmpty($sitecoreInstallRoot)))
    {
        $sitecoreInstallRoot = $sitecoreInstallRoot.Trim()
    }
    $sitecoreInstallFolder = $config.InstallSettings.WebServer.SitecoreInstallFolder
    if (!([string]::IsNullOrEmpty($sitecoreInstallFolder)))
    {
        $sitecoreInstallFolder = $sitecoreInstallFolder.Trim()
    }
    $sitecoreInstanceName = $config.InstallSettings.WebServer.SitecoreInstanceName
    if (!([string]::IsNullOrEmpty($sitecoreInstanceName)))
    {
        $sitecoreInstanceName = $sitecoreInstanceName.Trim()
    }
    $reportingApiKey = $config.InstallSettings.WebServer.ReportingApiKey
    if (!([string]::IsNullOrEmpty($reportingApiKey)))
    {
        $reportingApiKey = $reportingApiKey.Trim()
    }    
    $passwordHashAlgorithm = $config.InstallSettings.WebServer.PasswordHashAlgorithm
    if (!([string]::IsNullOrEmpty($passwordHashAlgorithm)))
    {
        $passwordHashAlgorithm = $passwordHashAlgorithm.Trim()
    }
    $lastChildFolderOfIncludeDirectory = $config.InstallSettings.WebServer.LastChildFolderOfIncludeDirectory
    if (!([string]::IsNullOrEmpty($lastChildFolderOfIncludeDirectory)))
    {
        $lastChildFolderOfIncludeDirectory = $lastChildFolderOfIncludeDirectory.Trim()
    }
    $iisWebSiteName = $config.InstallSettings.WebServer.IISWebSiteName
    if (!([string]::IsNullOrEmpty($iisWebSiteName)))
    {
        $iisWebSiteName = $iisWebSiteName.Trim()
    }
    $defaultRuntimeVersion = $config.InstallSettings.WebServer.DefaultRuntimeVersion
    if (!([string]::IsNullOrEmpty($defaultRuntimeVersion)))
    {
        $defaultRuntimeVersion = $defaultRuntimeVersion.Trim()
    }
    $appPoolIdentity = $config.InstallSettings.WebServer.AppPoolIdentity
    if (!([string]::IsNullOrEmpty($appPoolIdentity)))
    {
        $appPoolIdentity = $appPoolIdentity.Trim()
    }
    $appPoolIdentityPassword = $config.InstallSettings.WebServer.AppPoolIdentityPassword
    if (!([string]::IsNullOrEmpty($appPoolIdentityPassword)))
    {
        $appPoolIdentityPassword = $appPoolIdentityPassword.Trim()
    }

    $webserver | Add-Member -MemberType NoteProperty -Name LicenseFilePath -Value $licenseFilePath
    $webserver | Add-Member -MemberType NoteProperty -Name SitecoreInstallRoot -Value $sitecoreInstallRoot
    $webserver | Add-Member -MemberType NoteProperty -Name SitecoreInstallFolder -Value $sitecoreInstallFolder
    $webserver | Add-Member -MemberType NoteProperty -Name SitecoreInstanceName -Value $sitecoreInstanceName
    $webserver | Add-Member -MemberType NoteProperty -Name ReportingApiKey -Value $reportingApiKey    
    $webserver | Add-Member -MemberType NoteProperty -Name PasswordHashAlgorithm -Value $passwordHashAlgorithm
    $webserver | Add-Member -MemberType NoteProperty -Name LastChildFolderOfIncludeDirectory -Value $lastChildFolderOfIncludeDirectory
    $webserver | Add-Member -MemberType NoteProperty -Name EncryptConnectionStrings -Value (Get-ConfigOption $config "WebServer/EncryptConnectionStrings")
    $webserver | Add-Member -MemberType NoteProperty -Name IISWebSiteName -Value $iisWebSiteName
    $webserver | Add-Member -MemberType NoteProperty -Name DefaultRuntimeVersion -Value $defaultRuntimeVersion
    $webserver | Add-Member -MemberType NoteProperty -Name AppPoolIdentity -Value $appPoolIdentity
    $webserver | Add-Member -MemberType NoteProperty -Name AppPoolIdentityPassword -Value $appPoolIdentityPassword
    $webserver | Add-Member -MemberType NoteProperty -Name IISBindings -Value $iisbindings
    $webserver | Add-Member -MemberType NoteProperty -Name Analytics -Value $analytics
    $webserver | Add-Member -MemberType NoteProperty -Name CMServerSettings -Value $cmServerSettings
    $webserver | Add-Member -MemberType NoteProperty -Name CDServerSettings -Value $cdServerSettings
    $webserver | Add-Member -MemberType NoteProperty -Name IPWhiteList -Value $ipWhiteList
    $webserver | Add-Member -MemberType NoteProperty -Name SessionStateProvider -Value $sessionStateProvider
    $webserver | Add-Member -MemberType NoteProperty -Name Solr -Value $solr
    $webserver | Add-Member -MemberType NoteProperty -Name Azure -Value $azure
    $webserver | Add-Member -MemberType NoteProperty -Name MongoDb -Value $mongodb
    $webserver | Add-Member -MemberType NoteProperty -Name MediaRequestProtection -Value $mediaRequestProtection
    #endregion

    #region Database

    #region DatabaseNames
    $databases = New-Object 'System.Collections.Generic.List[PSObject]'
    foreach ($dbname in ($config.InstallSettings.Database.DatabaseNames.name))
    {
        $db = New-Object -TypeName PSObject

        $name = $dbname
        if (!([string]::IsNullOrEmpty($name)))
        {
            $name = $name.Trim()
        }

        $db | Add-Member -MemberType NoteProperty -Name Name -Value $name
        $db | Add-Member -MemberType NoteProperty -Name ConnectionStringName -Value $name.ToLower()
        $db | Add-Member -MemberType NoteProperty -Name Type -Value $config.InstallSettings.Database.type
        $databases.Add($db)
    }
    #endregion

    #region WebDatabaseCopies
    $webDatabaseCopies = New-Object 'System.Collections.Generic.List[PSObject]'
    foreach ($copy in ($config.InstallSettings.Database.WebDatabaseCopies.copy))
    {
        $db = New-Object -TypeName PSObject

        if ($copy.GetType().Name -eq "String")
        {
            $copyname = $copy
        }
        else
        {
            $copyname = $copy.InnerText
        }

        if (!([string]::IsNullOrEmpty($copyname)))
        {
            $copyname = $copyname.Trim()
        }

        $connectionStringName = $copy.connectionStringName
        if ([string]::IsNullOrEmpty($connectionStringName))
        {
            $connectionStringName = $copyname.ToLower()
        }
        else
        {
            $connectionStringName = $connectionStringName.Trim()
        }

        $db | Add-Member -MemberType NoteProperty -Name Name -Value $copyname
        $db | Add-Member -MemberType NoteProperty -Name ConnectionStringName -Value $connectionStringName
        $webDatabaseCopies.Add($db)
    }
    #endregion

    #region DatabaseInstallPath
    $databaseInstallPath = New-Object -TypeName PSObject

    $dataFiles = New-Object -TypeName PSObject
    $local = $config.InstallSettings.Database.DatabaseInstallPath.DataFiles.Local
    if (!([string]::IsNullOrEmpty($local)))
    {
        $local = $local.Trim()
    }
    $unc = $config.InstallSettings.Database.DatabaseInstallPath.DataFiles.Unc
    if (!([string]::IsNullOrEmpty($unc)))
    {
        $unc = $unc.Trim()
    }
    $dataFiles | Add-Member -MemberType NoteProperty -Name Local -Value $local
    $dataFiles | Add-Member -MemberType NoteProperty -Name Unc -Value $unc

    $logFiles = New-Object -TypeName PSObject
    $local = $config.InstallSettings.Database.DatabaseInstallPath.LogFiles.Local
    if (!([string]::IsNullOrEmpty($local)))
    {
        $local = $local.Trim()
    }
    $unc = $config.InstallSettings.Database.DatabaseInstallPath.LogFiles.Unc
    if (!([string]::IsNullOrEmpty($unc)))
    {
        $unc = $unc.Trim()
    }
    $logFiles | Add-Member -MemberType NoteProperty -Name Local -Value $local
    $logFiles | Add-Member -MemberType NoteProperty -Name Unc -Value $unc

    $databaseInstallPath | Add-Member -MemberType NoteProperty -Name DataFiles -Value $datafiles
    $databaseInstallPath | Add-Member -MemberType NoteProperty -Name LogFiles -Value $logfiles
    #endregion

    $database = New-Object -TypeName PSObject

    $sqlServerName = $config.InstallSettings.Database.SqlServerName
    if (!([string]::IsNullOrEmpty($sqlServerName)))
    {
        $sqlServerName = $sqlServerName.Trim()
    }
    $sqlLoginForInstall = $config.InstallSettings.Database.SqlLoginForInstall
    if (!([string]::IsNullOrEmpty($sqlLoginForInstall)))
    {
        $sqlLoginForInstall = $sqlLoginForInstall.Trim()
    }
    $sqlLoginForInstallPassword = $config.InstallSettings.Database.SqlLoginForInstallPassword
    if (!([string]::IsNullOrEmpty($sqlLoginForInstallPassword)))
    {
        $sqlLoginForInstallPassword = $sqlLoginForInstallPassword.Trim()
    }
    $sqlLoginForDataAccess = $config.InstallSettings.Database.SqlLoginForDataAccess
    if (!([string]::IsNullOrEmpty($sqlLoginForDataAccess)))
    {
        $sqlLoginForDataAccess = $sqlLoginForDataAccess.Trim()
    }
    $sqlLoginForDataAccessPassword = $config.InstallSettings.Database.SqlLoginForDataAccessPassword
    if (!([string]::IsNullOrEmpty($sqlLoginForDataAccessPassword)))
    {
        $sqlLoginForDataAccessPassword = $sqlLoginForDataAccessPassword.Trim()
    }
    $databaseNamePrefix = $config.InstallSettings.Database.DatabaseNamePrefix
    if (!([string]::IsNullOrEmpty($databaseNamePrefix)))
    {
        $databaseNamePrefix = $databaseNamePrefix.Trim()
    }


    $databaseType = $config.InstallSettings.Database.type
    if (!([string]::IsNullOrEmpty($databaseType)))
    {
        $databaseType = $databaseType.Trim()
    }

    
    $database | Add-Member -MemberType NoteProperty -Name Enabled -Value (Get-ConfigOption $config "Database/enabled" $TRUE)
    $database | Add-Member -MemberType NoteProperty -Name InstallDatabase -Value (Get-ConfigOption $config "Database/InstallDatabase")
    $database | Add-Member -MemberType NoteProperty -Name Databases -Value $databases
    $database | Add-Member -MemberType NoteProperty -Name WebDatabaseCopies -Value $webDatabaseCopies
    $database | Add-Member -MemberType NoteProperty -Name SqlServerName -Value $sqlServerName
    $database | Add-Member -MemberType NoteProperty -Name SqlLoginForInstall -Value $sqlLoginForInstall
    $database | Add-Member -MemberType NoteProperty -Name SqlLoginForInstallPassword -Value $sqlLoginForInstallPassword
    $database | Add-Member -MemberType NoteProperty -Name SqlLoginForDataAccess -Value $sqlLoginForDataAccess
    $database | Add-Member -MemberType NoteProperty -Name SqlLoginForDataAccessPassword -Value $sqlLoginForDataAccessPassword
    $database | Add-Member -MemberType NoteProperty -Name UseWindowsAuthenticationForSqlDataAccess -Value (Get-ConfigOption $config "Database/UseWindowsAuthenticationForSqlDataAccess")
    $database | Add-Member -MemberType NoteProperty -Name DatabaseInstallPath -Value $databaseInstallPath
    $database | Add-Member -MemberType NoteProperty -Name DatabaseNamePrefix -Value $databaseNamePrefix
    $database | Add-Member -MemberType NoteProperty -Name Type -Value $databaseType
    #endregion

    $script:configSettings = New-Object -TypeName PSObject

    $logFileName = $config.InstallSettings.LogFileName
    if (!([string]::IsNullOrEmpty($logFileName)))
    {
        $logFileName = $logFileName.Trim()
    }
    $sitecoreZipPath = $config.InstallSettings.SitecoreZipPath
    if (!([string]::IsNullOrEmpty($sitecoreZipPath)))
    {
        $sitecoreZipPath = $sitecoreZipPath.Trim()
    }
    $sitecoreConfigSpreadsheetPath = $config.InstallSettings.SitecoreConfigSpreadsheetPath
    if (!([string]::IsNullOrEmpty($sitecoreConfigSpreadsheetPath)))
    {
        $sitecoreConfigSpreadsheetPath = $sitecoreConfigSpreadsheetPath.Trim()
    }

    $script:configSettings | Add-Member -MemberType NoteProperty -Name LogFileName -Value $logFileName            
    $script:configSettings | Add-Member -MemberType NoteProperty -Name SitecoreZipPath -Value $sitecoreZipPath
    $script:configSettings | Add-Member -MemberType NoteProperty -Name SitecoreConfigSpreadsheetPath -Value $sitecoreConfigSpreadsheetPath
    $script:configSettings | Add-Member -MemberType NoteProperty -Name SuppressPrompts -Value (Get-ConfigOption $config "SuppressPrompts")
    $script:configSettings | Add-Member -MemberType NoteProperty -Name WebServer -Value $webserver
    $script:configSettings | Add-Member -MemberType NoteProperty -Name Database -Value $database
    $script:configSettings | Add-Member -MemberType NoteProperty -Name Azure -Value $azure
}
#endregion

#region Sanity Checks
function Test-Module([string]$name)
{
    if(-not(Get-Module -name $name))
    {
        if(Get-Module -ListAvailable | Where-Object { $_.name -eq $name })
        {
            Write-Message "Importing $name module." "Gray" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            Import-Module -Name $name -DisableNameChecking
            Write-Message "`n" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            $TRUE
        }
        else
        {
            $FALSE
        } 
    }
    else
    {
        Write-Message "$name module is already imported.`n" "Gray" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        $TRUE
    }
}

function Test-PreRequisites
{
    Write-Message "Testing script pre-requisites." "Gray" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )))
    {
        Write-Message "Warning: PowerShell must run as an Administrator." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    if ($script:configSettings.Database.Enabled)
    {
        $moduleName = "SQLPS"
        if (!(Test-Module $moduleName))
        {
            Write-Message "Warning: SQL PowerShell Module ($moduleName) is not installed." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
        else
        {
            Set-Location -Path $scriptDir
        }

        if($script:configSettings.Database.Type -eq "Azure")
        {
            $moduleName = "AzureRM.sql"
            if (!(Test-Module $moduleName))
            {
                Write-Message "Warning: SQL PowerShell Module ($moduleName) is not installed." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
                return $FALSE
            }
            else
            {
                Set-Location -Path $scriptDir
            }
        }
    }

    $moduleName = "WebAdministration"
    if (!(Test-Module $moduleName))
    {
        Write-Message "Warning: IIS PowerShell Module ($moduleName) is not installed." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    if(Test-ApplicationInitializationSetting)
    {
        $moduleName = "Servermanager"
        if (!(Test-Module $moduleName))
        {
            Write-Message "Warning: IIS PowerShell Module ($moduleName) is not installed." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
    }

    $versionToInstall = Get-SitecoreVersion -GetFromZip
    if ($versionToInstall -eq "10.0")
    {
        $moduleName = "ImportExcel"
        if (!(Test-Module $moduleName))
        {
            Write-Message "Warning: Import-Excel Module ($moduleName) is not installed." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
    }

    return $TRUE
}

function Test-SqlLoginConfiguration
{
    $login = Get-SqlLoginAccountForDataAccess
    if ($login -eq $null)
    {
        return $FALSE
    }

    return $TRUE
}

function Test-MemberOfRole([string]$memberName, [string]$roleName, [Microsoft.SqlServer.Management.Smo.Server]$sqlServerSmo)
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

function Test-SqlConnectionAndRoles
{
    [Microsoft.SqlServer.Management.Smo.Server]$sqlServerSmo = Get-SqlServerSmo

    try
    {
        # Validate SQL connection can be established
        $sqlServerSmo.ConnectionContext.Connect()

        # Validate server roles for install login: must be sysadmin
        $memberName = $script:configSettings.Database.SqlLoginForInstall
        $isSysAdmin = Test-MemberOfRole $memberName "sysadmin" $sqlServerSmo
        if (!$isSysAdmin)
        {
            Write-Message "$memberName doesn't have required server roles in SQL" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            Write-Message "Grant the sysadmin role to $memberName" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }

        # Validate data access login exists
        $loginName = Get-SqlLoginAccountForDataAccess
        if ($sqlServerSmo.Logins[$loginName] -eq $null)
        {
            Write-Message "Could not find a login called $loginName on SQL server" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }

        return $TRUE
    }
    catch [Exception]
    {
        Write-Message ($_.Exception) "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }
}

function Test-SqlPermissionForPath([string]$path)
{

    # Check that SQL has correct rights over install path, else Database Attach will fail
    [Microsoft.SqlServer.Management.Smo.Server]$sqlServerSmo = Get-SqlServerSmo        
    $user = $sqlServerSmo.SqlDomainGroup
    $acl = Get-Acl $path
    $isCorrectRights = $acl.Access | Where {($_.IdentityReference -eq $user) -and ($_.FileSystemRights -eq "FullControl")}
    if($isCorrectRights)
    {
        return $TRUE
    }  
    else
    {
        Write-Message "SQL doesn't appear to have enough rights for the install path." "Yellow" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        Write-Message "This might be because SQL is using builtin virtual service accounts, which are local accounts that exist on a different server than the Sitecore server. If this is true, you may IGNORE this message." "Yellow" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        Write-Message "Ensure that the SQL service for your SQL instance has FullControl of $path" "Yellow" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        Write-Message "Failure to do so will PREVENT the databases from attaching.`n" "Yellow" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable

        if ($script:configSettings.SuppressPrompts)
        {
            return $TRUE
        }
        else
        {
            $shell = new-object -comobject "WScript.Shell"
            $result = $shell.popup("Do you wish to proceed?",0,"Question",4+32)
            # $result will be 6 for yes, 7 for no.
            if ($result -eq 6)
            {
                return $TRUE
            }
        }
    }

    return $FALSE
}

function Test-ScriptPermissionForPath([string]$path)
{
    $uri = New-Object System.Uri($path)
    $split = $path.Split('\')
    $computer = $uri.host
    $share = $split[$split.Count-1]
    $scriptIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().Name

    try
    {
        $sharedSecurity = Get-WMIObject -Class Win32_LogicalShareSecuritySetting -Filter "name='$share'"  -ComputerName $computer
        $secdesc = $sharedSecurity.GetSecurityDescriptor().Descriptor
        foreach($ace in $secdesc.DACL)
        {
            $userName = $ace.Trustee.Name
            If ($ace.Trustee.Domain -ne $Null) {$userName = "$($ace.Trustee.Domain)\$UserName"}
            If ($ace.Trustee.Name -eq $Null) {$userName = $ace.Trustee.SIDString }
            if ($userName -ne $scriptIdentity) { continue }

            [Array]$accessRules += New-Object Security.AccessControl.FileSystemAccessRule($UserName, $ace.AccessMask, $ace.AceType)
            foreach($rule in $accessRules)
            {                
                if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow)
                {
                    if (($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) -eq [System.Security.AccessControl.FileSystemRights]::Modify)
                    {
                        return $TRUE
                    }
                }
            }
        }
    }
    catch
    {
        Write-Message "Unable to obtain permissions for $share" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }


    Write-Message "The script identity [$scriptIdentity] doesn't have 'Modify' rights for the UNC path [$path]" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
    return $FALSE
}

function Test-SqlInstallPaths
{
    $installPaths = New-Object 'System.Collections.Generic.List[PSObject]'
    $installPath = New-Object -TypeName PSObject
    $installPath | Add-Member -MemberType NoteProperty -Name Path -Value (Get-DatabaseInstallFolderPath -FileType DataFiles)
    $installPath | Add-Member -MemberType NoteProperty -Name IsLocalPath -Value ([string]::IsNullOrEmpty($script:configSettings.Database.DatabaseInstallPath.DataFiles.Unc))
    $installPaths.Add($installPath)
    $installPath = New-Object -TypeName PSObject
    $installPath | Add-Member -MemberType NoteProperty -Name Path -Value (Get-DatabaseInstallFolderPath -FileType LogFiles)
    $installPath | Add-Member -MemberType NoteProperty -Name IsLocalPath -Value ([string]::IsNullOrEmpty($script:configSettings.Database.DatabaseInstallPath.LogFiles.Unc))
    $installPaths.Add($installPath)

    if ($installPaths[1].Path.Length -eq 0)
    {
        $installPaths.RemoveAt(1)
    }

    $testResult = $TRUE
    foreach ($path in $installPaths)
    {
        if (!(Test-SqlPermissionForPath $path.Path))
        {
            $testResult = $FALSE
            break
        }

        if (!$path.IsLocalPath -and !(Test-ScriptPermissionForPath $path.Path))
        {
            $testResult = $FALSE
            break
        }
    }

    return $testResult
}

function Test-WebDatabseCopyNames
{
    $dbCopies = $script:configSettings.Database.WebDatabaseCopies

    if ($dbCopies.Count -ne ($dbCopies | Select Name -Unique | measure).Count)
    {
        Write-Message "The name of a web database copy was repeated in the config file." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    if ($dbCopies.Count -ne ($dbCopies | Select ConnectionStringName -Unique | measure).Count)
    {
        Write-Message "The value of the connectionStringName attribute for a web database copy was repeated in the config file." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    if ($dbCopies | Where-Object {$_.Name.ToLower() -eq "web"})
    {
        Write-Message "Cannot use 'web' (name is case-insensitive) as the name of a web database copy." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    return $TRUE
}

function Test-IISBindings
{
    foreach ($binding in $script:configSettings.WebServer.IISBindings)
    {
        if ($binding.IP.Length -eq 0)
        {
            Write-Message "Binding must contain a non-empty IP attribute." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }

        if ($binding.IP -ne "*" -and !([bool]($binding.IP -as [ipaddress])))
        {
            Write-Message "Binding's IP attribute must either be a valid IP or the '*' character." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }

        if ($binding.Port.Length -eq 0)
        {
            Write-Message "Binding must contain a non-empty Port attribute." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }

        if ($binding.Port -lt 1 -or $binding.Port -gt 65535)
        {
            Write-Message "Binding Port must be in the range 1-65535." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
    }

    return $TRUE
}

function Test-PublishingServerRole
{
    if ($script:configSettings.WebServer.CMServerSettings.Enabled)
    {    
        return ($script:configSettings.WebServer.CMServerSettings.Publishing.Enabled)            
    }
    return $FALSE
}

function Test-ApplicationInitializationSetting
{
    if (Test-PublishingServerRole)
    {    
        return ($script:configSettings.WebServer.CMServerSettings.Publishing.ApplicationInitializationEnabled)            
    }
    return $FALSE
}

function Test-ProcessingServerRole
{
    if ($script:configSettings.WebServer.CMServerSettings.Enabled)
    {    
        return ($script:configSettings.WebServer.CMServerSettings.Processing.Enabled)            
    }
    return $FALSE
}

function Test-SupportedSitecoreVersion
{
    $versionToInstall = Get-SitecoreVersion -GetFromZip

    if ($versionToInstall -eq "8.0" `
    -or $versionToInstall -eq "8.1" `
    -or $versionToInstall -eq "10.0")
    {
        return $TRUE
    }

    return $FALSE
}

function Test-MongoDbConfiguration
{
    if ($script:configSettings.WebServer.MongoDb.Enabled)
    {
        $username = $script:configSettings.WebServer.MongoDb.Credentials.Username
        $password = $script:configSettings.WebServer.MongoDb.Credentials.Password        
        if (!([string]::IsNullOrEmpty($username)))
        {
            if ([string]::IsNullOrEmpty($password))
            {
                Write-Message "A username was given without a password for MongoDB. The password cannot be blank." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
                return $FALSE
            }
        }

        if (!([string]::IsNullOrEmpty($password)))
        {
            if ([string]::IsNullOrEmpty($username))
            {
                Write-Message "A password was given without a username for MongoDB. The username cannot be blank." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
                return $FALSE
            }
        }
        
        $numhosts = 0
        foreach ($mongohost in $script:configSettings.WebServer.MongoDb.Hosts)
        {
            if ($mongohost.HostName.Length -eq 0)
            {
                Write-Message "MongoDB HostName must cannot be empty." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
                return $FALSE
            }
            else
            {
                $numhosts++
            }

            if ($mongohost.Port -lt 1 -or $mongohost.Port -gt 65535)
            {
                Write-Message "MongoDB host Port must be in the range 1-65535." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
                return $FALSE
            }
        }

        if ($numhosts -lt 1)
        {
            Write-Message "MongoDB requies at least one Host to be specified." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
    }

    return $TRUE
}

function Test-SessionStateConfiguration
{
    if ($script:configSettings.WebServer.CMServerSettings.Enabled)
    {
        if ($script:configSettings.WebServer.SessionStateProvider.Shared.ToLower() -ne "inproc")
        {
            Write-Message "Out of proc shared session state providers are not supported on CMs. You must use the inproc provider." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
    }

    $sessionStateProvider = $script:configSettings.WebServer.SessionStateProvider.Private.ToLower()
    if ($sessionStateProvider -eq "mongo")
    {
        Write-Message "Mongo is not currently supported by installer for a private SessionStateProvider" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }
    elseif ($sessionStateProvider -ne "inproc" -and $sessionStateProvider -ne "mssql")
    {
        Write-Message "Private SessionStateProvider selection is not recognized" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    $sessionStateProvider = $script:configSettings.WebServer.SessionStateProvider.Shared.ToLower()
    if ($sessionStateProvider -eq "mongo")
    {
        Write-Message "Mongo is not currently supported by installer for a shared SessionStateProvider" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }
    elseif ($sessionStateProvider -ne "inproc" -and $sessionStateProvider -ne "mssql")
    {
        Write-Message "Shared SessionStateProvider selection is not recognized" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    return $TRUE
}

function Test-ShouldSetAutogrowth
{
    if ($script:configSettings.WebServer.CMServerSettings.Publishing.Enabled -and $script:configSettings.WebServer.CMServerSettings.Publishing.Parallel.Enabled)
    {
        return $TRUE
    }

    return $FALSE
}

function Test-ConfigurationSettings
{
    if ([string]::IsNullOrEmpty($script:configSettings.SitecoreZipPath))
    {
        Write-Message "SitecoreZipPath cannot be null or empty" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }
    else
    {
        if (!(Test-Path $script:configSettings.SitecoreZipPath))
        {
            Write-Message "Couldn't find a file specified by SitecoreZipPath" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }

        if (!(Test-SupportedSitecoreVersion))
        {
            Write-Message "The version of Sitecore you are attempting to install is not supported." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
    }

    [decimal]$versionToInstall = Get-SitecoreVersion -GetFromZip
    if ($versionToInstall -ge 10.0)
    {
        if ([string]::IsNullOrEmpty($script:configSettings.SitecoreConfigSpreadsheetPath))
        {
            Write-Message "SitecoreConfigSpreadsheetPath cannot be null or empty" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
        else
        {
            if (!(Test-Path $script:configSettings.SitecoreConfigSpreadsheetPath))
            {
                Write-Message "Couldn't find file specified by SitecoreConfigSpreadsheetPath" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
                return $FALSE
            }
        }

        if (![string]::IsNullOrEmpty($script:configSettings.WebServer.ReportingApiKey))
        {
            if ($script:configSettings.WebServer.ReportingApiKey.Length -lt 32)
            {
                Write-Message "ReportingApiKey should have a minimum of 32 characters." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
                return $FALSE
            }
        }
    }

    if ([string]::IsNullOrEmpty($script:configSettings.WebServer.LicenseFilePath))
    {
        Write-Message "LicenseFilePath cannot be null or empty" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }
    else
    {
        if (!(Test-Path $script:configSettings.WebServer.LicenseFilePath))
        {
            Write-Message "Couldn't find a file specified by LicenseFilePath" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
    }

    if ([string]::IsNullOrEmpty($script:configSettings.WebServer.SitecoreInstallRoot))
    {
        Write-Message "SitecoreInstallRoot cannot be null or empty" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    if ([string]::IsNullOrEmpty($script:configSettings.WebServer.SitecoreInstallFolder))
    {
        Write-Message "SitecoreInstallFolder cannot be null or empty" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    if ($script:configSettings.WebServer.EncryptConnectionStrings -and (!(Test-Path (Get-AspNetRegIisPath))))
    {
        Write-Message "Couldn't find aspnet_regiis executable, which is required for encrypting connection strings" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    if ([string]::IsNullOrEmpty($script:configSettings.WebServer.IISWebSiteName))
    {
        Write-Message "IISWebSiteName cannot be null or empty" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    if ([string]::IsNullOrEmpty($script:configSettings.WebServer.DefaultRuntimeVersion))
    {
        Write-Message "DefaultRuntimeVersion cannot be null or empty" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    if ($script:configSettings.WebServer.IISBindings.Count -lt 1)
    {
        Write-Message "IISBindings should provide at least one Binding." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }
    else
    {
        if (!(Test-IISBindings))
        {
            Write-Message "There was a problem with an IIS Binding." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
    }

    if ([string]::IsNullOrEmpty($script:configSettings.WebServer.AppPoolIdentity))
    {
        Write-Message "AppPoolIdentity cannot be null or empty" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }
    elseif ($script:configSettings.WebServer.AppPoolIdentity -ne "ApplicationPoolIdentity" -and $script:configSettings.WebServer.AppPoolIdentity -ne "NetworkService")
    {
        # Validate that input is in the form <domain>\<username>
        $split = $script:configSettings.WebServer.AppPoolIdentity.Split("\")
        if ([string]::IsNullOrEmpty($split[0]) -or [string]::IsNullOrEmpty($split[1]))
        {
            Write-Message "AppPoolIdentity must be of the form <domain>\<username>" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }

        # Validate that we have a password
        if ([string]::IsNullOrEmpty($script:configSettings.WebServer.AppPoolIdentityPassword))
        {
            Write-Message "AppPoolIdentityPassword cannot be null or empty" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
    }
    else
    {
        # Using a built-in account, ensure it will not be used for SQL login
        if ($script:configSettings.Database.UseWindowsAuthenticationForSqlDataAccess)
        {
            Write-Message "Must use a domain account for application pool identity when also using Windows authentication for SQL login" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
    }

    if ($script:configSettings.WebServer.CMServerSettings.Enabled -and $script:configSettings.WebServer.CDServerSettings.Enabled)
    {
        Write-Message "CMServerSettings and CDServerSettings are both enabled. The Sitecore instance cannot be a CM and a CD server at the same time." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    if (!$script:configSettings.WebServer.CMServerSettings.Enabled -and !$script:configSettings.WebServer.CDServerSettings.Enabled)
    {
        Write-Message "Neither CMServerSettings nor CDServerSettings are enabled. You must choose a role for the Sitecore instance." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    if ($script:configSettings.WebServer.CMServerSettings.Enabled)
    {
        if (!([string]::IsNullOrEmpty($script:configSettings.WebServer.CMServerSettings.Publishing.InstanceName)))
        {
            if ([string]::IsNullOrEmpty($script:configSettings.WebServer.SitecoreInstanceName))
            {
                Write-Message "You cannot use a Publishing.InstanceName without also specifying an InstanceName." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
                return $FALSE
            }
        }
    }

    if (!(Test-SessionStateConfiguration))
    {
        Write-Message "There was a problem with the Session State configuration." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    if (!(Test-MongoDbConfiguration))
    {
        Write-Message "There was a problem with the MongoDB configuration." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    if ([string]::IsNullOrEmpty($script:configSettings.Database.SqlServerName))
    {
        Write-Message "SqlServerName cannot be null or empty" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }

    if ($script:configSettings.Database.Enabled)
    {
        if ([string]::IsNullOrEmpty($script:configSettings.Database.SqlLoginForInstall))
        {
            Write-Message "SqlLoginForInstall cannot be null or empty" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
        else
        {
            $split = $script:configSettings.Database.SqlLoginForInstall.Split("\")
            if ($split.Count -eq 2)
            {
                # Validate that input is in the form <domain>\<username>
                if ([string]::IsNullOrEmpty($split[0]) -or [string]::IsNullOrEmpty($split[1]))
                {
                    Write-Message "SqlLoginForInstall must be of the form <domain>\<username>" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
                    return $FALSE
                }
            }
        }

        if ([string]::IsNullOrEmpty($script:configSettings.Database.SqlLoginForInstallPassword))
        {
            Write-Message "SqlLoginForInstallPassword cannot be null or empty" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }

        if ($script:configSettings.Database.InstallDatabase -and $script:configSettings.Database.Type -ne "Azure")
        {
            if ([string]::IsNullOrEmpty($script:configSettings.Database.DatabaseInstallPath.DataFiles.Local))
            {
                Write-Message "DatabaseInstallPath.Local cannot be null or empty" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
                return $FALSE
            }

            if (!(Test-SqlInstallPaths))
            {
                Write-Message "DatabaseInstallPath is not valid." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
                return $FALSE
            }
        }

        if (!(Test-SqlLoginConfiguration))
        {
            Write-Message "The specified combination of accounts will not produce a valid SQL login for data access." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
        if ($script:configSettings.Database.Type -ne "Azure")
        {
            if(!(Test-SqlConnectionAndRoles))
            {
                Write-Message "A problem has been detected with the SQL connection." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
                return $FALSE
            }
        }
    }

    if (!([string]::IsNullOrEmpty($script:configSettings.Database.SqlLoginForDataAccess)))
    {
        if ([string]::IsNullOrEmpty($script:configSettings.Database.SqlLoginForDataAccessPassword))
        {
            Write-Message "SqlLoginForDataAccessPassword cannot be null or empty" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }

        # Validate that login is not a domain account
        $split = $script:configSettings.Database.SqlLoginForDataAccess.Split("\")
        if ($split.Count -eq 2)
        {
            Write-Message "SqlLoginForDataAccess cannot be a domain account" "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
    }

    if (!(Test-WebDatabseCopyNames))
    {
        Write-Message "There is a duplicate name in WebDatabaseCopies. Please remove the entry." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return $FALSE
    }
    
    $folderName = $script:configSettings.WebServer.LastChildFolderOfIncludeDirectory
    if (!([string]::IsNullOrEmpty($folderName)))
    {
        if (!($folderName.StartsWith("z")) -and !($folderName.StartsWith("Z")))
        {
            Write-Message "LastChildFolderOfIncludeDirectory should have a name that guarantees it is the last folder (alphanumerically) in the /App_Config/Include directory. Try prepending one or more 'z' characters to the name." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
    }

    if ($versionToInstall -eq "8.0")
    {
        if ((Test-PublishingServerRole) -or
            ($script:configSettings.WebServer.CDServerSettings.Enabled -and $script:configSettings.WebServer.CDServerSettings.ConfigureFilesForCD))
        {
            if ([string]::IsNullOrEmpty($folderName))
            {
                Write-Message "LastChildFolderOfIncludeDirectory cannot be null or empty." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
                return $FALSE
            }
        }
    }

    if ((Test-PublishingServerRole) -and (Test-ProcessingServerRole))
    {
            Write-Message "Prublishing and Processing are both enabled. The Sitecore instance cannot be a dedicated publishing and processing server at the same time." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
    }

    if (Test-PublishingServerRole)
    {
        if ([string]::IsNullOrEmpty($script:configSettings.WebServer.CMServerSettings.Publishing.PublishingInstance))
        {
            Write-Message "PublishingInstance cannot be null or empty." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }

        [int]$degrees = $null
        if (!([int32]::TryParse($script:configSettings.WebServer.CMServerSettings.Publishing.Parallel.MaxDegreesOfParallelism, [ref]$degrees)))
        {
            Write-Message "MaxDegreesOfParallelism must be an integer." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }

        [int]$growthsize = $null
        if (!([int32]::TryParse($script:configSettings.WebServer.CMServerSettings.Publishing.Parallel.WebDatabaseAutoGrowthInMB, [ref]$growthsize)))
        {
            Write-Message "WebDatabaseAutoGrowthInMB must be an integer." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
        elseif ($growthsize -lt 10)
        {
            Write-Message "WebDatabaseAutoGrowthInMB cannot be less than 10MB." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
        elseif ($growthsize -gt 100)
        {
            Write-Message "WebDatabaseAutoGrowthInMB cannot be greater than 100MB." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }

        [int]$timeout = $null
        if ([int32]::TryParse($script:configSettings.WebServer.CMServerSettings.Publishing.AppPoolIdleTimeout, [ref]$timeout))
        {
            if ($timeout -gt 43200)
            {
                Write-Message "AppPoolIdleTimeout must be less than or equal to 43200." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
                return $FALSE
            }
        }
        else
        {
            Write-Message "AppPoolIdleTimeout must be an integer." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
    }

    if (Test-ProcessingServerRole)
    {
        if ($versionToInstall -lt 10.0)
        {
            Write-Message "Script does not support installing a Processing server for this version of Sitecore." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
            return $FALSE
        }
    }
    
    return $TRUE
}
#endregion

#region Main Body
function Copy-DatabaseFiles([string]$zipPath)
{
    $dataFilesFolderPath = Get-DatabaseInstallFolderPath -FileType DataFiles
    $logFilesFolderPath = Get-DatabaseInstallFolderPath -FileType LogFiles

    Write-Message "Extracting database data files from $zipPath to $dataFilesFolderPath" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    Write-Message "Extracting database log files from $zipPath to $logFilesFolderPath" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

    $shell = New-Object -com shell.application
    $item = Find-FolderInZipFile $shell.NameSpace($zipPath).Items() "Databases"
    $dacItem = Find-FolderInZipFile $shell.NameSpace($zipPath).Items() "DACPAC"

    if ($script:configSettings.Database.Type -eq "Azure")
    {
        $destinationFolderPath = Join-Path `
            -Path $dataFilesFolderPath `
            -ChildPath "DACPAC"

        mkdir $destinationFolderPath -ErrorAction SilentlyContinue | Out-Null

        foreach($childItem in $shell.NameSpace($dacItem.Path).Items())
        {
            $childItemName = Split-Path -Path $childItem.Path -Leaf

            $fileName = $childItemName
            if ($childItemName -eq "Sitecore.Analytics.dacpac")
            {
                $fileName =
                    Get-SubstituteDatabaseFileName $childItemName "Reporting"
            }

            $filePath = Join-Path $destinationFolderPath -ChildPath $fileName

            if (Test-Path $filePath)
            {
                Write-Message "$filePath already exists, skipping extraction" "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
            }
            else
            {
                Write-Message `
                    "Extracting $childItemName to $filePath" `
                    "Gray" `
                    -WriteToLog $true `
                    -HostConsoleAvailable $hostScreenAvailable

                $shell.NameSpace($destinationFolderPath).CopyHere($childItem)

                if ($childItemName.ToLower() -like "sitecore.web.*")
                {
                    # Make copies of the web Database as required
                    foreach ($copy in $script:configSettings.Database.WebDatabaseCopies)
                    {
                        $copyName = Get-SubstituteDatabaseFileName `
                            $childItemName `
                            $copy.Name

                        $copyFilePath = Join-Path `
                            -Path $destinationFolderPath `
                            -ChildPath $copyName

                        Write-Message `
                            "Creating $copyName from $filePath" `
                            "Gray" `
                            -WriteToLog $true `
                            -HostConsoleAvailable $hostScreenAvailable

                        Copy-Item $filePath $copyFilePath
                    }
                }

                # Rename Analytics database files to Reporting
                if ($childItemName -eq "Sitecore.Analytics.dacpac")
                {
                    $sourcePath = Join-Path `
                        -Path $destinationFolderPath `
                        -ChildPath $childItemName

                    Rename-Item $sourcePath $fileName
                }
            }
        }
    }

    if ($script:configSettings.Database.Type -ne "Azure")
    {
        foreach($childItem in $shell.NameSpace($item.Path).Items())
        {
            $childItemName = Split-Path -Path $childItem.Path -Leaf

            # Rename SQL Analytics database files to avoid confusion
            if ($childItemName -eq "Sitecore.Analytics.ldf")
            {
                $fileName = "Sitecore.Reporting.ldf"
            }
            elseif ($childItemName -eq "Sitecore.Analytics.mdf")
            {
                $fileName = "Sitecore.Reporting.mdf"
            }
            else
            {
                $fileName = $childItemName
            }
        
            $destinationFolderPath = $dataFilesFolderPath
            if ($childItemName.EndsWith(".ldf"))
            {
                $destinationFolderPath = $logFilesFolderPath
            }

            $filePath = Join-Path $destinationFolderPath -ChildPath $fileName

            if (Test-Path $filePath)
            {
                Write-Message "$filePath already exists, skipping extraction" "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
            }
            else
            {
                $shell.NameSpace($destinationFolderPath).CopyHere($childItem)

                if ($childItemName.ToLower() -like "sitecore.web.*")
                {
                    # Make copies of the web Database as required
                    foreach ($copy in $script:configSettings.Database.WebDatabaseCopies)
                    {
                        $copyFilePath = Join-Path $destinationFolderPath -ChildPath (Get-SubstituteDatabaseFileName $childItemName $copy.Name)
                        Copy-Item $filePath $copyFilePath
                    }
                }

                # Rename Analytics database files to Reporting
                if ($childItemName.ToLower() -like "sitecore.analytics.*")
                {
                    Rename-Item "$destinationFolderPath\$($childItemName)" (Get-SubstituteDatabaseFileName $childItemName "Reporting")
                }
            }
        }
    }

    Write-Message "Database files copied." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
}

function Copy-SitecoreFiles
{
    Write-Message "`nCopying Sitecore files..." "Green" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

    $zipPath = $script:configSettings.SitecoreZipPath
    $installPath = $script:configSettings.WebServer.SitecoreInstallPath

    $shell = New-Object -com shell.application

    Write-Message "Extracting files from $zipPath to $installPath" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

    # Copy Data folder
    $folderName = "Data"
    $folderPath = Join-Path $installPath -ChildPath $folderName
    if (Test-Path $folderPath)
    {
        Write-Message "$folderPath already exists, skipping extraction" "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }
    else
    {
        $item = Find-FolderInZipFile $shell.NameSpace($zipPath).Items() $folderName
        $shell.NameSpace($installPath).CopyHere($item)
        Write-Message "$folderName folder copied." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }

    # Copy Website folder
    $folderName = "Website"
    $folderPath = Join-Path $installPath -ChildPath $folderName
    if (Test-Path $folderPath)
    {
        Write-Message "$folderPath already exists, skipping extraction" "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }
    else
    {
        $item = Find-FolderInZipFile $shell.NameSpace($zipPath).Items() $folderName
        $shell.NameSpace($installPath).CopyHere($item)
        Write-Message "$folderName folder copied." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }

    if ($script:configSettings.Database.Enabled -and $script:configSettings.Database.InstallDatabase)
    {
            Copy-DatabaseFiles $zipPath
    }
    else
    {
        if (!$script:configSettings.Database.Enabled)
        {
            Write-Message "Skipping database file extraction: Database configuration is disabled" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
        else
        {
            Write-Message "Skipping database file extraction: InstallDatabase option is false" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
    }
    
    $licenseInstallPath = Join-Path $installPath -ChildPath "Data\license"
    if (!(Test-Path $licenseInstallPath))
    {
        New-Item $licenseInstallPath -type directory -force | Out-Null
    }
    $licenseInstallPath = Join-Path $licenseInstallPath -ChildPath "license.xml"
    Copy-Item -Path $script:configSettings.WebServer.LicenseFilePath -Destination $licenseInstallPath

    Write-Message "File copying done!" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
}

function Attach-SitecoreDatabase([string]$databaseName, [Microsoft.SqlServer.Management.Smo.Server]$sqlServerSmo)
{
    $sqlpackage = $script:configSettings.Azure.SqlPackagePath
    
    $dbserver = $script:configSettings.Azure.ServerAddress
    $dbResourceGroup = $script:configSettings.Azure.ResourceGroup
    $dbEdition = $script:configSettings.Azure.Edition #None, Premium, Basic, Standard, DataWarehouse, Stretch, Free, PremiumRS
    $dbSize = $script:configSettings.Azure.MaxSize 
    $dbServiceObjective = $script:configSettings.Azure.ServiceObjective 
	$type = $script:configSettings.Database.Type

    $dbuser = $script:configSettings.Database.SqlLoginForInstall
    $dbpass = $script:configSettings.Database.SqlLoginForInstallPassword

    $fullDatabaseName = $script:configSettings.Database.DatabaseNamePrefix + $databaseName

    if (!$script:configSettings.Database.InstallDatabase)
    {
        Write-Message "Skipping database attach: InstallDatabase option is false" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        return $fullDatabaseName
    }
    
    if ($type -eq "Azure")
    {
        $dataFilesFolderPath = Get-DatabaseInstallFolderPath -FileType DataFiles -LocalPath
        $mydacpac = Join-Path $dataFilesFolderPath -ChildPath "DACPAC/Sitecore.$databaseName.dacpac"
        # New-AzureRmSqlDatabase -ResourceGroupName $dbResourceGroup -ServerName $dbserver -DatabaseName $fullDatabaseName -MaxSizeBytes $dbSize -Edition $dbEdition -RequestedServiceObjectiveName $dbServiceObjective

        Write-Message `
            "Publishing $mydacpac to $dbServer" `
            "White" `
            -WriteToLog $true `
            -HostConsoleAvailable $hostScreenAvailable

        & $sqlpackage /Action:Publish /tsn:tcp:$dbServer /tdn:$fullDatabaseName /sf:$mydacpac /tu:$dbuser /tp:$dbpass /p:AllowIncompatiblePlatform=true
    }
    else
    {
        if ($sqlServerSmo.databases[$fullDatabaseName] -eq $null)
        {
            # Try attaching
            try
            {
                $message = "Attaching database $fullDatabaseName to " + $sqlServerSmo.Name
                Write-Message $message "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

                # Get paths of the data and log file
                $dataFilesFolderPath = Get-DatabaseInstallFolderPath -FileType DataFiles -LocalPath
                $logFilesFolderPath = Get-DatabaseInstallFolderPath -FileType LogFiles -LocalPath

                $dataFilePath = Join-Path $dataFilesFolderPath -ChildPath "Sitecore.$databaseName.mdf"
                $logFilePath = [IO.Path]::Combine( $logFilesFolderPath, "Sitecore.$databaseName.ldf" )
		
                $files = New-Object System.Collections.Specialized.StringCollection 
                $files.Add($dataFilePath) | Out-Null
                $files.Add($logFilePath) | Out-Null
                $sqlServerSmo.AttachDatabase($fullDatabaseName, $files)
            
            }
            catch
            {
                Write-Message ($_.Exception) "Red" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
            }
        }
        else
        {
            $message = "Database $fullDatabaseName already exists on " + $sqlServerSmo.Name
            Write-Message $message "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
    }
    return $fullDatabaseName
}

function Set-DatabaseRoles([string]$databaseName, [Microsoft.SqlServer.Management.Smo.Server]$sqlServerSmo)
{
    $loginName = Get-SqlLoginAccountForDataAccess

    if ($loginName -eq "sa")
    {
        Write-Message "The login `"$loginName`" is the built-in sysadmin for SQL. Skip setting roles for this user." "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        return
    }

    $database = $sqlServerSmo.Databases[$databaseName]
    $dbUser = $database.Users | Where-Object {$_.Login -eq "$loginName"}
    if ($dbUser -eq $null)
    {
        $dbUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.User -ArgumentList $database, $loginName
        $dbUser.Login = $loginName
        $dbUser.Create()
    }

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
        Write-Message "Adding $roleName role for $($dbUser.Name) on $database" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $dbrole = $database.Roles[$roleName]
        $dbrole.AddMember($dbUser.Name)
        $dbrole.Alter | Out-Null
    }
}

function Grant-DatabasePermissions([string]$databaseName, [Microsoft.SqlServer.Management.Smo.Server]$sqlServerSmo)
{
    $loginName = Get-SqlLoginAccountForDataAccess
    $database = $sqlServerSmo.Databases[$databaseName]
    $dbUser = $database.Users | Where-Object {$_.Login -eq "$loginName"}

    if ($loginName -eq "sa")
    {
        Write-Message "The login `"$loginName`" is the built-in sysadmin for SQL. Skip setting permissions for this user." "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        return
    }

    if ($dbUser -eq $null)
    {
        Write-Message "Could not find a user for the login `"$loginName`". Cannot grant permissions." "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        return
    }

    $database = $sqlServerSmo.Databases[$databaseName]
    $permset = New-Object Microsoft.SqlServer.Management.Smo.DatabasePermissionSet 
    $permset.Execute = $true
    $database.Grant($permset, $loginName)
    $database.Alter();

    Write-Message "Granted Execute permission to $loginName on $database" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
}

function Set-DatabaseGrowth([string]$databaseName, [Microsoft.SqlServer.Management.Smo.Server]$sqlServerSmo)
{
    $fullDatabaseName = $script:configSettings.Database.DatabaseNamePrefix + $databaseName
    $database = $sqlServerSmo.Databases[$fullDatabaseName]
    [int]$growthsize = $script:configSettings.WebServer.CMServerSettings.Publishing.Parallel.WebDatabaseAutoGrowthInMB

    Write-Message "Setting Autogrowth size for $fullDatabaseName to $($growthsize)MB" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

    foreach ($file in $database.FileGroups.Files)
    {
        $file.GrowthType = "kb"
        $file.Growth = $growthsize * 1024
        $file.Alter()
    }

    foreach ($logfile in $database.LogFiles)
    {
        $logfile.GrowthType = "kb"
        $logfile.Growth = $growthsize * 1024
        $logfile.Alter()
    }
}

function Initialize-SitecoreDatabases
{
    if (!$script:configSettings.Database.Enabled)
    {
        Write-Message "Skipping database initialization. Database configuration is disabled." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        return
    }

    Write-Message "`nInitializing Sitecore Databases..." "Green" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

    [Microsoft.SqlServer.Management.Smo.Server]$sqlServerSmo = Get-SqlServerSmo

    $webDatabaseNames = New-Object 'System.Collections.Generic.List[string]'
    $databaseNames = New-Object 'System.Collections.Generic.List[string]'

    foreach ($db in $script:configSettings.Database.Databases)
    {
        $databaseNames.Add($db.Name)
    }

    $webDatabaseNames.Add("Web")
    foreach ($copy in $script:configSettings.Database.WebDatabaseCopies)
    {
        $databaseNames.Add($copy.Name)
        $webDatabaseNames.Add($copy.Name)
    }

    foreach ($dbname in $databaseNames)
    {
        $fullDatabaseName = Attach-SitecoreDatabase $dbname $sqlServerSmo
        if ($script:configSettings.Database.Type -ne "Azure")
        {
            Set-DatabaseRoles $fullDatabaseName $sqlServerSmo
            Grant-DatabasePermissions $fullDatabaseName $sqlServerSmo
        }
    }

    if (Test-ShouldSetAutogrowth)
    {
        foreach ($webDbName in $webDatabaseNames)
        {
            Set-DatabaseGrowth $webDbName $sqlServerSmo
        }
    }

    Write-Message "Database initialization complete!" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
}

function Set-ApplicationPoolIdentity($pool)
{
    $pool.processModel.userName = $script:configSettings.WebServer.AppPoolIdentity
    
    if ($script:configSettings.WebServer.AppPoolIdentity -ne "ApplicationPoolIdentity" -and $script:configSettings.WebServer.AppPoolIdentity -ne "NetworkService")
    {
        # Using a service account
        $pool.processModel.password = $script:configSettings.WebServer.AppPoolIdentityPassword
        # Set identity type for a "SpecificUser"
        $pool.processModel.identityType = 3
    }
    else
    {
        $pool.processModel.identityType = $script:configSettings.WebServer.AppPoolIdentity
    }

    $pool | Set-Item

    $identityName = $pool.processModel.userName
    if ($pool.processModel.identityType.Equals("ApplicationPoolIdentity"))
    {
        $identityName = "IIS APPPOOL\$appPoolName"
    }

    Write-Message "Identity of application pool is $identityName" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
}

function Add-IpRestrictionsToTarget([string]$target, [string]$iisSiteName)
{
    $pspath = "IIS:\"
    $filter = "/system.webserver/security/ipSecurity"
    $propertyName = "allowUnlisted"
    $propertyValue =  "false"
    $location = $iisSiteName + "/" + $target
 
    Set-WebConfigurationProperty -PSPath $pspath -Filter $filter -Name $propertyName -Value $propertyValue -Location $location

    Write-Message "Denying all unspecified clients for $target" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

    foreach ($ip in $script:configSettings.WebServer.IPWhiteList)
    {
        Add-WebConfiguration -pspath $pspath -filter $filter -value @{ipAddress=$ip;allowed="true"} -Location $location
        Write-Message "$ip added to IP whitelist for $target" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }
}

function Set-IpRestrictions([string]$iisSiteName)
{
    $targetItems = @("sitecore/admin", "sitecore/shell", "sitecore/login", "sitecore/default.aspx")
    foreach ($target in $targetItems)
    {
        Add-IpRestrictionsToTarget $target $iisSiteName
    }
}

function Enable-ApplicationInitializationAppPoolSettings
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$appPoolName
    )

    if(Test-ApplicationInitializationSetting)
    {
        Write-Message "Enabling Application Initialization module..." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        Add-WindowsFeature Web-AppInit | Out-Null
        Write-Message "Application Initialization module enabled." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

        Write-Message "Applying AppPool settings for Publishing Server Application Initialization..." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $appPoolPath = Join-Path 'IIS:\AppPools\' -ChildPath $appPoolName
        Set-ItemProperty $appPoolPath -Name autoStart -Value $true
        Set-ItemProperty $appPoolPath -Name startMode -Value "AlwaysRunning"
        Set-ItemProperty $appPoolPath -Name processModel.idleTimeout -Value ([TimeSpan]::FromMinutes(0))
        Set-ItemProperty $appPoolPath -Name recycling.periodicRestart.time -Value ([TimeSpan]::FromMinutes(0))
        Write-Message "AppPool settings for Publishing Server Application Initialization complete." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

    }
}

function Enable-ApplicationInitializationWebsiteSettings
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$siteName
    )

    if(Test-ApplicationInitializationSetting)
    {
        $site = Join-Path 'IIS:\Sites\' -ChildPath $siteName
        Set-ItemProperty $site -Name applicationDefaults.preloadEnabled -Value $true

    }
}

function Initialize-WebSite
{
    Write-Message "`nInitializing site in IIS..." "Green" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

    $siteName = $script:configSettings.WebServer.IISWebSiteName

    # Setup application pool
    $appPoolName = $siteName + "AppPool"
    if(Test-Path IIS:\AppPools\$appPoolName)
    {
        Write-Message "Application pool named $appPoolName already exists" "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }
    else
    {
        Write-Message "Provisioning new application pool in IIS - $appPoolName" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        New-WebAppPool -Name $appPoolName -force | Out-Null

        $pool = Get-Item IIS:\AppPools\$appPoolName
        Set-ApplicationPoolIdentity $pool
        $pool.managedRuntimeVersion = $script:configSettings.WebServer.DefaultRuntimeVersion
        $pool.processModel.loadUserProfile = $TRUE
        $pool.processModel.maxProcesses = 1

        if (Test-PublishingServerRole)
        {
            $pool.startMode = "AlwaysRunning"
            [int]$timeout = $script:configSettings.WebServer.CMServerSettings.Publishing.AppPoolIdleTimeout
            if ($timeout -gt $pool.recycling.periodicRestart.time.TotalMinutes)
            {
                Write-Message "AppPoolIdleTimeout of $timeout minutes cannot be greater than the app pool's periodic restart time, using $($pool.recycling.periodicRestart.time.TotalMinutes) minutes instead." "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
                $timeout = $pool.recycling.periodicRestart.time.TotalMinutes
            }
            $pool.processModel.idleTimeout = [TimeSpan]::FromMinutes($timeout)
        }

        $pool | Set-Item

        Enable-ApplicationInitializationAppPoolSettings $appPoolName
    }

    # Create IIS site
    $iisSiteName = $sitename
    if(Test-Path IIS:\Sites\$iisSiteName)
    {
        Write-Message "A site named $iisSiteName already exists in IIS" "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }
    else
    {
        Write-Message "Provisioning new IIS site name $iisSiteName" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $installPath = $script:configSettings.WebServer.SitecoreInstallPath
        $sitePath = Join-Path $installPath -ChildPath "Website"        
        $bindingIndex = 1
        foreach ($binding in $script:configSettings.WebServer.IISBindings)
        {
            if ($bindingIndex -eq 1)
            {
                New-Website -Name $iisSiteName -IPAddress $binding.IP -Port $binding.Port -HostHeader $binding.HostHeader -PhysicalPath $sitePath -ApplicationPool $appPoolName -force | Out-Null
            }
            else
            {
                New-WebBinding -Name $iisSiteName -IPAddress $binding.IP -Port $binding.Port -HostHeader $binding.HostHeader
            }

            if ($binding.HostHeader.Length -ne 0 -and !([string]::IsNullOrEmpty($binding.AddToHostsFile)) -and [System.Convert]::ToBoolean($binding.AddToHostsFile))
            {
                # Add hostname(s) to hosts file
                $hostsPath = "$env:windir\System32\drivers\etc\hosts"
                $hostEntry = ""
                if ($bindingIndex -eq 1)
                {
                    $hostEntry += "`n########################"
                    $hostEntry += "`n# $siteName"
                    $hostEntry += "`n########################"
                }

                Write-Message "Add $($binding.HostHeader) to hosts file" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
                $ip = $binding.IP
                if ($ip -eq "*")
                {
                    $ip = "127.0.0.1"
                }
                $hostEntry += "`n$ip $($binding.HostHeader)"
                Add-Content $hostsPath $hostEntry
            }

            $bindingIndex++
        }
    }

    Write-Message "IIS site initialization complete!" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

    return $iisSiteName
}

function Get-FilesToDisableOnCDServer
{
    $webrootPath = Join-Path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath "Website"

    # Based on https://doc.sitecore.net/sitecore_experience_platform/80/xdb_configuration/configure_a_content_delivery_server
    $filesFor80 = @(
                   # Marketing Platform
                   "App_Config\Include\Sitecore.Analytics.Automation.TimeoutProcessing.config",
                   "App_Config\Include\Sitecore.Analytics.Processing.Aggregation.Services.config",
                   "App_Config\Include\Sitecore.Analytics.Processing.Services.config",
                   "App_Config\Include\Sitecore.Analytics.Reporting.config",
                   "App_Config\Include\Sitecore.Marketing.Client.config",
                   "App_Config\Include\Sitecore.Processing.config",
                   "App_Config\Include\Sitecore.WebDAV.config",

                   # Path Analyzer
                   "App_Config\Include\Sitecore.PathAnalyzer.Client.config",
                   "App_Config\Include\Sitecore.PathAnalyzer.config",
                   "App_Config\Include\Sitecore.PathAnalyzer.Processing.config",
                   "App_Config\Include\Sitecore.PathAnalyzer.Services.config",
                   "App_Config\Include\Sitecore.PathAnalyzer.StorageProviders.config",
                   "bin\Sitecore.PathAnalyzer.dll",
                   "bin\Sitecore.PathAnalyzer.Client.dll",
                   "bin\Sitecore.PathAnalyzer.Services.dll",
                   "bin\Sitecore.SequenceAnalyzer.dll",

                   # Content Testing
                   "App_Config\Include\ContentTesting\Sitecore.ContentTesting.Processing.Aggregation.config",

                   # Experience Analytics
                   "App_Config\Include\ExperienceAnalytics\Sitecore.ExperienceAnalytics.Aggregation.config",
                   "App_Config\Include\ExperienceAnalytics\Sitecore.ExperienceAnalytics.Client.config",
                   "App_Config\Include\ExperienceAnalytics\Sitecore.ExperienceAnalytics.Reduce.config",
                   "App_Config\Include\ExperienceAnalytics\Sitecore.ExperienceAnalytics.StorageProviders.config",
                   "App_Config\Include\ExperienceAnalytics\Sitecore.ExperienceAnalytics.WebAPI.config",
               
                   # Experience Profile
                   "App_Config\Include\ExperienceProfile\Sitecore.ExperienceProfile.config",
                   "App_Config\Include\ExperienceProfile\Sitecore.ExperienceProfile.Client.config",
                   "App_Config\Include\ExperienceProfile\Sitecore.ExperienceProfile.Reporting.config",

                   # Federated Experience Manager
                   "App_Config\Include\FXM\Sitecore.FXM.Speak.config",
                   #"App_Config\Include\FXM\Sitecore.Services.Client.FXM.Enabler.config", # this appears to be a mistake in the documentation, does not ship with vanilla install

                   # List Management
                   "App_Config\Include\ListManagement\Sitecore.ListManagement.Client.config",
                   "App_Config\Include\ListManagement\Sitecore.ListManagement.config",
                   "App_Config\Include\ListManagement\Sitecore.ListManagement.Services.config",

                   # Social Connected
                   "App_Config\Include\Social\Sitecore.Social.ExperienceProfile.config",

                   # Search-related configs, using Lucene as provider
                   "App_Config\Include\Sitecore.ContentSearch.Lucene.Index.Master.config",
                   "App_Config\Include\Sitecore.ContentSearch.Solr.DefaultIndexConfiguration.config",
                   "App_Config\Include\Sitecore.ContentSearch.Solr.Index.Analytics.config",
                   "App_Config\Include\Sitecore.ContentSearch.Solr.Index.Core.config",
                   "App_Config\Include\Sitecore.ContentSearch.Solr.Index.Master.config",
                   "App_Config\Include\Sitecore.ContentSearch.Solr.Index.Web.config",
                   "App_Config\Include\Sitecore.Marketing.Definitions.MarketingAssets.Repositories.Lucene.Index.Master.config",
                   "App_Config\Include\Sitecore.Marketing.Definitions.MarketingAssets.Repositories.Solr.Index.Master.config",
                   "App_Config\Include\Sitecore.Marketing.Definitions.MarketingAssets.Repositories.Solr.Index.Web.config",
                   "App_Config\Include\Sitecore.Marketing.Definitions.MarketingAssets.Repositories.Solr.IndexConfiguration.config",
                   "App_Config\Include\ContentTesting\Sitecore.ContentTesting.Lucene.IndexConfiguration.config",
                   "App_Config\Include\ContentTesting\Sitecore.ContentTesting.Solr.IndexConfiguration.config",
                   "App_Config\Include\FXM\Sitecore.FXM.Solr.Index.DomainsSearch.config",
                   "App_Config\Include\ListManagement\Sitecore.ListManagement.Lucene.Index.List.config",
                   "App_Config\Include\ListManagement\Sitecore.ListManagement.Lucene.IndexConfiguration.config",
                   "App_Config\Include\ListManagement\Sitecore.ListManagement.Solr.Index.List.config",
                   "App_Config\Include\ListManagement\Sitecore.ListManagement.Solr.IndexConfiguration.config",
                   "App_Config\Include\Social\Sitecore.Social.Lucene.Index.Master.config",
                   "App_Config\Include\Social\Sitecore.Social.Solr.Index.Master.config",
                   "App_Config\Include\Social\Sitecore.Social.Solr.Index.Web.config",
                   "App_Config\Include\Social\Sitecore.Social.Solr.IndexConfiguration.config"
                   )

    # Based on https://doc.sitecore.net/sitecore_experience_platform/xdb_configuration/configure_a_content_delivery_server
    $filesFor81 = @(
                   # Marketing Platform
                   "App_Config\Include\Sitecore.Analytics.Automation.TimeoutProcessing.config",
                   "App_Config\Include\Sitecore.Analytics.Processing.Aggregation.config",
                   "App_Config\Include\Sitecore.Analytics.Processing.Aggregation.Services.config",
                   "App_Config\Include\Sitecore.Analytics.Processing.config",
                   "App_Config\Include\Sitecore.Analytics.Processing.Services.config",
                   "App_Config\Include\Sitecore.Analytics.Reporting.config",
                   "App_Config\Include\Sitecore.Marketing.Client.config",
                   "App_Config\Include\Sitecore.Processing.config",
                   "App_Config\Include\Sitecore.Shell.MarketingAutomation.config",
                   "App_Config\Include\Sitecore.WebDAV.config",

                   # Path Analyzer
                   "App_Config\Include\Sitecore.PathAnalyzer.Client.config",
                   "App_Config\Include\Sitecore.PathAnalyzer.config",
                   "App_Config\Include\Sitecore.PathAnalyzer.Processing.config",
                   "App_Config\Include\Sitecore.PathAnalyzer.Services.config",
                   "App_Config\Include\Sitecore.PathAnalyzer.StorageProviders.config",
 
                   # Content Testing
                   "App_Config\Include\ContentTesting\Sitecore.ContentTesting.Processing.Aggregation.config",

                   # Experience Analytics
                   "App_Config\Include\ExperienceAnalytics\Sitecore.ExperienceAnalytics.Aggregation.config",
                   "App_Config\Include\ExperienceAnalytics\Sitecore.ExperienceAnalytics.Client.config",
                   "App_Config\Include\ExperienceAnalytics\Sitecore.ExperienceAnalytics.Reduce.config",
                   "App_Config\Include\ExperienceAnalytics\Sitecore.ExperienceAnalytics.StorageProviders.config",
                   "App_Config\Include\ExperienceAnalytics\Sitecore.ExperienceAnalytics.WebAPI.config",

                   # Experience Profile
                   "App_Config\Include\ExperienceProfile\Sitecore.ExperienceProfile.config",
                   "App_Config\Include\ExperienceProfile\Sitecore.ExperienceProfile.Client.config",
                   "App_Config\Include\ExperienceProfile\Sitecore.ExperienceProfile.Reporting.config",

                   # Federated Experience Manager
                   "App_Config\Include\FXM\Sitecore.FXM.Speak.config",

                   # List Management
                   "App_Config\Include\ListManagement\Sitecore.ListManagement.Client.config",
                   "App_Config\Include\ListManagement\Sitecore.ListManagement.config",
                   "App_Config\Include\ListManagement\Sitecore.ListManagement.Services.config",

                   # Social Connected
                   "App_Config\Include\Social\Sitecore.Social.ExperienceProfile.config",

                   # Search-related configs, using Lucene as provider
                   "App_Config\Include\Sitecore.ContentSearch.Lucene.Index.Master.config",
                   "App_Config\Include\Sitecore.ContentSearch.Solr.DefaultIndexConfiguration.config",
                   "App_Config\Include\Sitecore.ContentSearch.Solr.Index.Analytics.config",
                   "App_Config\Include\Sitecore.ContentSearch.Solr.Index.Core.config",
                   "App_Config\Include\Sitecore.ContentSearch.Solr.Index.Master.config",
                   "App_Config\Include\Sitecore.ContentSearch.Solr.Index.Web.config",
                   "App_Config\Include\Sitecore.Marketing.Definitions.MarketingAssets.Repositories.Lucene.Index.Master.config",
                   "App_Config\Include\Sitecore.Marketing.Definitions.MarketingAssets.Repositories.Solr.Index.Master.config",
                   "App_Config\Include\Sitecore.Marketing.Definitions.MarketingAssets.Repositories.Solr.Index.Web.config",
                   "App_Config\Include\Sitecore.Marketing.Definitions.MarketingAssets.Repositories.Solr.IndexConfiguration.config",
                   "App_Config\Include\Sitecore.Marketing.Lucene.Index.Master.config",
                   "App_Config\Include\Sitecore.Marketing.Solr.Index.Master.config",
                   "App_Config\Include\Sitecore.Marketing.Solr.Index.Web.config",
                   "App_Config\Include\Sitecore.Marketing.Solr.IndexConfiguration.config",
                   "App_Config\Include\ContentTesting\Sitecore.ContentTesting.Lucene.IndexConfiguration.config",
                   "App_Config\Include\ContentTesting\Sitecore.ContentTesting.Solr.IndexConfiguration.config",
                   "App_Config\Include\FXM\Sitecore.FXM.Lucene.DomainsSearch.DefaultIndexConfiguration.config",
                   "App_Config\Include\FXM\Sitecore.FXM.Lucene.DomainsSearch.Index.Master.config",
                   "App_Config\Include\FXM\Sitecore.FXM.Lucene.DomainsSearch.Index.Web.config",
                   "App_Config\Include\FXM\Sitecore.FXM.Solr.DomainsSearch.DefaultIndexConfiguration.config",
                   "App_Config\Include\FXM\Sitecore.FXM.Solr.DomainsSearch.Index.Master.config",
                   "App_Config\Include\FXM\Sitecore.FXM.Solr.DomainsSearch.Index.Web.config",
                   "App_Config\Include\ListManagement\Sitecore.ListManagement.Lucene.Index.List.config",
                   "App_Config\Include\ListManagement\Sitecore.ListManagement.Lucene.IndexConfiguration.config",
                   "App_Config\Include\ListManagement\Sitecore.ListManagement.Solr.Index.List.config",
                   "App_Config\Include\ListManagement\Sitecore.ListManagement.Solr.IndexConfiguration.config",
                   "App_Config\Include\Social\Sitecore.Social.Lucene.Index.Master.config",
                   "App_Config\Include\Social\Sitecore.Social.Solr.Index.Master.config",
                   "App_Config\Include\Social\Sitecore.Social.Solr.Index.Web.config",
                   "App_Config\Include\Social\Sitecore.Social.Solr.IndexConfiguration.config"
                   )

    [decimal]$sitecoreVersion = Get-SitecoreVersion
    if ($sitecoreVersion -eq "8.0")
    {        
        return $filesFor80 | % { Join-Path $webrootPath -ChildPath $_ }
    }
    elseif ($sitecoreVersion -eq "8.1")
    {
        return $filesFor81 | % { Join-Path $webrootPath -ChildPath $_ }
    }
    elseif ($sitecoreVersion -eq "10.0")
    {
        return Get-SitecoreConfigurationFiles -ServerRole CD -ConfigFilter Disable `
        | % { Join-Path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath $_ }
    }
    else
    {
        throw [System.InvalidOperationException] "Sitecore version [$sitecoreVersion] is not supported by this installer."
    }
}

function Disable-FilesForCDServer
{
    Write-Message "Disabling config files not needed on CD server." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    foreach ($file in Get-FilesToDisableOnCDServer)
    {        
        if (Test-Path $file)
        {
            $fileName = Split-Path $file -leaf
            $newName = $fileName + ".disabled"
            Rename-Item -Path $file -NewName $newName
            Write-Message "Disabled: $file" "White" -WriteToLogOnly $TRUE -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
        else
        {
            Write-Message "File not found on server: $file" "Yellow" -WriteToLogOnly $TRUE -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
    }
}

function Get-FilesToEnableOnCDServer
{
    $webrootPath = Join-Path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath "Website"

    # Based on https://doc.sitecore.net/sitecore_experience_platform/80/xdb_configuration/configure_a_content_delivery_server
    $filesFor80 = @(
                   # Marketing Platform
                   "App_Config\Include\ScalabilitySettings.config",
                   #"App_Config\Include\Sitecore.EngagementAutomation.LiveSessionAgent.Processing.config", # this appears to be a mistake in the documentation, does not ship with vanilla install
                   "App_Config\Include\SwitchMasterToWeb.config"
                   )

    # Based on https://doc.sitecore.net/sitecore_experience_platform/xdb_configuration/configure_a_content_delivery_server
    $filesFor81 = @(
                   # Marketing Platform
                   "App_Config\Include\ScalabilitySettings.config",
                   "App_Config\Include\Sitecore.Analytics.MarketingTaxonomyCD.config",
                   "App_Config\Include\Sitecore.Marketing.config",
                   "App_Config\Include\Sitecore.Marketing.Definitions.MarketingAssets.RepositoriesCD.config",
                   "App_Config\Include\Sitecore.MarketingCD.config",
                   "App_Config\Include\Z.SwitchMasterToWeb\SwitchMasterToWeb.config",

                   # Social Connected
                   "App_Config\Include\Social\Sitecore.Social.ScalabilitySettings.config"
                   )

    [decimal]$sitecoreVersion = Get-SitecoreVersion
    if ($sitecoreVersion -eq "8.0")
    {        
        return $filesFor80 | % { Join-Path $webrootPath -ChildPath $_ }
    }
    elseif ($sitecoreVersion -eq "8.1")
    {
        return $filesFor81 | % { Join-Path $webrootPath -ChildPath $_ }
    }
    elseif ($sitecoreVersion -eq "10.0")
    {
        return Get-SitecoreConfigurationFiles -ServerRole CD -ConfigFilter Enable `
        | % { Join-Path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath $_ }
    }
    else
    {
        throw [System.InvalidOperationException] "Sitecore version [$sitecoreVersion] is not supported by this installer."
    }
}

function Enable-FilesForCDServer
{
    Write-Message "Enabling config files required by a CD server." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    foreach ($fileToEnable in Get-FilesToEnableOnCDServer)
    {
        if (Test-Path $fileToEnable)
        {
            # Do nothing, file is already enabled.
        }
        elseif (Test-Path ($fileToEnable + ".*"))
        {
            $match = Get-Item ($fileToEnable + ".*") | Select-Object -First 1

            $filename = Split-Path $fileToEnable -leaf
            if ($filename -eq "SwitchMasterToWeb.config")
            {
                [decimal]$sitecoreVersion = Get-SitecoreVersion
                if ($sitecoreVersion -eq 8.0)
                {        
                    $foldername = $script:configSettings.WebServer.LastChildFolderOfIncludeDirectory
                    $folderPath = Join-Path (Split-Path $fileToEnable) -ChildPath $foldername
                
                    # Create a new folder, this folder should be named so as to be patched last
                    New-Item $folderPath -type directory -force | Out-Null

                    $fileToEnable = Join-Path $folderPath -ChildPath $filename
                }
                elseif ($sitecoreVersion -gt 8.0)
                {
                    $newFolderName = $script:configSettings.WebServer.LastChildFolderOfIncludeDirectory
                    if (!([string]::IsNullOrEmpty($newFolderName)))
                    {
                        # Change name of folder to LastChildFolderOfIncludeDirectory
                        $folderPath = Split-Path $fileToEnable
                        $folderItem = Rename-Item $folderPath $newFolderName -PassThru

                        $fileToEnable = Join-Path $folderItem.FullName -ChildPath $filename

                        # The matching config file has been moved, must rewrite match path
                        $match = Join-Path $folderItem.FullName -ChildPath (Split-Path $match -leaf)
                    }
                }
            }

            Copy-Item -Path $match -Destination $fileToEnable
            Write-Message "Enabled: $fileToEnable" "White" -WriteToLogOnly $TRUE -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
        else
        {
            Write-Message "File not found on server: $fileToEnable" "Yellow" -WriteToLogOnly $TRUE -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
    }
}

function Disable-ExperienceAnalyticsAssemblies
{
    $webrootPath = Join-Path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath "Website"
    $assemblies = @(
                   "bin\Sitecore.ExperienceAnalytics.dll",
                   "bin\Sitecore.ExperienceAnalytics.Client.dll",
                   "bin\Sitecore.ExperienceAnalytics.ReAggregation.dll"
                   )

    Write-Message "Disabling ExperienceAnalytics assemblies." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    foreach ($file in ($assemblies | % { Join-Path $webrootPath -ChildPath $_ }))
    {
        if (Test-Path $file)
        {
            $fileName = Split-Path $file -leaf
            $newName = $fileName + ".disabled"
            Rename-Item -Path $file -NewName $newName
            Write-Message "Disabled: $file" "White" -WriteToLogOnly $TRUE -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
        else
        {
            Write-Message "File not found on server: $file" "Yellow" -WriteToLogOnly $TRUE -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
    }
}

function Disable-SitecoreAnalytics
{
    param
    (
        [System.Collections.Generic.List[string]]$backupfiles
    )
    if(Test-PublishingServerRole)
    {
        $xdbConfigPath = Join-Path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath "\Website\App_Config\Include\Sitecore.Xdb.config"
        $xdbConfig = [xml](Get-Content $xdbConfigPath)

        $currentDate = (Get-Date).ToString("yyyyMMdd_hh-mm-s")
        $backup = [string]$xdbConfigPath + "__$currentDate"
        $xdbConfig.Save($backup)
        $backupFiles.Add($backup) | Out-Null

        $xdbConfig.configuration.sitecore.settings.SelectSingleNode("setting[@name='Xdb.Enabled']").SetAttribute("value", $false.ToString().ToLower()) | Out-Null
        $xdbConfig.configuration.sitecore.settings.SelectSingleNode("setting[@name='Xdb.Tracking.Enabled']").SetAttribute("value", $false.ToString().ToLower()) | Out-Null
        $xdbConfig.Save($xdbConfigPath)
        Write-Message "Disabled Sitecore Analytics for publishing server" "White" -WriteToLogOnly $TRUE -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }

    return $backupfiles
}

function Get-FilesToEnableOnPublishingServer
{
    $webrootPath = Join-Path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath "Website"

    $files = @(
               "App_Config\Include\Sitecore.Publishing.DedicatedInstance.config",
               "App_Config\Include\Sitecore.Publishing.EventProvider.Async.config",
               "App_Config\Include\Sitecore.Publishing.Optimizations.config",

               # this file is optionally enabled for Parallel publishing
               "App_Config\Include\Sitecore.Publishing.Parallel.config",

               "App_Config\Include\Sitecore.Publishing.Recovery.config"

               )

    return $files | % { Join-Path $webrootPath -ChildPath $_ }
}

function Enable-FilesForPublishingServer
{
    Write-Message "Enabling files required by a Publishing server." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    foreach ($file in Get-FilesToEnableOnPublishingServer)
    {
        if (Test-Path $file)
        {
            # Do nothing, file is already enabled.
        }
        elseif (Test-Path ($file + ".*"))
        {
            $match = Get-Item ($file + ".*") | Select-Object -First 1

            $filename = Split-Path $file -leaf
            if ($filename -eq "Sitecore.Publishing.DedicatedInstance.config")
            {
                [decimal]$sitecoreVersion = Get-SitecoreVersion
                if ($sitecoreVersion -eq 8.0)
                {        
                    $foldername = $script:configSettings.WebServer.LastChildFolderOfIncludeDirectory
                    $filepath = Join-Path (Split-Path $file) -ChildPath $foldername
                
                    # Create a new folder, this folder should be named so as to be patched last
                    New-Item $filepath -type directory -force | Out-Null
                }
                elseif ($sitecoreVersion -gt 8.0)
                {
                    # Get built-in folder
                    $folderPath = Join-Path (Split-Path $file) -ChildPath "Z.SwitchMasterToWeb"
                    $filepath = $folderPath

                    $newFolderName = $script:configSettings.WebServer.LastChildFolderOfIncludeDirectory
                    if (!([string]::IsNullOrEmpty($newFolderName)))
                    {
                        # Change name of built-in folder to LastChildFolderOfIncludeDirectory
                        $folderItem = Rename-Item $folderPath $newFolderName -PassThru
                        $filepath = $folderItem.FullName
                    }
                }

                $file = Join-Path $filepath -ChildPath $filename
            }
            elseif ($filename -eq "Sitecore.Publishing.Parallel.config")
            {
                if (!$script:configSettings.WebServer.CMServerSettings.Publishing.Parallel.Enabled)
                {
                    continue
                }
            }

            Copy-Item -Path $match -Destination $file
            Write-Message "Enabled: $file" "White" -WriteToLogOnly $TRUE -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
        else
        {
            Write-Message "File not found on server: $file" "Yellow" -WriteToLogOnly $TRUE -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }        
    }
}

function Get-FilesToDisableForProcessingServer
{
    return Get-SitecoreConfigurationFiles -ServerRole Processing -ConfigFilter Disable `
    | % { Join-Path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath $_ }
}

function Get-FilesToEnableForProcessingServer
{
    return Get-SitecoreConfigurationFiles -ServerRole Processing -ConfigFilter Enable `
    | % { Join-Path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath $_ }
}

function Disable-FilesForProcessingServer
{
    Write-Message "Disabling config files not needed on a Processing server." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    foreach ($file in Get-FilesToDisableForProcessingServer)
    {
        if (Test-Path $file)
        {
            $fileName = Split-Path $file -leaf
            $newName = $fileName + ".disabled"
            Rename-Item -Path $file -NewName $newName
            Write-Message "Disabled: $file" "White" -WriteToLogOnly $TRUE -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
        else
        {
            Write-Message "File not found on server: $file" "Yellow" -WriteToLogOnly $TRUE -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
    }
}

function Enable-FilesForProcessingServer
{
    Write-Message "Enabling config files required by a Processing server." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    foreach ($fileToEnable in Get-FilesToEnableForProcessingServer)
    {
        if (Test-Path $fileToEnable)
        {
            # Do nothing, file is already enabled.
        }
        elseif (Test-Path ($fileToEnable + ".*"))
        {
            $match = Get-Item ($fileToEnable + ".*") | Select-Object -First 1
            Copy-Item -Path $match -Destination $fileToEnable
            Write-Message "Enabled: $fileToEnable" "White" -WriteToLogOnly $TRUE -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
        else
        {
            Write-Message "File not found on server: $fileToEnable" "Yellow" -WriteToLogOnly $TRUE -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
    }
}

function Remove-PhantomJs([System.Collections.Generic.List[string]]$backupfiles)
{
    # remove phantomjs directory
    $phantomJsFolder = "Data\tools\phantomjs"
    $phantomJsPath = Join-Path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath $phantomJsFolder
    if(Test-Path $phantomJsPath)
    {
        Get-ChildItem -Path $phantomJsPath -Recurse | Remove-Item -Force
        Remove-Item -Path $phantomJsPath
        Write-Message "Removed PhantomJs directory " "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }
    
    # remove getScreenshotUrl pipeline
    $contentTestingConfig = "Website/App_Config/Include/ContentTesting/Sitecore.ContentTesting.config"
    $contentTestingConfigPath = Join-Path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath $contentTestingConfig
    $contentTestingConfig = [xml](Get-Content $contentTestingConfigPath)
    
    Write-Message "Backing up Sitecore.ContentTesting.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    
    $currentDate = (Get-Date).ToString("yyyyMMdd_hh-mm-s")
    $backup = [string]$contentTestingConfigPath + "__$currentDate"
    $contentTestingConfig.Save($backup)
    $backupFiles.Add($backup)

    $node = $contentTestingConfig.configuration.sitecore.pipelines.getScreenshotForUrl
    $contentTestingConfig.configuration.sitecore.pipelines.RemoveChild($node) | Out-Null
    $contentTestingConfig.Save($contentTestingConfigPath)
    Write-Message "Removed getScreenshotForUrl pipeline" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

    return $backupfiles
}

function Set-MediaRequestProtection([System.Collections.Generic.List[string]]$backupfiles)
{
    Write-Message "Updating Media Request Protection settings..." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    $mediaRequestConfigPath = Find-MediaRequestConfig
    $mediaRequestConfig = [xml](Get-Content $mediaRequestConfigPath)

    $currentDate = (Get-Date).ToString("yyyyMMdd_hh-mm-s")
    $backup = [string]$mediaRequestConfigPath + "__$currentDate"
    $mediaRequestConfig.Save($backup)
    $backupFiles.Add($backup)

    $sharedSecret = $script:configSettings.WebServer.MediaRequestProtection.SharedSecret
    if ([string]::IsNullOrEmpty($sharedSecret))
    {
        Write-Message "No value provided for Media Request Protection Shared Secret - Sitecore default value will be used" "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }
    else 
    {
        $mediaRequestConfig.configuration.sitecore.settings.SelectSingleNode("setting[@name='Media.RequestProtection.SharedSecret']").SetAttribute("value", $sharedSecret)  | Out-Null
        Write-Message "Media Request Protection SharedSecret updated" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }

    $loggingEnabled = $script:configSettings.WebServer.MediaRequestProtection.LoggingEnabled.ToString()
    if ([string]::IsNullOrEmpty($loggingEnabled))
    {
        Write-Message "No value provided for Media Request Protection Logging - Sitecore default value will be used" "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }
    else 
    {
        $mediaRequestConfig.configuration.sitecore.settings.SelectSingleNode("setting[@name='Media.RequestProtection.Logging.Enabled']").SetAttribute("value", $loggingEnabled.ToLower()) | Out-Null
        if($script:configSettings.WebServer.MediaRequestProtection.LoggingEnabled)
        {
            Write-Message "Media Request Protection Logging enabled." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
        else 
        {
            Write-Message "Media Request Protection Logging disabled." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable  
        }  
    }

    $mediaRequestConfig.Save($mediaRequestConfigPath)
    
    Write-Message "Media Request Protection update complete" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

    return $backupfiles
}

function Set-ConfigurationFiles
{
    Write-Message "`nWriting changes to config files..." "Green" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

    [decimal]$sitecoreVersion = Get-SitecoreVersion
    $backupFiles = New-Object 'System.Collections.Generic.List[string]'
    $installPath = $script:configSettings.WebServer.SitecoreInstallPath
    $currentDate = (Get-Date).ToString("yyyyMMdd_hh-mm-s")

    #region Edit DataFolder.config file
    $dataFolderConfigExamplePath = Join-Path $installPath -ChildPath "Website\App_Config\Include\DataFolder.config.example"
    $dataFolderConfigPath = Join-Path $installPath -ChildPath "Website\App_Config\Include\DataFolder.config"
    Copy-Item -Path $dataFolderConfigExamplePath -Destination $dataFolderConfigPath

    # Set dataFolder path
    $dataFolderConfig = [xml](Get-Content $dataFolderConfigPath)
    $dataFolderPath = Join-Path $installPath -ChildPath "Data"
    $dataFolderConfig.configuration.sitecore."sc.variable".FirstChild.'#text' = $dataFolderPath.ToString()
    $dataFolderConfig.Save($dataFolderConfigPath)
    #endregion

    #region Edit web.config
    $webConfigPath = Join-Path $installPath -ChildPath "Website\web.config"
    $webconfig = [xml](Get-Content $webConfigPath)
    $backup = $webConfigPath + "__$currentDate"
    Write-Message "Backing up Web.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    $webconfig.Save($backup)
    $backupFiles.Add($backup)

    # Modify sessionState element and provider    
    if ($script:configSettings.WebServer.SessionStateProvider.Private.ToLower() -eq "mssql")
    {
        $webconfig.configuration.SelectSingleNode("system.web/sessionState/providers/add[@name='mssql']").SetAttribute("sessionType", "private")
        Write-Message "Setting sessionType attribute value of MSSQL provider to private." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

        $webconfig.configuration.SelectSingleNode("system.web/sessionState").SetAttribute("mode", "Custom")
        $webconfig.configuration.SelectSingleNode("system.web/sessionState").SetAttribute("customProvider", "mssql")
        Write-Message "Changing private session state provider to MSSQL" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }

    # Set HashAlgorithmType on Membership Provider
    if (!([string]::IsNullOrEmpty($script:configSettings.WebServer.PasswordHashAlgorithm)))
    {
        $webconfig.configuration.'system.web'.SelectSingleNode("membership").SetAttribute("hashAlgorithmType", $script:configSettings.WebServer.PasswordHashAlgorithm) | Out-Null
        Write-Message "Changing Membership Provider hashAlgorithmType to $($script:configSettings.WebServer.PasswordHashAlgorithm)" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }

    # Add Telerik Encryption
    if (($script:configSettings.Webserver.CMServerSettings.Enabled) -and ($script:configSettings.Webserver.CMServerSettings.AddTelerikEncryptionKey))
    {
        $key = $webconfig.CreateElement("add")
        $key.SetAttribute("key", "Telerik.AsyncUpload.ConfigurationEncryptionKey")
        $key.SetAttribute("value", $script:configSettings.Webserver.CMServerSettings.TelerikEncryptionKey)
        $webconfig.configuration.SelectSingleNode("appSettings").AppendChild($key) | Out-Null
        Write-Message "Set Telerik Configuration Encryption Key on CM Server" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }

    # Disable Sitecore's Upload Watcher
    if (($script:configSettings.Webserver.CDServerSettings.Enabled) -and ($script:configSettings.WebServer.CDServerSettings.DisableUploadWatcher))
    {
        $node = $webconfig.configuration.SelectSingleNode("system.webServer/modules/add[@name='SitecoreUploadWatcher']")
        $node.ParentNode.InnerXml = $node.ParentNode.InnerXml.Replace($node.OuterXml, $node.OuterXml.Insert(0, "<!--").Insert($node.OuterXml.Length+4, "-->"))
    }

    # Disable Telerik Controls
    if (($script:configSettings.Webserver.CDServerSettings.Enabled) -and ($script:configSettings.WebServer.CDServerSettings.DisableTelerikControls))
    {
        $node = $webconfig.configuration.SelectSingleNode("system.webServer/handlers/add[@name='Telerik_Web_UI_DialogHandler_aspx']")
        $webconfig.configuration.SelectSingleNode("system.webServer/handlers").RemoveChild($node) | Out-Null
        
        $node = $webconfig.configuration.SelectSingleNode("system.webServer/handlers/add[@name='Telerik_Web_UI_SpellCheckHandler_axd']")
        $webconfig.configuration.SelectSingleNode("system.webServer/handlers").RemoveChild($node) | Out-Null
        
        $node = $webconfig.configuration.SelectSingleNode("system.webServer/handlers/add[@name='Telerik_Web_UI_WebResource_axd']")
        $webconfig.configuration.SelectSingleNode("system.webServer/handlers").RemoveChild($node) | Out-Null
        Write-Message "Disabled Telerik Handlers for CD Server" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }
    
    # Modify license file path
    if ($sitecoreVersion -eq 8.0)
    {
        Write-Message "Changing license file path" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $sitecoreConfig.configuration.SelectSingleNode("sitecore/settings/setting[@name='LicenseFile']").SetAttribute("value", "`$(dataFolder)/license/license.xml")
    }

    # Comment out the entry for SitecoreAntiCSRF
    if (Test-ProcessingServerRole)
    {
        $node = $webconfig.configuration.SelectSingleNode("system.webServer/modules/add[@name='SitecoreAntiCSRF']")
        $node.ParentNode.InnerXml = $node.ParentNode.InnerXml.Replace($node.OuterXml, $node.OuterXml.Insert(0, "<!--").Insert($node.OuterXml.Length+4, "-->"))
    }

    # Set ApplicationInitialization for Publishing Server
    if(Test-ApplicationInitializationSetting)
    {        
        $node = $webConfig.configuration.'system.webServer'.applicationInitialization

        if($node -eq $null) 
        {
            $publishingHost = $script:configSettings.webServer.CMServerSettings.Publishing.PublishingInstance
            $add = $webconfig.CreateElement("add")
            $add.SetAttribute("hostName", $publishingHost) | Out-Null
            $add.SetAttribute("initializationPage","/default.aspx") | Out-Null
            $appInit = $webconfig.CreateElement("applicationInitialization")
            $appInit.SetAttribute("doAppInitAfterRestart","true")  | Out-Null
            $appInit.AppendChild($add)  | Out-Null
            $webconfig.configuration.SelectSingleNode("system.webServer").AppendChild($appInit) | Out-Null
            $webconfig.Save($webConfigPath)
        }

        $node = $webConfig.configuration.'system.webServer'.defaultDocument

        if($node -eq $null)
        {
            $add = $webconfig.CreateElement("add")
            $add.SetAttribute("value","default.aspx") | Out-Null
            $files = $webconfig.CreateElement("files")
            $files.AppendChild($add) | Out-Null
            $defaultDocument = $webconfig.CreateElement("defaultDocument")
            $defaultDocument.SetAttribute("enabled","true")
            $defaultDocument.AppendChild($files) | Out-Null
            $webconfig.configuration.SelectSingleNode("system.webServer").AppendChild($defaultDocument) | Out-Null
            $webconfig.Save($webConfigPath)
        }
    }

    Write-Message "Saving changes to Web.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    $webconfig.Save($webConfigPath)
    #endregion

    #region Edit connectionStrings.config
    $connectionStringsPath = Join-Path $installPath -ChildPath "Website\App_Config\ConnectionStrings.config"
    $connectionStringsConfig = [xml](Get-Content $connectionStringsPath)
    $backup = $connectionStringsPath + "__$currentDate"
    Write-Message "Backing up ConnectionStrings.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    $connectionStringsConfig.Save($backup)
    $backupFiles.Add($backup)

    $baseConnectionString = $script:configSettings.Database.BaseConnectionString
    foreach ($db in $script:configSettings.Database.Databases)
    {
        $fullDatabaseName = $script:configSettings.Database.DatabaseNamePrefix + $db.Name
        $connectionString = $baseConnectionString + $fullDatabaseName + ";"

        $node = $connectionStringsConfig.SelectSingleNode("connectionStrings/add[@name='$($db.ConnectionStringName)']")
        if ($node -ne $null)
        {
            $node.SetAttribute("connectionString", $connectionString)
        }
    }

    # Add additional connection strings for each web database copy
    foreach ($copy in $script:configSettings.Database.WebDatabaseCopies)
    {
        $node = $connectionStringsConfig.SelectSingleNode("connectionStrings/add[@name='$($copy.ConnectionStringName)']")
        if ($node -ne $null)
        {
            # Rewrite existing connection string
            $fullDatabaseName = $script:configSettings.Database.DatabaseNamePrefix + $copy.Name
            $connectionString = $baseConnectionString + $fullDatabaseName + ";"
            $node.SetAttribute("connectionString", $connectionString)
            Write-Message "Modified $($copy.ConnectionStringName) connection string to use $fullDatabaseName database." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
        else
        {
            # Create new connection string
            $dbElement = $connectionStringsConfig.CreateElement("add")

            $dbAttr = $connectionStringsConfig.CreateAttribute("name")
            $dbAttr.Value = $copy.ConnectionStringName
            $dbElement.Attributes.Append($dbAttr) | Out-Null
        
            $dbAttr = $connectionStringsConfig.CreateAttribute("connectionString")
            $dbAttr.Value = $baseConnectionString + $script:configSettings.Database.DatabaseNamePrefix + $copy.Name + ";"
            $dbElement.Attributes.Append($dbAttr) | Out-Null

            $connectionStringsConfig.DocumentElement.AppendChild($dbElement) | Out-Null

            Write-Message "Added a $($copy.ConnectionStringName) connection string." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }
    }

    # Optionally add a session connection string
    if ($script:configSettings.WebServer.SessionStateProvider.Private.ToLower() -eq "mssql" -or $script:configSettings.WebServer.SessionStateProvider.Private.ToLower() -eq "mssql")
    {
        $sessionElement = $connectionStringsConfig.CreateElement("add")

        $sessionAttr = $connectionStringsConfig.CreateAttribute("name")
        $sessionAttr.Value = "session"
        $sessionElement.Attributes.Append($sessionAttr) | Out-Null

        $sessionAttr = $connectionStringsConfig.CreateAttribute("connectionString")
        $sessionAttr.Value = $baseConnectionString + $script:configSettings.Database.DatabaseNamePrefix + "Sessions;"
        $sessionElement.Attributes.Append($sessionAttr) | Out-Null

        $connectionStringsConfig.DocumentElement.AppendChild($sessionElement) | Out-Null
        Write-Message "Added a session connection string" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }

    # Modify MongoDB connection strings
    if ($script:configSettings.WebServer.MongoDb.Enabled)
    {
        $mongoNodes = $connectionStringsConfig.SelectNodes("connectionStrings/add[contains(@connectionString, 'mongodb://')]")
        foreach ($node in $mongoNodes)
        {
            $url = [System.Uri]($node.connectionString)
            $builder = New-Object System.UriBuilder

            $credentials = ""            
            $username = $script:configSettings.WebServer.MongoDb.Credentials.Username
            $password = $script:configSettings.WebServer.MongoDb.Credentials.Password        
            if ($username.Length -gt 0)
            {
                $credentials = $username + ":" + $password + "@"
            }

            $hostAndPort = ""
            foreach ($mongohost in $script:configSettings.WebServer.MongoDb.Hosts)
            {
                if ($hostAndPort.Length -gt 0)
                {
                    $hostAndPort += ","
                }
                $hostAndPort += $mongohost.HostName
                if ($mongohost.Port.Length -gt 0)
                {
                    $hostAndPort += ":" + $mongohost.Port
                }
            }            
            if ($hostAndPort.Length -eq 0)
            {
                $hostAndPort = $url.Host
                if ($url.Port -lt 1)
                {
                    $hostAndPort += $url.Port.ToString()
                }
            }

            # Use the same prefix for MongoDB databases as we use for SQL
            $lastSegment = $script:configSettings.Database.DatabaseNamePrefix + $url.Segments[$url.Segments.Count-1]
            $newSegments = $url.Segments
            $newSegments[$newSegments.Count-1] = $lastSegment
            $databaseName = [string]::Join("",$newSegments)

            $connectionString = ("mongodb://{0}{1}{2}{3}" -f $credentials,$hostAndPort,$databaseName,$script:configSettings.WebServer.MongoDb.Options)
            $node.SetAttribute("connectionString", $connectionString)
        }

        Write-Message "Changing host name for MongoDb connection strings" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }

    # Comment out connection strings not needed by CD server
    if ($script:configSettings.WebServer.CDServerSettings.Enabled -and $script:configSettings.WebServer.CDServerSettings.DeactivateConnectionStrings)
    {
        $node = $connectionStringsConfig.SelectSingleNode("connectionStrings/add[@name='master']")
        $node.ParentNode.InnerXml = $node.ParentNode.InnerXml.Replace($node.OuterXml, $node.OuterXml.Insert(0, "<!--").Insert($node.OuterXml.Length+4, "-->"))

        $node = $connectionStringsConfig.SelectSingleNode("connectionStrings/add[@name='tracking.history']")
        $node.ParentNode.InnerXml = $node.ParentNode.InnerXml.Replace($node.OuterXml, $node.OuterXml.Insert(0, "<!--").Insert($node.OuterXml.Length+4, "-->"))

        $node = $connectionStringsConfig.SelectSingleNode("connectionStrings/add[@name='reporting']")
        $node.ParentNode.InnerXml = $node.ParentNode.InnerXml.Replace($node.OuterXml, $node.OuterXml.Insert(0, "<!--").Insert($node.OuterXml.Length+4, "-->"))

        Write-Message "Commenting out connection strings not need on CD server" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }

    # Comment out connection strings not needed by Processing server
    if ((Test-ProcessingServerRole) -and $script:configSettings.WebServer.CMServerSettings.Processing.DeactivateConnectionStrings)
    {
        $connectionStringNames = New-Object 'System.Collections.Generic.List[string]'
        $script:configSettings.Database.WebDatabaseCopies | ForEach-Object { $connectionStringNames.Add($_.ConnectionStringName) }
        $connectionStringNames.Add("web")

        foreach($name in $connectionStringNames)
        {
            $node = $connectionStringsConfig.SelectSingleNode("connectionStrings/add[@name='$name']")
            $node.ParentNode.InnerXml = $node.ParentNode.InnerXml.Replace($node.OuterXml, $node.OuterXml.Insert(0, "<!--").Insert($node.OuterXml.Length+4, "-->"))
        }

        Write-Message "Commenting out connection strings not need on Processing server" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }

    # Set the reporting.apikey connection string
    $node = $connectionStringsConfig.SelectSingleNode("connectionStrings/add[@name='reporting.apikey']")
    if ($node -ne $null)
    {
        # Write a reporting.apikey
        if (![string]::IsNullOrEmpty($script:configSettings.WebServer.ReportingApiKey))
        {
            $node.SetAttribute("connectionString", $script:configSettings.WebServer.ReportingApiKey)
        }
    }

    Write-Message "Saving ConnectionStrings.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    $connectionStringsConfig.Save($connectionStringsPath)
    #endregion

    #region Edit Sitecore.config...
    if ($sitecoreVersion -gt 8.0)
    {
        $sitecoreConfigPath = Join-Path $installPath -ChildPath "Website\App_Config\Sitecore.config"
        $sitecoreConfig = [xml](Get-Content $sitecoreConfigPath)
        $backup = $sitecoreConfigPath + "__$currentDate"
        Write-Message "Backing up Sitecore.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $sitecoreConfig.Save($backup)
        $backupFiles.Add($backup)

        # Modify license file path
        Write-Message "Changing license file path" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $sitecoreConfig.SelectSingleNode("sitecore/settings/setting[@name='LicenseFile']").SetAttribute("value", "`$(dataFolder)/license/license.xml")

        if (Test-ProcessingServerRole)
        {
            # Comment out web <database> element for Processing server
            Write-Message "Commenting out web <database> element" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
            $node = $sitecoreConfig.SelectSingleNode("sitecore/databases/database[@id='web']")
            $node.ParentNode.InnerXml = $node.ParentNode.InnerXml.Replace($node.OuterXml, $node.OuterXml.Insert(0, "<!--").Insert($node.OuterXml.Length+4, "-->"))

            # Comment out PublishAgent
            Write-Message "Commenting out PublishAgent" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
            $node = $sitecoreConfig.SelectSingleNode("sitecore/scheduling/agent[@type='Sitecore.Tasks.PublishAgent']")
            $node.ParentNode.InnerXml = $node.ParentNode.InnerXml.Replace($node.OuterXml, $node.OuterXml.Insert(0, "<!--").Insert($node.OuterXml.Length+4, "-->"))

            # Modify website <site> element
            Write-Message "Change database to master for the 'website' <site> element " "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
            $node = $sitecoreConfig.SelectSingleNode("sitecore/sites/site[@name='website']").SetAttribute("database", "master")
        }

        Write-Message "Saving Sitecore.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $sitecoreConfig.Save($sitecoreConfigPath)
    }
    #endregion

    #region Edit Sitecore.Analytics.Tracking.config
    if ($script:configSettings.WebServer.SessionStateProvider.Shared.ToLower() -eq "mssql")
    {
        $trackerPath = Join-Path $installPath -ChildPath "Website\App_Config\Include\Sitecore.Analytics.Tracking.config"
        $trackerConfig = [xml](Get-Content $trackerPath)
        $backup = $trackerPath + "__$currentDate"
        Write-Message "Backing up Sitecore.Analytics.Tracker.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $trackerConfig.Save($backup)
        $backupFiles.Add($backup)

        Write-Message "Changing shared session state provider to MSSQL" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $trackerConfig.configuration.SelectSingleNode("sitecore/tracking/sharedSessionState").SetAttribute("defaultProvider", "mssql")

        # Delete existing mssql provider if it exists
        $expression = "sitecore/tracking/sharedSessionState/providers/add[translate(@name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') = 'mssql']"
        $node = $trackerConfig.configuration.SelectSingleNode($expression)
        while ($node -ne $null)
        {
            $node.ParentNode.RemoveChild($node)
            $node = $trackerConfig.configuration.SelectSingleNode($expression)
        }

        # Create a mssql provider
        $expression = "sitecore/tracking/sharedSessionState/providers"
        $node = $trackerConfig.configuration.SelectSingleNode($expression)
        $element = $trackerConfig.CreateElement("add")
        #name
        $attribute = $trackerConfig.CreateAttribute("name")
        $attribute.Value = "mssql"
        $element.Attributes.Append($attribute) | Out-Null
        #type
        $attribute = $trackerConfig.CreateAttribute("type")
        $attribute.Value = "Sitecore.SessionProvider.Sql.SqlSessionStateProvider,Sitecore.SessionProvider.Sql"
        $element.Attributes.Append($attribute) | Out-Null
        #connectionStringName
        $attribute = $trackerConfig.CreateAttribute("connectionStringName")
        $attribute.Value = "session"
        $element.Attributes.Append($attribute) | Out-Null
        #pollingInterval
        $attribute = $trackerConfig.CreateAttribute("pollingInterval")
        $attribute.Value = "2"
        $element.Attributes.Append($attribute) | Out-Null
        #compression
        $attribute = $trackerConfig.CreateAttribute("compression")
        $attribute.Value = "true"
        $element.Attributes.Append($attribute) | Out-Null
        #sessionType
        $attribute = $trackerConfig.CreateAttribute("sessionType")
        $attribute.Value = "shared"
        $element.Attributes.Append($attribute) | Out-Null
        $node.AppendChild($element) | Out-Null

        # Set sharedSessionState's defaultProvider to mssql
        $node = $trackerConfig.configuration.SelectSingleNode("sitecore/tracking/sharedSessionState").SetAttribute("defaultProvider", "mssql")

        Write-Message "Saving changes to Sitecore.Analytics.Tracker.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $trackerConfig.Save($trackerPath)
    }

    if (!([string]::IsNullOrEmpty($script:configSettings.WebServer.Analytics.ClusterName)) `
        -or !([string]::IsNullOrEmpty($script:configSettings.WebServer.Analytics.HostName)))
    {
        $trackerPath = Join-Path $installPath -ChildPath "Website\App_Config\Include\Sitecore.Analytics.Tracking.config"
        $trackerConfig = [xml](Get-Content $trackerPath)

        $backup = $trackerPath + "__$currentDate"
        if (!$backupFiles.Contains($backup))
        {
            Write-Message "Backing up Sitecore.Analytics.Tracker.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
            $trackerConfig.Save($backup)
            $backupFiles.Add($backup)
        }

        if (!([string]::IsNullOrEmpty($script:configSettings.WebServer.Analytics.ClusterName)))
        {
            $trackerConfig.configuration.SelectSingleNode("sitecore/settings/setting[@name='Analytics.ClusterName']").SetAttribute("value", $script:configSettings.WebServer.Analytics.ClusterName)
            Write-Message "Changing Analytics.ClusterName" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }

        if (!([string]::IsNullOrEmpty($script:configSettings.WebServer.Analytics.HostName)))
        {
            $trackerConfig.configuration.SelectSingleNode("sitecore/settings/setting[@name='Analytics.HostName']").SetAttribute("value", $script:configSettings.WebServer.Analytics.HostName)
            Write-Message "Changing Analytics.HostName" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        }

        Write-Message "Saving changes to Sitecore.Analytics.Tracker.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $trackerConfig.Save($trackerPath)
    }
    #endregion

    #region Edit Sitecore.ContentSearch.Solr.DefaultIndexConfiguration.config.example
    if (!([string]::IsNullOrEmpty($script:configSettings.WebServer.Solr.ServiceBaseAddress)))
    {
        $solrConfigPath = Join-Path $installPath -ChildPath "Website\App_Config\Include\Sitecore.ContentSearch.Solr.DefaultIndexConfiguration.config.example"
        $solrConfig = [xml](Get-Content $solrConfigPath)
        $currentDate = (Get-Date).ToString("yyyyMMdd_hh-mm-s")
        $backup = $solrConfigPath + "__$currentDate"
        Write-Message "Backing up Sitecore.ContentSearch.Solr.DefaultIndexConfiguration.config.example" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $solrConfig.Save($backup)
        $backupFiles.Add($backup)

        $solrConfig.configuration.SelectSingleNode("sitecore/settings/setting[@name='ContentSearch.Solr.ServiceBaseAddress']").SetAttribute("value", $script:configSettings.WebServer.Solr.ServiceBaseAddress)
        Write-Message "Changing Solr ServiceBaseAddress" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

        Write-Message "Saving Sitecore.ContentSearch.Solr.DefaultIndexConfiguration.config.example" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $solrConfig.Save($solrConfigPath)
    }
    #endregion

    #region Configure CM/CD/Publishing/Processing roles
    if ($script:configSettings.WebServer.CDServerSettings.Enabled -and $script:configSettings.WebServer.CDServerSettings.ConfigureFilesForCD)
    {
        Disable-FilesForCDServer
        Enable-FilesForCDServer
    }

    if ($script:configSettings.WebServer.CDServerSettings.Enabled -and $script:configSettings.WebServer.CDServerSettings.DisableExperienceAnalyticsAssemblies)
    {
        Disable-ExperienceAnalyticsAssemblies
    }

    if ($script:configSettings.WebServer.CDServerSettings.Enabled -and $script:configSettings.WebServer.CDServerSettings.RemovePhantomJs)
    {
        [System.Collections.Generic.List[string]]$backupFiles = Remove-PhantomJs $backupFiles
    }

    if ((Test-ProcessingServerRole) -and $script:configSettings.WebServer.CMServerSettings.Processing.ConfigureFilesForProcessing)
    {
        Disable-FilesForProcessingServer
        Enable-FilesForProcessingServer
    }

    $scalabilityConfigPath = Join-Path $installPath -ChildPath "Website\App_Config\Include\ScalabilitySettings.config"
    if (Test-Path $scalabilityConfigPath)
    {
        # Do nothing, file is already enabled.
    }
    elseif (Test-Path ($scalabilityConfigPath + ".*"))
    {
        # Enable the file
        $match = Get-Item ($scalabilityConfigPath + ".*") | Select-Object -First 1

        Copy-Item -Path $match -Destination $scalabilityConfigPath
        Write-Message "Enabled: $scalabilityConfigPath" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }

    #region Edit Sitecore.Media.RequestProtection.config
    if($script:configSettings.WebServer.CDServerSettings.Enabled -or $script:configSettings.WebServer.CMServerSettings.Enabled)
    {
        [System.Collections.Generic.List[string]]$backupFiles = Set-MediaRequestProtection $backupFiles
    }
    #endregion

    #region Edit ScalabilitySettings.config
    $scalabilityConfigPath = Join-Path $installPath -ChildPath "Website\App_Config\Include\ScalabilitySettings.config"
    $scalabilityConfig = [xml](Get-Content $scalabilityConfigPath)
    $currentDate = (Get-Date).ToString("yyyyMMdd_hh-mm-s")
    $backup = $scalabilityConfigPath + "__$currentDate"
    Write-Message "Backing up ScalabilitySettings.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    $scalabilityConfig.Save($backup)
    $backupFiles.Add($backup)
    $instanceName = $script:configSettings.WebServer.SitecoreInstanceName
    $scalabilityConfig.configuration.SelectSingleNode("sitecore/settings/setting[@name='InstanceName']").ChildNodes[0].InnerText = $instanceName
    Write-Message "Saving changes to ScalabilitySettings.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    $scalabilityConfig.Save($scalabilityConfigPath)

    if ($script:configSettings.WebServer.CMServerSettings.Enabled)
    {
        $publishingInstanceName = $script:configSettings.WebServer.CMServerSettings.Publishing.PublishingInstance
        if (!([string]::IsNullOrEmpty($publishingInstanceName)))
        {
            # This value MUST be set on all CM servers if it has been provided
            $scalabilityConfig.configuration.SelectSingleNode("sitecore/settings/setting[@name='Publishing.PublishingInstance']").ChildNodes[0].InnerText = $publishingInstanceName
        }

        Write-Message "Saving changes to ScalabilitySettings.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $scalabilityConfig.Save($scalabilityConfigPath)

        if (Test-PublishingServerRole)
        {
            Enable-FilesForPublishingServer
            $backupFiles = Disable-SitecoreAnalytics $backupFiles

            if ($script:configSettings.WebServer.CMServerSettings.Publishing.Parallel.Enabled)
            {
                # Edit Sitecore.Publishing.Parallel.config
                $parallelConfigPath = Join-Path $installPath -ChildPath "Website\App_Config\Include\Sitecore.Publishing.Parallel.config"
                $parallelConfig = [xml](Get-Content $parallelConfigPath)
                $currentDate = (Get-Date).ToString("yyyyMMdd_hh-mm-s")
                $backup = $parallelConfigPath + "__$currentDate"
                Write-Message "Backing up Sitecore.Publishing.Parallel.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
                $parallelConfig.Save($backup)
                $backupFiles.Add($backup)
                $maxDegrees = $script:configSettings.WebServer.CMServerSettings.Publishing.Parallel.MaxDegreesOfParallelism
                $parallelConfig.configuration.SelectSingleNode("sitecore/settings/setting[@name='Publishing.MaxDegreeOfParallelism']").ChildNodes[0].InnerText = $maxDegrees
                Write-Message "Saving changes to Sitecore.Publishing.Parallel.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
                $parallelConfig.Save($parallelConfigPath)


                # Edit Sitecore.Publishing.DedicatedInstance.config
                if (!$script:configSettings.WebServer.CMServerSettings.Publishing.DisableScheduledTaskExecution)
                {
                    $file = Get-ChildItem -Recurse -Filter "Sitecore.Publishing.DedicatedInstance.config" -Path (Join-Path $installPath -ChildPath "Website")
                    $dedicatedInstanceConfigPath = $file.FullName
                    $dedicatedInstanceConfig = [xml](Get-Content $dedicatedInstanceConfigPath)
                    $currentDate = (Get-Date).ToString("yyyyMMdd_hh-mm-s")
                    $backup = $dedicatedInstanceConfigPath + "__$currentDate"
                    Write-Message "Backing up Sitecore.Publishing.DedicatedInstance.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
                    $dedicatedInstanceConfig.Save($backup)
                    $backupFiles.Add($backup)
                    $node = $dedicatedInstanceConfig.configuration.SelectSingleNode("sitecore/scheduling/frequency")
                    $node.ParentNode.InnerXml = $node.ParentNode.InnerXml.Replace($node.OuterXml, $node.OuterXml.Insert(0, "<!--").Insert($node.OuterXml.Length+4, "-->"))
                    Write-Message "Saving changes to Sitecore.Publishing.DedicatedInstance.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
                    $dedicatedInstanceConfig.Save($dedicatedInstanceConfigPath)
                }
            }
        }
    }
    #endregion

    #region Sitecore.ContentSearch.DefaultConfigurations.config
    if (Test-ProcessingServerRole)
    {
        $searchConfigPath = Join-Path $installPath -ChildPath "Website\App_Config\Include\Sitecore.ContentSearch.DefaultConfigurations.config"
        $searchConfig = [xml](Get-Content $searchConfigPath)
        $backup = $searchConfigPath + "__$currentDate"
        Write-Message "Backing up Sitecore.ContentSearch.DefaultConfigurations.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $searchConfig.Save($backup)
        $backupFiles.Add($backup)

        # Comment out web-related index strategies
        $nodes = $searchConfig.configuration.SelectNodes("sitecore/contentSearch/indexConfigurations/indexUpdateStrategies/*/param[@desc='database'][text()='web']")
        $total = $nodes.Count
        for ($i=0; $i -lt $total; $i++)
        {
            Write-Message "Commenting out web-related index update strategy" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
            $nodes = $searchConfig.configuration.SelectNodes("sitecore/contentSearch/indexConfigurations/indexUpdateStrategies/*/param[@desc='database'][text()='web']")

            $strategy = $nodes[0].ParentNode 
            $strategy = Remove-ChildXmlComments $strategy
            $strategy.ParentNode.InnerXml = $strategy.ParentNode.InnerXml.Replace($strategy.OuterXml, $strategy.OuterXml.Insert(0, "<!--").Insert($strategy.OuterXml.Length+4, "-->"))
        }

        Write-Message "Saving changes to Sitecore.ContentSearch.DefaultConfigurations.config" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $searchConfig.Save($searchConfigPath)
    }
    #endregion

    #endregion

    Write-Message "Modifying config files complete!" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    return $backupFiles
}

function Add-AppPoolIdentityToLocalGroup([string]$groupName, [string]$iisSiteName)
{
    if ($script:configSettings.WebServer.AppPoolIdentity -eq "ApplicationPoolIdentity")
    {
        $domain = "IIS APPPOOL"
        $site = Get-Item "IIS:\sites\$iisSiteName"
        $userName = $site.applicationPool
    }
    elseif ($script:configSettings.WebServer.AppPoolIdentity -eq "NetworkService")
    {
        $domain = "NT AUTHORITY"
        $userName = "Network Service"
    }
    else
    {
        $split = $script:configSettings.WebServer.AppPoolIdentity.split("\")
        $domain = $split[0]
        $userName = $split[1]
    }

    if (Test-IsUserMemberOfLocalGroup $groupName $userName)
    {
        Write-Message "$userName is already a member of $groupName" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }
    else
    {
        $group = [ADSI]"WinNT://$env:COMPUTERNAME/$groupName,group"
        $group.Add("WinNT://$domain/$userName,user")
        Write-Message "$userName added as a member of $groupName" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }
}

function Set-FileSystemPermissions([string]$iisSiteName)
{
    $installPath = $script:configSettings.WebServer.SitecoreInstallPath

    # Get app pool from site name
    $site = Get-Item "IIS:\sites\$iisSiteName" 
    $appPoolName = $site.applicationPool
    $pool = Get-Item IIS:\AppPools\$appPoolName

    $identityName = $pool.processModel.userName
    if ($pool.processModel.identityType.Equals("ApplicationPoolIdentity"))
    {
        $identityName = "IIS APPPOOL\$appPoolName"
    }

    # Set ACLs for "Website"
    $folderPath = Join-Path $installPath -ChildPath "Website"
    Set-AclForFolder $identityName "Modify" $folderPath
    Set-AclForFolder "IUSR" "Read" $folderPath

    # Set ACLs for "Data"
    $folderPath = Join-Path $installPath -ChildPath "Data"
    Set-AclForFolder $identityName "Modify" $folderPath
}

function Block-AnonymousUsers([string]$iisSiteName)
{
    Write-Message "Blocking anonymous access to sensitive folders on server." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    $filter = "/system.WebServer/security/authentication/anonymousAuthentication"
    $folderList = @("/App_Config", "/sitecore/admin", "/sitecore/debug", "/sitecore/shell/WebService")
    foreach ($folder in $folderList)
    {
        Set-WebConfigurationProperty -Filter $filter -PSPath IIS:\ -Name enabled -Location "$iisSiteName$folder" -Value false
        Write-Message "Blocked folder: $folder" "White" -WriteToLogOnly $TRUE -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }
}

function Revoke-ExecutePermission([string]$iisSiteName, [string]$folderPath)
{
    Write-Message "Denying execute permission on the $folderPath folder." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    Set-WebConfigurationProperty /system.WebServer/handlers "IIS:\sites\$iisSiteName\$folderPath" -Name accessPolicy -value "Read"
}

function Protect-ConnectionStrings
{
    Write-Message "Encrypting the contents of ConnectionString.config." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    $webrootPath = Join-Path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath "Website"
    $args = "-pef connectionStrings " + $webrootPath
    Start-Process -FilePath (Get-AspNetRegIisPath) -ArgumentList $args
}

function Set-SecuritySettings([string]$iisSiteName)
{
    Write-Message "`nApplying recommended security settings..." "Green" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

    Set-FileSystemPermissions $iisSiteName

    Add-AppPoolIdentityToLocalGroup "IIS_IUSRS" $iisSiteName
    Add-AppPoolIdentityToLocalGroup "Performance Monitor Users" $iisSiteName

    if ($script:configSettings.WebServer.EncryptConnectionStrings)
    {
        Protect-ConnectionStrings
    }

    if ($script:configSettings.WebServer.CDServerSettings.Enabled)
    {
        if ($script:configSettings.WebServer.CDServerSettings.ApplyIPWhitelist)
        {
            Set-IpRestrictions $iisSiteName
        }

        if ($script:configSettings.WebServer.CDServerSettings.PreventAnonymousAccess)
        {
            Block-AnonymousUsers $iisSiteName
        }

        if ($script:configSettings.WebServer.CDServerSettings.DenyExecutePermission)
        {
            Revoke-ExecutePermission $iisSiteName "temp"
            Revoke-ExecutePermission $iisSiteName "upload"
        }
    }

    if (Test-ProcessingServerRole)
    {
        if ($script:configSettings.WebServer.CMServerSettings.Processing.ApplyIPWhitelist)
        {
            Set-IpRestrictions $iisSiteName
        }

        if ($script:configSettings.WebServer.CMServerSettings.Processing.PreventAnonymousAccess)
        {
            Block-AnonymousUsers $iisSiteName
        }
    }
    
    if(Test-PublishingServerRole)
    {
        Enable-ApplicationInitializationWebsiteSettings $iisSiteName    
        Set-IpRestrictions $iisSiteName
    }

    Write-Message "Security settings complete!" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
}

function Get-SiteUrl
{
    $binding = $script:configSettings.WebServer.IISBindings | Select-Object -First 1

    $hostname = $binding.HostHeader
    if ($hostname.Length -eq 0)
    {
        $hostname = $binding.IP
        if ($hostname -eq "*")
        {
            $hostname = "127.0.0.1"
        }
    }

    $url = "http://" + $hostname

    $port = $binding.Port
    if ($port -ne "80")
    {
        $url = $url + ":" + $port
    }

    return $url
}

function Start-Browser([string]$url)
{
    if ([string]::IsNullOrEmpty($url))
    {
        $url = Get-SiteUrl
    }
    Write-Message "`nLaunching site in browser: $url" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
    $ie = new-object -comobject "InternetExplorer.Application" 
    $ie.visible = $true
    $ie.navigate($url)
}

function Set-DefaultAdminPassword()
{
    $password = $script:configSettings.WebServer.CMServerSettings.DefaultSitecoreAdminPassword
    $passwordHash = $script:configSettings.WebServer.PasswordHashAlgorithm

    if (!$script:configSettings.WebServer.CMServerSettings.Enabled)
    {
        return
    }
    
    if (!($password) -and ([string]::IsNullOrEmpty($passwordHash)))
    {
        return
    }
    
    if (!([string]::IsNullOrEmpty($passwordHash)) -and ([string]::IsNullOrEmpty($password)))
    {
        $password = "b"
        Write-Message "Password Hash Algorithm has been strengthened, but no admin password provided. Admin password will be set to default." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }
    
    Write-Message "Attempting to change default Sitecore admin's password..." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    
    # Thanks to Grant Killian for the basis of this idea: https://grantkillian.wordpress.com/2016/02/04/programmatically-setting-the-sitecore-admin-password-and-how-to-secure-it/
    $html = "<%@ Language=`"C#`" %>`r`n"
    $html += "<script runat=server>`r`n"
    $html += "  public void Page_Load(object sender, EventArgs e)`r`n"
    $html += "  {`r`n"
    $html += "    string newPwd = `"$password`";`r`n"
    $html += "    if (string.IsNullOrWhiteSpace(newPwd))`r`n"
    $html += "    {`r`n"
    $html += "      lblSummary.Text = `"No action was taken. A new password was not supplied.`";`r`n"
    $html += "      hfPasswordChanged.Value = `"false`";`r`n"
    $html += "    }`r`n"
    $html += "    else`r`n"
    $html += "    {`r`n"
    $html += "      System.Web.Security.MembershipUser user = GetDefaultSitecoreAdmin(); `r`n"
    $html += "      Sitecore.Diagnostics.Assert.IsNotNull((object) user, typeof (Sitecore.Security.Accounts.User)); `r`n"
    $html += "      string resetPassword = user.ResetPassword();`r`n"
    $html += "      user.ChangePassword(resetPassword, newPwd);`r`n"
    $html += "      lblSummary.Text = `"New password set to `" + newPwd + `" for UserName `" + user.UserName;  `r`n"
    $html += "      hfPasswordChanged.Value = `"true`";`r`n"
    $html += "    }`r`n"
    $html += "  }`r`n"
    $html += "  System.Web.Security.MembershipUser GetDefaultSitecoreAdmin()`r`n"
    $html += "  {`r`n"
    $html += "    return System.Web.Security.Membership.GetUser(@`"sitecore\admin`");`r`n"
    $html += "  }`r`n"
    $html += "</script>`r`n"
    $html += "<html>`r`n"
    $html += "  <head></head>`r`n"
    $html += "  <body>`r`n"
    $html += "    <form id=`"MyForm`" runat=`"server`">`r`n"
    $html += "      <asp:HiddenField id=`"hfPasswordChanged`" runat=`"server`" value=`"false`" />`r`n"
    $html += "      <asp:Label runat=`"server`" ID=`"lblSummary`"></asp:Label>`r`n"
    $html += "    </form>`r`n"
    $html += "  </body>`r`n"
    $html += "</html>"
    
    $pagePath = "\sitecore\admin\SetDefaultAdminPassword.aspx"
    $filePath = Join-Path $script:configSettings.WebServer.SitecoreInstallPath -ChildPath "Website"
    $filePath = Join-Path $filePath -ChildPath $pagePath
    $html | out-file -FilePath $filePath

    # Request the page
    $baseUrl = [System.Uri](Get-SiteUrl)
    $combinedUrl = New-Object System.Uri($baseUrl, $pagePath)
    $result = Invoke-WebRequest $combinedUrl.ToString()
    Remove-Item -Path $filePath

    # Examine page content
    [xml]$contentXml = $result.Content
    try
    {
        $passwordSet = [System.Convert]::ToBoolean($contentXml.html.body.form.input.value) 
    }
    catch
    {
        $passwordSet = $false
    }

    if ($passwordSet)
    {
        Write-Message "...password was successfully changed." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }
    else
    {
        Write-Message "...unable to change default Sitecore admin password!" "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }
}
#endregion

function Initialize-SitecoreInstaller([string]$configPath)
{
    [xml]$configXml = Read-InstallConfigFile $configPath
    if ($configXml -eq $null)
    {
        throw "configXml is null"
    }

    New-ConfigSettings $configXml
        
    if (!(Test-PreRequisites))
    {
        throw "Please satisfy pre-requisites and try again."
    }

    $configIsValid = Test-ConfigurationSettings
    if (!$configIsValid)
    {
        throw "A bad configuration setting was found."
    }
    
    Add-CalculatedPropertiesToConfigurationSettings

    # Create install directory    
    if (!(Test-Path $script:configSettings.WebServer.SitecoreInstallPath))
    {
        New-Item $script:configSettings.WebServer.SitecoreInstallPath -type directory -force | Out-Null
    }

    $versionToInstall = Get-SitecoreVersion -GetFromZip
    if ($versionToInstall -eq "10.0")
    {
        New-SitecoreConfigurationCsvFile $script:configSettings.SitecoreConfigSpreadsheetPath
    }
    else
    {
        $script:configSettings.ConfigurationFilesCsvPath = $null
    }
}

function Install-SitecoreApplication([string]$configPath, [bool]$SuppressOutputToScreen=$FALSE)
{
    $hostScreenAvailable = !$SuppressOutputToScreen
    $deleteBackupFiles = $TRUE

    try
    {
        Initialize-SitecoreInstaller $configPath
    }
    catch [Exception]
    {
        if (!([string]::IsNullOrEmpty($_.Exception.Message)))
        {
            Write-Message ($_.Exception.Message) "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        }
        if (!([string]::IsNullOrEmpty($_.Exception.ErrorRecord.ScriptStackTrace)))
        {
            Write-Message ($_.Exception.ErrorRecord.ScriptStackTrace) "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        }
        Write-Message "Aborting install: No action taken." "Red" -WriteToLog $FALSE -HostConsoleAvailable $hostScreenAvailable
        return
    }

    $stopWatch = [Diagnostics.Stopwatch]::StartNew()
    $date = Get-Date    
    $message = "Starting Sitecore install [Sitecore.Kernel.dll version $(Get-SitecoreVersion -GetFromZip -GetFullVersion)] - $date" 
    Write-Message $message "Green" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

    $isCMRole = $false
    if ($script:configSettings.WebServer.CMServerSettings.Enabled)
    {
        $role = "CM"
        if (Test-PublishingServerRole)
        {
            $role = "Publishing Server"
        }
        elseif (Test-ProcessingServerRole)
        {
            $role = "Processing Server"            
        }
        $isCMRole = $true
    }
    elseif ($script:configSettings.WebServer.CDServerSettings.Enabled)
    {
        $role = "CD"
    }
    Write-Message "Configuring server for [$role] role." "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

    if ($isCMRole -and !$script:configSettings.WebServer.CMServerSettings.DefaultSitecoreAdminPassword)
    {
        Write-Message "Caution: the default Sitecore admin password should be changed. A new password wasn't supplied." "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }

    if (Test-ShouldSetAutogrowth)
    {
        Write-Message "Caution: cannot set autogrowth for web database(s) because database configuration is disabled." "Yellow" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
    }

    try
    {
        $loginName = $script:configSettings.Database.SqlLoginForInstall
        Write-Message "Using $loginName as the SQL login during installation" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $loginName = Get-SqlLoginAccountForDataAccess
        Write-Message "Using $loginName as the SQL login for data access" "White" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

        Copy-SitecoreFiles

        [System.Collections.Generic.List[string]]$backupFiles = Set-ConfigurationFiles

        $iisSiteName = Initialize-WebSite

        Set-SecuritySettings $iisSiteName

        Initialize-SitecoreDatabases

        Set-DefaultAdminPassword
    }
    catch [Exception]
    {
        Write-Message  ($_.Exception.Message) "Red" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        Write-Message "Aborting install." "Red" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable
        $deleteBackupFiles = $FALSE
    }
    finally
    {
        if ($deleteBackupFiles)
        {
            Remove-BackupFiles $backupFiles
        }

        $stopWatch.Stop()
        $message = "`nSitecore install finished - Elapsed time {0}:{1:D2} minute(s)" -f $stopWatch.Elapsed.Minutes, $stopWatch.Elapsed.Seconds
        Write-Message $message "Green" -WriteToLog $TRUE -HostConsoleAvailable $hostScreenAvailable

        Start-Browser
    }
}

Install-SitecoreApplication $ConfigPath -SuppressOutputToScreen $FALSE
