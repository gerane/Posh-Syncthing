Function Add-SyncthingDevice
{
    [CmdletBinding()]
    Param
    (            
        [String]$Computer="localhost",

        [String]$Port="8384",

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName = $true)]
        [String]$DeviceID,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$Name,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$NewName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Array]$Addresses = @('dynamic'),

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$Compression = 'metadata',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$CertName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Boolean]$Introducer = $true
    )

    Process
    {
        if($SyncthingConfig -eq $null)
        {
            $SyncthingConfig = Get-SyncthingConfig -Computer $Computer -Port $Port
        }

        $Device = [PSCustomObject]@{
            deviceID    = $DeviceID       
            name        = $Name     
            addresses   = @($Addresses)
            compression = $Compression
            certName    = $CertName
            introducer  = $Introducer
        }

        $SyncthingConfig.devices += $Device
        Set-SyncthingConfig -Computer $Computer -Port $Port -SyncthingConfig $SyncthingConfig
    }
}

Function Update-SyncthingDevice
{
    [CmdletBinding()]
    Param
    (            
        [String]$Computer="localhost",

        [String]$Port="8384",

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName = $true)]
        [String]$DeviceID,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$Name,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$NewName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Array]$Addresses = @('dynamic'),

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$Compression = 'metadata',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$CertName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Boolean]$Introducer = $true
    )

    Process
    {
        if($SyncthingConfig -eq $null)
        {
            $SyncthingConfig = Get-SyncthingConfig -Computer $Computer -Port $Port
        }

        if (! $NewName)
        {
            $NewName = $Name
        }

        $Device = [PSCustomObject]@{
            deviceID    = $DeviceID       
            name        = $NewName     
            addresses   = @($Addresses)
            compression = $Compression
            certName    = $CertName
            introducer  = $Introducer
        }
       

        $SyncthingConfig.devices | ForEach-Object { 
            if ($_.name -eq $Name)
            {
                $Index = ([Array]::IndexOf($SyncthingConfig.devices,$_))
                $SyncthingConfig.devices[$Index] = $Device
            }
        }
     
        Set-SyncthingConfig -Computer $Computer -Port $Port -SyncthingConfig $SyncthingConfig
    }
}

Function Add-SyncthingFolder
{
    [CmdletBinding()]
    Param
    (
        [String]$Computer="localhost",

        [String]$Port="8384", 

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [String]$FolderId,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$Label,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$Path,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$Type = 'readwrite',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [PSCustomObject]$Devices,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$rescanIntervalS = '60',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [boolean]$IgnorePerms = $False,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [boolean]$AutoNormalize = $True,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$MinDiskFreePct = '1',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [PSCustomObject]$Versioning = [PSCustomObject]@{type='simple';params=[PSCustomObject]@{keep='5'}},

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$Copiers = '0',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$Pullers = '0',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$Hashers = '0',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$Order = 'random',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [boolean]$IgnoreDelete = $False,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$scanProgressIntervalS = '0',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$PullerSleepS = '0',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$PullerPauseS = '0',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$MaxConflicts = '10',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [boolean]$DisableSparseFiles = $False,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [boolean]$DisableTempIndexes = $False
    )

    Process
    {
        if(!($SyncthingConfig))
        {
            $SyncthingConfig = Get-SyncthingConfig -Computer $Computer -Port $Port
        }

        $Folder = [PSCustomObject]@{
            id                    = $FolderId
            label                 = $Label
            path                  = $Path
            type                  = $Type
            devices               = $Devices
            rescanIntervalS       = $rescanIntervalS
            ignorePerms           = $IgnorePerms        
            autoNormalize         = $AutoNormalize
            mindDiskFreePct       = $MinDiskFreePct
            versioning            = $Versioning        
            copiers               = $Copiers
            pullers               = $Pullers        
            hashers               = $Hashers
            order                 = $Order
            ignoreDelete          = $IgnoreDelete
            scanProgressIntervalS = $ScanProgressIntervalS
            pullerSleepS          = $PullerSleepS
            pullerPauseS          = $PullerPauseS
            maxConflicts          = $MaxConflicts
            disableSparseFiles    = $DisableSparseFiles
            disableTempIndexes    = $DisableTempIndexes             
        }

        Write-Verbose "Adding folder to config"
        $SyncthingConfig.folders += $Folder
        Set-SyncthingConfig -Computer $Computer -Port $Port -SyncthingConfig $SyncthingConfig
    }
}

function Update-SyncthingFolder
{
    [cmdletbinding()]
    param
    (
        [String]$Computer="localhost",

        [String]$Port="8384", 

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [String]$FolderId,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('NewId')]
        [String]$NewFolderId,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$Label,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$Path,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$Type = 'readwrite',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [PSCustomObject]$Devices,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$rescanIntervalS = '60',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [boolean]$IgnorePerms = $False,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [boolean]$AutoNormalize = $True,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$MinDiskFreePct = '1',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [PSCustomObject]$Versioning = [PSCustomObject]@{type='simple';params=[PSCustomObject]@{keep='5'}},

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$Copiers = '0',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$Pullers = '0',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$Hashers = '0',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$Order = 'random',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [boolean]$IgnoreDelete = $False,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$scanProgressIntervalS = '0',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$PullerSleepS = '0',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$PullerPauseS = '0',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Int32]$MaxConflicts = '10',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [boolean]$DisableSparseFiles = $False,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [boolean]$DisableTempIndexes = $False
    )

    Process
    {
        if(!($SyncthingConfig))
        {
            $SyncthingConfig = Get-SyncthingConfig -Computer $Computer -Port $Port
        }

        if (! $NewFolderId)
        {
            $NewFolderId = $FolderId
        }

        $Folder = [PSCustomObject]@{
            id                    = $NewFolderId
            label                 = $Label
            path                  = $Path
            type                  = $Type
            devices               = @($Devices)
            rescanIntervalS       = $rescanIntervalS
            ignorePerms           = $IgnorePerms        
            autoNormalize         = $AutoNormalize
            mindDiskFreePct       = $MinDiskFreePct
            versioning            = $Versioning        
            copiers               = $Copiers
            pullers               = $Pullers        
            hashers               = $Hashers
            order                 = $Order
            ignoreDelete          = $IgnoreDelete
            scanProgressIntervalS = $ScanProgressIntervalS
            pullerSleepS          = $PullerSleepS
            pullerPauseS          = $PullerPauseS
            maxConflicts          = $MaxConflicts
            disableSparseFiles    = $DisableSparseFiles
            disableTempIndexes    = $DisableTempIndexes             
        }

        Write-Verbose "Adding folder to config"
        
        $SyncthingConfig.folders | ForEach-Object { 
            if ($_.id -eq $FolderID)
            {
                $Index = ([Array]::IndexOf($SyncthingConfig.folders,$_))
                $SyncthingConfig.folders[$Index] = $Folder
            }
        }

        Set-SyncthingConfig -Computer $Computer -Port $Port -SyncthingConfig $SyncthingConfig
        
    }
}

function Remove-SyncthingFolder
{
    [cmdletbinding()]
    param
    (
        [String]$Computer="localhost",

        [String]$Port="8384", 

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [String]$FolderId        
    )

    Process
    {
        if(!($SyncthingConfig))
        {
            $SyncthingConfig = Get-SyncthingConfig -Computer $Computer -Port $Port
        }
        
        $NewFolders = @()
        $SyncthingConfig.folders | ForEach-Object { 
            if ($_.id -ne $FolderID)
            {
                
                $NewFolders += $_
            }
            $SyncthingConfig.folders = $NewFolders
        }

        Set-SyncthingConfig -Computer $Computer -Port $Port -SyncthingConfig $SyncthingConfig
    }
}

Function Get-SyncthingAPIkey
{
    [CmdletBinding()]
    Param
    (
        [String]$Computer="localhost",
        
        [String]$Port="8384"   
    )

    Process
    {
        $PatternMatch = Get-Content "$Env:Appdata\SyncTrayzor\config.xml" | Select-String "^.*<SyncthingApiKey>(.*)</SyncthingApiKey>.*$"
        $ApiKey = $PatternMatch.Matches.Groups[1].value

        return $ApiKey
    }
}

Function Get-SyncthingConfig    
{
    [CmdletBinding()]
    Param
    (
        [String]$Computer="localhost",
        
        [String]$Port="8384"   
    )

    Process
    {
        $ApiKey = Get-SyncthingAPIkey -Computer $Computer -Port $Port
        $Url = "http://$Computer"+":"+"$Port/rest/system/config"
        
        Write-Verbose "Getting config from $url"
        
        $SyncthingConfig = Invoke-RestMethod -Uri $Url -Method Get -Headers @{"X-API-Key" = $ApiKey}
        
        return $SyncthingConfig
    }
}

Function Get-SyncthingDeviceID
{
    <#
        .SYNOPSIS
        Gets the device ID of Syncthing.
 
        .DESCRIPTION
        This command gets the device ID of Syncthing.
 
        .EXAMPLE
        Get-SyncthingDeviceID -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Get-SyncthingDeviceID
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
    #>

    [CmdletBinding()]
    Param
    (
        [String]$Computer="localhost",

        [String]$Port="8384"   
    )

        $SyncthingConfig = Get-SyncthingStatus -Computer $Computer -Port $Port
        $MyDeviceID = $SyncthingConfig.myID
        
        return $MyDeviceID
    }

Function Get-SyncthingDevices
{
    <#
        .SYNOPSIS
        Gets the devices of Syncthing.
 
        .DESCRIPTION
        This command gets all the devices of Syncthing.
 
        .EXAMPLE
        Get-SyncthingDevices -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Get-SyncthingDevices
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
    #>

    [CmdletBinding()]
    Param
    (
        [String]$Computer="localhost",

        [String]$Port="8384"   
    )

    Process
    {
        $SyncthingConfig = Get-SyncthingConfig -Computer $Computer -Port $Port
        $Devices = $SyncthingConfig.devices
        
        return $Devices
    }
}

Function Get-SyncthingFilesRemaining
{
    <#
        .SYNOPSIS
        Gets the remaining files of a Syncthing folder.
 
        .DESCRIPTION
        This command gets the remaining files of a given Syncthing Folder.
 
        .EXAMPLE
        Get-SyncthingFolders -Computer 192.168.1.100 -Port 8080 -FolderID Private_Folder
 
        .EXAMPLE
        Get-SyncthingFolders -FolderID Private_Folder
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384

        .PARAMETER FolderID
        The FolderID of the folder you wish to get a list of remaining files
        
    #>

    [CmdletBinding()]
    Param
    (
        [String]$Computer="localhost",

        [String]$Port="8384",

        [Parameter(Mandatory=$true)]
        [String]$FolderID 
    )

    Process
    {
        $ApiKey = Get-SyncthingAPIkey -Computer $Computer -Port $Port
        $BaseUrl = "http://$Computer"+":"+"$Port/rest/db/need"
        $Url = $BaseUrl+"?folder=$FolderID"
        
        $Files = Invoke-RestMethod -Uri $Url -Method Get -Headers @{"X-API-Key" = $ApiKey}
        
        return $Files
    }
}

Function Get-SyncthingFolders
{
    <#
        .SYNOPSIS
        Gets the folders of Syncthing.
 
        .DESCRIPTION
        This command gets all the folders of Syncthing.
 
        .EXAMPLE
        Get-SyncthingFolders -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Get-SyncthingFolders
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
    #>

    [CmdletBinding()]
    Param
    (
        [String]$Computer="localhost",

        [String]$Port="8384"   
    )

    Process
    {
        $SyncthingConfig = Get-SyncthingConfig -Computer $Computer -Port $Port
        $Folders = $SyncthingConfig.folders

        return $Folders
    }
}

Function Get-SyncthingStatus
{
    <#
        .SYNOPSIS
        Gets the current Syncthing status.
 
        .DESCRIPTION
        This command gets the current status of Syncthing.
 
        .EXAMPLE
        Get-SyncthingStatus -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Get-SyncthingStatus
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
    #>

    [CmdletBinding()]
    Param
    (
        [String]$Computer="localhost",
        [String]$Port="8384"   
    )

    Process
    {
        $ApiKey = Get-SyncthingAPIkey
        $Url = "http://$Computer"+":"+"$Port/rest/system/status"
        $Status = Invoke-RestMethod -Uri $Url -Method Get -Headers @{"X-API-Key" = $ApiKey}
     
        return $Status
    }
}

Function Get-SyncthingSyncStatus
{
    <#
        .SYNOPSIS
        Gets the Syncthing Sync Status.
 
        .DESCRIPTION
        This command gets the sync status of all folders. Takes a lot of CPU, use sparingly.
 
        .EXAMPLE
        Get-SyncthingSyncStatus -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Get-SyncthingSyncStatus
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
    #>

    [CmdletBinding()]
    Param
    (
        [String]$Computer="localhost",

        [String]$Port="8384"
    )

    Process
    {
        $ApiKey = Get-SyncthingAPIkey -Computer $Computer -Port $Port
        $SyncStatusArray = @()

        foreach ($FolderID in ((Get-SyncthingFolders -Computer $Computer -Port $Port).id))
        {
            $BaseUrl = "http://$Computer"+":"+"$Port/rest/db/status"
            $Url = $BaseUrl+"?folder=$FolderID"
            $Completion = Invoke-RestMethod -Uri $Url -Method Get -Headers @{"X-API-Key" = $ApiKey}
            $MegaBytesRemaining = [math]::Round($Completion.needBytes/1000000)

            $Files = Get-SyncthingFilesRemaining -Computer $Computer -Port $Port -FolderID $FolderID

            $SyncStatus = New-Object -TypeName psobject
            $SyncStatus | Add-Member -MemberType NoteProperty -Name FolderID -Value $FolderID
            $SyncStatus | Add-Member -MemberType NoteProperty -Name MegaBytesRemaining -Value $MegaBytesRemaining
            $SyncStatus | Add-Member -MemberType NoteProperty -Name FilesRemaining -Value $Completion.needFiles
            $SyncStatus | Add-Member -MemberType NoteProperty -Name QueuedFiles -Value $Files.queued.name
            $SyncStatus | Add-Member -MemberType NoteProperty -Name RestFiles -Value $Files.rest.name
            $SyncStatusArray += $SyncStatus
        }
        
        return $SyncStatusArray
    }
}

Function Get-SyncthingVersion    
{
    <#
        .SYNOPSIS
        Gets the current Syncthing version.
 
        .DESCRIPTION
        This command gets the current version of Syncthing.
 
        .EXAMPLE
        Get-SyncthingVersion -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Get-SyncthingConfig
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
    #>

    [CmdletBinding()]
    Param
    (
        [String]$Computer="localhost",

        [String]$Port="8384"   
    )

    Process
    {
        $ApiKey = Get-SyncthingAPIkey -Computer $Computer -Port $Port
        $Url = "http://$Computer"+":"+"$Port/rest/system/upgrade"
        $Version = Invoke-RestMethod -Uri $Url -Method Get -Headers @{"X-API-Key" = $ApiKey}
        
        return $Version
    }
}


Function Restart-Syncthing
{
    <#
        .SYNOPSIS
        Restarts Syncthing.
 
        .DESCRIPTION
        This command restarts Syncthing.
 
        .EXAMPLE
        Restart-Syncthing -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Restart-Syncthing
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
    #>

    [CmdletBinding()]
    Param
    (
        [String]$Computer="localhost",

        [String]$Port="8384"   
    )

    Process
    {
        $ApiKey = Get-SyncthingAPIkey -Computer $Computer -Port $Port
        $Url = "http://$Computer"+":"+"$Port/rest/system/restart"
        Invoke-RestMethod -Uri $Url -Method Post -Headers @{"X-API-Key" = $ApiKey} | Out-Null
        Write-Verbose "Syncthing is restarting"
    }
}

Function Set-SyncthingConfig
{
    <#
        .SYNOPSIS
        Sets the Syncthing Config.
 
        .DESCRIPTION
        This command sets the config of Syncthing. It converts the psobject to json and posts it to Syncthing. Gets applied only after syncthing restarts. Use Restart-Syncthing or the webui to do so.
 
        .EXAMPLE
        Set-SyncthingConfig -Computer 192.168.1.100 -Port 8080 -SyncthingConfig $SyncthingConfig
 
        .EXAMPLE
        Set-SyncthingConfig -SyncthingConfig $SyncthingConfig
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384

        .PARAMETER Config
        The config object, originally from Get-SyncthingConfig
        
    #>

    [CmdletBinding()]
    Param
    (
        [String]$Computer="localhost",

        [String]$Port="8384",

        $SyncthingConfig
    )

    Process
    {
        $Url = "http://$Computer"+":"+"$Port/rest/system/config"
        $ApiKey = Get-SyncthingAPIkey -Computer $Computer -Port $Port
        $SyncthingConfigJson = $SyncthingConfig | ConvertTo-Json -Compress -Depth 6
        Write-Verbose "Posting Config to $Url"
 
        Invoke-RestMethod -Uri $Url -Method Post -Body $SyncthingConfigJson -Headers @{"X-API-Key" = $ApiKey} -ContentType application/json
    }
}

Function Stop-Syncthing
{
    <#
        .SYNOPSIS
        Shuts down syncthing.
 
        .DESCRIPTION
        This command shuts down Syncthing.
 
        .EXAMPLE
        Shutdown-Syncthing -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Shutdown-Syncthing
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
    #>
    
    [CmdletBinding()]
    Param
    (
        [String]$Computer="localhost",

        [String]$Port="8384"   
    )

    Process
    {
        $ApiKey = Get-SyncthingAPIkey -Computer $Computer -Port $Port
        $Url = "http://$Computer"+":"+"$Port/rest/system/shutdown"
        Invoke-RestMethod -Uri $Url -Method Post -Headers @{"X-API-Key" = $ApiKey} | Out-Null
        Write-Verbose "Syncthing has shut down"
    }
}
    
function Install-SyncTrayzor
{
    [CmdletBinding()]
    param()
    
    Process
    {
        Try
        {
            $Rest = Invoke-RestMEthod 'https://api.github.com/repos/canton7/SyncTrayzor/releases/latest'
            $Uri = $Rest.assets.browser_download_url | Where-Object { $_ -like '*SyncTrayzorSetup-x64.exe' }
            Invoke-RestMethod -Method Get -Uri $Uri -OutFile "$env:TEMP\SyncTrayzorSetup-x64.exe"

            Start-Process -FilePath "$env:TEMP\SyncTrayzorSetup-x64.exe" -ArgumentList "/VERYSILENT /NORESTART" -PassThru -WindowStyle Hidden -Wait
        }
        catch
        {
            Throw
        }
    }
}

#Function Install-Syncthing
#{
#    <#
#        .SYNOPSIS
#        Installs Syncthing.
# 
#        .DESCRIPTION
#        This Command downloads and installs the latest stable version of Syncthing.
# 
#        .EXAMPLE
#        Install-Syncthing -Path "C:\Program Files(x86)" -RunAtStartup $true
# 
#        .EXAMPLE
#        Install-Syncthing
# 
#        .PARAMETER Path
#        The path where Syncthing will get installed. Default is "C:".
#
#        .PARAMETER RunAtStartup
#        Whether or not Syncthing shall start automatically. Default is $false
#        
#    #>
#
#    [CmdletBinding()]
#    Param
#    (
#        [String]$Path="C:\",
#        [ValidateSet($true,$false)][string]$RunAtStartup=$false  
#    )
#
#    Process
#    {
#        if(!(Test-Path $Path))
#        {
#            Write-Verbose "Creating $Path"
#            New-Item -ItemType Directory -Path $Path -Force
#        }
#        
#        Write-Verbose "Getting latest release"
#        $htmlsyncthing = Invoke-WebRequest "https://github.com/syncthing/syncthing/releases" -DisableKeepAlive
#        $syncthingzipurl = "https://github.com" + ($htmlsyncthing.Links.href | Where-Object {$_ -like "*windows-amd64*"} | select -First 1)
#        Write-Verbose "Downloading Syncthing"
#        Invoke-WebRequest $syncthingzipurl -OutFile $env:TEMP\Syncthing.zip -DisableKeepAlive
#        Write-Verbose "Installing Syncthing"
#        Expand-Archive $env:TEMP\Syncthing.zip $Path -Force
#        Get-ChildItem $Path | Where-Object {$_.Name -like "*syncthing*"} | Rename-Item -NewName "Syncthing"
#
#        if($RunAtStartup -eq $true)
#        {
#            '"'+"$Path\Syncthing\syncthing.exe"+'"'+ ' -no-console -no-browser' | Out-File "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\syncthing.cmd"
#        }
#
#        Write-Verbose "Syncthing is installed. The exe is located in $($Path)\Syncthing"
#    }
#}

Export-ModuleMember *