Import-Module $Home\OneDrive\PowerShell\Modules\Posh-Syncthing\Posh-Syncthing.psm1 -Force

# Install SyncTrayzor
$Package = get-package -ProviderName Programs | Where-Object { $_.Name -like '*SyncTrayzor*' }
if (! $Package)
{
    Install-SyncTrayzor
}

Start-Process -FilePath "$Env:ProgramFiles\SyncTrayzor\SyncTrayzor.exe" -ArgumentList '-minimized' -WindowStyle Hidden
Start-Sleep -Seconds 5

$SyncthingConfig = Get-SyncthingConfig
if (!(Test-Path "$Home\OneDrive\Syncthing\Config\Devices.xml") -OR !(Test-Path "$Home\OneDrive\Syncthing\Config\Folders.xml")) { Throw "Config files are missing"}
$DevicesXml = Import-Clixml -Path "$Home\OneDrive\Syncthing\Config\Devices.xml"
$FoldersXml = Import-Clixml -Path "$Home\OneDrive\Syncthing\Config\Folders.xml"
$DeviceID = Get-SyncthingDeviceID

# Add Missing Devices
foreach ($Device in $DevicesXml)
{
    if ($SyncthingConfig.devices -notcontains $Device)
    {
        $Device | Add-SyncthingDevice -Introducer $true
    }
}
$SyncthingConfig = Get-SyncthingConfig
$Devices = Get-SyncthingDevices


# Folders
foreach ($folder in (Get-SyncthingFolders))
{
    if ($Folder.label -like '*default folder*' -OR $Folder.id -eq 'default')
    {
        Remove-SyncthingFolder -FolderId $folder.id
    }
}


$Folders = Get-SyncthingFolders
foreach ($Folder in $FoldersXml)
{
    if ($SyncthingConfig.folders.id -notcontains $Folder.Id)
    {
        if (! (Test-Path $folder.path -ErrorAction SilentlyContinue))
        {
            New-Item -Path $Folder.path -Force -ItemType Directory

            if (Test-Path "$Home\OneDrive\Syncthing\Config\stignore\${$folder.id}\.stignore" -ErrorAction SilentlyContinue)
            {
                Copy-Item -Path "$Home\OneDrive\Syncthing\Config\stignore\${$folder.id}\.stignore" -Destination "${$Folder.path}\.stignore" -Force
            }
        }

        $folder | Add-SyncthingFolder
    }
}


Get-SyncthingDevices | Export-Clixml -Path "$Home\OneDrive\Syncthing\Config\Devices.xml"
Get-SyncthingFolders | Export-Clixml -Path "$Home\OneDrive\Syncthing\Config\Folders.xml"