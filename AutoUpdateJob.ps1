$ConfigData = Get-Content -Path "$env:APPDATA\ARK-Ascended-Server-Manager\config.json" -Raw | ConvertFrom-Json

function Get-Mcrcon {
    $mcrconPath = Join-Path $env:TEMP "mcrcon.exe"
    if (-not (Test-Path -Path $mcrconPath)) {
        $downloadURL = "https://github.com/Tiiffi/mcrcon/releases/download/v0.7.2/mcrcon-0.7.2-windows-x86-64.zip"
        $zipPath = Join-Path $env:TEMP "mcrcon.zip"
        Invoke-RestMethod -Uri $downloadURL -OutFile $zipPath
        Expand-Archive -Path $zipPath -DestinationPath $env:TEMP -Force
        Remove-Item -Path $zipPath -Force
    }
    return $mcrconPath
}

function Send-RconCommand {
    param ($ServerIP, $RCONPort, $AdminPassword, $Command)

    try {
        $mcrconPath = Get-Mcrcon
        $mcrconOutput = Invoke-Expression "$mcrconPath -H $ServerIP -P $RCONPort -p '$AdminPassword' '$Command'"
        $mcrconOutput = $mcrconOutput -replace "`r`n|`r|`n|`n", "`n"
        return "$mcrconOutput`n"
    } catch {
        throw "An error occurred: $_"
    }
}

$stopServerCommand = "doexit"
$mcrconOutput = Send-RconCommand -ServerIP $ConfigData.ServerIP -RCONPort $ConfigData.RCONPort -AdminPassword $ConfigData.AdminPassword -Command $stopServerCommand

Write-Output "Command: $stopServerCommand"
Write-Output "Response: $($mcrconOutput -join "`r`n")"

$processName = "ArkAscendedServer"
$runningProcess = Get-Process -Name $processName -ErrorAction SilentlyContinue

if ($runningProcess) {
    Stop-Process -Name $processName -Force
} else {
    Write-Host "The Prozess '$processName' not running."
}

Start-Process -FilePath "$($ConfigData.SteamCMD)\SteamCMD\steamcmd.exe" -ArgumentList "+force_install_dir $($ConfigData.ARKServerPath) +login anonymous +app_update $($ConfigData.AppID) +quit" -Wait

foreach ($property in @("ServerMAP", "ServerName", "Port", "QueryPort", "Password", "AdminPassword", "Mods", "MaxPlayers")) {
    if ($ConfigData.$property -ne $null) {
        $ConfigData.$property = $ConfigData.$property.Trim()
    }
}

$ForceRespawnDinosValue = if ($ConfigData.ForceRespawnDinos) { "ForceRespawnDinos" } else { "" }

$ServerArguments = [System.String]::Format('start {0}?listen?SessionName="{1}"?Port={2}?QueryPort={3}?ServerPassword="{4}"?MaxPlayers={5}?RCONEnabled={6}?RCONPort={7}?ServerAdminPassword="{8}" -{9} -automanagedmods -mods={10}, -{11}', $ConfigData.ServerMAP, $ConfigData.ServerName, $ConfigData.Port, $ConfigData.QueryPort, $ConfigData.Password, $ConfigData.MaxPlayers, $ConfigData.RCONEnabled, $ConfigData.RCONPort, $ConfigData.AdminPassword, $ConfigData.BattleEye, $ConfigData.Mods, $ForceRespawnDinosValue)

Write-Output "ServerArguments: $ServerArguments"

$ServerPath = Join-Path -Path $ConfigData.ARKServerPath -ChildPath "ShooterGame\Binaries\Win64\ArkAscendedServer.exe"

if (-not [string]::IsNullOrWhiteSpace($ServerArguments)) {
    Start-Process -FilePath $ServerPath -ArgumentList $ServerArguments -NoNewWindow
} else {
    Write-Output "Error: ServerArguments are null or spaces."
}
