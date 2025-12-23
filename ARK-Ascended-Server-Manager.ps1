#requires -version 5.1
param(
    [ValidateSet('Gui','FirstInstall','UpdateServerFiles')]
    [string]$Mode = 'Gui',

    # GUI passes a file path here. Worker writes "0" on success or "1`r`n<error>" on failure.
    [string]$StatusFile = ""
)

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# =========================
# Global / Paths / Defaults
# =========================
$script:AppName     = "ARK Ascended Server Manager"
$script:AppFolder   = Join-Path $env:APPDATA "ARK-Ascended-Server-Manager"
$script:ConfigPath  = Join-Path $script:AppFolder "Config.json"
$script:ToolsFolder = Join-Path $script:AppFolder "tools"
$script:LogsFolder  = Join-Path $script:AppFolder "logs"
$script:LogFile     = Join-Path $script:LogsFolder "app.log"

$script:McrconExe   = Join-Path $script:ToolsFolder "mcrcon.exe"
$script:AutoUpdateScriptPath = Join-Path $script:AppFolder "AutoUpdateJob.ps1"

$script:ArkAppId        = "2430930"
$script:SteamCmdZipUrl  = "https://steamcdn-a.akamaihd.net/client/installer/steamcmd.zip"
$script:VcRedistUrl     = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
$script:DirectXUrl      = "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe"

$script:DefaultServerName = "ARK Ascended Server"
$script:DefaultAdminPass  = "ChangeMe_ARKAdmin_123!"

# Map presets + allow manual entry in GUI
$script:MapPresets = @(
    "TheIsland_WP",
    "ScorchedEarth_WP",
    "TheCenter_WP",
    "Aberration_WP",
    "Extinction_WP",
    "Ragnarok_WP",
    "Valguero_WP",
    "LostColony_WP"
)

$script:DefaultConfig = [ordered]@{
    SteamCMD              = "C:\GameServer\SteamCMD"
    ARKServerPath         = "C:\GameServer\ARK-Survival-Ascended-Server"
    ServerMAP             = "TheIsland_WP"
    ServerName            = $script:DefaultServerName
    MaxPlayers            = "70"
    Port                  = "27015"
    QueryPort             = "27016"
    BattleEye             = "NoBattlEye"
    AdminPassword         = $script:DefaultAdminPass
    Password              = ""
    Mods                  = ""            # comma-separated
    RCONPort              = "27020"
    RCONEnabled           = "True"
    ForceRespawnDinos     = $false
    ServerIP              = "127.0.0.1"
    ServerPlatform        = "PC+XSX+WINGDK"

    UseCustomServerArgs   = $false
    CustomServerArgs      = ""

    AutoUpdateTime        = "03:00"       # HH:mm
    AutoUpdateTaskSuffix  = "ARK"
    BackupMsiLastPath     = ""
}

# =========================
# Helpers: IO + Logging
# =========================
function Ensure-Directory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -ItemType Directory -Force | Out-Null }
}
Ensure-Directory -Path $script:AppFolder
Ensure-Directory -Path $script:ToolsFolder
Ensure-Directory -Path $script:LogsFolder

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR")][string]$Level = "INFO"
    )
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts][$Level] $Message"
    try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
}

function Validate-Port {
    param([string]$Value, [string]$Name)
    $tmp = 0
    if (-not [int]::TryParse($Value, [ref]$tmp)) { throw "$Name must be a number." }
    if ($tmp -lt 1 -or $tmp -gt 65535) { throw "$Name must be between 1 and 65535." }
}

# -------------------------
# Tail reader that survives RedirectStandardOutput encoding (UTF-16 w/o BOM is common)
# -------------------------
if (-not $script:_TailEncoding) { $script:_TailEncoding = @{} }

function Get-TailEncoding {
    param([Parameter(Mandatory)][string]$File)

    if ($script:_TailEncoding.ContainsKey($File)) { return $script:_TailEncoding[$File] }

    try {
        $fs = [System.IO.File]::Open($File,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
        try {
            if ($fs.Length -lt 4) { return $null }

            $bufLen = [int][Math]::Min(4096, $fs.Length)
            $buf = New-Object byte[] $bufLen
            $fs.Seek(0,[System.IO.SeekOrigin]::Begin) | Out-Null
            [void]$fs.Read($buf,0,$bufLen)

            # BOM checks
            if ($bufLen -ge 3 -and $buf[0] -eq 0xEF -and $buf[1] -eq 0xBB -and $buf[2] -eq 0xBF) {
                $enc = [System.Text.Encoding]::UTF8
                $script:_TailEncoding[$File] = $enc
                return $enc
            }
            if ($bufLen -ge 2 -and $buf[0] -eq 0xFF -and $buf[1] -eq 0xFE) {
                $enc = [System.Text.Encoding]::Unicode # UTF-16LE
                $script:_TailEncoding[$File] = $enc
                return $enc
            }
            if ($bufLen -ge 2 -and $buf[0] -eq 0xFE -and $buf[1] -eq 0xFF) {
                $enc = [System.Text.Encoding]::BigEndianUnicode
                $script:_TailEncoding[$File] = $enc
                return $enc
            }

            # Heuristic: many 0x00 bytes => UTF-16LE without BOM
            $zeroCount = 0
            foreach ($b in $buf) { if ($b -eq 0) { $zeroCount++ } }
            $ratio = $zeroCount / [double]$bufLen

            if ($ratio -ge 0.15) {
                $enc = [System.Text.Encoding]::Unicode
                $script:_TailEncoding[$File] = $enc
                return $enc
            }

            $enc = [System.Text.Encoding]::UTF8
            $script:_TailEncoding[$File] = $enc
            return $enc
        } finally { $fs.Close() }
    } catch {
        return [System.Text.Encoding]::UTF8
    }
}

function Read-NewFileTail {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$File,

        [Parameter(Mandatory)]
        [ref]$Pos
    )

    if ([string]::IsNullOrWhiteSpace($File)) { return "" }
    if (-not (Test-Path -LiteralPath $File)) { return "" }

    try {
        $fs = [System.IO.File]::Open($File,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
        try {
            if ($fs.Length -le $Pos.Value) { return "" }

            $enc = Get-TailEncoding -File $File
            if (-not $enc) { $enc = [System.Text.Encoding]::UTF8 }

            [void]$fs.Seek($Pos.Value,[System.IO.SeekOrigin]::Begin)
            $sr = New-Object System.IO.StreamReader($fs, $enc, $true)

            $txt = $sr.ReadToEnd()
            $Pos.Value = $fs.Position

            if ($txt -and ($txt -match "`0") -and $Pos.Value -gt 0) {
                $script:_TailEncoding.Remove($File) | Out-Null
            }

            return ($txt -replace "`0","")
        } finally {
            $fs.Close()
        }
    } catch {
        return ""
    }
}

# =========================
# Config Load/Save
# =========================
function Read-Config {
    if (-not (Test-Path $script:ConfigPath)) {
        return [ordered]@{} + $script:DefaultConfig
    }
    try {
        $raw   = Get-Content -Path $script:ConfigPath -Raw -ErrorAction Stop
        $cfgO  = $raw | ConvertFrom-Json -ErrorAction Stop

        $merged = [ordered]@{}
        foreach ($k in $script:DefaultConfig.Keys) {
            if ($cfgO.PSObject.Properties.Name -contains $k) { $merged[$k] = $cfgO.$k }
            else { $merged[$k] = $script:DefaultConfig[$k] }
        }

        if ([string]::IsNullOrWhiteSpace($merged.ServerName))    { $merged.ServerName = $script:DefaultServerName }
        if ([string]::IsNullOrWhiteSpace($merged.AdminPassword)) { $merged.AdminPassword = $script:DefaultAdminPass }
        if ([string]::IsNullOrWhiteSpace($merged.ServerMAP))     { $merged.ServerMAP = "TheIsland_WP" }

        return $merged
    } catch {
        Write-Log ("Config read error: {0}" -f $_.Exception.Message) "WARN"
        return [ordered]@{} + $script:DefaultConfig
    }
}

function Write-Config {
    param([Parameter(Mandatory)][hashtable]$Config)
    Ensure-Directory -Path $script:AppFolder
    $Config | ConvertTo-Json -Depth 10 | Set-Content -Path $script:ConfigPath -Encoding UTF8 -Force
}

$script:Config = Read-Config
try { Write-Config -Config $script:Config } catch {}

# =========================
# Download + Processes
# =========================
function Invoke-Download {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$OutFile,
        [int]$Retries = 3,
        [int]$MinBytes = 1
    )
    for ($i=1; $i -le $Retries; $i++) {
        try {
            Write-Log "Download: $Uri -> $OutFile (try $i/$Retries)" "INFO"
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -ErrorAction Stop
            if (-not (Test-Path $OutFile)) { throw "Download failed: $OutFile" }
            $len = (Get-Item $OutFile).Length
            if ($len -lt $MinBytes) { throw "Downloaded file too small ($len bytes): $OutFile" }
            return
        } catch {
            Write-Log ("Download error: {0}" -f $_.Exception.Message) "WARN"
            if ($i -eq $Retries) { throw }
            Start-Sleep -Seconds (2*$i)
        }
    }
}

function Invoke-ExternalProcess {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int]$TimeoutSec = 0
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $FilePath
    $psi.Arguments              = ($ArgumentList -join " ")
    $psi.RedirectStandardOutput  = $true
    $psi.RedirectStandardError   = $true
    $psi.UseShellExecute         = $false
    $psi.CreateNoWindow          = $true

    Write-Log "Process start: $FilePath $($psi.Arguments)" "INFO"

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    $null = $p.Start()

    if ($TimeoutSec -gt 0) {
        if (-not $p.WaitForExit($TimeoutSec*1000)) {
            try { $p.Kill() } catch {}
            throw "Timeout after $TimeoutSec seconds: $FilePath"
        }
    } else {
        $p.WaitForExit() | Out-Null
    }

    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()

    Write-Log "Process exit: $FilePath ExitCode=$($p.ExitCode)" "INFO"
    if ($err) { Write-Log "stderr: $err" "WARN" }

    [pscustomobject]@{ ExitCode=$p.ExitCode; StdOut=$out; StdErr=$err }
}

# =========================
# Dependencies: mcrcon / SteamCMD / Prereqs / CA
# =========================
function Ensure-Mcrcon {
    if (Test-Path $script:McrconExe) { return $script:McrconExe }

    Ensure-Directory -Path $script:ToolsFolder
    $zipUrl  = "https://github.com/Tiiffi/mcrcon/releases/download/v0.7.2/mcrcon-0.7.2-windows-x86-64.zip"
    $zipPath = Join-Path $script:ToolsFolder "mcrcon.zip"

    Invoke-Download -Uri $zipUrl -OutFile $zipPath -Retries 3 -MinBytes 10KB
    Expand-Archive -Path $zipPath -DestinationPath $script:ToolsFolder -Force
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $script:McrconExe)) {
        $found = Get-ChildItem -Path $script:ToolsFolder -Recurse -Filter "mcrcon.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { Copy-Item -Path $found.FullName -Destination $script:McrconExe -Force }
    }

    if (-not (Test-Path $script:McrconExe)) { throw "mcrcon.exe could not be installed." }
    return $script:McrconExe
}

function Invoke-Rcon {
    param(
        [Parameter(Mandatory)][string]$ServerIP,
        [Parameter(Mandatory)][int]$RCONPort,
        [Parameter(Mandatory)][string]$AdminPassword,
        [Parameter(Mandatory)][string]$Command
    )
    $exe = Ensure-Mcrcon
    $out = & $exe -H $ServerIP -P $RCONPort -p $AdminPassword $Command 2>&1
    ($out | Out-String).TrimEnd()
}

function Test-VcRuntimeInstalled {
    try {
        $k = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" -ErrorAction Stop
        return ($k.Installed -eq 1)
    } catch { return $false }
}

function Test-DirectXJune2010Installed {
    Test-Path "$env:WINDIR\System32\d3dx9_43.dll"
}

function Install-Component {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string[]]$Arguments,
        [int[]]$OkExitCodes = @(0,3010,1641,1638)
    )
    $dl = Join-Path $env:TEMP $FileName
    Invoke-Download -Uri $Url -OutFile $dl -Retries 3 -MinBytes 100KB
    $r = Invoke-ExternalProcess -FilePath $dl -ArgumentList $Arguments -TimeoutSec 1800
    if ($OkExitCodes -notcontains $r.ExitCode) {
        throw "Installation failed: $FileName (ExitCode=$($r.ExitCode))`r`n$($r.StdErr)"
    }
}

function Get-SteamCmdExe {
    param([string]$SteamCmdBaseDir)

    $p1 = Join-Path $SteamCmdBaseDir "steamcmd.exe"
    if (Test-Path $p1) { return $p1 }

    $p2 = Join-Path (Join-Path $SteamCmdBaseDir "SteamCMD") "steamcmd.exe"
    if (Test-Path $p2) { return $p2 }

    return $p2
}

function Ensure-SteamCmd {
    param([Parameter(Mandatory)][string]$SteamCmdBaseDir)

    Ensure-Directory -Path $SteamCmdBaseDir

    $exeDirect = Join-Path $SteamCmdBaseDir "steamcmd.exe"
    if (Test-Path $exeDirect) { return $exeDirect }

    $installDir = Join-Path $SteamCmdBaseDir "SteamCMD"
    Ensure-Directory -Path $installDir

    $exe = Join-Path $installDir "steamcmd.exe"
    if (Test-Path $exe) { return $exe }

    $zip = Join-Path $env:TEMP "steamcmd.zip"
    Invoke-Download -Uri $script:SteamCmdZipUrl -OutFile $zip -Retries 3 -MinBytes 100KB
    Expand-Archive -Path $zip -DestinationPath $installDir -Force
    Remove-Item -Path $zip -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $exe)) { throw "steamcmd.exe not found after extraction: $exe" }
    return $exe
}

function Assert-ArkServerFilesPresent {
    param([Parameter(Mandatory)][string]$ArkServerPath)

    $exe  = Join-Path $ArkServerPath "ShooterGame\Binaries\Win64\ArkAscendedServer.exe"
    $paks = Join-Path $ArkServerPath "ShooterGame\Content\Paks"

    if (-not (Test-Path $exe)) {
        throw "Validation failed: ArkAscendedServer.exe missing: $exe"
    }

    $exeSize = (Get-Item $exe).Length
    if ($exeSize -lt 5MB) {
        throw "Validation failed: ArkAscendedServer.exe looks too small ($([Math]::Round($exeSize/1MB,2)) MB)."
    }

    if (-not (Test-Path $paks)) {
        throw "Validation failed: Paks folder missing: $paks"
    }

    $pakCount = (Get-ChildItem -Path $paks -Filter "*.pak" -File -ErrorAction SilentlyContinue).Count
    if ($pakCount -lt 1) {
        throw "Validation failed: No .pak files found in: $paks"
    }

    return [pscustomobject]@{
        Exe        = $exe
        ExeSizeMB  = [Math]::Round($exeSize/1MB,2)
        PakCount   = $pakCount
    }
}

function Invoke-SteamCmdUpdate {
    param(
        [Parameter(Mandatory)][string]$SteamCmdExe,
        [Parameter(Mandatory)][string]$ArkServerPath
    )

    Ensure-Directory -Path $ArkServerPath

    $args = @(
        "+force_install_dir", $ArkServerPath,
        "+login", "anonymous",
        "+app_update", $script:ArkAppId, "validate",
        "+quit"
    )

    Write-Log "SteamCMD run: $SteamCmdExe $($args -join ' ')" "INFO"
    Write-Output "SteamCMD start: $SteamCmdExe $($args -join ' ')"

    & $SteamCmdExe @args 2>&1 | ForEach-Object {
        $line = ($_ | Out-String).TrimEnd()
        if ($line) {
            Write-Output $line
            Write-Log ("[SteamCMD] {0}" -f $line) "INFO"
        }
    }

    $code = $LASTEXITCODE
    Write-Log "SteamCMD ExitCode=$code" "INFO"
    if ($code -ne 0) {
        throw "SteamCMD update failed (ExitCode=$code). See log/output."
    }
}

function Ensure-AmazonCA {
    param([scriptblock]$Report)

    if (-not (Test-IsAdmin)) { throw "CA installation requires Administrator privileges." }

    & $Report "CA installation: Installing Amazon Trust CAs (mandatory)."

    $rootUrl  = "https://www.amazontrust.com/repository/AmazonRootCA1.cer"
    $intHttps = "https://crt.r2m02.amazontrust.com/r2m02.cer"
    $intHttp  = "http://crt.r2m02.amazontrust.com/r2m02.cer"

    $rootFile = Join-Path $env:TEMP "AmazonRootCA1.cer"
    $intFile  = Join-Path $env:TEMP "r2m02.cer"

    Invoke-Download -Uri $rootUrl -OutFile $rootFile -Retries 3 -MinBytes 200
    try { Invoke-Download -Uri $intHttps -OutFile $intFile -Retries 3 -MinBytes 200 }
    catch { Invoke-Download -Uri $intHttp  -OutFile $intFile -Retries 3 -MinBytes 200 }

    $rootCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($rootFile)
    $intCert  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($intFile)

    function Ensure-InStore {
        param(
            [string]$StoreLocation,
            [string]$StoreName,
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
        )
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName,$StoreLocation)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $exists = $false
        foreach ($c in $store.Certificates) {
            if ($c.Thumbprint -eq $Cert.Thumbprint) { $exists = $true; break }
        }
        if (-not $exists) { $store.Add($Cert) }
        $store.Close()
    }

    Ensure-InStore -StoreLocation "CurrentUser"  -StoreName "Root" -Cert $rootCert
    Ensure-InStore -StoreLocation "LocalMachine" -StoreName "Root" -Cert $rootCert
    Ensure-InStore -StoreLocation "CurrentUser"  -StoreName "CA"   -Cert $intCert
    Ensure-InStore -StoreLocation "LocalMachine" -StoreName "CA"   -Cert $intCert

    & $Report "CA installation: OK"
}

# =========================
# Auto-Update Job Script (local)
# =========================
function Ensure-AutoUpdateScript {
    $content = @'
#requires -version 5.1
[CmdletBinding()]
param(
    # If empty: use Config.json in the same directory as this AutoUpdateJob.ps1
    [string]$ConfigPath = "",

    # Start server after update (recommended for scheduled jobs)
    [switch]$StartServer
)

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}
try { [Console]::InputEncoding  = New-Object System.Text.UTF8Encoding($false) } catch {}

function Ensure-Dir([string]$p){ if (-not (Test-Path -LiteralPath $p)) { New-Item -Path $p -ItemType Directory -Force | Out-Null } }

$ScriptRoot = $PSScriptRoot

# Deterministic config resolution:
# 1) If -ConfigPath given -> MUST exist, otherwise exit
# 2) Else -> Config.json next to this AutoUpdateJob.ps1
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $ScriptRoot "Config.json"
}

$LogDir = Join-Path $ScriptRoot "logs"
Ensure-Dir $LogDir
$LogFile = Join-Path $LogDir "autoupdate.log"

function Log([string]$Message){
    try {
        $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Add-Content -Path $LogFile -Value ("[{0}] {1}" -f $ts, $Message) -Encoding UTF8
    } catch {}
}

Log "AutoUpdate start"
Log ("User       : " + [Environment]::UserName)
Log ("ScriptRoot : " + $ScriptRoot)
Log ("ConfigPath : " + $ConfigPath)
Log ("LogFile    : " + $LogFile)

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    Log ("ERROR: Config file not found: " + $ConfigPath)
    exit 10
}

try {
    $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
} catch {
    Log ("ERROR: Config parse failed: " + $_.Exception.Message)
    exit 12
}

# Diagnostics: prove what we loaded
try {
    $fi = Get-Item -LiteralPath $ConfigPath
    Log ("ConfigSize : " + $fi.Length + " bytes")
    Log ("ConfigMTime: " + $fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"))
} catch {}

$keys = ($cfg.PSObject.Properties.Name | Sort-Object) -join ","
Log ("ConfigKeys : " + $keys)

function Normalize-Bool([object]$v) {
    if ($null -eq $v) { return $false }
    $s = ($v.ToString()).Trim().ToLowerInvariant()
    return ($s -eq "true" -or $s -eq "1" -or $s -eq "yes")
}

function Get-SteamExe([string]$Base){
    if ([string]::IsNullOrWhiteSpace($Base)) { return "" }
    $p1 = Join-Path $Base "steamcmd.exe"
    if (Test-Path -LiteralPath $p1) { return $p1 }
    $p2 = Join-Path (Join-Path $Base "SteamCMD") "steamcmd.exe"
    if (Test-Path -LiteralPath $p2) { return $p2 }
    return $p2
}

function Sanitize-Args([string]$Args) {
    if ([string]::IsNullOrWhiteSpace($Args)) { return "" }
    $a = $Args.Trim()
    # Remove leading "start " prefix
    if ($a -match '^\s*start\s+') { $a = ($a -replace '^\s*start\s+','').Trim() }
    return $a
}

function Build-ArgsFromFields($cfg) {
    # Hard defaults so this can never be empty
    $map = (($cfg.ServerMAP + "").Trim()); if (-not $map) { $map = "TheIsland_WP" }
    $sessionName = (($cfg.ServerName + "").Trim()); if (-not $sessionName) { $sessionName = "ARK Ascended Server" }

    $port      = (($cfg.Port + "").Trim()); if (-not $port) { $port = "27015" }
    $queryPort = (($cfg.QueryPort + "").Trim()); if (-not $queryPort) { $queryPort = "27016" }
    $maxPlayers = (($cfg.MaxPlayers + "").Trim()); if (-not $maxPlayers) { $maxPlayers = "70" }

    $serverPw = (($cfg.Password + "").Trim())
    $adminPw  = (($cfg.AdminPassword + "").Trim())

    $rconEnabled = Normalize-Bool $cfg.RCONEnabled
    $rconPort = (($cfg.RCONPort + "").Trim()); if (-not $rconPort) { $rconPort = "27020" }

    $platform = (($cfg.ServerPlatform + "").Trim()); if (-not $platform) { $platform = "PC" }

    $mods = (($cfg.Mods + "") -replace '\s','') -replace ',{2,}', ','
    $mods = $mods.Trim(',')

    $forceDinos = Normalize-Bool $cfg.ForceRespawnDinos

    $qs = @("listen")
    $qs += ('SessionName="{0}"' -f $sessionName)
    $qs += ("Port={0}" -f $port)
    $qs += ("QueryPort={0}" -f $queryPort)
    if ($serverPw) { $qs += ('ServerPassword="{0}"' -f $serverPw) }

    if ($rconEnabled) {
        $qs += "RCONEnabled=True"
        $qs += ("RCONPort={0}" -f $rconPort)
    } else {
        $qs += "RCONEnabled=False"
    }

    if ($adminPw) { $qs += ('ServerAdminPassword="{0}"' -f $adminPw) }

    $base = ('{0}?{1}' -f $map, ($qs -join '?'))

    $flags = @()
    $battleEye = (($cfg.BattleEye + "").Trim())
    if ($battleEye -eq "UseBattlEye") { $flags += "-UseBattlEye" } else { $flags += "-NoBattlEye" }
    $flags += "-automanagedmods"
    $flags += ("-WinLiveMaxPlayers={0}" -f $maxPlayers)
    $flags += ("-ServerPlatform={0}" -f $platform)
    if ($mods) { $flags += ("-mods={0}" -f $mods) }
    if ($forceDinos) { $flags += "-ForceRespawnDinos" }

    return ($base + " " + ($flags -join " ")).Trim()
}

# Validate mandatory basics for update
if ([string]::IsNullOrWhiteSpace(($cfg.SteamCMD + "")) -or [string]::IsNullOrWhiteSpace(($cfg.ARKServerPath + ""))) {
    Log "ERROR: Config invalid: SteamCMD and/or ARKServerPath is empty."
    exit 13
}

$steamExe  = Get-SteamExe ($cfg.SteamCMD + "")
$serverExe = Join-Path ($cfg.ARKServerPath + "") "ShooterGame\Binaries\Win64\ArkAscendedServer.exe"

Log ("SteamCMD base: " + ($cfg.SteamCMD + ""))
Log ("SteamCMD exe : " + $steamExe)
Log ("Install dir  : " + ($cfg.ARKServerPath + ""))
Log ("Server exe   : " + $serverExe)

if (-not (Test-Path -LiteralPath $steamExe))  { Log ("ERROR: steamcmd.exe missing: " + $steamExe); exit 11 }
if (-not (Test-Path -LiteralPath $serverExe)) { Log ("ERROR: Server exe missing: " + $serverExe); exit 30 }

# Check if server is running before update
$wasRunning = $false
if (Get-Process -Name "ArkAscendedServer" -ErrorAction SilentlyContinue) { $wasRunning = $true }
Log ("WasRunning  : " + $wasRunning)

# Stop server if running (RCON first, then force if needed)
if ($wasRunning) {
    Log "Server process detected. Attempting graceful stop via RCON..."

    $mcr = Join-Path $ScriptRoot "tools\mcrcon.exe"
    $rconEnabled = Normalize-Bool $cfg.RCONEnabled
    $adminPw = (($cfg.AdminPassword + "").Trim())
    $ip = (($cfg.ServerIP + "").Trim()); if (-not $ip) { $ip = "127.0.0.1" }
    $rconPortStr = (($cfg.RCONPort + "").Trim()); if (-not $rconPortStr) { $rconPortStr = "27020" }

    Log ("mcrcon path: " + $mcr)
    try {
        if ((Test-Path -LiteralPath $mcr) -and $rconEnabled -and (-not [string]::IsNullOrWhiteSpace($adminPw))) {
            & $mcr -H $ip -P $rconPortStr -p $adminPw saveworld | Out-Null
            Start-Sleep -Seconds 2
            & $mcr -H $ip -P $rconPortStr -p $adminPw doexit   | Out-Null
        } else {
            Log "RCON stop skipped (mcrcon missing or RCON disabled or AdminPassword empty)."
        }
    } catch {
        Log ("RCON stop failed: " + $_.Exception.Message)
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt 120) {
        if (-not (Get-Process -Name "ArkAscendedServer" -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Seconds 2
    }

    if (Get-Process -Name "ArkAscendedServer" -ErrorAction SilentlyContinue) {
        Log "Server still running after 120s. Forcing stop..."
        try { Stop-Process -Name "ArkAscendedServer" -Force -ErrorAction SilentlyContinue } catch {}
        Start-Sleep -Seconds 2
    }

    if (Get-Process -Name "ArkAscendedServer" -ErrorAction SilentlyContinue) {
        Log "ERROR: Server could not be stopped. Aborting update."
        exit 20
    }

    Log "Server stopped."
}

# SteamCMD update
Log "Running SteamCMD update..."
$LASTEXITCODE = 0

& $steamExe `
  +force_install_dir ($cfg.ARKServerPath + "") `
  +login anonymous `
  +app_update 2430930 validate `
  +quit 2>&1 | ForEach-Object {
      $line = ($_ | Out-String).TrimEnd()
      if ($line) { Log ("[SteamCMD] " + $line) }
  }

$code = $LASTEXITCODE
Log ("SteamCMD exit code: " + $code)
if ($code -ne 0) { Log "ERROR: SteamCMD returned non-zero. Aborting."; exit $code }

# Build restart args:
# 1) Prefer CustomServerArgs ALWAYS if present
# 2) Else generate from fields
$rawCustom = ($cfg.CustomServerArgs + "")
Log ("RawCustomArgsLength : " + $rawCustom.Length)

$args = Sanitize-Args $rawCustom
$src  = "CustomServerArgs"

if ([string]::IsNullOrWhiteSpace($args)) {
    $args = Sanitize-Args (Build-ArgsFromFields $cfg)
    $src  = "GeneratedFromFields"
}

# Hard last resort (should never be needed, but guarantees non-empty)
if ([string]::IsNullOrWhiteSpace($args)) {
    $args = 'TheIsland_WP?listen?SessionName="ARK Ascended Server"?Port=27015?QueryPort=27016 -NoBattlEye -automanagedmods -WinLiveMaxPlayers=70 -ServerPlatform=PC'
    $src  = "HardDefault"
}

Log ("Args source : " + $src)
Log ("Args length : " + $args.Length)
Log ("Args preview: " + ($args.Substring(0, [Math]::Min(160,$args.Length))))

# Decide whether to start:
# - start if it was running before, OR if -StartServer is set
$doStart = $wasRunning -or $StartServer.IsPresent
Log ("DoStart     : " + $doStart)

if (-not $doStart) {
    Log "Restart skipped: server was not running and -StartServer not specified."
    exit 0
}

Log ("Starting server with args: " + $args)
try {
    Start-Process -FilePath $serverExe -ArgumentList $args -WorkingDirectory (Split-Path $serverExe -Parent) | Out-Null
    Start-Sleep -Seconds 6

    if (Get-Process -Name "ArkAscendedServer" -ErrorAction SilentlyContinue) {
        Log "Server restart: OK"
        exit 0
    } else {
        Log "Server restart: FAILED (process not found after start)"
        exit 40
    }
} catch {
    Log ("Server restart failed: " + $_.Exception.Message)
    exit 41
}
'@

    Set-Content -Path $script:AutoUpdateScriptPath -Value $content -Encoding UTF8 -Force
}


function Create-OrUpdateScheduledAutoUpdate {
    param(
        [Parameter(Mandatory)][string]$TimeHHmm,
        [Parameter(Mandatory)][string]$TaskSuffix
    )

    if (-not (Test-IsAdmin)) { throw "Scheduled Task requires Administrator privileges." }

    Ensure-AutoUpdateScript

    $taskName = "ARK-AutoUpdate-$TaskSuffix"

    # Pass the REAL config path explicitly (no SYSTEM/APPDATA surprises)
    $psArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$script:AutoUpdateScriptPath`"",
        "-ConfigPath", "`"$script:ConfigPath`"",
        "-StartServer"
    ) -join " "

    $action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $psArgs
    $trigger   = New-ScheduledTaskTrigger -Daily -At $TimeHHmm
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $task      = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings

    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }

    Register-ScheduledTask -TaskName $taskName -InputObject $task | Out-Null
    return $taskName
}




# =========================
# Backup Tool Download
# =========================
#function Get-SaveFileLocation {
#    param(
#        [string]$Title,
#        [string]$Filter,
#        [string]$FileName
#    )
#    Add-Type -AssemblyName System.Windows.Forms | Out-Null
#    $dlg = New-Object System.Windows.Forms.SaveFileDialog
#    $dlg.Title = $Title
#    $dlg.Filter = $Filter
#    $dlg.FileName = $FileName
#    $res = $dlg.ShowDialog()
#    if ($res -eq [System.Windows.Forms.DialogResult]::OK) { return $dlg.FileName }
#    return ""
#}
#
#function Download-BackupTool {
#    if (-not (Test-IsAdmin)) { throw "Backup tool download requires Administrator privileges." }
#
#    $url = "https://github.com/Ch4r0ne/Backup-Tool/releases/download/1.0.3/BackupJobSchedulerGUI.msi"
#    $fileName = [IO.Path]::GetFileName($url)
#    $path = Get-SaveFileLocation -Title "Select download location" -Filter "MSI Files (*.msi)|*.msi" -FileName $fileName
#    if (-not $path) { return }
#
#    Invoke-Download -Uri $url -OutFile $path -Retries 3 -MinBytes 200KB
#
#    $cfg = Read-Config
#    $cfg.BackupMsiLastPath = $path
#    Write-Config -Config $cfg
#}

# =========================
# Server Args
# =========================
function Build-GeneratedServerArgs {
    param([hashtable]$cfg)

    $map = ($cfg.ServerMAP + "").Trim()
    if (-not $map) { $map = "TheIsland_WP" }

    $sessionName = ($cfg.ServerName + "").Trim()
    if (-not $sessionName) { $sessionName = $script:DefaultServerName }

    $serverPw = ($cfg.Password + "").Trim()
    $adminPw  = ($cfg.AdminPassword + "").Trim()

    $mods = (($cfg.Mods + "") -replace '\s','') -replace ',{2,}', ','
    $mods = $mods.Trim(',')

    $qs = @("listen")
    $qs += ('SessionName="{0}"' -f $sessionName)
    $qs += ('Port={0}' -f $cfg.Port)
    $qs += ('QueryPort={0}' -f $cfg.QueryPort)
    if ($serverPw) { $qs += ('ServerPassword="{0}"' -f $serverPw) }

    if ($cfg.RCONEnabled -eq "True") {
        $qs += "RCONEnabled=True"
        $qs += ('RCONPort={0}' -f $cfg.RCONPort)
    } else {
        $qs += "RCONEnabled=False"
    }

    if ($adminPw) { $qs += ('ServerAdminPassword="{0}"' -f $adminPw) }

    # Keep the original behavior ("start ...") to remain compatible with typical ARK server syntax
    $base = ('start {0}?{1}' -f $map, ($qs -join '?'))

    $flags = @()
    if ($cfg.BattleEye -eq "UseBattlEye") { $flags += "-UseBattlEye" } else { $flags += "-NoBattlEye" }
    $flags += "-automanagedmods"
    $flags += ('-WinLiveMaxPlayers={0}' -f $cfg.MaxPlayers)
    $flags += ('-ServerPlatform={0}' -f $cfg.ServerPlatform)
    if ($mods) { $flags += ('-mods={0}' -f $mods) }
    if ([bool]$cfg.ForceRespawnDinos) { $flags += "-ForceRespawnDinos" }

    ($base + " " + ($flags -join " ")).Trim()
}

function Start-ArkServer {
    param([hashtable]$cfg)

    $serverExe = Join-Path $cfg.ARKServerPath "ShooterGame\Binaries\Win64\ArkAscendedServer.exe"
    if (-not (Test-Path $serverExe)) { throw "ArkAscendedServer.exe not found. Please download server files first." }

    $args = if ($cfg.UseCustomServerArgs -and ($cfg.CustomServerArgs.Trim())) {
        $cfg.CustomServerArgs.Trim()
    } else {
        Build-GeneratedServerArgs -cfg $cfg
    }

    Start-Process -FilePath $serverExe -ArgumentList $args -WorkingDirectory (Split-Path $serverExe -Parent) | Out-Null
}

function Stop-ArkServerViaRcon {
    param([hashtable]$cfg)

    if ([string]::IsNullOrWhiteSpace($cfg.ServerIP) -or [string]::IsNullOrWhiteSpace($cfg.AdminPassword)) {
        throw "Server IP and Admin Password are required."
    }

    $port = [int]$cfg.RCONPort
    [void](Invoke-Rcon -ServerIP $cfg.ServerIP -RCONPort $port -AdminPassword $cfg.AdminPassword -Command "saveworld")
    Start-Sleep -Seconds 1
    [void](Invoke-Rcon -ServerIP $cfg.ServerIP -RCONPort $port -AdminPassword $cfg.AdminPassword -Command "doexit")
}

#function Get-PlayerCountViaRcon {
#    param([hashtable]$cfg)
#
#    $port = [int]$cfg.RCONPort
#    $out = Invoke-Rcon -ServerIP $cfg.ServerIP -RCONPort $port -AdminPassword $cfg.AdminPassword -Command "listplayers"
#
#    if ($out -match "No Players Connected") { return 0 }
#    $lines = ($out -split "`r?`n") | Where-Object { $_.Trim() }
#    return $lines.Count
#}

# =========================
# INI Open
# =========================
function Ensure-IniParentFolder {
    param([Parameter(Mandatory)][string]$FilePath)
    $dir = Split-Path -Parent $FilePath
    Ensure-Directory -Path $dir
}

function Open-GameUserSettings {
    param([hashtable]$cfg)
    $path = Join-Path $cfg.ARKServerPath "ShooterGame\Saved\Config\WindowsServer\GameUserSettings.ini"
    Ensure-IniParentFolder -FilePath $path

    if (-not (Test-Path $path)) {
        Add-Type -AssemblyName System.Windows.Forms | Out-Null
        $r = [System.Windows.Forms.MessageBox]::Show(
            "GameUserSettings.ini does not exist yet. ARK will create it on the first server start.`r`n`r`nCreate an empty file now for editing?",
            "Info",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {
            New-Item -Path $path -ItemType File -Force | Out-Null
        } else {
            Invoke-Item (Split-Path $path -Parent)
            return
        }
    }
    Invoke-Item $path
}

function Open-GameIni {
    param([hashtable]$cfg)
    $path = Join-Path $cfg.ARKServerPath "ShooterGame\Saved\Config\WindowsServer\Game.ini"
    Ensure-IniParentFolder -FilePath $path

    if (-not (Test-Path $path)) {
        Add-Type -AssemblyName System.Windows.Forms | Out-Null
        $r = [System.Windows.Forms.MessageBox]::Show(
            "Game.ini does not exist yet. ARK will create it on the first server start.`r`n`r`nCreate an empty file now for editing?",
            "Info",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {
            New-Item -Path $path -ItemType File -Force | Out-Null
        } else {
            Invoke-Item (Split-Path $path -Parent)
            return
        }
    }
    Invoke-Item $path
}

# =========================
# Worker Mode (no GUI, no Runspace issues)
# =========================
function Invoke-WorkerMode {
    param([Parameter(Mandatory)][ValidateSet('FirstInstall','UpdateServerFiles')][string]$WorkerAction)

    $ErrorActionPreference = "Stop"
    Write-Log ("Worker start Mode={0} User={1} Admin={2}" -f $WorkerAction, $env:USERNAME, (Test-IsAdmin)) "INFO"

    $cfg = Read-Config

    $Report = {
        param([string]$msg)
        Write-Log ("[{0}] {1}" -f $WorkerAction, $msg) "INFO"
        Write-Output $msg
    }

    if (-not (Test-IsAdmin)) { throw "Worker mode requires Administrator privileges." }

    switch ($WorkerAction) {
        'FirstInstall' {
            & $Report "CA installation (mandatory) ..."
            Ensure-AmazonCA -Report $Report

            if (-not (Test-VcRuntimeInstalled)) {
                & $Report "Installing Visual C++ Runtime..."
                Install-Component -Url $script:VcRedistUrl -FileName "vc_redist.x64.exe" -Arguments @("/install","/passive","/norestart") -OkExitCodes @(0,3010,1641,1638)
                & $Report "Visual C++ Runtime: OK"
            } else { & $Report "Visual C++ Runtime: OK" }

            if (-not (Test-DirectXJune2010Installed)) {
                & $Report "Installing DirectX Legacy Runtime..."
                Install-Component -Url $script:DirectXUrl -FileName "dxwebsetup.exe" -Arguments @("/Q") -OkExitCodes @(0,3010,1641)
                & $Report "DirectX Legacy Runtime: OK"
            } else { & $Report "DirectX Legacy Runtime: OK" }

            & $Report "Installing / checking SteamCMD..."
            $steamcmdExe = Ensure-SteamCmd -SteamCmdBaseDir $cfg.SteamCMD
            & $Report ("SteamCMD: OK ({0})" -f $steamcmdExe)

            & $Report "Installing / checking mcrcon..."
            [void](Ensure-Mcrcon)
            & $Report "mcrcon: OK"

            & $Report "Downloading / updating ARK server files (SteamCMD)..."
            [void](Invoke-SteamCmdUpdate -SteamCmdExe $steamcmdExe -ArkServerPath $cfg.ARKServerPath)

            # Hard validation: ensure the server files are really there
            $val = Assert-ArkServerFilesPresent -ArkServerPath $cfg.ARKServerPath
            & $Report ("Validation: OK (Exe={0} MB, Paks={1})" -f $val.ExeSizeMB, $val.PakCount)

            & $Report "FirstInstall: DONE"

            if (($cfg.AdminPassword + "") -eq $script:DefaultAdminPass) {
                & $Report "WARNING: AdminPassword is still the default. Change it after First Install."
            }
        }

        'UpdateServerFiles' {
            $steamcmdExe = Get-SteamCmdExe -SteamCmdBaseDir $cfg.SteamCMD
            if (-not (Test-Path $steamcmdExe)) { throw "steamcmd.exe not found ($steamcmdExe). Run First Install first." }

            & $Report "SteamCMD update starting..."
            [void](Invoke-SteamCmdUpdate -SteamCmdExe $steamcmdExe -ArkServerPath $cfg.ARKServerPath)

            $val = Assert-ArkServerFilesPresent -ArkServerPath $cfg.ARKServerPath
            & $Report ("Validation: OK (Exe={0} MB, Paks={1})" -f $val.ExeSizeMB, $val.PakCount)

            & $Report "UpdateServerFiles: DONE"
        }
    }
}

# =========================
# Worker entry point (writes StatusFile)
# =========================
if ($Mode -ne 'Gui') {
    try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}
    try { [Console]::InputEncoding  = New-Object System.Text.UTF8Encoding($false) } catch {}

    try {
        Invoke-WorkerMode -WorkerAction $Mode

        if ($StatusFile) {
            try { Set-Content -Path $StatusFile -Value "0" -Encoding ASCII -Force } catch {}
        }
        exit 0
    }
    catch {
        $errText = $_.Exception.ToString()
        Write-Log ("Worker error Mode={0}: {1}" -f $Mode, $errText) "ERROR"
        Write-Error $_

        if ($StatusFile) {
            try { Set-Content -Path $StatusFile -Value ("1`r`n{0}" -f $errText) -Encoding UTF8 -Force } catch {}
        }
        exit 1
    }
}

# =========================
# GUI-only: Forms + Elevation
# =========================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-Info {
    param([string]$Text, [string]$Title = $script:AppName)
    [System.Windows.Forms.MessageBox]::Show($Text,$Title,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
}
function Show-Error {
    param([string]$Text, [string]$Title = "Error")
    [System.Windows.Forms.MessageBox]::Show($Text,$Title,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
}

function Restart-ScriptAsAdmin {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath) -or -not (Test-Path $PSCommandPath)) {
        Show-Error "Auto-elevation works only when the script is executed from a .ps1 file." "Admin restart not possible"
        return $false
    }
    $args = @("-NoProfile","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`"")
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $args | Out-Null
    return $true
}

$script:IsAdmin = Test-IsAdmin
Write-Log ("Application start. User={0} Admin={1}" -f $env:USERNAME, $script:IsAdmin) "INFO"

$script:LimitedMode = $false
if (-not $script:IsAdmin) {
    $res = [System.Windows.Forms.MessageBox]::Show(
        "Administrator privileges are required for:`r`n- First Install`r`n- Download/Update Server Files`r`n- Save Config`r`n- Auto-Update (Task Scheduler)`r`n- Backup Tool Download`r`n`r`nRestart now as Administrator?",
        "Administrator privileges required",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    if ($res -eq [System.Windows.Forms.DialogResult]::Yes) {
        if (Restart-ScriptAsAdmin) { return }
    } else {
        $script:LimitedMode = $true
    }
}

# =========================
# GUI: Form + Controls
# =========================
$Form = New-Object System.Windows.Forms.Form
$Form.Text = $script:AppName
$Form.StartPosition = "CenterScreen"
$Form.Size = New-Object System.Drawing.Size(1120, 760)
$Form.MaximizeBox = $false

$toolTip = New-Object System.Windows.Forms.ToolTip
$toolTip.AutoPopDelay = 20000
$toolTip.InitialDelay = 400
$toolTip.ReshowDelay  = 200
$toolTip.ShowAlways   = $true

function New-Label($text,$x,$y) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $text
    $l.Location = New-Object System.Drawing.Point($x,$y)
    $l.AutoSize = $true
    $Form.Controls.Add($l)
    $l
}
function New-TextBox($x,$y,$w=300) {
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location = New-Object System.Drawing.Point($x,$y)
    $t.Size = New-Object System.Drawing.Size($w,20)
    $Form.Controls.Add($t)
    $t
}
function New-Combo($x,$y,$items,$w=150,$defaultIndex=0) {
    $c = New-Object System.Windows.Forms.ComboBox
    $c.Location = New-Object System.Drawing.Point($x,$y)
    $c.Size = New-Object System.Drawing.Size($w,20)
    $c.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    [void]$c.Items.AddRange($items)
    if ($c.Items.Count -gt 0) { $c.SelectedIndex = [Math]::Min($defaultIndex, $c.Items.Count-1) }
    $Form.Controls.Add($c)
    $c
}
function New-ComboEditable($x,$y,$items,$w=220) {
    $c = New-Object System.Windows.Forms.ComboBox
    $c.Location = New-Object System.Drawing.Point($x,$y)
    $c.Size = New-Object System.Drawing.Size($w,20)
    $c.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDown  # editable
    [void]$c.Items.AddRange($items)
    $Form.Controls.Add($c)
    $c
}

#$PlayerCountLabel = New-Object System.Windows.Forms.Label
#$PlayerCountLabel.Location = New-Object System.Drawing.Point(10, 12)
#$PlayerCountLabel.AutoSize = $true
#$Form.Controls.Add($PlayerCountLabel)

#$UpdatePlayerCountButton = New-Object System.Windows.Forms.Button
#$UpdatePlayerCountButton.Location = New-Object System.Drawing.Point(240, 8)
#$UpdatePlayerCountButton.Size = New-Object System.Drawing.Size(170, 28)
#$UpdatePlayerCountButton.Text = "Refresh Player Count"
#$toolTip.SetToolTip($UpdatePlayerCountButton, "RCON: listplayers (mcrcon is downloaded automatically).")
#$Form.Controls.Add($UpdatePlayerCountButton)

New-Label "SteamCMD path:" 50 55 | Out-Null
$SteamCMDPathTextBox = New-TextBox 220 52 360

New-Label "ARK server path:" 50 85 | Out-Null
$ARKServerPathTextBox = New-TextBox 220 82 360

New-Label "Server map:" 50 115 | Out-Null
$ServerMAPComboBox = New-ComboEditable 220 112 $script:MapPresets 220
$toolTip.SetToolTip($ServerMAPComboBox, "Select a map preset or type a custom map name manually.")

New-Label "Server name:" 50 145 | Out-Null
$ServerNameTextBox = New-TextBox 220 142 360

New-Label "Max players:" 50 175 | Out-Null
$MaxPlayersTextBox = New-TextBox 220 172 70

New-Label "Server IP:" 50 205 | Out-Null
$ServerIPTextBox = New-TextBox 220 202 160

New-Label "Port:" 50 235 | Out-Null
$PortTextBox = New-TextBox 220 232 70

New-Label "Query port:" 50 265 | Out-Null
$QueryPortTextBox = New-TextBox 220 262 70

New-Label "BattleEye:" 50 295 | Out-Null
$BattleEyeComboBox = New-Combo 220 292 @("NoBattlEye","UseBattlEye") 140 0

New-Label "Admin password:" 50 325 | Out-Null
$AdminPasswordTextBox = New-TextBox 220 322 220

New-Label "Server password:" 50 355 | Out-Null
$PasswordTextBox = New-TextBox 220 352 220

New-Label "RCON enabled:" 50 385 | Out-Null
$RCONEnabledComboBox = New-Combo 220 382 @("True","False") 90 0

New-Label "RCON port:" 330 385 | Out-Null
$RCONPortTextBox = New-TextBox 410 382 70

New-Label "Mods:" 50 415 | Out-Null
$ModsTextBox = New-TextBox 220 412 360

$ForceRespawnDinosCheckBox = New-Object System.Windows.Forms.CheckBox
$ForceRespawnDinosCheckBox.Location = New-Object System.Drawing.Point(220, 442)
$ForceRespawnDinosCheckBox.Size = New-Object System.Drawing.Size(20,20)
$Form.Controls.Add($ForceRespawnDinosCheckBox)
New-Label "Force respawn dinos" 50 445 | Out-Null

New-Label "Server platform:" 260 445 | Out-Null
$ServerPlatformTextBox = New-TextBox 410 442 170

# RCON area
New-Label "Enter command:" 610 55 | Out-Null
$CommandTextBox = New-Object System.Windows.Forms.TextBox
$CommandTextBox.Location = New-Object System.Drawing.Point(740, 52)
$CommandTextBox.Size = New-Object System.Drawing.Size(220,20)
$Form.Controls.Add($CommandTextBox)

$SendCommandButton = New-Object System.Windows.Forms.Button
$SendCommandButton.Text = "Send"
$SendCommandButton.Location = New-Object System.Drawing.Point(970, 50)
$SendCommandButton.Size = New-Object System.Drawing.Size(90,24)
$Form.Controls.Add($SendCommandButton)

New-Label "Console output:" 610 90 | Out-Null
$ConsoleOutputTextBox = New-Object System.Windows.Forms.TextBox
$ConsoleOutputTextBox.Location = New-Object System.Drawing.Point(610, 110)
$ConsoleOutputTextBox.Size = New-Object System.Drawing.Size(450, 260)
$ConsoleOutputTextBox.Multiline = $true
$ConsoleOutputTextBox.ScrollBars = "Vertical"
$ConsoleOutputTextBox.ReadOnly = $true
$Form.Controls.Add($ConsoleOutputTextBox)

# INI buttons
$OpenGUSButton = New-Object System.Windows.Forms.Button
$OpenGUSButton.Location = New-Object System.Drawing.Point(610, 385)
$OpenGUSButton.Size = New-Object System.Drawing.Size(210, 28)
$OpenGUSButton.Text = "Open GameUserSettings.ini"
$Form.Controls.Add($OpenGUSButton)

$OpenGameIniButton = New-Object System.Windows.Forms.Button
$OpenGameIniButton.Location = New-Object System.Drawing.Point(850, 385)
$OpenGameIniButton.Size = New-Object System.Drawing.Size(210, 28)
$OpenGameIniButton.Text = "Open Game.ini"
$Form.Controls.Add($OpenGameIniButton)

# Startup args preview/override
New-Label "Startup arguments (Preview / Override):" 50 480 | Out-Null
$UseCustomArgsCheckBox = New-Object System.Windows.Forms.CheckBox
$UseCustomArgsCheckBox.Location = New-Object System.Drawing.Point(310, 478)
$UseCustomArgsCheckBox.Size = New-Object System.Drawing.Size(160, 20)
$UseCustomArgsCheckBox.Text = "Manual override"
$Form.Controls.Add($UseCustomArgsCheckBox)

$ServerArgsTextBox = New-Object System.Windows.Forms.TextBox
$ServerArgsTextBox.Location = New-Object System.Drawing.Point(50, 505)
$ServerArgsTextBox.Size = New-Object System.Drawing.Size(1010, 70)
$ServerArgsTextBox.Multiline = $true
$ServerArgsTextBox.ScrollBars = "Vertical"
$Form.Controls.Add($ServerArgsTextBox)

# Action buttons
$FirstInstallButton = New-Object System.Windows.Forms.Button
$FirstInstallButton.Location = New-Object System.Drawing.Point(50, 600)
$FirstInstallButton.Size = New-Object System.Drawing.Size(150, 32)
$FirstInstallButton.Text = "First Install"
$toolTip.SetToolTip($FirstInstallButton, "Installs prerequisites: Amazon CA, VC++ runtime, DirectX, SteamCMD, mcrcon, server files.")
$Form.Controls.Add($FirstInstallButton)

$ServerUpdateButton = New-Object System.Windows.Forms.Button
$ServerUpdateButton.Location = New-Object System.Drawing.Point(210, 600)
$ServerUpdateButton.Size = New-Object System.Drawing.Size(240, 32)
$ServerUpdateButton.Text = "Download/Update Server Files"
$Form.Controls.Add($ServerUpdateButton)

$SaveButton = New-Object System.Windows.Forms.Button
$SaveButton.Location = New-Object System.Drawing.Point(460, 600)
$SaveButton.Size = New-Object System.Drawing.Size(120, 32)
$SaveButton.Text = "Save Config"
$Form.Controls.Add($SaveButton)

$StartServerButton = New-Object System.Windows.Forms.Button
$StartServerButton.Location = New-Object System.Drawing.Point(590, 600)
$StartServerButton.Size = New-Object System.Drawing.Size(120, 32)
$StartServerButton.Text = "Start Server"
$Form.Controls.Add($StartServerButton)

$StopServerButton = New-Object System.Windows.Forms.Button
$StopServerButton.Location = New-Object System.Drawing.Point(720, 600)
$StopServerButton.Size = New-Object System.Drawing.Size(120, 32)
$StopServerButton.Text = "Stop Server"
$Form.Controls.Add($StopServerButton)

$AutoUpdateButton = New-Object System.Windows.Forms.Button
$AutoUpdateButton.Location = New-Object System.Drawing.Point(850, 600)
$AutoUpdateButton.Size = New-Object System.Drawing.Size(210, 32)
$AutoUpdateButton.Text = "Create Auto-Update Job"
$Form.Controls.Add($AutoUpdateButton)

#$BackupButton = New-Object System.Windows.Forms.Button
#$BackupButton.Location = New-Object System.Drawing.Point(850, 640)
#$BackupButton.Size = New-Object System.Drawing.Size(210, 32)
#$BackupButton.Text = "Backup Tool"
#$Form.Controls.Add($BackupButton)

# =========================
# Config <-> GUI
# =========================
function Ensure-UiDefaults {
    if ([string]::IsNullOrWhiteSpace($ServerNameTextBox.Text))    { $ServerNameTextBox.Text = $script:DefaultServerName }
    if ([string]::IsNullOrWhiteSpace($AdminPasswordTextBox.Text)) { $AdminPasswordTextBox.Text = $script:DefaultAdminPass }
    if ([string]::IsNullOrWhiteSpace($ServerMAPComboBox.Text))    { $ServerMAPComboBox.Text = "TheIsland_WP" }

    if (-not $BattleEyeComboBox.SelectedItem)   { $BattleEyeComboBox.SelectedIndex = 0 }
    if (-not $RCONEnabledComboBox.SelectedItem) { $RCONEnabledComboBox.SelectedIndex = 0 }
    if ([string]::IsNullOrWhiteSpace($ServerPlatformTextBox.Text)) { $ServerPlatformTextBox.Text = "PC+XSX+WINGDK" }
}

function Get-ConfigFromGui {
    Ensure-UiDefaults

    $cfg = [ordered]@{
        SteamCMD            = $SteamCMDPathTextBox.Text
        ARKServerPath       = $ARKServerPathTextBox.Text
        ServerMAP           = $ServerMAPComboBox.Text
        ServerName          = $ServerNameTextBox.Text
        MaxPlayers          = $MaxPlayersTextBox.Text
        Port                = $PortTextBox.Text
        QueryPort           = $QueryPortTextBox.Text
        BattleEye           = [string]$BattleEyeComboBox.SelectedItem
        AdminPassword       = $AdminPasswordTextBox.Text
        Password            = $PasswordTextBox.Text
        Mods                = $ModsTextBox.Text
        RCONPort            = $RCONPortTextBox.Text
        RCONEnabled         = [string]$RCONEnabledComboBox.SelectedItem
        ForceRespawnDinos   = [bool]$ForceRespawnDinosCheckBox.Checked
        ServerIP            = $ServerIPTextBox.Text
        ServerPlatform      = $ServerPlatformTextBox.Text
        UseCustomServerArgs = [bool]$UseCustomArgsCheckBox.Checked
        CustomServerArgs    = $ServerArgsTextBox.Text

        AutoUpdateTime        = $script:Config.AutoUpdateTime
        AutoUpdateTaskSuffix  = $script:Config.AutoUpdateTaskSuffix
        BackupMsiLastPath     = $script:Config.BackupMsiLastPath
    }

    Validate-Port -Value $cfg.Port      -Name "Port"
    Validate-Port -Value $cfg.QueryPort -Name "Query Port"
    Validate-Port -Value $cfg.RCONPort  -Name "RCON Port"

    if ([string]::IsNullOrWhiteSpace($cfg.SteamCMD))      { throw "SteamCMD path is empty." }
    if ([string]::IsNullOrWhiteSpace($cfg.ARKServerPath)) { throw "ARK server path is empty." }
    if ([string]::IsNullOrWhiteSpace(($cfg.ServerMAP + "").Trim())) { throw "Server map is empty." }

    return $cfg
}

function Save-ConfigFromGui {
    $gui = Get-ConfigFromGui
    foreach ($k in $script:DefaultConfig.Keys) {
        if ($gui.Contains($k)) { $script:Config[$k] = $gui[$k] }
    }
    Write-Config -Config $script:Config
#    $PlayerCountLabel.Text = "Players Online: 0/$($script:Config.MaxPlayers)"
}

function Apply-ConfigToGui {
    param([hashtable]$cfg)

    $SteamCMDPathTextBox.Text   = $cfg.SteamCMD
    $ARKServerPathTextBox.Text  = $cfg.ARKServerPath
    $ServerMAPComboBox.Text     = $cfg.ServerMAP
    $ServerNameTextBox.Text     = $cfg.ServerName
    $MaxPlayersTextBox.Text     = $cfg.MaxPlayers
    $PortTextBox.Text           = $cfg.Port
    $QueryPortTextBox.Text      = $cfg.QueryPort
    $AdminPasswordTextBox.Text  = $cfg.AdminPassword
    $PasswordTextBox.Text       = $cfg.Password
    $ModsTextBox.Text           = $cfg.Mods
    $RCONPortTextBox.Text       = $cfg.RCONPort
    $ServerIPTextBox.Text       = $cfg.ServerIP
    $ServerPlatformTextBox.Text = $cfg.ServerPlatform
    $ForceRespawnDinosCheckBox.Checked = [bool]$cfg.ForceRespawnDinos

    $BattleEyeComboBox.SelectedItem = $cfg.BattleEye
    if (-not $BattleEyeComboBox.SelectedItem) { $BattleEyeComboBox.SelectedIndex = 0 }

    $RCONEnabledComboBox.SelectedItem = $cfg.RCONEnabled
    if (-not $RCONEnabledComboBox.SelectedItem) { $RCONEnabledComboBox.SelectedIndex = 0 }

    $UseCustomArgsCheckBox.Checked = [bool]$cfg.UseCustomServerArgs
    $ServerArgsTextBox.Text = $cfg.CustomServerArgs

    Ensure-UiDefaults
#    $PlayerCountLabel.Text = "Players Online: 0/$($cfg.MaxPlayers)"
}

function Update-ArgsUiState {
    try {
        $gui = Get-ConfigFromGui
        $generated = Build-GeneratedServerArgs -cfg $gui

        if ($UseCustomArgsCheckBox.Checked) {
            $ServerArgsTextBox.ReadOnly = $false
            $ServerArgsTextBox.BackColor = [System.Drawing.Color]::White
            if ([string]::IsNullOrWhiteSpace($ServerArgsTextBox.Text)) { $ServerArgsTextBox.Text = $generated }
        } else {
            $ServerArgsTextBox.ReadOnly = $true
            $ServerArgsTextBox.BackColor = [System.Drawing.Color]::Gainsboro
            $ServerArgsTextBox.Text = $generated
        }
    } catch {}
}

Apply-ConfigToGui -cfg $script:Config
Update-ArgsUiState

# =========================
# Worker Process Runner (GUI stays responsive)
# =========================
$script:RunningWorkerProcess = $null

function Start-WorkerProcess {
    param(
        [Parameter(Mandatory)][ValidateSet('FirstInstall','UpdateServerFiles')]
        [string]$WorkerMode,
        [Parameter(Mandatory)][System.Windows.Forms.Control[]]$DisableControls,
        [string]$DoneMessage = "Done."
    )

    if ([string]::IsNullOrWhiteSpace($PSCommandPath) -or -not (Test-Path $PSCommandPath)) {
        throw "PSCommandPath is empty. The script must be started from a .ps1 file."
    }

    if ($script:RunningWorkerProcess -and -not $script:RunningWorkerProcess.HasExited) {
        throw "Another action is already running. Please wait until it finishes."
    }

    foreach ($c in $DisableControls) { if ($c) { $c.Enabled = $false } }
    $Form.UseWaitCursor = $true

    $stdoutFile = Join-Path $script:LogsFolder ("worker-{0}-stdout.log" -f $WorkerMode.ToLower())
    $stderrFile = Join-Path $script:LogsFolder ("worker-{0}-stderr.log" -f $WorkerMode.ToLower())
    $statusFile = Join-Path $script:LogsFolder ("worker-{0}-status.txt" -f $WorkerMode.ToLower())

    Remove-Item $stdoutFile, $stderrFile, $statusFile -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $stdoutFile -ItemType File -Force | Out-Null
    New-Item -Path $stderrFile -ItemType File -Force | Out-Null

    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Mode $WorkerMode -StatusFile `"$statusFile`""

    $p = Start-Process -FilePath "powershell.exe" -ArgumentList $args -PassThru `
        -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -WindowStyle Hidden

    $script:RunningWorkerProcess = $p
    $script:_tailStdOutPos = 0L
    $script:_tailStdErrPos = 0L

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 400

    $timer.Tag = [pscustomobject]@{
        StdOutFile       = $stdoutFile
        StdErrFile       = $stderrFile
        StatusFile       = $statusFile
        WorkerMode       = $WorkerMode
        DoneMessage      = $DoneMessage
        DisableControls  = $DisableControls
        Proc             = $p
    }

    $timer.Add_Tick({
        param($sender, $e)

        $state = $sender.Tag
        if (-not $state) { return }

        $outFile = $state.StdOutFile
        $errFile = $state.StdErrFile

        if ([string]::IsNullOrWhiteSpace($outFile) -or [string]::IsNullOrWhiteSpace($errFile)) {
            $sender.Stop()
            $Form.UseWaitCursor = $false
            foreach ($c in $state.DisableControls) { if ($c) { $c.Enabled = $true } }
            Show-Error "Internal error: worker log file paths are empty. Please re-run the script. (StdOut/StdErr path resolution failed.)"
            return
        }

        $newOut = Read-NewFileTail -File $outFile -Pos ([ref]$script:_tailStdOutPos)
        if ($newOut) { $ConsoleOutputTextBox.AppendText($newOut) }

        $newErr = Read-NewFileTail -File $errFile -Pos ([ref]$script:_tailStdErrPos)
        if ($newErr) { $ConsoleOutputTextBox.AppendText("[ERR] " + $newErr) }

        if ($state.Proc.HasExited) {
            $sender.Stop()

            $newOut2 = Read-NewFileTail -File $outFile -Pos ([ref]$script:_tailStdOutPos)
            if ($newOut2) { $ConsoleOutputTextBox.AppendText($newOut2) }
            $newErr2 = Read-NewFileTail -File $errFile -Pos ([ref]$script:_tailStdErrPos)
            if ($newErr2) { $ConsoleOutputTextBox.AppendText("[ERR] " + $newErr2) }

            $Form.UseWaitCursor = $false
            foreach ($c in $state.DisableControls) { if ($c) { $c.Enabled = $true } }

            $exit = $null
            $statusText = ""
            if (Test-Path $state.StatusFile) {
                try {
                    $statusText = Get-Content -Path $state.StatusFile -Raw -ErrorAction Stop
                    $firstLine = ($statusText -split "`r?`n")[0].Trim()
                    if ($firstLine -match '^\d+$') { $exit = [int]$firstLine }
                } catch {}
            }
            if ($exit -eq $null) { $exit = [int]$state.Proc.ExitCode }

            if ($exit -eq 0) {
                [System.Windows.Forms.MessageBox]::Show(
                    $state.DoneMessage, "Success",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                ) | Out-Null
            } else {
                [System.Windows.Forms.MessageBox]::Show(
                    "Action '$($state.WorkerMode)' failed (ExitCode=$exit)`r`n`r`nLog:`r`n$script:LogFile`r`n`r`nStdOut:`r`n$($state.StdOutFile)`r`nStdErr:`r`n$($state.StdErrFile)`r`n`r`nStatus:`r`n$statusText",
                    "Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                ) | Out-Null
            }
        }
    })

    $timer.Start()
    return $p
}

# =========================
# AutoUpdate Dialog (GUI)
# =========================
function Show-AutoUpdateDialog {
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "Create Auto-Update Job"
    $dlg.StartPosition = "CenterParent"
    $dlg.Size = New-Object System.Drawing.Size(420, 210)
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = "Enter the details for the Auto-Update job:"
    $lbl.Location = New-Object System.Drawing.Point(10, 15)
    $lbl.AutoSize = $true
    $dlg.Controls.Add($lbl)

    $lblTime = New-Object System.Windows.Forms.Label
    $lblTime.Text = "Scheduled time:"
    $lblTime.Location = New-Object System.Drawing.Point(10, 50)
    $lblTime.AutoSize = $true
    $dlg.Controls.Add($lblTime)

    $tp = New-Object System.Windows.Forms.DateTimePicker
    $tp.Location = New-Object System.Drawing.Point(130, 45)
    $tp.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom
    $tp.CustomFormat = "HH:mm"
    $tp.ShowUpDown = $true
    try {
        $base = [DateTime]::Today.AddHours([int]($script:Config.AutoUpdateTime.Split(':')[0])).AddMinutes([int]($script:Config.AutoUpdateTime.Split(':')[1]))
        $tp.Value = $base
    } catch {}
    $dlg.Controls.Add($tp)

    $lblName = New-Object System.Windows.Forms.Label
    $lblName.Text = "Task suffix:"
    $lblName.Location = New-Object System.Drawing.Point(10, 85)
    $lblName.AutoSize = $true
    $dlg.Controls.Add($lblName)

    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Location = New-Object System.Drawing.Point(130, 82)
    $tb.Size = New-Object System.Drawing.Size(240, 20)
    $tb.Text = $script:Config.AutoUpdateTaskSuffix
    $dlg.Controls.Add($tb)

    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = "OK"
    $ok.Location = New-Object System.Drawing.Point(130, 125)
    $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $dlg.Controls.Add($ok)

    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = "Cancel"
    $cancel.Location = New-Object System.Drawing.Point(220, 125)
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dlg.Controls.Add($cancel)

    $dlg.AcceptButton = $ok
    $dlg.CancelButton = $cancel

    $res = $dlg.ShowDialog($Form)
    if ($res -ne [System.Windows.Forms.DialogResult]::OK) { return $null }

    $time = $tp.Value.ToString("HH:mm")
    $suffix = $tb.Text.Trim()
    if (-not $suffix) { $suffix = "ARK" }

    return [pscustomobject]@{ Time=$time; Suffix=$suffix }
}

function Validate-AutoUpdateEffectiveConfig {
    # This validates what the scheduled task script will actually read from disk.
    $cfgDisk = Read-Config

    if ([string]::IsNullOrWhiteSpace($cfgDisk.SteamCMD))      { throw "Auto-Update validation failed: SteamCMD path is empty in Config.json." }
    if ([string]::IsNullOrWhiteSpace($cfgDisk.ARKServerPath)) { throw "Auto-Update validation failed: ARKServerPath is empty in Config.json." }

    $steamExe = Get-SteamCmdExe -SteamCmdBaseDir $cfgDisk.SteamCMD
    if (-not (Test-Path $steamExe)) {
        throw "Auto-Update validation failed: steamcmd.exe not found at: $steamExe"
    }

    # If RCON enabled, ensure we have minimum required fields (not strictly mandatory for update, but for graceful stop)
    if (($cfgDisk.RCONEnabled + "") -eq "True") {
        if ([string]::IsNullOrWhiteSpace($cfgDisk.ServerIP))      { throw "Auto-Update validation failed: ServerIP is empty (RCON enabled)." }
        if ([string]::IsNullOrWhiteSpace($cfgDisk.AdminPassword)) { throw "Auto-Update validation failed: AdminPassword is empty (RCON enabled)." }
        Validate-Port -Value $cfgDisk.RCONPort -Name "RCON Port"
    }

    # Also validate that ARKServerPath at least exists or can be created (task runs as SYSTEM)
    # We do not create it here, just sanity check formatting.
    return [pscustomobject]@{
        SteamCmdExe   = $steamExe
        InstallDir    = $cfgDisk.ARKServerPath
        RconEnabled   = $cfgDisk.RCONEnabled
        ServerIP      = $cfgDisk.ServerIP
        RconPort      = $cfgDisk.RCONPort
    }
}

# =========================
# Wire up events
# =========================
$watchControls = @(
    $SteamCMDPathTextBox,$ARKServerPathTextBox,$ServerNameTextBox,$MaxPlayersTextBox,
    $PortTextBox,$QueryPortTextBox,$ModsTextBox,$RCONPortTextBox,$ServerPlatformTextBox,$AdminPasswordTextBox,
    $PasswordTextBox,$ServerIPTextBox
)
foreach ($c in $watchControls) { $c.Add_TextChanged({ Update-ArgsUiState }) }

$ServerMAPComboBox.Add_TextChanged({ Update-ArgsUiState })
$ServerMAPComboBox.Add_SelectedIndexChanged({ Update-ArgsUiState })

$BattleEyeComboBox.Add_SelectedIndexChanged({ Update-ArgsUiState })
$RCONEnabledComboBox.Add_SelectedIndexChanged({ Update-ArgsUiState })
$ForceRespawnDinosCheckBox.Add_CheckedChanged({ Update-ArgsUiState })

$UseCustomArgsCheckBox.Add_CheckedChanged({
    Update-ArgsUiState
    try { Save-ConfigFromGui } catch {}
})

$ServerArgsTextBox.Add_TextChanged({
    if ($UseCustomArgsCheckBox.Checked) {
        try { Save-ConfigFromGui } catch {}
    }
})

$SaveButton.Add_Click({
    try {
        Ensure-UiDefaults
        Save-ConfigFromGui
        Update-ArgsUiState
        Show-Info "Config saved."
    } catch { Show-Error $_.Exception.Message }
})

$FirstInstallButton.Add_Click({
    try {
        Ensure-UiDefaults
        Save-ConfigFromGui
        $ConsoleOutputTextBox.AppendText("=== First Install started ===`r`n")

        Start-WorkerProcess -WorkerMode "FirstInstall" `
            -DisableControls @($FirstInstallButton,$ServerUpdateButton,$SaveButton,$StartServerButton,$StopServerButton,$AutoUpdateButton,$BackupButton) `
            -DoneMessage "First Install completed."
    } catch { Show-Error $_.Exception.Message }
})

$ServerUpdateButton.Add_Click({
    try {
        Ensure-UiDefaults
        Save-ConfigFromGui
        $ConsoleOutputTextBox.AppendText("=== Download/Update Server Files started ===`r`n")

        Start-WorkerProcess -WorkerMode "UpdateServerFiles" `
            -DisableControls @($FirstInstallButton,$ServerUpdateButton,$SaveButton,$StartServerButton,$StopServerButton,$AutoUpdateButton,$BackupButton) `
            -DoneMessage "Update completed."
    } catch { Show-Error $_.Exception.Message }
})

$StartServerButton.Add_Click({
    try {
        Ensure-UiDefaults
        Save-ConfigFromGui
        $cfg = Get-ConfigFromGui
        Update-ArgsUiState
        Start-ArkServer -cfg $cfg
        Show-Info "Server started."
    } catch { Show-Error $_.Exception.Message }
})

$StopServerButton.Add_Click({
    try {
        Ensure-UiDefaults
        Save-ConfigFromGui
        $cfg = Get-ConfigFromGui

        $ConsoleOutputTextBox.AppendText("RCON: saveworld / doexit`r`n")
        Stop-ArkServerViaRcon -cfg $cfg
        Show-Info "Stop command sent."
    } catch { Show-Error $_.Exception.Message }
})

$SendCommandButton.Add_Click({
    try {
        Ensure-UiDefaults
        Save-ConfigFromGui
        $cfg = Get-ConfigFromGui

        $cmd = $CommandTextBox.Text.Trim()
        if (-not $cmd) { throw "Please enter a command." }

        $ConsoleOutputTextBox.AppendText("Command: $cmd`r`n")
        $resp = Invoke-Rcon -ServerIP $cfg.ServerIP -RCONPort ([int]$cfg.RCONPort) -AdminPassword $cfg.AdminPassword -Command $cmd
        $ConsoleOutputTextBox.AppendText("Response:`r`n$resp`r`n`r`n")
    } catch { Show-Error $_.Exception.Message }
})

#$UpdatePlayerCountButton.Add_Click({
#    try {
#        Ensure-UiDefaults
#        Save-ConfigFromGui
#        $cfg = Get-ConfigFromGui
#        $count = Get-PlayerCountViaRcon -cfg $cfg
#        $PlayerCountLabel.Text = "Players Online: $count/$($cfg.MaxPlayers)"
#    } catch { Show-Error $_.Exception.Message }
#})

$OpenGUSButton.Add_Click({
    try {
        Ensure-UiDefaults
        Save-ConfigFromGui
        $cfg = Get-ConfigFromGui
        Open-GameUserSettings -cfg $cfg
    } catch { Show-Error $_.Exception.Message }
})

$OpenGameIniButton.Add_Click({
    try {
        Ensure-UiDefaults
        Save-ConfigFromGui
        $cfg = Get-ConfigFromGui
        Open-GameIni -cfg $cfg
    } catch { Show-Error $_.Exception.Message }
})

$AutoUpdateButton.Add_Click({
    try {
        if (-not (Test-IsAdmin)) { throw "Auto-Update job requires Administrator privileges." }

        # CRITICAL: ensure the job reads the correct parameters
        Ensure-UiDefaults
        Save-ConfigFromGui

        # Dialog values
        $dlg = Show-AutoUpdateDialog
        if (-not $dlg) { return }

        $script:Config.AutoUpdateTime = $dlg.Time
        $script:Config.AutoUpdateTaskSuffix = $dlg.Suffix
        Write-Config -Config $script:Config

        # Validate what the scheduled task script will actually use
        $eff = Validate-AutoUpdateEffectiveConfig

        # Ensure the job script is written with the current version
        Ensure-AutoUpdateScript

        $taskName = Create-OrUpdateScheduledAutoUpdate -TimeHHmm $dlg.Time -TaskSuffix $dlg.Suffix

        Show-Info ("Scheduled Task created/updated:`r`n{0}`r`nTime: {1}`r`nUser: SYSTEM (Highest)`r`n`r`nEffective config validation:`r`nSteamCMD: {2}`r`nInstallDir: {3}`r`nRCON: {4} (IP={5}, Port={6})`r`n`r`nAutoUpdate log:`r`n{7}" -f `
            $taskName, $dlg.Time, $eff.SteamCmdExe, $eff.InstallDir, $eff.RconEnabled, $eff.ServerIP, $eff.RconPort, (Join-Path $script:LogsFolder "autoupdate.log")
        )

        Start-Process "taskschd.msc" | Out-Null
    } catch { Show-Error $_.Exception.Message }
})

#$BackupButton.Add_Click({
#    try {
#        Download-BackupTool
#        Show-Info "Backup tool downloaded."
#    } catch { Show-Error $_.Exception.Message }
#})

if ($script:LimitedMode) {
    $FirstInstallButton.Enabled = $false
    $ServerUpdateButton.Enabled = $false
    $SaveButton.Enabled = $false
    $AutoUpdateButton.Enabled = $false
    $BackupButton.Enabled = $false
    $ConsoleOutputTextBox.AppendText("Limited mode: Not running as Administrator. Install/Update/Save/AutoUpdate/Backup disabled.`r`nLog: $script:LogFile`r`n`r`n")
}

[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::Run($Form)
