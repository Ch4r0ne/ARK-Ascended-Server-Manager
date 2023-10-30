Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Define default values
$DefaultConfig = @{
    SteamCMD = "C:\GameServer\SteamCMD"
    ARKServerPath = "C:\GameServer\ARK-Survival-Ascended-Server"
    ServerMAP = "TheIsland_WP"
    ServerName = ""
    MaxPlayers = "20"
    AppID = "2430930"
    Port = "27025"
    QueryPort = "27026"
    BattleEye = "NoBattlEye"
    AdminPassword = ""
    Password = ""
}

# Create configuration folder and file if not exists
$ConfigFolderPath = Join-Path $env:APPDATA "ARK-Ascended-Server-Manager"
$ScriptConfig = Join-Path $ConfigFolderPath "Config.json"

if (-not (Test-Path -Path $ConfigFolderPath)) {
    New-Item -Path $ConfigFolderPath -ItemType Directory -Force
}

# Function to save configuration to file
function Save-Config {
    $ConfigData = @{
        SteamCMD = $SteamCMDPathTextBox.Text
        ARKServerPath = $ARKServerPathTextBox.Text
        ServerMAP = $ServerMAPTextBox.Text
        ServerName = $ServerNameTextBox.Text
        MaxPlayers = $MaxPlayersTextBox.Text
        AppID = $AppIDTextBox.Text
        Port = $PortTextBox.Text
        QueryPort = $QueryPortTextBox.Text
        BattleEye = $BattleEyeComboBox.SelectedItem.ToString()
        AdminPassword = $AdminPasswordTextBox.Text
        Password = $PasswordTextBox.Text
    }
    $ConfigData | ConvertTo-Json | Set-Content -Path $ScriptConfig -Force
}

# Load configuration from file or set default values
if (Test-Path -Path $ScriptConfig) {
    try {
        $ConfigData = Get-Content -Path $ScriptConfig -Raw | ConvertFrom-Json
        foreach ($key in $DefaultConfig.Keys) {
            if (-not $ConfigData.PSObject.Properties[$key]) {
                $ConfigData | Add-Member -MemberType NoteProperty -Name $key -Value $DefaultConfig[$key]
            }
        }
    } catch {
        Write-Output "Fehler beim Lesen der Konfigurationsdatei. Standardkonfiguration wird verwendet."
        $ConfigData = $DefaultConfig
    }
} else {
    Write-Output "Keine Konfigurationsdatei gefunden. Standardkonfiguration wird verwendet."
    $ConfigData = $DefaultConfig
}

# Use configuration data
$SteamCMD = $ConfigData.SteamCMD
$ARKServerPath = $ConfigData.ARKServerPath
$ServerMAP = $ConfigData.ServerMAP
$ServerName = $ConfigData.ServerName
$MaxPlayers = $ConfigData.MaxPlayers
$AppID = $ConfigData.AppID
$Port = $ConfigData.Port
$QueryPort = $ConfigData.QueryPort
$BattleEye = $ConfigData.BattleEye
$AdminPassword = $ConfigData.AdminPassword
$Password = $ConfigData.Password

# Create GUI window
$Form = New-Object Windows.Forms.Form
$Form.Text = "ARK-Ascended-Server-Manager"
$Form.Size = New-Object Drawing.Size(600, 500)

# SteamCMD path
$SteamCMDLabel = New-Object Windows.Forms.Label
$SteamCMDLabel.Text = "SteamCMD Pfad:"
$SteamCMDLabel.Location = New-Object Drawing.Point(50, 50)
$Form.Controls.Add($SteamCMDLabel)

$SteamCMDPathTextBox = New-Object Windows.Forms.TextBox
$SteamCMDPathTextBox.Location = New-Object Drawing.Point(200, 50)
$SteamCMDPathTextBox.Size = New-Object Drawing.Size(300, 20)
$Form.Controls.Add($SteamCMDPathTextBox)

# ARK Server Path
$ARKServerLabel = New-Object Windows.Forms.Label
$ARKServerLabel.Text = "ARK Server Pfad:"
$ARKServerLabel.Location = New-Object Drawing.Point(50, 80)
$Form.Controls.Add($ARKServerLabel)

$ARKServerPathTextBox = New-Object Windows.Forms.TextBox
$ARKServerPathTextBox.Location = New-Object Drawing.Point(200, 80)
$ARKServerPathTextBox.Size = New-Object Drawing.Size(300, 20)
$Form.Controls.Add($ARKServerPathTextBox)

# Server MAP
$ServerMAPLabel = New-Object Windows.Forms.Label
$ServerMAPLabel.Text = "Server MAP:"
$ServerMAPLabel.Location = New-Object Drawing.Point(50, 110)
$Form.Controls.Add($ServerMAPLabel)

$ServerMAPTextBox = New-Object Windows.Forms.TextBox
$ServerMAPTextBox.Location = New-Object Drawing.Point(200, 110)
$ServerMAPTextBox.Size = New-Object Drawing.Size(300, 20)
$Form.Controls.Add($ServerMAPTextBox)

# Server Name
$ServerNameLabel = New-Object Windows.Forms.Label
$ServerNameLabel.Text = "Server Name:"
$ServerNameLabel.Location = New-Object Drawing.Point(50, 140)
$Form.Controls.Add($ServerNameLabel)

$ServerNameTextBox = New-Object Windows.Forms.TextBox
$ServerNameTextBox.Location = New-Object Drawing.Point(200, 140)
$ServerNameTextBox.Size = New-Object Drawing.Size(300, 20)
$Form.Controls.Add($ServerNameTextBox)

# Max Players
$MaxPlayersLabel = New-Object Windows.Forms.Label
$MaxPlayersLabel.Text = "Max Players:"
$MaxPlayersLabel.Location = New-Object Drawing.Point(50, 170)
$Form.Controls.Add($MaxPlayersLabel)

$MaxPlayersTextBox = New-Object Windows.Forms.TextBox
$MaxPlayersTextBox.Location = New-Object Drawing.Point(200, 170)
$MaxPlayersTextBox.Size = New-Object Drawing.Size(50, 20)
$Form.Controls.Add($MaxPlayersTextBox)

# AppID
$AppIDLabel = New-Object Windows.Forms.Label
$AppIDLabel.Text = "AppID:"
$AppIDLabel.Location = New-Object Drawing.Point(50, 200)
$Form.Controls.Add($AppIDLabel)

$AppIDTextBox = New-Object Windows.Forms.TextBox
$AppIDTextBox.Location = New-Object Drawing.Point(200, 200)
$AppIDTextBox.Size = New-Object Drawing.Size(50, 20)
$Form.Controls.Add($AppIDTextBox)

# Port
$PortLabel = New-Object Windows.Forms.Label
$PortLabel.Text = "Port:"
$PortLabel.Location = New-Object Drawing.Point(50, 230)
$Form.Controls.Add($PortLabel)

$PortTextBox = New-Object Windows.Forms.TextBox
$PortTextBox.Location = New-Object Drawing.Point(200, 230)
$PortTextBox.Size = New-Object Drawing.Size(50, 20)
$Form.Controls.Add($PortTextBox)

# QueryPort
$QueryPortLabel = New-Object Windows.Forms.Label
$QueryPortLabel.Text = "Query Port:"
$QueryPortLabel.Location = New-Object Drawing.Point(50, 260)
$Form.Controls.Add($QueryPortLabel)

$QueryPortTextBox = New-Object Windows.Forms.TextBox
$QueryPortTextBox.Location = New-Object Drawing.Point(200, 260)
$QueryPortTextBox.Size = New-Object Drawing.Size(50, 20)
$Form.Controls.Add($QueryPortTextBox)

# BattleEye
$BattleEyeLabel = New-Object Windows.Forms.Label
$BattleEyeLabel.Text = "BattleEye:"
$BattleEyeLabel.Location = New-Object Drawing.Point(50, 290)
$Form.Controls.Add($BattleEyeLabel)

$BattleEyeComboBox = New-Object Windows.Forms.ComboBox
$BattleEyeComboBox.Items.AddRange(@("NoBattlEye", "UseBattlEye"))
$BattleEyeComboBox.Location = New-Object Drawing.Point(200, 290)
$BattleEyeComboBox.SelectedItem = "NoBattlEye"
$Form.Controls.Add($BattleEyeComboBox)

# Admin Password
$AdminPasswordLabel = New-Object Windows.Forms.Label
$AdminPasswordLabel.Text = "Admin Password:"
$AdminPasswordLabel.Location = New-Object Drawing.Point(50, 320)
$Form.Controls.Add($AdminPasswordLabel)

$AdminPasswordTextBox = New-Object Windows.Forms.TextBox
$AdminPasswordTextBox.Location = New-Object Drawing.Point(200, 320)
$AdminPasswordTextBox.Size = New-Object Drawing.Size(150, 20)
$Form.Controls.Add($AdminPasswordTextBox)

# Password
$PasswordLabel = New-Object Windows.Forms.Label
$PasswordLabel.Text = "Password:"
$PasswordLabel.Location = New-Object Drawing.Point(50, 350)
$Form.Controls.Add($PasswordLabel)

$PasswordTextBox = New-Object Windows.Forms.TextBox
$PasswordTextBox.Location = New-Object Drawing.Point(200, 350)
$PasswordTextBox.Size = New-Object Drawing.Size(150, 20)
$Form.Controls.Add($PasswordTextBox)

# Install Button
$InstallButton = New-Object Windows.Forms.Button
$InstallButton.Text = "Install"
$InstallButton.Location = New-Object Drawing.Point(50, 400)
$Form.Controls.Add($InstallButton)
$InstallButton.Add_Click({
    Save-Config
	Update-Config
})

# Server Update Button
$ServerUpdateButton = New-Object Windows.Forms.Button
$ServerUpdateButton.Text = "Update Server"
$ServerUpdateButton.Location = New-Object Drawing.Point(150, 400)
$Form.Controls.Add($ServerUpdateButton)
$ServerUpdateButton.Add_Click({
    Save-Config
	Update-Config
})

# Start Server Button
$StartServerButton = New-Object Windows.Forms.Button
$StartServerButton.Text = "Start Server"
$StartServerButton.Location = New-Object Drawing.Point(250, 400)
$Form.Controls.Add($StartServerButton)
$StartServerButton.Add_Click({
    Save-Config
	Update-Config
})

# Function to update the GUI elements with the loaded configuration data
function Update-GUIFromConfig {
    $SteamCMDPathTextBox.Text = $SteamCMD
    $ARKServerPathTextBox.Text = $ARKServerPath
    $ServerMAPTextBox.Text = $ServerMAP
    $ServerNameTextBox.Text = $ServerName
    $MaxPlayersTextBox.Text = $MaxPlayers
    $AppIDTextBox.Text = $AppID
    $PortTextBox.Text = $Port
    $QueryPortTextBox.Text = $QueryPort
    $BattleEyeComboBox.SelectedItem = $BattleEye
    $AdminPasswordTextBox.Text = $AdminPassword
    $PasswordTextBox.Text = $Password
}

# Load configuration from file or set default values
if (Test-Path -Path $ScriptConfig) {
    try {
        $ConfigData = Get-Content -Path $ScriptConfig -Raw | ConvertFrom-Json
        foreach ($key in $DefaultConfig.Keys) {
            if (-not $ConfigData.PSObject.Properties[$key]) {
                $ConfigData | Add-Member -MemberType NoteProperty -Name $key -Value $DefaultConfig[$key]
            }
        }
        # Update GUI with config data
        Update-GUIFromConfig
    } catch {
        Write-Output "Error reading the configuration file. Default configuration is used."
        $ConfigData = $DefaultConfig
    }
} else {
    Write-Output "No configuration file found. Default configuration is used."
    $ConfigData = $DefaultConfig
    # Update GUI with default config data
    Update-GUIFromConfig
}

# Function to start the ARK server
function Start-ARKServer {

    # Update configuration settings
    Update-Config

    # Read the data from the configuration file
    $ConfigData = Get-Content -Path $ScriptConfig -Raw | ConvertFrom-Json

    # Trim the variables to remove spaces
    $ServerMAP = $ServerMAP.Trim()
    $ServerName = $ServerName.Trim()
    $Port = $Port.Trim()
    $QueryPort = $QueryPort.Trim()
    $MaxPlayers = $MaxPlayers.Trim()
    $BattleEye = $BattleEye.Trim()

    # Create the ServerArguments string with formatting
    $ServerArguments = [System.String]::Format('{0}?listen?SessionName="{1}"?Port={2}?QueryPort={3}?ServerPassword="{4}"?ServerAdminPassword="{5}"?MaxPlayers="{6}" -{7}', $ServerMAP, $ServerName, $Port, $QueryPort, $Password, $AdminPassword, $MaxPlayers, $BattleEye)

    # Check the ServerArguments string
    Write-Output "ServerArguments: $ServerArguments"

    # Start the server
    $ServerPath = Join-Path -Path $ARKServerPath -ChildPath "ShooterGame\Binaries\Win64\ArkAscendedServer.exe"

    if (-not [string]::IsNullOrWhiteSpace($ServerArguments)) {
        Start-Process -FilePath $ServerPath -ArgumentList $ServerArguments -NoNewWindow
    } else {
        Write-Output "Fehler: ServerArguments are null or spaces."
    }
}

# Call the function when the "Start Server" button is clicked.
$StartServerButton.Add_Click({
    Start-ARKServer
})

# Function to update the ARK server
function Update-ARKServer {

    # Update configuration settings
    Update-Config

    # Read the data from the configuration file
    $ConfigData = Get-Content -Path $ScriptConfig -Raw | ConvertFrom-Json

    Start-Process -FilePath $SteamCMD\SteamCMD\steamcmd.exe -ArgumentList "+force_install_dir $ARKServerPath +login anonymous +app_update $AppID +quit" -Wait

}
# Call the function when the "Server Update" button is clicked.
$ServerUpdateButton.Add_Click({
    Update-ARKServer
})

# Funktion zum Aktualisieren der Konfigurationsdatei
function Update-Config {
    # Lesen der Variablen aus den GUI-Elementen und in der Konfigurationsdatei speichern
    $ConfigData.SteamCMD = $SteamCMDPathTextBox.Text
    $ConfigData.ARKServerPath = $ARKServerPathTextBox.Text
    $ConfigData.ServerMAP = $ServerMAPTextBox.Text
    $ConfigData.ServerName = $ServerNameTextBox.Text
    $ConfigData.MaxPlayers = $MaxPlayersTextBox.Text
    $ConfigData.AppID = $AppIDTextBox.Text
    $ConfigData.Port = $PortTextBox.Text
    $ConfigData.QueryPort = $QueryPortTextBox.Text
    $ConfigData.BattleEye = $BattleEyeComboBox.SelectedItem.ToString()
    $ConfigData.AdminPassword = $AdminPasswordTextBox.Text
    $ConfigData.Password = $PasswordTextBox.Text

    Save-Config
}

# Function for installing the ARK server
function Install-ARKServer {
    try {

        $SteamCMD = ""
        $TargetPath = ""
        $SteamCMDExecutable = ""
        $TempPath = ""
        $downloadPath = ""

        # Update configuration settings
        Update-Config
		
		# Read the data from the configuration file
		$ConfigData = Get-Content -Path $ScriptConfig -Raw | ConvertFrom-Json
		


        # Define paths and URLs
        $SteamCMD = $ConfigData.SteamCMD
        $TargetPath = Join-Path -Path $SteamCMD -ChildPath "SteamCMD"
        $SteamCMDURL = "https://steamcdn-a.akamaihd.net/client/installer/steamcmd.zip"
        $downloadPath = $env:TEMP
        $vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
        $directXUrl = "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe"

        # Function to handle installations
        function Install-Component($url, $outputFile, $arguments) {
            Write-Output "Starte Installation von $outputFile..."
            Invoke-WebRequest -Uri $url -OutFile "$downloadPath\$outputFile"
            $process = Start-Process -FilePath "$downloadPath\$outputFile" -ArgumentList $arguments -PassThru -Wait
            if ($process.ExitCode -eq 0) {
                Write-Output "$outputFile was successfully installed."
            } else {
                throw "Error during the installation of $outputFile. Exit-Code: $($process.ExitCode)"
            }
        }

        # Install Visual C++ Redistributable if not already installed
        if (!(Test-Path -Path "HKLM:\Software\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" -ErrorAction SilentlyContinue)) {
            Install-Component -url $vcRedistUrl -outputFile "vc_redist.x64.exe" -arguments "/install", "/quiet", "/norestart"
        } else {
            Write-Output "Visual C++ Redistributable already installed."
        }

        # Install DirectX Runtime if not already installed
        if (!(Test-Path "HKLM:\Software\Microsoft\DirectX" -ErrorAction SilentlyContinue)) {
            Install-Component -url $directXUrl -outputFile "dxwebsetup.exe" -arguments "/silent"
        } else {
            Write-Output "DirectX Runtime already installed."
        }

        # Create the SteamCMD folder if it does not exist
        if (-not (Test-Path -Path $TargetPath)) {
            New-Item -Path $TargetPath -ItemType Directory -Force
        }

        # Download and install SteamCMD
        Write-Output "Download SteamCMD and install ARK Server.."
        Invoke-WebRequest -Uri $SteamCMDURL -OutFile "$downloadPath\steamcmd.zip"
        Expand-Archive -Path "$downloadPath\steamcmd.zip" -DestinationPath $TargetPath -Force
        $SteamCmdPath = Join-Path -Path $TargetPath -ChildPath "steamcmd.exe"
        Start-Process -FilePath $SteamCmdPath -ArgumentList @("+force_install_dir", "$ARKServerPath", "+login", "anonymous", "+app_update", "$AppID", "+quit") -Wait

        [System.Windows.Forms.MessageBox]::Show("ARK Server has been successfully installed.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error while installing the ARK server: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}


$InstallButton.Add_Click({
    Install-ARKServer
})

# Funktion, um die GUI anzuzeigen
[Windows.Forms.Application]::Run($Form)
