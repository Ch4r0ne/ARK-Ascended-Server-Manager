Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create configuration file in the AppData folder
$ConfigFolderPath = Join-Path $env:APPDATA "ARK-Ascended-Server-Manager"

# If the folder does not exist, create it
if (-not (Test-Path -Path $ConfigFolderPath)) {
    New-Item -Path $ConfigFolderPath -ItemType Directory -Force
}

# Function for saving the configuration file
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


# Create GUI window
$Form = New-Object Windows.Forms.Form
$Form.Text = "ARK-Ascended-Server-Manager"
$Form.Size = New-Object Drawing.Size(600, 500)

# Script Config
$ScriptConfig = Join-Path $env:APPDATA "ARK-Ascended-Server-Manager\Ark_Survival_Ascended_Config.json"


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
$ARKServerPathTextBox.Text = "C:\ArkServer"
$Form.Controls.Add($ARKServerPathTextBox)

# Server MAP
$ServerMAPLabel = New-Object Windows.Forms.Label
$ServerMAPLabel.Text = "Server MAP:"
$ServerMAPLabel.Location = New-Object Drawing.Point(50, 110)
$Form.Controls.Add($ServerMAPLabel)

$ServerMAPTextBox = New-Object Windows.Forms.TextBox
$ServerMAPTextBox.Location = New-Object Drawing.Point(200, 110)
$ServerMAPTextBox.Size = New-Object Drawing.Size(300, 20)
$ServerMAPTextBox.Text = "TheIsland_WP"
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
$MaxPlayersTextBox.Text = "20"
$Form.Controls.Add($MaxPlayersTextBox)

# AppID
$AppIDLabel = New-Object Windows.Forms.Label
$AppIDLabel.Text = "AppID:"
$AppIDLabel.Location = New-Object Drawing.Point(50, 200)
$Form.Controls.Add($AppIDLabel)

$AppIDTextBox = New-Object Windows.Forms.TextBox
$AppIDTextBox.Location = New-Object Drawing.Point(200, 200)
$AppIDTextBox.Size = New-Object Drawing.Size(50, 20)
$AppIDTextBox.Text = "2430930"
$Form.Controls.Add($AppIDTextBox)

# Port
$PortLabel = New-Object Windows.Forms.Label
$PortLabel.Text = "Port:"
$PortLabel.Location = New-Object Drawing.Point(50, 230)
$Form.Controls.Add($PortLabel)

$PortTextBox = New-Object Windows.Forms.TextBox
$PortTextBox.Location = New-Object Drawing.Point(200, 230)
$PortTextBox.Size = New-Object Drawing.Size(50, 20)
$PortTextBox.Text = "7777"
$Form.Controls.Add($PortTextBox)

# QueryPort
$QueryPortLabel = New-Object Windows.Forms.Label
$QueryPortLabel.Text = "Query Port:"
$QueryPortLabel.Location = New-Object Drawing.Point(50, 260)
$Form.Controls.Add($QueryPortLabel)

$QueryPortTextBox = New-Object Windows.Forms.TextBox
$QueryPortTextBox.Location = New-Object Drawing.Point(200, 260)
$QueryPortTextBox.Size = New-Object Drawing.Size(50, 20)
$QueryPortTextBox.Text = "27015"
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

# Config Update Button
$ConfigUpdateButton = New-Object Windows.Forms.Button
$ConfigUpdateButton.Text = "WR Config"
$ConfigUpdateButton.Location = New-Object Drawing.Point(350, 400)
$Form.Controls.Add($ConfigUpdateButton)
$ConfigUpdateButton.Add_Click({
    Save-Config
    [Windows.Forms.MessageBox]::Show("Konfig wurde aktualisiert.", "Erfolg", [Windows.Forms.MessageBoxButtons]::OK, [Windows.Forms.MessageBoxIcon]::Information)
})

# Server Update Button
$ServerUpdateButton = New-Object Windows.Forms.Button
$ServerUpdateButton.Text = "Update Server"
$ServerUpdateButton.Location = New-Object Drawing.Point(150, 400)
$Form.Controls.Add($ServerUpdateButton)

# Start Server Button
$StartServerButton = New-Object Windows.Forms.Button
$StartServerButton.Text = "Start Server"
$StartServerButton.Location = New-Object Drawing.Point(250, 400)
$Form.Controls.Add($StartServerButton)

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

# Read the configuration data from the file, if available
if (Test-Path -Path $ScriptConfig) {
    $ConfigData = Get-Content -Path $ScriptConfig | ConvertFrom-Json -ErrorAction SilentlyContinue
} else {
    Write-Output "Keine Konfigurationsdatei gefunden. Konfigurationsdaten werden nicht geladen."
}


# Use the read data
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

# Read the configuration data from the file, if available
if (Test-Path -Path $ScriptConfig) {
    $ConfigData = Get-Content -Path $ScriptConfig | ConvertFrom-Json -ErrorAction SilentlyContinue

    # Update the GUI elements with the loaded configuration data
    Update-GUIFromConfig
} else {
    Write-Output "Keine Konfigurationsdatei gefunden. GUI-Elemente werden nicht aktualisiert."
}


# Function to start the ARK server
function Start-ARKServer {
    # Use the read data
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

    # Trim the variables to remove spaces
    $ServerMAP = $ServerMAP.Trim()
    $ServerName = $ServerName.Trim()
    $Port = $Port.Trim()
    $QueryPort = $QueryPort.Trim()
    $MaxPlayers = $MaxPlayers.Trim()
    $BattleEye = $BattleEye.Trim()
    
  
    # Create the ServerArguments string with formatting
    $ServerArguments = [System.String]::Format('{0}?listen?Port={1}?QueryPort={2}?SessionName="{3}"?ServerPassword="{4}"?ServerAdminPassword="{5}" -{6}', $ServerMAP, $Port, $QueryPort, $ServerName, $Password, $AdminPassword, $BattleEye)

    # Check the ServerArguments string
    Write-Output "ServerArguments: $ServerArguments"
    
    # Start the server
    $ServerPath = Join-Path -Path $ARKServerPath -ChildPath "ShooterGame\Binaries\Win64\ArkAscendedServer.exe"
    
    if (-not [string]::IsNullOrWhiteSpace($ServerArguments)) {
        Start-Process -FilePath $ServerPath -ArgumentList $ServerArguments -NoNewWindow
    } else {
        Write-Output "Error: ServerArguments are null or spaces."
    }

}
# Call the function when the "Start Server" button is clicked.
$StartServerButton.Add_Click({
    Start-ARKServer
})

# Function to update the ARK server
function Update-ARKServer {
    # Use the read data
    $SteamCMD = $ConfigData.SteamCMD
    $ARKServerPath = $ConfigData.ARKServerPath
    $ServerMAP = $ConfigData.ServerMAP
    $ServerName = $ConfigData.ServerName
    $MaxPlayers = $ConfigData.MaxPlayers
    $AppID = $ConfigData.AppID
    $Port = $ConfigData.Port
    $QueryPort = $ConfigData.QueryPort
    $BattleEye = $ConfigData.BattleEye

    Start-Process -FilePath $SteamCMD\SteamCMD\steamcmd.exe -ArgumentList "+force_install_dir $ARKServerPath +login anonymous +app_update $AppID +quit" -Wait

}
# Call the function when the "Server Update" button is clicked.
$ServerUpdateButton.Add_Click({
    Update-ARKServer
})

# Function to update the configuration file
function Update-Config {
    # Read the variables from the GUI elements and save them in the configuration file
    Save-Config
}
# Call the function when the "Config Update" button is clicked.
$ConfigUpdateButton.Add_Click({
    Update-Config
})

# Function for installing the ARK server
function Install-ARKServer {

    Update-Config

    $SteamCMD = ""
    $TargetPath = ""
    $SteamCMDExecutable = ""
    $SteamCMD = $ConfigData.SteamCMD
    $ARKServerPath = $ConfigData.ARKServerPath
    $ServerMAP = $ConfigData.ServerMAP
    $ServerName = $ConfigData.ServerName
    $MaxPlayers = $ConfigData.MaxPlayers
    $AppID = $ConfigData.AppID
    $Port = $ConfigData.Port
    $QueryPort = $ConfigData.QueryPort
    $BattleEye = $ConfigData.BattleEye

    # The SteamCMD folder is created in the directory where the script is run
    $TargetPath = Join-Path -Path $SteamCMD -ChildPath "SteamCMD"

    # Create the destination folder if it does not exist
    if (-not (Test-Path -Path $TargetPath)) {
        New-Item -Path $TargetPath -ItemType Directory -Force
    }

    # URL for SteamCMD download
    $SteamCMDURL = "https://steamcdn-a.akamaihd.net/client/installer/steamcmd.zip"

    # Define the path where the SteamCMD zip file will be temporarily saved
    $TempPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "steamcmd.zip")

    # Download the SteamCMD zip file
    Invoke-WebRequest -Uri $SteamCMDURL -OutFile $TempPath

    # Extract the SteamCMD zip file to the target folder
    Expand-Archive -Path $TempPath -DestinationPath $TargetPath -Force

    # Delete the temporary SteamCMD zip file
    Remove-Item -Path $TempPath -Force

    # Define the path for the SteamCMD executable
    $SteamCMDExecutable = Join-Path -Path $TargetPath -ChildPath "steamcmd.exe"

    # Run the SteamCMD installer
    Start-Process -FilePath $SteamCMDExecutable -ArgumentList @("+quit") -Wait

    # Output a confirmation message
    Write-Output "SteamCMD has been successfully downloaded, installed, and saved in the target folder: $TargetPath"

    # Pfad Download-Folder
    $downloadPath = "%Temp%"

    # URL Visual C++ Redistributable-Download
    $vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"

    # URL DirectX Runtime-Download
    $directXUrl = "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe"

    # Überprüfen, ob Download-Verzeichnis vorhanden ist, andernfalls erstellen
    if (!(Test-Path -Path $downloadPath -PathType Container)) {
        New-Item -Path $downloadPath -ItemType Directory -Force
    }

    # Download Visual C++ Redistributable
    Write-Output "Lade Visual C++ Redistributable herunter..."
    Invoke-WebRequest -Uri $vcRedistUrl -OutFile "$downloadPath\vc_redist.x64.exe"

    # Download DirectX Runtime
    Write-Output "Lade DirectX Runtime herunter..."
    Invoke-WebRequest -Uri $directXUrl -OutFile "$downloadPath\dxwebsetup.exe"

    # Check if Visual C++ Redistributable is already installed
    if (!(Get-ItemProperty -Path "HKLM:\Software\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" -ErrorAction SilentlyContinue)) {
        Write-Output "Visual C++ Redistributable nicht gefunden. Starte die Installation..."
        $vcRedistPath = "$downloadPath\vc_redist.x64.exe"
        $vcRedistProcess = Start-Process -FilePath $vcRedistPath -ArgumentList "/install", "/quiet", "/norestart" -PassThru -Wait
        if ($vcRedistProcess.ExitCode -eq 0) {
            Write-Output "Visual C++ Redistributable wurde erfolgreich installiert."
        } else {
            Write-Output "Fehler bei der Installation von Visual C++ Redistributable. Exit-Code: $($vcRedistProcess.ExitCode)"
        }
    } else {
        Write-Output "Visual C++ Redistributable bereits installiert."
    }

    # Check whether DirectX Runtime is already installed
    if (!(Test-Path "HKLM:\Software\Microsoft\DirectX" -ErrorAction SilentlyContinue)) {
        Write-Output "DirectX Runtime nicht gefunden. Starte die Installation..."
        $directXPath = "$downloadPath\dxwebsetup.exe"
        $directXProcess = Start-Process -FilePath $directXPath -ArgumentList "/silent" -PassThru -Wait
        if ($directXProcess.ExitCode -eq 0) {
            Write-Output "DirectX Runtime wurde erfolgreich installiert."
        } else {
            Write-Output "Fehler bei der Installation von DirectX Runtime. Exit-Code: $($directXProcess.ExitCode)"
        }
    } else {
        Write-Output "DirectX Runtime bereits installiert."
    }

    # Define the path to the SteamCMD exe relative to the script directory
    $SteamCmdPath = Join-Path -Path $SteamCMD -ChildPath "SteamCMD\steamcmd.exe"

    # SteamCMD Installation und Update mit anonymem Account
    Start-Process -FilePath $SteamCmdPath -ArgumentList "+force_install_dir $ARKServerPath +login anonymous +app_update $AppID +quit" -Wait
}

$InstallButton.Add_Click({
    Install-ARKServer
})

# Funktion, um die GUI anzuzeigen
[Windows.Forms.Application]::Run($Form)
