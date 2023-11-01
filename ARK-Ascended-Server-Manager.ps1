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
    Port = "27015"
    QueryPort = "27016"
    BattleEye = "NoBattlEye"
    AdminPassword = ""
    Password = ""
    Mods= ""
    RCONPort = "27020"
    RCONEnabled = "False"
    ForceRespawnDinos = $false  # Set the default value as a boolean
    #ClusterDirOverride = ""
    #clusterid = ""
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
        Mods = $ModsTextBox.Text
        RCONPort = $RCONPortTextBox.Text
        RCONEnabled = $RCONEnabledComboBox.SelectedItem.ToString()
        ForceRespawnDinos = $ForceRespawnDinosCheckBox.Checked  # Convert the checkbox value to boolean
        #ClusterDirOverride = $ClusterDirOverrideTextBox.Text
        #clusterid = $ClusterIdTextBox.Text
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
        Write-Output "Error reading configuration file. Default configuration is used."
        $ConfigData = $DefaultConfig
    }
} else {
    Write-Output "No configuration file found. Default configuration is used."
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
$Mods = $ConfigData.Mods
$RCONPort = $ConfigData.RCONPort
$RCONEnabled = $ConfigData.RCONEnabled
$ForceRespawnDinos = $ConfigData.ForceRespawnDinos
#$ClusterDirOverride = $ConfigData.ClusterDirOverride
#$clusterid = $ConfigData.clusterid

# Create GUI window
$Form = New-Object Windows.Forms.Form
$Form.Text = "ARK-Ascended-Server-Manager"
$Form.Size = New-Object Drawing.Size(600, 600)

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

# Mods
$ModsLabel = New-Object Windows.Forms.Label
$ModsLabel.Text = "Mods:"
$ModsLabel.Location = New-Object Drawing.Point(50, 410)
$Form.Controls.Add($ModsLabel)

$ModsTextBox = New-Object Windows.Forms.TextBox
$ModsTextBox.Location = New-Object Drawing.Point(200, 410)
$ModsTextBox.Size = New-Object Drawing.Size(330, 20)
$Form.Controls.Add($ModsTextBox)

# Password
$PasswordLabel = New-Object Windows.Forms.Label
$PasswordLabel.Text = "Password:"
$PasswordLabel.Location = New-Object Drawing.Point(50, 350)
$Form.Controls.Add($PasswordLabel)

$PasswordTextBox = New-Object Windows.Forms.TextBox
$PasswordTextBox.Location = New-Object Drawing.Point(200, 350)
$PasswordTextBox.Size = New-Object Drawing.Size(150, 20)
$Form.Controls.Add($PasswordTextBox)

# RCON Enabled
$RCONEnabledLabel = New-Object Windows.Forms.Label
$RCONEnabledLabel.Text = "RCON Enabled:"
$RCONEnabledLabel.Location = New-Object Drawing.Point(50, 380)
$Form.Controls.Add($RCONEnabledLabel)

$RCONEnabledComboBox = New-Object Windows.Forms.ComboBox
$RCONEnabledComboBox.Items.AddRange(@("True", "False"))
$RCONEnabledComboBox.Location = New-Object Drawing.Point(200, 380)
$RCONEnabledComboBox.SelectedItem = "False"
$Form.Controls.Add($RCONEnabledComboBox)

# RCON Port
$RCONPortLabel = New-Object Windows.Forms.Label
$RCONPortLabel.Text = "RCON Port:"
$RCONPortLabel.Location = New-Object Drawing.Point(330, 385)
$Form.Controls.Add($RCONPortLabel)

$RCONPortTextBox = New-Object Windows.Forms.TextBox
$RCONPortTextBox.Location = New-Object Drawing.Point(440, 382)
$RCONPortTextBox.Size = New-Object Drawing.Size(50, 20)
$Form.Controls.Add($RCONPortTextBox)

# Force Respawn Dinos (Checkbox)
$ForceRespawnDinosLabel = New-Object Windows.Forms.Label
$ForceRespawnDinosLabel.Text = "Force Respawn Dinos:"
$ForceRespawnDinosLabel.AutoSize = $true
$ForceRespawnDinosLabel.Location = New-Object Drawing.Point(50, 440)
$Form.Controls.Add($ForceRespawnDinosLabel)

$ForceRespawnDinosCheckBox = New-Object Windows.Forms.CheckBox
$ForceRespawnDinosCheckBox.Location = New-Object Drawing.Point(200, 440)
$ForceRespawnDinosCheckBox.Size = New-Object Drawing.Size(20, 20)
$Form.Controls.Add($ForceRespawnDinosCheckBox)


# ClusterDirOverride (Textfeld)
#$ClusterDirOverrideLabel = New-Object Windows.Forms.Label
#$ClusterDirOverrideLabel.Text = "ClusterDirOverride"
#$ClusterDirOverrideLabel.Location = New-Object Drawing.Point(50, 470)
#$Form.Controls.Add($ClusterDirOverrideLabel)

#$ClusterDirOverrideTextBox = New-Object Windows.Forms.TextBox
#$ClusterDirOverrideTextBox.Location = New-Object Drawing.Point(200, 470)
#$ClusterDirOverrideTextBox.Size = New-Object Drawing.Size(100, 20)
#$Form.Controls.Add($ClusterDirOverrideTextBox)

# clusterid (Textfeld)
#$ClusterIdLabel = New-Object Windows.Forms.Label
#$ClusterIdLabel.Text = "clusterid"
#$ClusterIdLabel.Location = New-Object Drawing.Point(330, 470)
#$Form.Controls.Add($ClusterIdLabel)

#$ClusterIdTextBox = New-Object Windows.Forms.TextBox
#$ClusterIdTextBox.Location = New-Object Drawing.Point(440, 470)
#$ClusterIdTextBox.Size = New-Object Drawing.Size(100, 20)
#$Form.Controls.Add($ClusterIdTextBox)

# Install Button
$InstallButton = New-Object Windows.Forms.Button
$InstallButton.Location = New-Object Drawing.Point(50, 500)
$InstallButton.Size = New-Object Drawing.Size(80, 30)
$InstallButton.Text = "Install"
$Form.Controls.Add($InstallButton)
$InstallButton.Add_Click({
    Save-Config
    Update-Config
	Install-ARKServer
})

# Server Update Button
$ServerUpdateButton = New-Object Windows.Forms.Button
$ServerUpdateButton.Location = New-Object Drawing.Point(150, 500)
$ServerUpdateButton.Size = New-Object Drawing.Size(80, 30)
$ServerUpdateButton.Text = "Update"
$Form.Controls.Add($ServerUpdateButton)
$ServerUpdateButton.Add_Click({
    try {
        Save-Config
        Update-Config
        Update-ARKServer
        [System.Windows.Forms.MessageBox]::Show("ARK Server has been updated successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error while updating the ARK server: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# Save Button
$SaveButton = New-Object Windows.Forms.Button
$SaveButton.Location = New-Object Drawing.Point(250, 500)
$SaveButton.Size = New-Object Drawing.Size(80, 30)
$SaveButton.Text = "Save"
$Form.Controls.Add($SaveButton)
$SaveButton.Add_Click({
    try {
        Save-Config
        Update-Config
        [System.Windows.Forms.MessageBox]::Show("Configuration has been saved and updated successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error while saving and updating the configuration: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# Start Server Button
$StartServerButton = New-Object Windows.Forms.Button
$StartServerButton.Location = New-Object Drawing.Point(350, 500)
$StartServerButton.Size = New-Object Drawing.Size(80, 30)
$StartServerButton.Text = "Start"
$Form.Controls.Add($StartServerButton)
$StartServerButton.Add_Click({
    try {
        Save-Config
        Update-Config
        Start-ARKServer
        [System.Windows.Forms.MessageBox]::Show("ARK Server has been started successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error while starting the ARK server: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
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
    $ModsTextBox.Text = $Mods
    $RCONPortTextBox.Text = $RCONPort
    $RCONEnabledComboBox.SelectedItem = $RCONEnabled
    $ForceRespawnDinosCheckBox.Checked = [System.Boolean]::Parse($ConfigData.ForceRespawnDinos)  # Set checkbox value based on the saved boolean value
    #$ClusterDirOverrideTextBox.Text = $ClusterDirOverride
    #$ClusterIdTextBox.Text = $clusterid

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
	
	$ForceRespawnDinos = $ConfigData.ForceRespawnDinos
	if ($ForceRespawnDinos -eq $true) {
		$ForceRespawnDinosValue = "ForceRespawnDinos"
	} else {
		$ForceRespawnDinosValue = ""
	}

    # Create the ServerArguments string with formatting
    $ServerArguments = [System.String]::Format('{0}?listen?SessionName="{1}"?Port={2}?QueryPort={3}?ServerPassword="{4}"?ServerAdminPassword="{5}"?MaxPlayers="{6}"?RCONEnabled={7}?RCONPort={8} -{9} -automanagedmods -mods={10}, -{11}', $ServerMAP, $ServerName, $Port, $QueryPort, $Password, $AdminPassword, $MaxPlayers, $RCONEnabled, $RCONPort, $BattleEye, $Mods, $ForceRespawnDinosValue)

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

# Function to update the ARK server
function Update-ARKServer {

    # Update configuration settings
    Update-Config

    # Read the data from the configuration file
    $ConfigData = Get-Content -Path $ScriptConfig -Raw | ConvertFrom-Json

    Start-Process -FilePath $SteamCMD\SteamCMD\steamcmd.exe -ArgumentList "+force_install_dir $ARKServerPath +login anonymous +app_update $AppID +quit" -Wait
}

function Update-Config {
    # Reading the variables from the GUI elements and saving them in the configuration file
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
    $ConfigData.Mods = $ModsTextBox.Text
    $ConfigData.RCONPort = $RCONPortTextBox.Text
    $ConfigData.RCONEnabled = $RCONEnabledComboBox.SelectedItem.ToString()
    $ConfigData.ForceRespawnDinos = $ForceRespawnDinosCheckBox.Checked  # Convert the checkbox value to boolean
    #$ConfigData.ClusterDirOverride = $ClusterDirOverrideTextBox.Text
    #$ConfigData.clusterid = $ClusterIdTextBox.Text


    # Update global variables with new values
    $script:SteamCMD = $ConfigData.SteamCMD
    $script:ARKServerPath = $ConfigData.ARKServerPath
    $script:ServerMAP = $ConfigData.ServerMAP
    $script:ServerName = $ConfigData.ServerName
    $script:MaxPlayers = $ConfigData.MaxPlayers
    $script:AppID = $ConfigData.AppID
    $script:Port = $ConfigData.Port
    $script:QueryPort = $ConfigData.QueryPort
    $script:BattleEye = $ConfigData.BattleEye
    $script:AdminPassword = $ConfigData.AdminPassword
    $script:Password = $ConfigData.Password
    $script:Mods = $ConfigData.Mods
    $script:RCONPort = $ConfigData.RCONPort
    $script:RCONEnabled = $ConfigData.RCONEnabled
    $script:ForceRespawnDinos = $ConfigData.ForceRespawnDinos  # Assign boolean value directly
    #$script:ClusterDirOverride = $ConfigData.ClusterDirOverride
    #$script:clusterid = $ConfigData.clusterid

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
		
			    # Invoke certificate installation script
				. {
					# Certificate installation script
					# URL of the certificate
					$amazonRootCAUrl = "https://www.amazontrust.com/repository/AmazonRootCA1.cer"
					$certificateUrl = "http://crt.r2m02.amazontrust.com/r2m02.cer"

					# Target directory for the certificate
					$amazonRootCADirectory = "$env:TEMP\AmazonRootCA1.cer"
					$targetDirectory = "$env:TEMP\r2m02.cer"

					try {
						
						# AmazonRootCA1-Zertifikat downloade
						Invoke-WebRequest -Uri $amazonRootCAUrl -OutFile $amazonRootCADirectory -UseBasicParsing -ErrorAction Stop
						
						# Download the certificate with SSL/TLS certificate validation
						Invoke-WebRequest -Uri $certificateUrl -OutFile $targetDirectory -UseBasicParsing -ErrorAction Stop

						# Add certificate to current user's intermediate CA
						Import-Certificate -FilePath $amazonRootCADirectory -CertStoreLocation Cert:\CurrentUser\CA -ErrorAction Stop
						
						$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
						$cert.Import($targetDirectory)
						$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("CA", "CurrentUser")
						$store.Open("ReadWrite")
						$store.Add($cert)
						$store.Close()

						# Add certificate to the intermediate certification authority of the local machine (administrator rights required)
						$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("CA", "LocalMachine")
						$store.Open("ReadWrite")
						$store.Add($cert)
						$store.Close()
					}
					catch {
						Write-Error "Error occurred while installing the certificate: $_"
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

# Funktion, um die GUI anzuzeigen
[Windows.Forms.Application]::Run($Form)
