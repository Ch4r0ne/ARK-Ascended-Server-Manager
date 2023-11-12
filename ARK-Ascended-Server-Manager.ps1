Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Define default values
$DefaultConfig = @{
    SteamCMD = "C:\GameServer\SteamCMD"
    ARKServerPath = "C:\GameServer\ARK-Survival-Ascended-Server"
    ServerMAP = "TheIsland_WP"
    ServerName = ""
    MaxPlayers = "70"
    Port = "27015"
    QueryPort = "27016"
    BattleEye = "NoBattlEye"
    AdminPassword = ""
    Password = ""
    Mods= ""
    RCONPort = "27020"
    RCONEnabled = "True"
    ForceRespawnDinos = $false  # Set the default value as a boolean"
    ServerIP = "localhost"
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
        Port = $PortTextBox.Text
        QueryPort = $QueryPortTextBox.Text
        BattleEye = $BattleEyeComboBox.SelectedItem.ToString()
        AdminPassword = $AdminPasswordTextBox.Text
        Password = $PasswordTextBox.Text
        Mods = $ModsTextBox.Text
        RCONPort = $RCONPortTextBox.Text
        RCONEnabled = $RCONEnabledComboBox.SelectedItem.ToString()
        ForceRespawnDinos = $ForceRespawnDinosCheckBox.Checked  # Convert the checkbox value to boolean
        ServerIP = $ServerIPTextBox.Text
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
$Port = $ConfigData.Port
$QueryPort = $ConfigData.QueryPort
$BattleEye = $ConfigData.BattleEye
$AdminPassword = $ConfigData.AdminPassword
$Password = $ConfigData.Password
$Mods = $ConfigData.Mods
$RCONPort = $ConfigData.RCONPort
$RCONEnabled = $ConfigData.RCONEnabled
$ForceRespawnDinos = $ConfigData.ForceRespawnDinos
$ServerIP = $ConfigData.ServerIP

# Create GUI window
$Form = New-Object Windows.Forms.Form
$Form.Text = "ARK-Ascended-Server-Manager"
$Form.Size = New-Object Drawing.Size(1000, 600)

# Label to display player count
$PlayerCountLabel = New-Object Windows.Forms.Label
$PlayerCountLabel.Text = "Players Online: 0/$MaxPlayers"
#$PlayerCountLabel.AutoSize = $true
$PlayerCountLabel.Location = New-Object Drawing.Point(10, 10)
$Form.Controls.Add($PlayerCountLabel)

# Button to trigger player count update
$UpdatePlayerCountButton = New-Object Windows.Forms.Button
$UpdatePlayerCountButton.Location = New-Object Drawing.Point(120, 10)
$UpdatePlayerCountButton.Size = New-Object Drawing.Size(80, 30)
$UpdatePlayerCountButton.Text = "Update Player Count"
$UpdatePlayerCountButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
$UpdatePlayerCountButton.Add_Click({ 
    Get-PlayerCount
    Get-Mcrcon
})
$Form.Controls.Add($UpdatePlayerCountButton)


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

# Server IP
$ServerIPLabel = New-Object Windows.Forms.Label
$ServerIPLabel.Text = "Server IP:"
$ServerIPLabel.Location = New-Object Drawing.Point(50, 200)
$Form.Controls.Add($ServerIPLabel)

$ServerIPTextBox = New-Object Windows.Forms.TextBox
$ServerIPTextBox.Location = New-Object Drawing.Point(200, 200)
$ServerIPTextBox.Size = New-Object Drawing.Size(150, 20)
$Form.Controls.Add($ServerIPTextBox)

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

# Command Input Field
$CommandLabel = New-Object Windows.Forms.Label
$CommandLabel.Text = "Enter Command:"
$CommandLabel.AutoSize = $true
$CommandLabel.Location = New-Object Drawing.Point(550, 50)
$Form.Controls.Add($CommandLabel)

$CommandTextBox = New-Object Windows.Forms.TextBox
$CommandTextBox.Location = New-Object Drawing.Point(650, 50)
$CommandTextBox.Size = New-Object Drawing.Size(220, 20)
$Form.Controls.Add($CommandTextBox)

# Console Output Field
$ConsoleOutputLabel = New-Object Windows.Forms.Label
$ConsoleOutputLabel.Text = "Console Output:"
$ConsoleOutputLabel.Location = New-Object Drawing.Point(50, 110)
$Form.Controls.Add($ConsoleOutputLabel)

$ConsoleOutputTextBox = New-Object Windows.Forms.TextBox
$ConsoleOutputTextBox.Location = New-Object Drawing.Point(550, 80)
$ConsoleOutputTextBox.Size = New-Object Drawing.Size(400, 100)
$ConsoleOutputTextBox.Multiline = $true
$ConsoleOutputTextBox.ScrollBars = "Vertical"
$ConsoleOutputTextBox.ReadOnly = $true
$Form.Controls.Add($ConsoleOutputTextBox)

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
$SaveButton.Text = "Save Config"
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
$StartServerButton.Text = "Start Server"
$Form.Controls.Add($StartServerButton)
$StartServerButton.Add_Click({
    try {
        Save-Config
        Update-Config
        #Update-ARKServer
        Start-ARKServer
        [System.Windows.Forms.MessageBox]::Show("ARK Server has been started successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error while starting the ARK server: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# Backup Button
$BackupButton = New-Object Windows.Forms.Button
$BackupButton.Location = New-Object Drawing.Point(875, 500)
$BackupButton.Size = New-Object Drawing.Size(80, 30)
$BackupButton.Text = "Backup"
$Form.Controls.Add($BackupButton)
$BackupButton.Add_Click({
    $downloadConfirmation = [System.Windows.Forms.MessageBox]::Show("Do you want to download the backup tool?", "Confirmation", [System.Windows.Forms.MessageBoxButtons]::OKCancel, [System.Windows.Forms.MessageBoxIcon]::Question)
    if ($downloadConfirmation -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            Download-BackupTool
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Backup process canceled.", "Canceled", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

# Create Auto Update Job button
$buttonAutoUpdateJob = New-Object Windows.Forms.Button
$buttonAutoUpdateJob.Location = New-Object Drawing.Point(700, 500)
$buttonAutoUpdateJob.Size = New-Object Drawing.Size(150, 30)
$buttonAutoUpdateJob.Text = "Create Auto-Update Job"
$Form.Controls.Add($buttonAutoUpdateJob)
$buttonAutoUpdateJob.Add_Click({
    function Create-AutoUpdateJob {
        param (
            [string]$TaskName,
            [string]$ScriptPath,
            [string]$ConfigFolderPath
        )

        # Create a form for better user interaction
        $form = New-Object Windows.Forms.Form
        $form.Text = "Create Auto-Update Job"
        $form.Size = New-Object Drawing.Size(400, 200)
        $form.StartPosition = "CenterScreen"

        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point(10, 20)
        $label.Size = New-Object Drawing.Size(380, 20)
        $label.Text = "Please enter the details for the Auto-Update job:"

        $labelTime = New-Object Windows.Forms.Label
        $labelTime.Location = New-Object Drawing.Point(10, 50)
        $labelTime.Size = New-Object Drawing.Size(100, 20)
        $labelTime.Text = "Scheduled Time:"

        $dateTimePicker = New-Object Windows.Forms.DateTimePicker
        $dateTimePicker.Location = New-Object Drawing.Point(120, 50)
        $dateTimePicker.Format = [Windows.Forms.DateTimePickerFormat]::Custom
        $dateTimePicker.CustomFormat = "HH:mm"

        $labelTaskName = New-Object Windows.Forms.Label
        $labelTaskName.Location = New-Object Drawing.Point(10, 80)
        $labelTaskName.Size = New-Object Drawing.Size(100, 20)
        $labelTaskName.Text = "Task Name:"

        $textBoxTaskName = New-Object Windows.Forms.TextBox
        $textBoxTaskName.Location = New-Object Drawing.Point(120, 80)
        $textBoxTaskName.Size = New-Object Drawing.Size(200, 20)

        $buttonOK = New-Object Windows.Forms.Button
        $buttonOK.Location = New-Object Drawing.Point(120, 120)
        $buttonOK.Size = New-Object Drawing.Size(75, 23)
        $buttonOK.Text = "OK"
        $buttonOK.DialogResult = [Windows.Forms.DialogResult]::OK

        $buttonCancel = New-Object Windows.Forms.Button
        $buttonCancel.Location = New-Object Drawing.Point(220, 120)
        $buttonCancel.Size = New-Object Drawing.Size(75, 23)
        $buttonCancel.Text = "Cancel"
        $buttonCancel.DialogResult = [Windows.Forms.DialogResult]::Cancel

        # Add controls to the form
        $form.Controls.Add($label)
        $form.Controls.Add($labelTime)
        $form.Controls.Add($dateTimePicker)
        $form.Controls.Add($labelTaskName)
        $form.Controls.Add($textBoxTaskName)
        $form.Controls.Add($buttonOK)
        $form.Controls.Add($buttonCancel)

        # Show the form
        $result = $form.ShowDialog()

        if ($result -eq [Windows.Forms.DialogResult]::OK) {
            $selectedTime = $dateTimePicker.Value.ToString("HH:mm")
            $selectedTaskName = $textBoxTaskName.Text

            # Download AutoUpdateJob.ps1 from GitHub if it does not exist
            $autoUpdateScriptPath = Join-Path $ScriptPath "AutoUpdateJob.ps1"
            if (-not (Test-Path $autoUpdateScriptPath)) {
                $downloadUrl = "https://raw.githubusercontent.com/Ch4r0ne/ARK-Ascended-Server-Manager/main/AutoUpdateJob.ps1"
                Invoke-WebRequest -Uri $downloadUrl -OutFile $autoUpdateScriptPath
            }

            # Create scheduled task
            $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "$autoUpdateScriptPath"
            $taskTrigger = New-ScheduledTaskTrigger -Daily -At $selectedTime

            Register-ScheduledTask -Action $taskAction -Trigger $taskTrigger -TaskName "$TaskName - $selectedTaskName" -Force
        }
    }

    # Define script and task names
    $scriptPath = $ConfigFolderPath
    $taskName = "AutoUpdateJob"

    # Check if task with the same name already exists
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

    if ($existingTask -ne $null) {
        $result = [Windows.Forms.MessageBox]::Show("A task with the name $taskName already exists. Do you want to overwrite it?", "Warning", [Windows.Forms.MessageBoxButtons]::YesNo, [Windows.Forms.MessageBoxIcon]::Warning)

        if ($result -eq [Windows.Forms.DialogResult]::No) {
            return
        }
    }

    # Create Auto-Update job
    Create-AutoUpdateJob -TaskName $taskName -ScriptPath $scriptPath -ConfigFolderPath $ConfigFolderPath

    Start-Process "taskschd.msc"
})



# Send button for the RCON command
$buttonSend = New-Object Windows.Forms.Button
$buttonSend.Text = "Send"
$buttonSend.Location = New-Object Drawing.Point(875, 50)
$Form.Controls.Add($buttonSend)
$buttonSend.Add_Click({
    Get-Mcrcon
    try {
        # Validate user inputs
        if (-not $ServerIP -or -not $AdminPassword) {
            throw "Server IP and Admin Password are required."
        }

        $rconCommand = $CommandTextBox.Text
        $mcrconOutput = Send-RconCommand -ServerIP $ServerIP -RCONPort $RCONPort -AdminPassword $AdminPassword -Command $rconCommand

        # Write the RCON input into the RichTextBox
        $ConsoleOutputTextBox.AppendText("Command: $rconCommand`r`n")

        # Write the RCON output to the RichTextBox
        $ConsoleOutputTextBox.AppendText("Response: $($mcrconOutput -join "`r`n")`r`n")
    } catch {
        [System.Windows.Forms.MessageBox]::Show("An error occurred: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# Stop Server button
$buttonStopServer = New-Object Windows.Forms.Button
$buttonStopServer.Location = New-Object Drawing.Point(450, 500)
$buttonStopServer.Size = New-Object Drawing.Size(80, 30)
$buttonStopServer.Text = "Stop Server"
$Form.Controls.Add($buttonStopServer)
$buttonStopServer.Add_Click({
    Get-Mcrcon
    try {
        # Validate user inputs
        if (-not $ServerIP -or -not $AdminPassword) {
            throw "Server IP and Admin Password are required."
        }

        # Stop server command
        $stopServerCommand = "doexit"
        $mcrconOutput = Send-RconCommand -ServerIP $ServerIP -RCONPort $RCONPort -AdminPassword $AdminPassword -Command $stopServerCommand

        # Write the RCON input into the RichTextBox
        $ConsoleOutputTextBox.AppendText("Command: $stopServerCommand`r`n")

        # Write the RCON output to the RichTextBox
        $ConsoleOutputTextBox.AppendText("Response: $($mcrconOutput -join "`r`n")`r`n")
    } catch {
        [System.Windows.Forms.MessageBox]::Show("An error occurred: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# Open GameUserSettings.ini button
$buttonOpenGameUserSettings = New-Object Windows.Forms.Button
$buttonOpenGameUserSettings.Location = New-Object Drawing.Point(550, 200)
$buttonOpenGameUserSettings.Size = New-Object Drawing.Size(200, 30)
$buttonOpenGameUserSettings.Text = "Open GameUserSettings.ini"
$buttonOpenGameUserSettings.FlatStyle = [System.Windows.Forms.FlatStyle]::Popup  # Modified button style
$buttonOpenGameUserSettings.Add_Click({
    $GameUserSettingsPath = Join-Path $ARKServerPath "ShooterGame\Saved\Config\WindowsServer\GameUserSettings.ini"

    if (-not (Test-Path -Path $GameUserSettingsPath)) {
        New-Item -ItemType File -Path $GameUserSettingsPath
    }

    Invoke-Item $GameUserSettingsPath
})
$Form.Controls.Add($buttonOpenGameUserSettings)

# Open Game.ini button
$buttonOpenGameIni = New-Object Windows.Forms.Button
$buttonOpenGameIni.Location = New-Object Drawing.Point(760, 200)
$buttonOpenGameIni.Size = New-Object Drawing.Size(200, 30)
$buttonOpenGameIni.Text = "Open Game.ini"
$buttonOpenGameIni.FlatStyle = [System.Windows.Forms.FlatStyle]::Popup  # Modified button style
$buttonOpenGameIni.Add_Click({
    $GameIniPath = Join-Path $ARKServerPath "ShooterGame\Saved\Config\WindowsServer\Game.ini"

    # Check if Game.ini exists
    if (-not (Test-Path -Path $GameIniPath)) {
        # Create an empty Game.ini
        New-Item -ItemType File -Path $GameIniPath | Out-Null
    }

    # Read the content of Game.ini
    $gameIniContent = Get-Content $GameIniPath -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrEmpty($gameIniContent)) {
        # Write default content to Game.ini if it's empty
        @"
[/Script/ShooterGame.ShooterGameMode]
BabyImprintingStatScaleMultiplier=1
BabyCuddleIntervalMultiplier=1
BabyCuddleGracePeriodMultiplier=1
BabyCuddleLoseImprintQualitySpeedMultiplier=1
PerLevelStatsMultiplier_DinoTamed[0]=0.200000003
PerLevelStatsMultiplier_DinoTamed[1]=1
PerLevelStatsMultiplier_DinoTamed[2]=1
PerLevelStatsMultiplier_DinoTamed[3]=1
PerLevelStatsMultiplier_DinoTamed[4]=1
PerLevelStatsMultiplier_DinoTamed[5]=1
PerLevelStatsMultiplier_DinoTamed[6]=1
PerLevelStatsMultiplier_DinoTamed[7]=1
PerLevelStatsMultiplier_DinoTamed[8]=0.173999995
PerLevelStatsMultiplier_DinoTamed[9]=1
PerLevelStatsMultiplier_DinoTamed[10]=1
PerLevelStatsMultiplier_DinoTamed_Add[0]=0.140000001
PerLevelStatsMultiplier_DinoTamed_Add[1]=1
PerLevelStatsMultiplier_DinoTamed_Add[2]=1
PerLevelStatsMultiplier_DinoTamed_Add[3]=1
PerLevelStatsMultiplier_DinoTamed_Add[4]=1
PerLevelStatsMultiplier_DinoTamed_Add[5]=1
PerLevelStatsMultiplier_DinoTamed_Add[6]=1
PerLevelStatsMultiplier_DinoTamed_Add[7]=1
PerLevelStatsMultiplier_DinoTamed_Add[8]=0.140000001
PerLevelStatsMultiplier_DinoTamed_Add[9]=1
PerLevelStatsMultiplier_DinoTamed_Add[10]=1
PerLevelStatsMultiplier_DinoTamed_Affinity[0]=0.439999998
PerLevelStatsMultiplier_DinoTamed_Affinity[1]=1
PerLevelStatsMultiplier_DinoTamed_Affinity[2]=1
PerLevelStatsMultiplier_DinoTamed_Affinity[3]=1
PerLevelStatsMultiplier_DinoTamed_Affinity[4]=1
PerLevelStatsMultiplier_DinoTamed_Affinity[5]=1
PerLevelStatsMultiplier_DinoTamed_Affinity[6]=1
PerLevelStatsMultiplier_DinoTamed_Affinity[7]=1
PerLevelStatsMultiplier_DinoTamed_Affinity[8]=0.439999998
PerLevelStatsMultiplier_DinoTamed_Affinity[9]=1
PerLevelStatsMultiplier_DinoTamed_Affinity[10]=1
PerLevelStatsMultiplier_DinoWild[0]=1
PerLevelStatsMultiplier_DinoWild[1]=1
PerLevelStatsMultiplier_DinoWild[2]=1
PerLevelStatsMultiplier_DinoWild[3]=1
PerLevelStatsMultiplier_DinoWild[4]=1
PerLevelStatsMultiplier_DinoWild[5]=1
PerLevelStatsMultiplier_DinoWild[6]=1
PerLevelStatsMultiplier_DinoWild[7]=1
PerLevelStatsMultiplier_DinoWild[8]=1
PerLevelStatsMultiplier_DinoWild[9]=1
PerLevelStatsMultiplier_DinoWild[10]=1
PerLevelStatsMultiplier_Player[0]=1
PerLevelStatsMultiplier_Player[1]=1
PerLevelStatsMultiplier_Player[2]=1
PerLevelStatsMultiplier_Player[3]=1
PerLevelStatsMultiplier_Player[4]=1
PerLevelStatsMultiplier_Player[5]=1
PerLevelStatsMultiplier_Player[6]=1
PerLevelStatsMultiplier_Player[7]=1
PerLevelStatsMultiplier_Player[8]=1
PerLevelStatsMultiplier_Player[9]=1
PerLevelStatsMultiplier_Player[10]=1
GlobalSpoilingTimeMultiplier=0
GlobalItemDecompositionTimeMultiplier=0
GlobalCorpseDecompositionTimeMultiplier=6
PvPZoneStructureDamageMultiplier=6
StructureDamageRepairCooldown=180
IncreasePvPRespawnIntervalCheckPeriod=300
IncreasePvPRespawnIntervalMultiplier=2
IncreasePvPRespawnIntervalBaseAmount=59.9999809
ResourceNoReplenishRadiusPlayers=1
ResourceNoReplenishRadiusStructures=1
CropGrowthSpeedMultiplier=1
LayEggIntervalMultiplier=1
PoopIntervalMultiplier=1
CropDecaySpeedMultiplier=1
MatingIntervalMultiplier=1
EggHatchSpeedMultiplier=1
BabyMatureSpeedMultiplier=1
BabyFoodConsumptionSpeedMultiplier=1
DinoTurretDamageMultiplier=1
DinoHarvestingDamageMultiplier=3.20000005
PlayerHarvestingDamageMultiplier=1
CustomRecipeEffectivenessMultiplier=1
CustomRecipeSkillMultiplier=1
AutoPvEStartTimeSeconds=0
AutoPvEStopTimeSeconds=0
KillXPMultiplier=1
HarvestXPMultiplier=1
CraftXPMultiplier=1
GenericXPMultiplier=1
SpecialXPMultiplier=1
FuelConsumptionIntervalMultiplier=1
PhotoModeRangeLimit=3000
bDisablePhotoMode=False
bIncreasePvPRespawnInterval=True
bAutoPvETimer=False
bAutoPvEUseSystemTime=False
bDisableFriendlyFire=False
bFlyerPlatformAllowUnalignedDinoBasing=False
bDisableLootCrates=False
bAllowCustomRecipes=True
bPassiveDefensesDamageRiderlessDinos=False
bPvEAllowTribeWar=True
bPvEAllowTribeWarCancel=False
MaxDifficulty=False
bUseSingleplayerSettings=True
bUseCorpseLocator=True
bShowCreativeMode=False
bHardLimitTurretsInRange=True
bDisableStructurePlacementCollision=False
bAllowPlatformSaddleMultiFloors=False
bAllowUnlimitedRespecs=False
bDisableDinoRiding=False
bDisableDinoTaming=False
OverrideMaxExperiencePointsPlayer=0
OverrideMaxExperiencePointsDino=0
MaxNumberOfPlayersInTribe=0
ExplorerNoteXPMultiplier=1
BossKillXPMultiplier=1
AlphaKillXPMultiplier=1
WildKillXPMultiplier=1
CaveKillXPMultiplier=1
TamedKillXPMultiplier=1
UnclaimedKillXPMultiplier=1
SupplyCrateLootQualityMultiplier=1
FishingLootQualityMultiplier=1
CraftingSkillBonusMultiplier=1
bAllowSpeedLeveling=False
bAllowFlyerSpeedLeveling=False

[ShooterGameMode_TEMPOverrides]
bUseCorpseLocator=True
"@ | Set-Content -Path $GameIniPath
    } else {
        # File has content, do nothing or provide a message
        Write-Host "Game.ini already has content. Not overwriting."
    }

    Invoke-Item $GameIniPath
})
$Form.Controls.Add($buttonOpenGameIni)

# Function to update the GUI elements with the loaded configuration data
function Update-GUIFromConfig {
    $SteamCMDPathTextBox.Text = $SteamCMD
    $ARKServerPathTextBox.Text = $ARKServerPath
    $ServerMAPTextBox.Text = $ServerMAP
    $ServerNameTextBox.Text = $ServerName
    $MaxPlayersTextBox.Text = $MaxPlayers
    $PortTextBox.Text = $Port
    $QueryPortTextBox.Text = $QueryPort
    $BattleEyeComboBox.SelectedItem = $BattleEye
    $AdminPasswordTextBox.Text = $AdminPassword
    $PasswordTextBox.Text = $Password
    $ModsTextBox.Text = $Mods
    $RCONPortTextBox.Text = $RCONPort
    $RCONEnabledComboBox.SelectedItem = $RCONEnabled
    $ForceRespawnDinosCheckBox.Checked = [System.Boolean]::Parse($ConfigData.ForceRespawnDinos)  # Set checkbox value based on the saved boolean value
    $ServerIPTextBox.Text =  $ServerIP

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

# Function to get player count using RCON
function Get-PlayerCount {
    try {
        # Validate user inputs
        if (-not $ServerIP -or -not $AdminPassword) {
            throw "Server IP and Admin Password are required."
        }

        # RCON command to get player list
        $getPlayerCountCommand = "listplayers"
        $mcrconOutput = Send-RconCommand -ServerIP $ServerIP -RCONPort $RCONPort -AdminPassword $AdminPassword -Command $getPlayerCountCommand

        # Check if the output contains "No Players Connected"
        if ($mcrconOutput -match "No Players Connected") {
            $playerCount = 0
        } else {
            # Count the number of lines in the output, each line represents a player
            $playerCount = $mcrconOutput.Count
        }

        # Update the PlayerCountLabel
        $PlayerCountLabel.Text = "Players Online: $playerCount/$MaxPlayers"
    } catch {
        [System.Windows.Forms.MessageBox]::Show("An error occurred: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

# Function to download and extract mcrcon.exe
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

# Function to send RCON command
function Send-RconCommand {
    param (
        [string]$ServerIP,
        [int]$RCONPort,
        [string]$AdminPassword,
        [string]$Command
    )

    try {
        $mcrconPath = Get-Mcrcon

        # Connect to the server via RCON and send the command
        $mcrconOutput = Invoke-Expression "$mcrconPath -H $ServerIP -P $RCONPort -p '$AdminPassword' '$Command'"

        # Replace all newline characters with `n` in the output
        $mcrconOutput = $mcrconOutput -replace "`r`n|`r|`n|`n", "`n"

        return "$mcrconOutput`n"
    } catch {
        throw "An error occurred: $_"
    }
}

# Function Download Backup Tool
function Download-BackupTool {
    $BackupToolURL = "https://github.com/Ch4r0ne/Backup-Tool/releases/download/1.0.2/BackupJobSchedulerGUI.msi"
    
    # Extrahiere den Dateinamen aus der URL
    $fileName = [System.IO.Path]::GetFileName($BackupToolURL)
    
    # Ask user for download location
    $downloadPath = Get-SaveFileLocation -Title "Select download location" -Filter "MSI Files (*.msi)|*.msi" -FileName $fileName

    # Check if the user selected a location
    if ($downloadPath -ne "") {
        Write-Output "Downloading Backup Tool to $downloadPath..."
        Invoke-WebRequest -Uri $BackupToolURL -OutFile $downloadPath
        Write-Output "Backup Tool downloaded successfully to $downloadPath."
    } else {
        Write-Output "Download canceled by user."
    }
}

# Function to show Save File Dialog
function Get-SaveFileLocation {
    param (
        [string]$Title,
        [string]$Filter,
        [string]$FileName
    )

    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null

    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Title = $Title
    $saveFileDialog.Filter = $Filter
    $saveFileDialog.FileName = $FileName

    $result = $saveFileDialog.ShowDialog()

    if ($result -eq "OK" -or $result -eq "Yes") {
        return $saveFileDialog.FileName
    } else {
        return ""
    }
}

# Function to start the ARK server
function Start-ARKServer {

    # Update configuration settings
    Update-Config

    # Read the data from the configuration file
    $ConfigData = Get-Content -Path $ScriptConfig -Raw | ConvertFrom-Json

    # Trim the variables to remove spaces
    $ServerMAP = $ConfigData.ServerMAP.Trim()
    $ServerName = $ConfigData.ServerName.Trim()
    $Port = $ConfigData.Port.Trim()
    $QueryPort = $ConfigData.QueryPort.Trim()
    $Password = $ConfigData.Password.Trim()
    $AdminPassword = $ConfigData.AdminPassword.Trim()
    $RCONEnabled = $ConfigData.RCONEnabled
    $RCONPort = $ConfigData.RCONPort
    $BattleEye = $ConfigData.BattleEye
    $Mods = $ConfigData.Mods.Trim()
    $MaxPlayer = $ConfigData.MaxPlayer

    $ForceRespawnDinos = $ConfigData.ForceRespawnDinos
    if ($ForceRespawnDinos -eq $true) {
        $ForceRespawnDinosValue = "ForceRespawnDinos"
    } else {
        $ForceRespawnDinosValue = ""
    }

    $MaxPlayers = $ConfigData.MaxPlayers.Trim()

    # Create the ServerArguments string with formatting
    $ServerArguments = [System.String]::Format('start {0}?listen?SessionName="{1}"?Port={2}?QueryPort={3}?ServerPassword="{4}"?MaxPlayers="{6}"?RCONEnabled={7}?RCONPort={8}?ServerAdminPassword="{5}" -{9} -automanagedmods -mods={10}, -{11}', $ServerMAP, $ServerName, $Port, $QueryPort, $Password, $AdminPassword, $MaxPlayers, $RCONEnabled, $RCONPort, $BattleEye, $Mods, $ForceRespawnDinosValue)

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
    $ConfigData.Port = $PortTextBox.Text
    $ConfigData.QueryPort = $QueryPortTextBox.Text
    $ConfigData.BattleEye = $BattleEyeComboBox.SelectedItem.ToString()
    $ConfigData.AdminPassword = $AdminPasswordTextBox.Text
    $ConfigData.Password = $PasswordTextBox.Text
    $ConfigData.Mods = $ModsTextBox.Text
    $ConfigData.RCONPort = $RCONPortTextBox.Text
    $ConfigData.RCONEnabled = $RCONEnabledComboBox.SelectedItem.ToString()
    $ConfigData.ForceRespawnDinos = $ForceRespawnDinosCheckBox.Checked  # Convert the checkbox value to boolean
    $ConfigData.ServerIP = $ServerIPTextBox.Text  # Save Server IP


    # Update global variables with new values
    $script:SteamCMD = $ConfigData.SteamCMD
    $script:ARKServerPath = $ConfigData.ARKServerPath
    $script:ServerMAP = $ConfigData.ServerMAP
    $script:ServerName = $ConfigData.ServerName
    $script:MaxPlayers = $ConfigData.MaxPlayers
    $script:Port = $ConfigData.Port
    $script:QueryPort = $ConfigData.QueryPort
    $script:BattleEye = $ConfigData.BattleEye
    $script:AdminPassword = $ConfigData.AdminPassword
    $script:Password = $ConfigData.Password
    $script:Mods = $ConfigData.Mods
    $script:RCONPort = $ConfigData.RCONPort
    $script:RCONEnabled = $ConfigData.RCONEnabled
    $script:ForceRespawnDinos = $ConfigData.ForceRespawnDinos  # Assign boolean value directly
    $script:ServerIP = $ConfigData.ServerIP  # Assign Server IP

    Save-Config
}

# Function for installing the ARK server
function Install-ARKServer {
    try {
        # Update configuration settings
        Update-Config
        # Downloade Mcrcon
        Get-Mcrcon


        # Configuration settings
        $ConfigData = Get-Content -Path $ScriptConfig -Raw | ConvertFrom-Json
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

        # Certificate installation
        . {
            $amazonRootCAUrl = "https://www.amazontrust.com/repository/AmazonRootCA1.cer"
            $certificateUrl = "http://crt.r2m02.amazontrust.com/r2m02.cer"
            $amazonRootCADirectory = "$env:TEMP\AmazonRootCA1.cer"
            $targetDirectory = "$env:TEMP\r2m02.cer"

            try {
                Invoke-WebRequest -Uri $amazonRootCAUrl -OutFile $amazonRootCADirectory -UseBasicParsing -ErrorAction Stop
                Invoke-WebRequest -Uri $certificateUrl -OutFile $targetDirectory -UseBasicParsing -ErrorAction Stop

                Import-Certificate -FilePath $amazonRootCADirectory -CertStoreLocation Cert:\CurrentUser\CA -ErrorAction Stop
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $cert.Import($targetDirectory)
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("CA", "CurrentUser")
                $store.Open("ReadWrite")
                $store.Add($cert)
                $store.Close()

                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("CA", "LocalMachine")
                $store.Open("ReadWrite")
                $store.Add($cert)
                $store.Close()
            }
            catch {
                Write-Error "Error occurred while installing the certificate: $_"
            }
        }

        # Output installation message with Cancel button
        $result = [System.Windows.Forms.MessageBox]::Show("The installation process will start now. Please wait, this may take 1-10 minutes. Required components will be downloaded and installed. Click 'Cancel' to stop the installation.", "Installation Start", [System.Windows.Forms.MessageBoxButtons]::OKCancel, [System.Windows.Forms.MessageBoxIcon]::Information)

        if ($result -eq [System.Windows.Forms.DialogResult]::Cancel) {
            Write-Output "Installation canceled."
            return
        }

        # Install Visual C++ Redistributable if not already installed
        if (!(Test-Path -Path "HKLM:\Software\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" -ErrorAction SilentlyContinue)) {
            Install-Component -url $vcRedistUrl -outputFile "vc_redist.x64.exe" -arguments "/install", "/passive", "/norestart" -wait
        } else {
            Write-Output "Visual C++ Redistributable already installed."
        }

        # Install DirectX Runtime if not already installed
        if (!(Test-Path "HKLM:\Software\Microsoft\DirectX" -ErrorAction SilentlyContinue)) {
            Install-Component -url $directXUrl -outputFile "dxwebsetup.exe" -arguments "/silent" -wait
        } else {
            Write-Output "DirectX Runtime already installed."
        }

        # Create SteamCMD folder if it does not exist
        $TargetPath = Join-Path -Path $ConfigData.SteamCMD -ChildPath "SteamCMD"
        if (-not (Test-Path -Path $TargetPath)) {
            New-Item -Path $TargetPath -ItemType Directory -Force
        }

        # Download and install SteamCMD
        Write-Output "Downloading SteamCMD and installing ARK Server..."
        Invoke-WebRequest -Uri $SteamCMDURL -OutFile "$downloadPath\steamcmd.zip" -UseBasicParsing
        Expand-Archive -Path "$downloadPath\steamcmd.zip" -DestinationPath $TargetPath -Force
        $SteamCmdPath = Join-Path -Path $TargetPath -ChildPath "steamcmd.exe"
        Start-Process -FilePath $SteamCmdPath -ArgumentList @("+force_install_dir", "$ARKServerPath", "+login", "anonymous", "+app_update", "2430930", "+quit") -Wait

        [System.Windows.Forms.MessageBox]::Show("ARK Server has been successfully installed.", "Installation Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error occurred while installing the ARK server: $_", "Installation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

[Windows.Forms.Application]::Run($Form)