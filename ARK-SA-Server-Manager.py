import ctypes
import os
import json
import subprocess
import tkinter as tk
from tkinter import messagebox
import winreg
import zipfile
import requests
import threading

# Define default values
default_config = {
    "SteamCMD": "C:\\GameServer\\SteamCMD",
    "ARKServerPath": "C:\\GameServer\\ARK-Survival-Ascended-Server",
    "ServerMAP": "TheIsland_WP",
    "ServerName": "default",
    "MaxPlayers": "70",
    "Port": "7777",
    "QueryPort": "27015",
    "BattleEye": False,
    "AdminPassword": "AdminPassword",
    "Password": "Password",
    "Mods": "",
    "RCONPort": "27020",
    "RCONEnabled": False,
    "ForceRespawnDinos": False,
    "UpdateAndValidate": False 
}
app_id = "376030"
task_thread = None

# Create configuration folder and file if not exists
config_folder_path = os.path.join(os.getenv('APPDATA'), "ARK-Ascended-Server-Manager")
script_config = os.path.join(config_folder_path, "testConfig.json")

if not os.path.exists(config_folder_path):
    os.makedirs(config_folder_path)

# Function to save configuration to file
def save_config():
    config_data = {
        "SteamCMD": steam_cmd_path.get(),
        "ARKServerPath": ark_server_path.get(),
        "ServerMAP": server_map.get(),
        "ServerName": server_name.get(),
        "MaxPlayers": max_players.get(),
        "Port": port.get(),
        "QueryPort": query_port.get(),
        "BattleEye": battle_eye_enabled.get(),
        "AdminPassword": admin_password.get(),
        "Password": password.get(),
        "Mods": mods.get(),
        "RCONPort": rcon_port.get(),
        "RCONEnabled": rcon_enabled.get(),
        "ForceRespawnDinos": force_respawn_dinos_var.get(),
        "UpdateAndValidate": update_and_validate_var.get()
    }
    
    with open(script_config, 'w') as config_file:
        json.dump(config_data, config_file, indent=4)

# Load configuration from file or set default values
if os.path.exists(script_config):
    try:
        with open(script_config, 'r') as config_file:
            config_data = json.load(config_file)
        
        for key in default_config.keys():
            if key not in config_data:
                config_data[key] = default_config[key]
    except:
        messagebox.showinfo("Error", "Error reading configuration file. Default configuration is used.")
        config_data = default_config
else:
    messagebox.showinfo("Info", "No configuration file found. Default configuration is used.")
    config_data = default_config

# Create GUI window
form = tk.Tk()
form.title("ARK-Ascended-Server-Manager")
form.geometry("600x600")

# SteamCMD path
steam_cmd_label = tk.Label(form, text="SteamCMD Path:")
steam_cmd_label.place(x=50, y=50)

steam_cmd_path = tk.Entry(form)
steam_cmd_path.place(x=200, y=50, width=300, height=20)
steam_cmd_path.insert(0, config_data["SteamCMD"])

# ARK Server Path
ark_server_label = tk.Label(form, text="ARK Server Path:")
ark_server_label.place(x=50, y=80)

ark_server_path = tk.Entry(form)
ark_server_path.place(x=200, y=80, width=300, height=20)
ark_server_path.insert(0, config_data["ARKServerPath"])

# Server MAP
server_map_label = tk.Label(form, text="Server MAP:")
server_map_label.place(x=50, y=110)

server_map = tk.Entry(form)
server_map.place(x=200, y=110, width=300, height=20)
server_map.insert(0, config_data["ServerMAP"])

# Server Name
server_name_label = tk.Label(form, text="Server Name:")
server_name_label.place(x=50, y=140)

server_name = tk.Entry(form)
server_name.place(x=200, y=140, width=300, height=20)
server_name.insert(0, config_data["ServerName"])

# Max Players
max_players_label = tk.Label(form, text="Max Players:")
max_players_label.place(x=50, y=170)

max_players = tk.Entry(form)
max_players.place(x=200, y=170, width=50, height=20)
max_players.insert(0, config_data["MaxPlayers"])

# Port
port_label = tk.Label(form, text="Port:")
port_label.place(x=50, y=230)

port = tk.Entry(form)
port.place(x=200, y=230, width=50, height=20)
port.insert(0, config_data["Port"])

# Query Port
query_port_label = tk.Label(form, text="Query Port:")
query_port_label.place(x=50, y=260)

query_port = tk.Entry(form)
query_port.place(x=200, y=260, width=50, height=20)
query_port.insert(0, config_data["QueryPort"])

# BattleEye (Checkbox)
battle_eye_label = tk.Label(form, text="BattleEye:")
battle_eye_label.place(x=50, y=290)

battle_eye_enabled = tk.BooleanVar()
battle_eye_enabled.set(config_data["BattleEye"])
battle_eye_checkbox = tk.Checkbutton(form, variable=battle_eye_enabled)
battle_eye_checkbox.place(x=200, y=290)

# Admin Password
admin_password_label = tk.Label(form, text="Admin Password:")
admin_password_label.place(x=50, y=320)

admin_password = tk.Entry(form)
admin_password.place(x=200, y=320, width=150, height=20)
admin_password.insert(0, config_data["AdminPassword"])

# Mods
mods_label = tk.Label(form, text="Mods:")
mods_label.place(x=50, y=410)

mods = tk.Entry(form)
mods.place(x=200, y=410, width=300, height=20)
mods.insert(0, config_data["Mods"])

# Password
password_label = tk.Label(form, text="Password:")
password_label.place(x=50, y=350)

password = tk.Entry(form)
password.place(x=200, y=350, width=150, height=20)
password.insert(0, config_data["Password"])

# RCON Enabled (Checkbox)
rcon_enabled_label = tk.Label(form, text="RCON Enabled:")
rcon_enabled_label.place(x=50, y=380)

rcon_enabled = tk.BooleanVar()
rcon_enabled.set(config_data["RCONEnabled"])
rcon_checkbox = tk.Checkbutton(form, variable=rcon_enabled)
rcon_checkbox.place(x=200, y=378)

# RCON Port
rcon_port_label = tk.Label(form, text="RCON Port:")
rcon_port_label.place(x=230, y=378)

rcon_port = tk.Entry(form)
rcon_port.place(x=300, y=380, width=50, height=20)
rcon_port.insert(0, config_data["RCONPort"])

# Force Respawn Dinos (Checkbox)
force_respawn_dinos_label = tk.Label(form, text="Force Respawn Dinos:")
force_respawn_dinos_label.place(x=50, y=440)

force_respawn_dinos_var = tk.BooleanVar()
force_respawn_dinos_var.set(config_data["ForceRespawnDinos"])
force_respawn_dinos_checkbox = tk.Checkbutton(form, variable=force_respawn_dinos_var)
force_respawn_dinos_checkbox.place(x=200, y=440)

# Update/Validate on server start (Checkbox)
update_and_validate_label = tk.Label(form, text="Update/Validate on server start:")
update_and_validate_label.place(x=230, y=440)

update_and_validate_var = tk.BooleanVar()
update_and_validate_var.set(config_data["UpdateAndValidate"])
update_and_validate_checkbox = tk.Checkbutton(form, variable=update_and_validate_var)
update_and_validate_checkbox.place(x=400, y=440)

# Install Button
def install_button_click():
    global task_thread
    save_config()
    if task_thread and task_thread.is_alive():
        print("Task is already running.")
    else:
        task_thread = threading.Thread(target=install_ark_server)
        task_thread.start()
    
    
install_button = tk.Button(form, text="Install", command=install_button_click)
install_button.place(x=50, y=500, width=80, height=30)

def install_ark_server():
    steamcmd_url = "https://steamcdn-a.akamaihd.net/client/installer/steamcmd.zip"
    vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
    directXUrl = "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe"
    steamcmd_path = config_data["SteamCMD"]
    ark_server_path = config_data["ARKServerPath"]
    
    # URLs for the certificates
    amazon_root_ca_url = "https://www.amazontrust.com/repository/AmazonRootCA1.cer"
    certificate_url = "http://crt.r2m02.amazontrust.com/r2m02.cer"

    # Paths for certificate storage
    amazon_root_ca_path = os.path.join(os.environ['TEMP'], 'AmazonRootCA1.cer')
    target_path = os.path.join(os.environ['TEMP'], 'r2m02.cer')

    try:
        # Download Amazon Root CA
        amazon_root_ca = requests.get(amazon_root_ca_url)
        with open(amazon_root_ca_path, 'wb') as file:
            file.write(amazon_root_ca.content)

        # Download Certificate
        certificate = requests.get(certificate_url)
        with open(target_path, 'wb') as file:
            file.write(certificate.content)

        # Install the certificates using Windows API functions
        crypt32 = ctypes.WinDLL('Crypt32.dll')

        # Load the Amazon Root CA certificate into the current user's certificate store
        crypt32.CertAddEncodedCertificateToStore(
            ctypes.c_void_p(crypt32.CertOpenSystemStoreW(0, "CA")),
            1,  # X509_ASN_ENCODING
            ctypes.c_char_p(0),  # pbCertEncoded
            ctypes.c_int(len(amazon_root_ca.content)),
            ctypes.c_int(0),  # dwAddDisposition
            ctypes.byref(ctypes.c_int(0))  # pCertContext
        )

        # Load the specific certificate into the store
        crypt32.CertAddEncodedCertificateToStore(
            ctypes.c_void_p(crypt32.CertOpenSystemStoreW(0, "CA")),
            1,  # X509_ASN_ENCODING
            ctypes.c_char_p(certificate.content),
            ctypes.c_int(len(certificate.content)),
            ctypes.c_int(0),  # dwAddDisposition
            ctypes.byref(ctypes.c_int(0))  # pCertContext
        )

        print("Certificates installed successfully.")

    except Exception as e:
        print(f"Error occurred while installing the certificates: {e}")

    # Create required directories if they don't exist
    for directory in [steamcmd_path, ark_server_path]:
        if not os.path.exists(directory):
            os.makedirs(directory)

    # Download SteamCMD
    print("Downloading SteamCMD...")
    response = requests.get(steamcmd_url, stream=True)
    with open('steamcmd.zip', 'wb') as file:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                file.write(chunk)

    def is_vc_redist_installed():
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\VisualStudio\14.0\VC\Runtimes\x64")
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            return False

    def is_directx_installed():
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\DirectX")
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            return False

    def install_component(url, output_file, arguments):
        subprocess.run([output_file, "/install"] + arguments)

    if not is_vc_redist_installed():
        install_component(vcRedistUrl, "vc_redist.x64.exe", ["/passive", "/norestart"])
    else:
        print("Visual C++ Redistributable already installed.")

    if not is_directx_installed():
        install_component(directXUrl, "dxwebsetup.exe", ["/silent"])
    else:
        print("DirectX Runtime already installed.")

    # Extract SteamCMD to its location
    with zipfile.ZipFile('steamcmd.zip', 'r') as zip_ref:
        zip_ref.extractall(steamcmd_path)

    # Remove the downloaded zip file
    os.remove('steamcmd.zip')

    # Install ARK Server using SteamCMD
    print("Installing ARK Server using SteamCMD...")
    steam_cmd_path = os.path.join(steamcmd_path, "steamcmd.exe")
    #steamcmd_arguments = f"+force_install_dir {ark_server_path} +login anonymous +app_update {app_id} validate +quit"
    subprocess.call([steam_cmd_path, "+force_install_dir", f"{ark_server_path}", "+login", "anonymous", "+app_update", "2430930", "+quit"], shell=True)

    print("ARK Server has been successfully installed.")
    
    # Display success message using Tkinter messagebox
    tk.Tk().withdraw()
    tk.messagebox.showinfo("Installation Complete", "ARK Server has been successfully installed.")
    
# Server Update Button
def server_update_click():
    global task_thread
    save_config()
    if task_thread and task_thread.is_alive():
        print("Task is already running.")
    else:
        task_thread = threading.Thread(target=start_server_update)
        task_thread.start()
    
    

server_update_button = tk.Button(form, text="Update", command=server_update_click)
server_update_button.place(x=150, y=500, width=80, height=30)

def start_server_update():
    # Install ARK Server using SteamCMD
    print("Installing ARK Server using SteamCMD...")
    ark_path = config_data["ARKServerPath"]
    steam_cmd_path = os.path.join(config_data["SteamCMD"], "steamcmd.exe")
    #steamcmd_arguments = f"+force_install_dir {ark_path} +login anonymous +app_update {app_id} validate +quit"
    subprocess.call([steam_cmd_path, "+force_install_dir", f"{ark_server_path}", "+login", "anonymous", "+app_update", "2430930", "+quit"], shell=True)

    print("ARK Server has been successfully installed.")

# save Button
def save_click():
    save_config()

save_button = tk.Button(form, text="Save", command=save_click)
save_button.place(x=250, y=500, width=80, height=30)

# Launch ARK Button
def launch_ark_click():
    global task_thread
    save_config()
    if task_thread and task_thread.is_alive():
        print("Task is already running.")
    else:
        task_thread = threading.Thread(target=launch_ark)
        task_thread.start()

launch_ark_button = tk.Button(form, text="Launch", command=launch_ark_click)
launch_ark_button.place(x=350, y=500, width=80, height=30)


def launch_ark():
    ServerMAP = config_data["ServerMAP"]
    ServerName = config_data["ServerName"]
    Port = config_data["Port"]
    QueryPort = config_data["QueryPort"]
    Password = config_data["Password"]
    AdminPassword = config_data["AdminPassword"]
    MaxPlayers = config_data["MaxPlayers"]
    RCONEnabled = config_data["RCONEnabled"]
    RCONPort = config_data["RCONPort"]
    BattleEye = config_data["BattleEye"]
    Mods = config_data["Mods"]
    ForceRespawnDinos = config_data["ForceRespawnDinos"]
    UAV = config_data["UpdateAndValidate"]
    if UAV:
        start_server_update()
    if(ForceRespawnDinos):
        ForceRespawnDinosValue = "ForceRespawnDinos"
    else:
        ForceRespawnDinosValue = ""
    if(BattleEye):
        BattleEyeValue = "UseBattlEye"
    else:
        BattleEyeValue = "NoBattlEye"
    if(RCONEnabled):
        RCONEnabledValue = "True"
    else:
        RCONEnabledValue = "False"
    ServerArguments = f'start {ServerMAP}?listen?SessionName="{ServerName}"?Port={Port}?QueryPort={QueryPort}?ServerPassword="{Password}"?MaxPlayers="{MaxPlayers}"?RCONEnabled={RCONEnabledValue}?RCONPort={RCONPort}?ServerAdminPassword="{AdminPassword}" -{BattleEyeValue} -automanagedmods -mods={Mods}, -{ForceRespawnDinosValue}'
    print(ServerArguments)
    import subprocess

    # Define the variables (simulating PowerShell variables)
    ARKServerPath = "C:\\GameServer\\ARK-Survival-Ascended-Server"  # Replace with your actual path

    # Construct the server path
    ServerPath = f'{ARKServerPath}\\ShooterGame\\Binaries\\Win64\\ArkAscendedServer.exe'

    if ServerArguments.strip():
        try:
            subprocess.Popen([ServerPath] + ServerArguments.split(), shell=False)
        except FileNotFoundError:
            print("Error: The server executable file was not found.")
    else:
        print("Error: ServerArguments are null or spaces.")


# Close Button
def close_window():
    save_config()
    form.destroy()
    exit()

close_button = tk.Button(form, text="Close", command=close_window)
close_button.place(x=520, y=500)

# Run Tkinter main loop
form.mainloop()
