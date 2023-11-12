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



# Create configuration folder and file if not exists
config_folder_path = os.path.join(os.getenv('APPDATA'), "ARK-Ascended-Server-Manager")
script_config = os.path.join(config_folder_path, "testConfig.json")

if not os.path.exists(config_folder_path):
    os.makedirs(config_folder_path)



class ServerManagerApp:
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
    
    task_thread = None
    app_id = "376030"

    # Load configuration from file or set default values
    def load(self):
        if os.path.exists(script_config):
            try:
                with open(script_config, 'r') as config_file:
                    self.config_data = json.load(config_file)

                for key in self.default_config.keys():
                    if key not in self.config_data:
                        self.config_data[key] = self.default_config[key]
            except:
                messagebox.showinfo("Error", "Error reading configuration file. Default configuration is used.")
                self.config_data = self.default_config
        else:
            messagebox.showinfo("Info", "No configuration file found. Default configuration is used.")
            self.config_data = self.default_config

    def __init__(self, root):
        self.load()
        self.root = root
        self.root.title("ARK-Ascended-Server-Manager")
        self.root.geometry("600x600")

        # SteamCMD path
        self.steam_cmd_label = tk.Label(root, text="SteamCMD Path:")
        self.steam_cmd_label.place(x=50, y=50)

        self.steam_cmd_path = tk.Entry(root)
        self.steam_cmd_path.place(x=200, y=50, width=300, height=20)
        self.steam_cmd_path.insert(0, self.config_data["SteamCMD"])

        # ARK Server Path
        self.ark_server_label = tk.Label(root, text="ARK Server Path:")
        self.ark_server_label.place(x=50, y=80)

        self.ark_server_path = tk.Entry(root)
        self.ark_server_path.place(x=200, y=80, width=300, height=20)
        self.ark_server_path.insert(0, self.config_data["ARKServerPath"])

        # Server MAP
        self.server_map_label = tk.Label(root, text="Server MAP:")
        self.server_map_label.place(x=50, y=110)

        self.server_map = tk.Entry(root)
        self.server_map.place(x=200, y=110, width=300, height=20)
        self.server_map.insert(0, self.config_data["ServerMAP"])

        # Server Name
        self.server_name_label = tk.Label(root, text="Server Name:")
        self.server_name_label.place(x=50, y=140)

        self.server_name = tk.Entry(root)
        self.server_name.place(x=200, y=140, width=300, height=20)
        self.server_name.insert(0, self.config_data["ServerName"])

        # Max Players
        self.max_players_label = tk.Label(root, text="Max Players:")
        self.max_players_label.place(x=50, y=170)

        self.max_players = tk.Entry(root)
        self.max_players.place(x=200, y=170, width=50, height=20)
        self.max_players.insert(0, self.config_data["MaxPlayers"])

        # Port
        self.port_label = tk.Label(root, text="Port:")
        self.port_label.place(x=50, y=230)

        self.port = tk.Entry(root)
        self.port.place(x=200, y=230, width=50, height=20)
        self.port.insert(0, self.config_data["Port"])

        # Query Port
        self.query_port_label = tk.Label(root, text="Query Port:")
        self.query_port_label.place(x=50, y=260)

        self.query_port = tk.Entry(root)
        self.query_port.place(x=200, y=260, width=50, height=20)
        self.query_port.insert(0, self.config_data["QueryPort"])

        # BattleEye (Checkbox)
        self.battle_eye_label = tk.Label(root, text="BattleEye:")
        self.battle_eye_label.place(x=50, y=290)

        self.battle_eye_enabled = tk.BooleanVar()
        self.battle_eye_enabled.set(self.config_data["BattleEye"])
        self.battle_eye_checkbox = tk.Checkbutton(root, variable=self.battle_eye_enabled)
        self.battle_eye_checkbox.place(x=200, y=290)

        # Admin Password
        self.admin_password_label = tk.Label(root, text="Admin Password:")
        self.admin_password_label.place(x=50, y=320)

        self.admin_password = tk.Entry(root)
        self.admin_password.place(x=200, y=320, width=150, height=20)
        self.admin_password.insert(0, self.config_data["AdminPassword"])

        # Mods
        self.mods_label = tk.Label(root, text="Mods:")
        self.mods_label.place(x=50, y=410)

        self.mods = tk.Entry(root)
        self.mods.place(x=200, y=410, width=300, height=20)
        self.mods.insert(0, self.config_data["Mods"])

        # Password
        self.password_label = tk.Label(root, text="Password:")
        self.password_label.place(x=50, y=350)

        self.password = tk.Entry(root)
        self.password.place(x=200, y=350, width=150, height=20)
        self.password.insert(0, self.config_data["Password"])

        # RCON Enabled (Checkbox)
        self.rcon_enabled_label = tk.Label(root, text="RCON Enabled:")
        self.rcon_enabled_label.place(x=50, y=380)

        self.rcon_enabled = tk.BooleanVar()
        self.rcon_enabled.set(self.config_data["RCONEnabled"])
        self.rcon_checkbox = tk.Checkbutton(root, variable=self.rcon_enabled)
        self.rcon_checkbox.place(x=200, y=378)

        # RCON Port
        self.rcon_port_label = tk.Label(root, text="RCON Port:")
        self.rcon_port_label.place(x=230, y=378)

        self.rcon_port = tk.Entry(root)
        self.rcon_port.place(x=300, y=380, width=50, height=20)
        self.rcon_port.insert(0, self.config_data["RCONPort"])

        # Force Respawn Dinos (Checkbox)
        self.force_respawn_dinos_label = tk.Label(root, text="Force Respawn Dinos:")
        self.force_respawn_dinos_label.place(x=50, y=440)

        self.force_respawn_dinos_var = tk.BooleanVar()
        self.force_respawn_dinos_var.set(self.config_data["ForceRespawnDinos"])
        self.force_respawn_dinos_checkbox = tk.Checkbutton(root, variable=self.force_respawn_dinos_var)
        self.force_respawn_dinos_checkbox.place(x=200, y=440)

        # Update/Validate on server start (Checkbox)
        self.update_and_validate_label = tk.Label(root, text="Update/Validate on server start:")
        self.update_and_validate_label.place(x=230, y=440)

        self.update_and_validate_var = tk.BooleanVar()
        self.update_and_validate_var.set(self.config_data["UpdateAndValidate"])
        self.update_and_validate_checkbox = tk.Checkbutton(root, variable=self.update_and_validate_var)
        self.update_and_validate_checkbox.place(x=400, y=440)

        self.install_button = tk.Button(root, text="Install", command=self.install_button_click)
        self.install_button.place(x=50, y=500, width=80, height=30)

        self.server_update_button = tk.Button(root, text="Update", command=self.server_update_click)
        self.server_update_button.place(x=150, y=500, width=80, height=30)

        self.save_button = tk.Button(root, text="Save", command=self.save_click)
        self.save_button.place(x=250, y=500, width=80, height=30)

        self.launch_ark_button = tk.Button(root, text="Launch", command=self.launch_ark_click)
        self.launch_ark_button.place(x=350, y=500, width=80, height=30)

        self.close_button = tk.Button(root, text="Close", command=self.close_window)
        self.close_button.place(x=520, y=500)

    # Function to save configuration to file
    def save_config(self):
        config_data = {
            "SteamCMD": self.steam_cmd_path.get(),
            "ARKServerPath": self.ark_server_path.get(),
            "ServerMAP": self.server_map.get(),
            "ServerName": self.server_name.get(),
            "MaxPlayers": self.max_players.get(),
            "Port": self.port.get(),
            "QueryPort": self.query_port.get(),
            "BattleEye": self.battle_eye_enabled.get(),
            "AdminPassword": self.admin_password.get(),
            "Password": self.password.get(),
            "Mods": self.mods.get(),
            "RCONPort": self.rcon_port.get(),
            "RCONEnabled": self.rcon_enabled.get(),
            "ForceRespawnDinos": self.force_respawn_dinos_var.get(),
            "UpdateAndValidate": self.update_and_validate_var.get()
        }

        with open(script_config, 'w') as config_file:
            json.dump(config_data, config_file, indent=4)

    def install_button_click(self):
        global task_thread
        self.save_config()
        if task_thread and task_thread.is_alive():
            print("Task is already running.")
        else:
            task_thread = threading.Thread(target=self.install_ark_server)
            task_thread.start()


    def install_ark_server(self):
        steamcmd_url = "https://steamcdn-a.akamaihd.net/client/installer/steamcmd.zip"
        vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
        directXUrl = "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe"
        steamcmd_path = self.config_data["SteamCMD"]
        ark_server_path = self.config_data["ARKServerPath"]
        
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
            
        def downlaod_file(url, target_path = os.path.join(os.environ['TEMP'])):
            response = requests.get(url, stream=True)
            with open(target_path, 'wb') as file:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        file.write(chunk)

        def install_component(url, output_file, arguments):
            component_path = os.path.join(os.environ['TEMP'], output_file)
            downlaod_file(url)
            subprocess.run([component_path, "/install"] + arguments)

        if not is_vc_redist_installed():
            install_component(vcRedistUrl, "vc_redist.x64.exe", ["/passive", "/norestart"])
        else:
            print("Visual C++ Redistributable already installed.")

        if not is_directx_installed():
            install_component(directXUrl, "dxwebsetup.exe", ["/silent"])
        else:
            print("DirectX Runtime already installed.")

        # Download SteamCMD
        if os.path.exists(os.path.join(steamcmd_path, 'steamcmd.exe')):
            print("Downloading SteamCMD...")
            downlaod_file(steamcmd_url)

            # Extract SteamCMD to its location
            with zipfile.ZipFile(os.path.join(os.environ['TEMP'],'steamcmd.zip'), 'r') as zip_ref:
                zip_ref.extractall(steamcmd_path)

            os.remove('steamcmd.zip')

        # Install ARK Server using SteamCMD
        print("Installing ARK Server using SteamCMD...")
        steam_cmd_path = os.path.join(steamcmd_path, "steamcmd.exe")
        subprocess.call([steam_cmd_path, "+force_install_dir", f"{ark_server_path}", "+login", "anonymous", "+app_update", "2430930", "+quit"], shell=True)

        print("ARK Server has been successfully installed.")
        
        # Display success message using Tkinter messagebox
        tk.Tk().withdraw()
        tk.messagebox.showinfo("Installation Complete", "ARK Server has been successfully installed.")
        

    # Server Update Button
    def server_update_click(self):
        self.save_config()
        if self.task_thread and self.task_thread.is_alive():
            print("Task is already running.")
        else:
            self.task_thread = threading.Thread(target=self.start_server_update)
            self.task_thread.start()


    def start_server_update(self):
        # Install ARK Server using SteamCMD
        print("Installing ARK Server using SteamCMD...")
        ark_path = self.config_data["ARKServerPath"]
        steam_cmd_path = os.path.join(self.config_data["SteamCMD"], "steamcmd.exe")
        #steamcmd_arguments = f"+force_install_dir {ark_path} +login anonymous +app_update {app_id} validate +quit"
        subprocess.call([steam_cmd_path, "+force_install_dir", f"{ark_path}", "+login", "anonymous", "+app_update", "2430930", "+quit"], shell=True)

        print("ARK Server has been successfully installed.")


    # save Button
    def save_click(self):
        self.save_config()


    # Launch ARK Button
    def launch_ark_click(self):
        self.save_config()
        if self.task_thread and self.task_thread.is_alive():
            print("Task is already running.")
        else:
            self.task_thread = threading.Thread(target=self.launch_ark)
            self.task_thread.start()


    def launch_ark(self):
        ARKServerPath = self.config_data["ARKServerPath"]
        ServerMAP = self.config_data["ServerMAP"]
        ServerName = self.config_data["ServerName"]
        Port = self.config_data["Port"]
        QueryPort = self.config_data["QueryPort"]
        Password = self.config_data["Password"]
        AdminPassword = self.config_data["AdminPassword"]
        MaxPlayers = self.config_data["MaxPlayers"]
        RCONEnabled = self.config_data["RCONEnabled"]
        RCONPort = self.config_data["RCONPort"]
        BattleEye = self.config_data["BattleEye"]
        Mods = self.config_data["Mods"]
        ForceRespawnDinos = self.config_data["ForceRespawnDinos"]
        UAV = self.config_data["UpdateAndValidate"]
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
    def close_window(self):
        self.save_config()
        self.root.destroy()
        exit()


if __name__ == "__main__":
    root = tk.Tk()
    app = ServerManagerApp(root)
    root.mainloop()