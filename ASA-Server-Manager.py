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
from typing import Union
import time
import socket
import struct

DEFAULT_TIMEOUT = 60
CHAR = '\u00A7'
OLD = '\u001b'
MAP = {'0': '\033[0m\033[30m',
       '1': '\033[0m\033[34m',
       '2': '\033[0m\033[32m',
       '3': '\033[0m\033[36m',
       '4': '\033[0m\033[31m',
       '5': '\033[0m\033[36m',
       '6': '\033[0m\033[33m',
       '7': '\033[0m\033[38;5;246m',
       '8': '\033[0m\033[38;5;243m',
       '9': '\033[0m\033[34;1m',
       'a': '\033[0m\033[32;1m',
       'b': '\033[0m\033[36;1m',
       'c': '\033[0m\033[31;1m',
       'd': '\033[0m\033[35;1m',
       'e': '\033[0m\033[33;1m',
       'f': '\033[0m\033[37;1m',
       'l': '\033[1m',
       'k': '\033[5m',
       'm': '\033[9m',
       'n': '\033[4m',
       'o': '\033[3m',
       'r': '\033[0m'}  # Mapping format chars with ASCII values

# Create configuration folder and file if not exists
config_folder_path = os.path.join(os.getenv('APPDATA'), "ARK-Ascended-Server-Manager")
script_config = os.path.join(config_folder_path, "Config.json")

if not os.path.exists(config_folder_path):
    os.makedirs(config_folder_path)


class MCToolsError(Exception):
    pass


class ProtocolError(MCToolsError):
    pass


class ProtoConnectionClosed(ProtocolError):

    def __init__(self, message) -> None:
        self.message = message  # Explanation of the error


class RCONError(MCToolsError):
    pass


class RCONAuthenticationError(RCONError):

    def __init__(self, message):
        self.message = message  # Explanation of the error


class RCONMalformedPacketError(RCONError):

    def __init__(self, message):
        self.message = message  # Explanation of the error


class RCONCommunicationError(RCONError):

    def __init__(self, message):
        self.message = message  # Explanation of the error


class RCONLengthError(RCONError):

    def __init__(self, message, length):
        self.message = message  # Explanation of error
        self.length = length  # Length of data


class BaseEncoder(object):

    @staticmethod
    def encode(data):
        raise NotImplementedError("Override this method in child class!")

    @staticmethod
    def decode(data):
        raise NotImplementedError("Override this method in child class!")


class RCONEncoder(BaseEncoder):
    PAD = b'\x00\x00'

    @staticmethod
    def encode(data):
        # Encoding the request ID and Request type:
        byts = struct.pack("<ii", data[0], data[1])
        # Encoding payload and padding:
        byts = byts + data[2].encode("utf8") + RCONEncoder.PAD
        # Encoding length:
        byts = struct.pack("<i", len(byts)) + byts
        return byts

    @staticmethod
    def decode(byts):
        # Getting request ID and request type
        reqid, reqtype = struct.unpack("<ii", byts[:8])
        # Getting payload
        payload = byts[8:len(byts) - 2]
        # Checking padding:
        if not byts[len(byts) - 2:] == RCONEncoder.PAD:
            # No padding detected, something is wrong:
            raise RCONMalformedPacketError("Missing or malformed padding!")
        # Returning values:
        return reqid, reqtype, payload.decode("utf8")


class BaseFormatter(object):

    @staticmethod
    def format(text):
        return text

    @staticmethod
    def clean(text):
        return text

    @staticmethod
    def get_id():
        return 20


class DefaultFormatter(BaseFormatter):

    @staticmethod
    def format(text):
        # Iterate through the text until we find the format char:
        index = 0
        while index < len(text) - 1 and type(text) == str:
            # Checking for CHAR at index:
            if text[index] == CHAR:
                # Found a char, getting next value:
                form = text[index + 1]
                # Checking if we need to add a reset value to the front the of the color value,
                # Replacing format char with ASCII value:
                if form in MAP:
                    # Character is a valid format char, format it:
                    text = text.replace(CHAR + form, MAP[form], 1)
                    # Decrementing index, as we removed some stuff:
                    index = index - 1
                    continue
            # Increment index, nothing was found!
            index = index + 1
        # Adding reset char, so we don't mess up output
        text = text + MAP['r']
        return text

    @staticmethod
    def clean(text):
        index = 0
        while index < len(text) - 1 and type(text) == str:
            # Iterate through text until we find a format char:
            if text[index] == CHAR:
                # Found a format char, getting next char:
                form = text[index + 1]
                # Checking if format char is valid:
                if form in MAP:
                    # Yes, format char is valid. Removing all values:
                    text = text.replace(CHAR + form, '')
                    # Decrementing, as we removed some stuff
                    index = index - 1
                    continue
            index = index + 1
        return text

    @staticmethod
    def get_id():

        return 10


class FormatterCollection:
    QUERY = 'QUERY_PROTOCOL'
    PING = 'PING_PROTOCOL'

    def __init__(self):
        self._form = []  # List of formatters

    def _get_id(self, form):
        return form.get_id()

    def add(self, form, command, ignore=None):
        # Checking formatter parent class:
        if not issubclass(form, BaseFormatter):
            # Form is not a subclass
            raise Exception("Invalid Formatter! Must inherit from BaseFormatter!")
        # Checking command type:
        command = self._convert_type(command, 'Command')
        # Checking ignore type:
        ignore = self._convert_type(ignore, 'Ignore')
        # Adding formatter to list
        self._form.append([form, command, ignore])
        # Sorting list of formatters:
        self._form.sort(key=lambda x: x[0].get_id())
        return True

    def _convert_type(self, thing, text):
        if type(thing) not in [str, tuple, list] and thing is not None:
            # Ignore is not a valid type, checking if it is an int, so we can convert it:
            if type(thing) == int:
                # Converting int to string
                return str(thing)
            else:
                raise Exception("Invalid {}} Type! Must be str, list, or tuple!".format(text))
        return thing

    def remove(self, form):
        # Attempting to remove formatter:
        try:
            self._form.remove(form)
        except Exception:
            # Formatter not found, returning
            return False
        # Formatter removed!
        return True

    def clear(self):
        # Clearing list:
        self._form.clear()
        return

    def get(self):
        return self._form

    def format(self, text, command):
        # Iterating through every formatter:
        for form in self._form:
            # Checking if formatter is relevant:
            if self._is_relevant(form, command):
                # Formatter is relevant, formatting text:
                text = form[0].format(text)
        # Return formatted text:
        return text

    def clean(self, text, command):
        # Iterating through every formatter:
        for form in self._form:
            # Checking if formatter is relevant:
            if self._is_relevant(form, command):
                # Formatter is relevant, formatting text:
                text = form[0].clean(text)

        # Return formatted text
        return text

    def _is_relevant(self, form, command):
        # Checking ignore values first:
        if (type(form[2]) == str and form[2] == command) or (type(form[2]) in [list, tuple] and command in form[2]):
            # Command is a value we are ignoring
            return False
        # Checking if value is one we are accepting:
        if form[1] == '' or (type(form[1]) == str and form[1] == command) or (
                type(form[1]) in [list, tuple] and command in form[1]):
            # Command is a command we can handel:
            return True
        return False

    def __len__(self):
        return len(self._form)


class BasePacket(object):

    @classmethod
    def from_bytes(cls, byts):
        raise NotImplementedError("Override this method in child class!")

    def __repr__(self):
        raise NotImplementedError("Override this method in child class!")

    def __str__(self):
        raise NotImplementedError("Override this method in child class!")

    def __bytes__(self):
        raise NotImplementedError("Override this method in child class!")


class RCONPacket(BasePacket):

    def __init__(self, reqid, reqtype, payload, length=0):
        self.reqid = reqid  # Request ID of the RCON packet
        self.reqtype = reqtype  # Request type of the RCON packet
        self.payload = payload  # Payload of the RCON packet
        self.length = length  # Length of the packet, helps determine if we are fragmented
        self.type = 'rcon'  # Determining what type of packet we are

    @classmethod
    def from_bytes(cls, byts):
        reqid, reqtype, payload = RCONEncoder.decode(byts)

        return cls(reqid, reqtype, payload, length=len(byts))

    def __repr__(self):
        return "packet.RCONPacket({}, {}, {})".format(self.reqid, self.reqtype, self.payload)

    def __str__(self):
        return "RCON Packet:\n - Request ID: {}\n - Request Type: {}\n - Payload: {}".format(self.reqid,
                                                                                             self.reqtype,
                                                                                             self.payload)

    def __bytes__(self):
        return RCONEncoder.encode((self.reqid, self.reqtype, self.payload))


class BaseProtocol(object):

    def __init__(self) -> None:
        # Dummy init, primarily meant to specify the socket parameter:
        self.sock = None
        self.sock: socket.socket

        self.timeout = DEFAULT_TIMEOUT  # Defines and sets the timeout value
        self.connected = False  # Value determining if we are connected

    def start(self):
        raise NotImplementedError("Override this method in child class!")

    def stop(self):
        raise NotImplementedError("Override this method in child class!")

    def send(self, data):
        raise NotImplementedError("Override this method in child class!")

    def read(self):
        raise NotImplementedError("Override this method in child class!")

    def read_tcp(self, length):
        byts = b''
        # We have to read in parts, as our buffsize may not be big enough:
        while len(byts) < length:
            last = self.sock.recv(length - len(byts))
            byts = byts + last
            if last == b'':
                # We received nothing, lets close this connection:
                self.stop()
                # Raise the 'ConnectionClosed' exception:
                raise ProtoConnectionClosed("Connection closed by remote host!")
        return byts

    def write_tcp(self, byts):
        return self.sock.sendall(byts)

    def read_udp(self):
        return self.sock.recvfrom(1024)

    def write_udp(self, byts, host, port):
        self.sock.sendto(byts, (host, port))

    def set_timeout(self, timeout):
        # First, set the timeout value:
        self.timeout = timeout
        # Next, determine if we should set the socket timeout:
        if self.connected:
            # Set the timeout:
            self.sock.settimeout(timeout)

    def __del__(self):
        try:
            self.sock.close()
        except Exception:
            pass


class RCONProtocol(BaseProtocol):

    def __init__(self, host, port, timeout):

        # Init super class
        super().__init__()

        self.host = host  # Host of the RCON server
        self.port = int(port)  # Port of the RCON server
        self.LOGIN = 3  # Packet type used for logging in
        self.COMMAND = 2  # Packet type for issuing a command
        self.RESPONSE = 0  # Packet type for response
        self.MAX_SIZE = 4096  # Maximum packet size

        # Finally, set the timeout:

        self.set_timeout(timeout)

    def start(self):
        if self.connected:
            # Already started
            return
        # Create an ip4 tcp socket:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set the timeout:
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
        self.connected = True

    def stop(self):
        self.sock.close()
        self.connected = False

    def send(self, pack, length_check=False):
        # Getting encoded packet data:
        data = bytes(pack)
        # Check if data is too big:
        if length_check and len(data) >= 1460:
            # Too big, raise an exception!
            raise RCONLengthError("Packet type is too big!", len(data))
        # Sending packet:
        self.write_tcp(data)

    def read(self):
        # Getting first 4 bytes to determine length of packet:
        length_data = self.read_tcp(4)
        # Unpacking length data:
        length = struct.unpack("<i", length_data)[0]
        # Reading the rest of the packet:
        byts = self.read_tcp(length)
        # Generating packet:
        pack = RCONPacket.from_bytes(byts)
        return pack


class BaseClient(object):
    # Formatting codes
    RAW = 0
    REPLACE = 1
    REMOVE = 2

    def __init__(self) -> None:
        # Dummy init method
        self.formatters = None
        self.proto = None
        self.proto: BaseProtocol
        self.formatters: BaseFormatter

    def gen_reqid(self):
        return int(time.time())

    def set_timeout(self, timeout):
        # Have the protocol object set the timeout:

        self.proto.set_timeout(timeout)

    def start(self):
        raise NotImplementedError("Override this method in child class!")

    def stop(self):
        raise NotImplementedError("Override this method in child class!")

    def is_connected(self):
        raise NotImplementedError("Override this method in child class!")

    def raw_send(self, *args):
        raise NotImplementedError("Override this method in child class!")

    def get_formatter(self):
        return self.formatters

    def __enter__(self):
        raise NotImplementedError("Override this method in child class!")

    def __exit__(self, exc_type, exc_val, exc_tb):
        raise NotImplementedError("Override this method in child class!")


class RCONClient(BaseClient):

    def __init__(self, host, port=25575, reqid=None, format_method=BaseClient.REPLACE, timeout=DEFAULT_TIMEOUT):

        super().__init__()
        self.proto: RCONProtocol = RCONProtocol(host, port,
                                                timeout)  # RCONProtocol, used for communicating with RCON server
        self.formatters: FormatterCollection = FormatterCollection()  # Formatters instance, formats text from server
        self.auth = False  # Value determining if we are authenticated
        self.format = format_method  # Value determining how to format output

        self.reqid = self.gen_reqid() if reqid is None else int(reqid)  # Generating a request ID

        # Adding the relevant formatters:
        self.formatters.add(DefaultFormatter, '', ignore=[self.formatters.PING, self.formatters.QUERY])

    def start(self):

        # Start the protocol instance:
        if not self.is_connected():
            self.proto.start()

    def stop(self):

        # Stop the protocol instance
        if self.is_connected():
            self.auth = False

            self.proto.stop()

    def is_connected(self) -> bool:
        return self.proto.connected

    def is_authenticated(self) -> bool:
        return self.auth

    def raw_send(self, reqtype: int, payload: str, frag_check: bool = True, length_check: bool = True) -> RCONPacket:
        if not self.is_connected():
            # Connection not started, user obviously wants to connect, so start it
            self.start()
        # Sending packet:
        self.proto.send(RCONPacket(self.reqid, reqtype, payload), length_check=length_check)
        # Receiving response packet:
        pack = self.proto.read()
        # Check if our stuff is valid:
        if pack.reqid != self.reqid and self.is_authenticated() and reqtype != self.proto.LOGIN:
            # Client/server ID's do not match!
            raise RCONMalformedPacketError("Client and server request ID's do not match!")
        elif pack.reqid != self.reqid and reqtype != self.proto.LOGIN:
            # Authentication issue!
            raise RCONAuthenticationError("Client and server request ID's do not match! We are not authenticated!")
        # Check if the packet is fragmented(And if we even care about fragmentation):
        if frag_check and pack.length >= self.proto.MAX_SIZE:
            # Send a junk packet:
            self.proto.send(RCONPacket(self.reqid, 0, ''))
            # Read until we get a valid response:
            while True:
                # Get a packet from the server:
                temp_pack = self.proto.read()
                if temp_pack.reqtype == self.proto.RESPONSE and temp_pack.payload == 'Unknown request 0':
                    # Break, we are done here
                    break
                if temp_pack.reqid != self.reqid:
                    # Client/server ID's do not match!
                    raise RCONMalformedPacketError("Client and server request ID's do not match!")
                # Add the packet content to the master pack:
                pack.payload = pack.payload + temp_pack.payload
        # Return our junk:
        return pack

    def login(self, password) -> bool:
        # Checking if we are logged in.
        if self.is_authenticated():
            # Already authenticated, no need to do it again.
            return True
        # Sending login packet:
        pack = self.raw_send(self.proto.LOGIN, password)
        # Checking login packet
        if pack.reqid != self.reqid:
            # Login failed, request IDs do not match
            return False
        # Request ID matches!
        self.auth = True
        return True

    def authenticate(self, password) -> bool:
        return self.login(password)

    def command(self, com: str, check_auth: bool = True, format_method: int = None, return_packet: bool = False,
                frag_check: bool = True, length_check: bool = True) -> Union[RCONPacket, str]:
        # Checking authentication status:
        if check_auth and not self.is_authenticated():
            # Not authenticated, let the user know this:
            raise RCONAuthenticationError("Not authenticated to the RCON server!")
        # Sending command packet:
        pack = self.raw_send(self.proto.COMMAND, com, frag_check=frag_check, length_check=length_check)
        # Get the formatted content:
        pack = self._format(pack, com, format_method=format_method)
        if return_packet:
            # Return the entire packet:
            return pack
        # Return just the payload
        return pack.payload

    def _format(self, pack, com, format_method=None):
        if format_method is None:
            # Use the global format method
            format_method = self.format
        # Formatting text:
        if format_method == 'replace' or format_method == 1:
            # Replacing format chars
            pack.payload = self.formatters.format(pack.payload, com)
        elif format_method == 'clean' or format_method == 2:
            # Removing format chars
            pack.payload = self.formatters.clean(pack.payload, com)
        return pack

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Stopping connection:
        self.stop()
        return False


task_thread = None


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
        self.root.geometry("1200x600")
        self.task_thread = None

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

        # Command Field
        self.CommandLabel = tk.Label(root, text="Enter Command:")
        self.CommandLabel.place(x=550, y=50)

        self.CommandTextBox = tk.Entry(root)
        self.CommandTextBox.place(x=650, y=50, width=220, height=20)

        self.CommandSendButton = tk.Button(root, text="Send", command=self.command_send)
        self.CommandSendButton.place(x=875, y=50, width=80, height=20)

        self.CommandOutputText = tk.Text(root, state="disabled", wrap="word", height=20, width=80)
        self.CommandOutputScrollbar = tk.Scrollbar(root, command=self.CommandOutputText.yview)
        self.CommandOutputText['yscrollcommand'] = self.CommandOutputScrollbar.set
        self.CommandOutputText.place(x=550, y=80)
        self.CommandOutputScrollbar.place(x=1180, y=80, height=325)

    def command_send(self):
        command = self.CommandTextBox.get()
        port = int(self.rcon_port.get())
        host = "127.0.0.1"
        passwd = self.admin_password.get()

        rcon = RCONClient(host, port=port)
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")

        if rcon.login(passwd):
            response = rcon.command(command).replace("\033", "").replace("[0m", "").replace("\n", "")
            print(response)
            self.CommandOutputText.config(state="normal")
            self.CommandOutputText.insert(tk.END, f"{current_time}: {response}\n")
            self.CommandOutputText.config(state="disabled")
            self.CommandTextBox.delete(0, tk.END)

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

        def downlaod_file(url, target_path=None):
            if not target_path:
                file_name = url.split('/')[-1]
                target_path = os.path.join(os.environ['TEMP'], file_name)

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

        # Download SteamCMD if it doesn't exist
        if not os.path.exists(os.path.join(steamcmd_path, 'steamcmd.exe')):
            print("Downloading SteamCMD...")
            steamcmd_zip_path = os.path.join(os.environ['TEMP'], 'steamcmd.zip')
            downlaod_file(steamcmd_url, steamcmd_zip_path)

            # Extract SteamCMD to its location
            with zipfile.ZipFile(steamcmd_zip_path, 'r') as zip_ref:
                zip_ref.extractall(steamcmd_path)

            os.remove(steamcmd_zip_path)

        # Install ARK Server using SteamCMD
        print("Installing ARK Server using SteamCMD...")
        steam_cmd_path = os.path.join(steamcmd_path, "steamcmd.exe")
        subprocess.call(
            [steam_cmd_path, "+force_install_dir", f"{ark_server_path}", "+login", "anonymous", "+app_update",
             "2430930", "+quit"], shell=True)

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

    def start_server_update(self, validate=False):
        # Install ARK Server using SteamCMD
        print("Installing ARK Server using SteamCMD...")
        ark_path = self.config_data["ARKServerPath"]
        steam_cmd_path = os.path.join(self.config_data["SteamCMD"], "steamcmd.exe")
        # steamcmd_arguments = f"+force_install_dir {ark_path} +login anonymous +app_update {app_id} validate +quit"
        if validate:
            subprocess.call(
                [steam_cmd_path, "+force_install_dir", f"{ark_path}", "+login", "anonymous", "+app_update", "2430930",
                 "validate", "+quit"], shell=True)
        else:
            subprocess.call(
                [steam_cmd_path, "+force_install_dir", f"{ark_path}", "+login", "anonymous", "+app_update", "2430930",
                 "+quit"], shell=True)

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

    def updateconfig(self, target_setting, new_value, config="GameUserSettings.ini"):
        path = os.path.join(self.config_data.get("ARKServerPath", ""), 'ShooterGame', 'Saved', 'Config', 'WindowsServer', config)

        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as file:
                file.write("[ServerSettings]\n")

        with open(path, 'r') as file:
            lines = file.readlines()

        found = False
        for i, line in enumerate(lines):
            if target_setting in line:
                parts = line.split('=')
                parts[1] = f'"{new_value}"\n'
                lines[i] = '='.join(parts)
                found = True
                break

        if not found:
            lines.append(f"{target_setting}=\"{new_value}\"\n")

        with open(path, 'w') as file:
            file.writelines(lines)

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
            self.start_server_update(validate=True)
        if ForceRespawnDinos:
            force_respawn_dinos_value = "ForceRespawnDinos"
        else:
            force_respawn_dinos_value = ""
        if BattleEye:
            battle_eye_value = "UseBattlEye"
        else:
            battle_eye_value = "NoBattlEye"
        if RCONEnabled:
            rcon_enabled_value = "True"
        else:
            rcon_enabled_value = "False"

        self.updateconfig("ServerPassword", Password)
        self.updateconfig("ServerAdminPassword", AdminPassword)

        server_arguments = f'start {ServerMAP}?listen?SessionName="{ServerName}"?Port={Port}?QueryPort={QueryPort}?RCONEnabled={rcon_enabled_value}?RCONPort={RCONPort} -{battle_eye_value} -automanagedmods -mods={Mods}, -WinLiveMaxPlayers={MaxPlayers}, -{force_respawn_dinos_value}'
        print(server_arguments)
        import subprocess

        # Construct the server path
        server_path = f'{ARKServerPath}\\ShooterGame\\Binaries\\Win64\\ArkAscendedServer.exe'


        if server_arguments.strip():
            try:
                subprocess.Popen([server_path] + server_arguments.split(), shell=False)
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
