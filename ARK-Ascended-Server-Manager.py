# ARK: Survival Ascended Dedicated Server Manager (Windows)

from __future__ import annotations

import ctypes
import json
import logging
import os
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen

import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

try:
    import winreg  # type: ignore
except Exception:
    winreg = None


# =============================================================================
# GLOBALS
# =============================================================================

APP_NAME = "ARK: Survival Ascended Server Manager"
APP_USERMODEL_ID = "Ch4r0ne.ARKASAManager"
APP_ID = 2430930  # ASA Dedicated Server AppID

STEAMCMD_ZIP_URL = "https://steamcdn-a.akamaihd.net/client/installer/steamcmd.zip"
VC_REDIST_X64_URL = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
DXWEBSETUP_URL = "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe"

DEFAULT_STEAMCMD_DIR = r"C:\GameServer\SteamCMD"
DEFAULT_SERVER_DIR = r"C:\GameServer\ARK-Survival-Ascended-Server"
DEFAULT_MAP = "TheIsland_WP"
DEFAULT_SERVER_NAME = "default"
DEFAULT_PORT = 7777
DEFAULT_QUERY_PORT = 27015
DEFAULT_MAX_PLAYERS = 70

DEFAULT_RCON_HOST = "127.0.0.1"
DEFAULT_RCON_PORT = 27020

DOWNLOAD_TIMEOUT_SEC = 120
AUTOSAVE_DEBOUNCE_MS = 700
INI_APPLY_DEBOUNCE_MS = 500

MAP_PRESETS = [
    "TheIsland_WP",
    "ScorchedEarth_WP",
    "TheCenter_WP",
    "Aberration_WP",
    "Extinction_WP",
    "Ragnarok_WP",
    "Valguero_WP",
    "LostColony_WP",
]
MAP_CUSTOM_SENTINEL = "Custom..."

APPDATA_DIR_NAME = "ARK-Ascended-Server-Manager"
LOG_DIR_NAME = "logs"
LOG_FILE_NAME = "app.log"
STAGING_DIR_NAME = "staging"
BASELINE_DIR_NAME = "baseline"
BACKUP_DIR_NAME = "backups"

GAMEUSERSETTINGS_REL = Path(r"ShooterGame\Saved\Config\WindowsServer\GameUserSettings.ini")
GAME_INI_REL = Path(r"ShooterGame\Saved\Config\WindowsServer\Game.ini")

LOG_LEVEL = logging.INFO


# =============================================================================
# PATH / ICON HELPERS
# =============================================================================

def resource_path(relative: str) -> str:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return str(Path(base) / relative)
    return str(Path(__file__).resolve().parent / relative)


def set_windows_appusermodel_id(app_id: str) -> None:
    if os.name != "nt":
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
    except Exception:
        pass


def apply_window_icon(root: tk.Tk) -> None:
    ico = resource_path(r"assets\app.ico")
    try:
        root.iconbitmap(ico)
    except Exception:
        pass


# =============================================================================
# LOW-LEVEL UTILITIES
# =============================================================================

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    if os.name != "nt":
        return False
    if is_admin():
        return True
    try:
        exe = sys.executable
        params = " ".join([f'"{a}"' for a in sys.argv[1:]])
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return int(rc) > 32
    except Exception:
        return False


def app_data_dir() -> Path:
    base = os.getenv("APPDATA") or str(Path.home())
    return Path(base) / APPDATA_DIR_NAME


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def now_ts() -> str:
    return time.strftime("%Y-%m-%d_%H-%M-%S")


def safe_int(s: str, default: int) -> int:
    try:
        return int(str(s).strip())
    except Exception:
        return default


def open_folder(path: Path) -> None:
    ensure_dir(path)
    try:
        os.startfile(str(path))
    except Exception:
        pass


def open_file(path: Path) -> None:
    if not path.exists():
        return
    try:
        os.startfile(str(path))
    except Exception:
        pass


def download_file(url: str, dest: Path, logger: logging.Logger, timeout: int = DOWNLOAD_TIMEOUT_SEC) -> None:
    ensure_dir(dest.parent)
    logger.info(f"Downloading: {url}")
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        while True:
            chunk = r.read(1024 * 256)
            if not chunk:
                break
            f.write(chunk)
    logger.info(f"Saved: {dest}")


def run_and_stream(cmd: List[str], logger: logging.Logger, cwd: Optional[Path] = None) -> int:
    logger.info(" ".join(cmd))
    p = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )
    assert p.stdout is not None
    for line in p.stdout:
        logger.info(line.rstrip())
    return p.wait()


# =============================================================================
# CONFIG
# =============================================================================

@dataclass
class AppConfig:
    schema_version: int = 4

    steamcmd_dir: str = DEFAULT_STEAMCMD_DIR
    server_dir: str = DEFAULT_SERVER_DIR

    map_name: str = DEFAULT_MAP
    server_name: str = DEFAULT_SERVER_NAME

    port: int = DEFAULT_PORT
    query_port: int = DEFAULT_QUERY_PORT
    max_players: int = DEFAULT_MAX_PLAYERS

    join_password: str = ""
    admin_password: str = "AdminPassword"

    enable_battleye: bool = False

    enable_rcon: bool = True
    rcon_host: str = DEFAULT_RCON_HOST
    rcon_port: int = DEFAULT_RCON_PORT

    automanaged_mods: bool = True
    mods: str = ""  # stored as CSV

    validate_on_update: bool = False

    backup_on_stop: bool = True
    backup_dir: str = ""          # empty => appdata/backups
    backup_retention: int = 20
    backup_include_configs: bool = False

    auto_update_restart: bool = False
    auto_update_interval_min: int = 360

    # RCON UX
    rcon_saved_commands: List[str] = field(default_factory=lambda: [
        "SaveWorld",
        "DoExit",
        "ListPlayers",
        "DestroyWildDinos",
    ])

    # Advanced Start Args
    cluster_enable: bool = False
    cluster_id: str = ""
    cluster_custom_path_enable: bool = False
    cluster_dir_override: str = ""
    no_transfer_from_filtering: bool = False
    alt_save_directory_name: str = ""

    dino_mode: str = ""  # "", "NoDinos", "NoDinosExceptForcedSpawn", ...

    log_servergamelog: bool = False
    log_servergamelogincludetribelogs: bool = False
    log_serverrconoutputtribelogs: bool = False

    mech_disablecustomcosmetics: bool = False
    mech_autodestroystructures: bool = False
    mech_forcerespawndinos: bool = False
    mech_nowildbabies: bool = False
    mech_forceallowcaveflyers: bool = False
    mech_disabledinonetrangescaling: bool = False
    mech_unstasisdinoobstructioncheck: bool = False
    mech_alwaystickdedicatedskeletalmeshes: bool = False
    mech_disablecharactertracker: bool = False
    mech_useservernetspeedcheck: bool = False
    mech_stasiskeepcontrollers: bool = False
    mech_ignoredupeditems: bool = False

    def normalized_mods(self) -> str:
        raw = (self.mods or "").strip()
        if not raw:
            return ""
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        return ",".join(parts)

    def set_mods_from_text(self, text: str) -> None:
        items: List[str] = []
        for line in (text or "").replace("\r", "\n").split("\n"):
            line = line.strip()
            if not line:
                continue
            for tok in line.split(","):
                t = tok.strip()
                if t:
                    items.append(t)
        self.mods = ",".join(items)


class ConfigStore:
    def __init__(self, path: Path):
        self.path = path

    def load(self) -> AppConfig:
        cfg = AppConfig()
        if not self.path.exists():
            return cfg
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return cfg

        for k, v in data.items():
            if hasattr(cfg, k):
                try:
                    setattr(cfg, k, v)
                except Exception:
                    pass
        # normalize list type if needed
        if not isinstance(cfg.rcon_saved_commands, list):
            cfg.rcon_saved_commands = ["SaveWorld", "DoExit", "ListPlayers", "DestroyWildDinos"]
        return cfg

    def save(self, cfg: AppConfig) -> None:
        ensure_dir(self.path.parent)
        self.path.write_text(json.dumps(asdict(cfg), indent=2), encoding="utf-8")


# =============================================================================
# DEPENDENCIES
# =============================================================================

def reg_open_key_64(root: Any, subkey: str) -> Any:
    if winreg is None:
        raise FileNotFoundError("winreg unavailable")
    access = winreg.KEY_READ
    try:
        access |= winreg.KEY_WOW64_64KEY  # type: ignore[attr-defined]
    except Exception:
        pass
    return winreg.OpenKey(root, subkey, 0, access)


def vc14_x64_version() -> Optional[str]:
    if winreg is None:
        return None
    try:
        key_path = r"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
        with reg_open_key_64(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            installed, _ = winreg.QueryValueEx(key, "Installed")
            version, _ = winreg.QueryValueEx(key, "Version")
            if int(installed) == 1:
                return str(version)
            return None
    except Exception:
        return None


def install_vcredist(logger: logging.Logger) -> None:
    temp = Path(os.environ.get("TEMP", str(Path.home() / "AppData/Local/Temp")))
    exe = temp / "vc_redist.x64.exe"
    download_file(VC_REDIST_X64_URL, exe, logger)
    code = run_and_stream([str(exe), "/install", "/passive", "/norestart"], logger)
    logger.info(f"VC++ installer exit code: {code}")


def install_directx_web(logger: logging.Logger) -> None:
    temp = Path(os.environ.get("TEMP", str(Path.home() / "AppData/Local/Temp")))
    exe = temp / "dxwebsetup.exe"
    download_file(DXWEBSETUP_URL, exe, logger)
    code = run_and_stream([str(exe), "/Q"], logger)
    logger.info(f"DirectX web installer exit code: {code}")


# =============================================================================
# STEAMCMD
# =============================================================================

def ensure_steamcmd(steamcmd_dir: Path, logger: logging.Logger) -> Path:
    ensure_dir(steamcmd_dir)
    candidates = [
        steamcmd_dir / "steamcmd.exe",
        steamcmd_dir / "SteamCMD" / "steamcmd.exe",
    ]
    for c in candidates:
        if c.exists():
            return c

    zip_path = steamcmd_dir / "steamcmd.zip"
    download_file(STEAMCMD_ZIP_URL, zip_path, logger)
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(steamcmd_dir)
    try:
        zip_path.unlink(missing_ok=True)  # type: ignore[arg-type]
    except Exception:
        pass

    for c in candidates:
        if c.exists():
            return c

    raise FileNotFoundError(f"steamcmd.exe not found after extraction in: {steamcmd_dir}")


def steamcmd_update_server(steamcmd_exe: Path, server_dir: Path, logger: logging.Logger, validate: bool) -> None:
    ensure_dir(server_dir)
    cmd = [
        str(steamcmd_exe),
        "+force_install_dir", str(server_dir),
        "+login", "anonymous",
        "+app_update", str(APP_ID),
    ]
    if validate:
        cmd.append("validate")
    cmd.append("+quit")
    code = run_and_stream(cmd, logger, cwd=steamcmd_exe.parent)
    if code != 0:
        raise RuntimeError(f"SteamCMD exited with code {code}")


# =============================================================================
# INI (order-preserving)
# =============================================================================

@dataclass
class IniLine:
    kind: str  # "section" | "kv" | "other"
    raw: str
    section: str = ""
    key: str = ""
    value: str = ""


class IniDocument:
    def __init__(self, lines: List[IniLine]):
        self.lines = lines

    @staticmethod
    def parse(text: str) -> "IniDocument":
        cur_section = ""
        out: List[IniLine] = []
        for raw in text.splitlines(True):
            s = raw.strip()
            if s.startswith("[") and s.endswith("]"):
                cur_section = s[1:-1].strip()
                out.append(IniLine(kind="section", raw=raw, section=cur_section))
                continue
            if not s or s.startswith(";") or s.startswith("#"):
                out.append(IniLine(kind="other", raw=raw, section=cur_section))
                continue
            if "=" in raw:
                k, v = raw.split("=", 1)
                key = k.strip()
                val = v.strip().rstrip("\r\n")
                out.append(IniLine(kind="kv", raw=raw, section=cur_section, key=key, value=val))
                continue
            out.append(IniLine(kind="other", raw=raw, section=cur_section))
        return IniDocument(out)

    def get(self) -> Dict[str, Dict[str, str]]:
        data: Dict[str, Dict[str, str]] = {}
        for line in self.lines:
            if line.kind == "kv":
                data.setdefault(line.section, {})[line.key] = line.value
        return data

    def set(self, section: str, key: str, value: str) -> None:
        section = section.strip()
        key = key.strip()
        value = str(value)

        if not any(l.kind == "section" and l.section == section for l in self.lines):
            if self.lines and not self.lines[-1].raw.endswith("\n"):
                self.lines[-1].raw += "\n"
            self.lines.append(IniLine(kind="other", raw="\n"))
            self.lines.append(IniLine(kind="section", raw=f"[{section}]\n", section=section))

        for l in self.lines:
            if l.kind == "kv" and l.section == section and l.key.lower() == key.lower():
                l.key = key
                l.value = value
                l.raw = f"{key}={value}\n"
                return

        insert_at = None
        for i, l in enumerate(self.lines):
            if l.kind == "section" and l.section == section:
                insert_at = i + 1
                for j in range(i + 1, len(self.lines)):
                    if self.lines[j].kind == "section":
                        insert_at = j
                        break
                    insert_at = j + 1
                break

        if insert_at is None:
            insert_at = len(self.lines)

        self.lines.insert(insert_at, IniLine(kind="kv", raw=f"{key}={value}\n", section=section, key=key, value=value))

    def to_text(self) -> str:
        return "".join(l.raw for l in self.lines)


def read_ini(path: Path) -> IniDocument:
    if not path.exists():
        return IniDocument.parse("")
    return IniDocument.parse(path.read_text(encoding="utf-8", errors="ignore"))


def write_ini(path: Path, doc: IniDocument) -> None:
    ensure_dir(path.parent)
    path.write_text(doc.to_text(), encoding="utf-8")


# =============================================================================
# RCON
# =============================================================================

class RCONError(Exception): ...
class RCONAuthError(RCONError): ...
class RCONConnectionError(RCONError): ...
class RCONProtocolError(RCONError): ...


class BuiltinRCONClient:
    SERVERDATA_RESPONSE_VALUE = 0
    SERVERDATA_EXECCOMMAND = 2
    SERVERDATA_AUTH = 3
    SERVERDATA_AUTH_RESPONSE = 2

    def __init__(self, host: str, port: int, password: str, timeout: float = 4.0):
        self.host = host
        self.port = int(port)
        self.password = password
        self.timeout = float(timeout)
        self._sock: Optional[socket.socket] = None
        self._req_id = 100

    def __enter__(self) -> "BuiltinRCONClient":
        self.connect()
        self.login()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def connect(self) -> None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            self._sock = s
        except Exception as e:
            raise RCONConnectionError(str(e))

    def close(self) -> None:
        try:
            if self._sock:
                self._sock.close()
        finally:
            self._sock = None

    @staticmethod
    def _pack(req_id: int, ptype: int, payload: str) -> bytes:
        body = struct.pack("<ii", req_id, ptype) + payload.encode("utf-8") + b"\x00\x00"
        return struct.pack("<i", len(body)) + body

    def _recv_exact(self, n: int) -> bytes:
        assert self._sock is not None
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise RCONConnectionError("Connection closed by remote host")
            buf += chunk
        return buf

    def _recv_packet(self) -> Tuple[int, int, str]:
        assert self._sock is not None
        length = struct.unpack("<i", self._recv_exact(4))[0]
        data = self._recv_exact(length)
        if len(data) < 10:
            raise RCONProtocolError("Malformed packet")
        req_id, ptype = struct.unpack("<ii", data[:8])
        payload = data[8:-2].decode("utf-8", errors="replace")
        return req_id, ptype, payload

    def login(self) -> None:
        assert self._sock is not None
        self._req_id += 1
        self._sock.sendall(self._pack(self._req_id, self.SERVERDATA_AUTH, self.password))

        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                rid, ptype, _ = self._recv_packet()
            except socket.timeout:
                break
            if ptype == self.SERVERDATA_AUTH_RESPONSE:
                if rid == -1:
                    raise RCONAuthError("Authentication failed")
                if rid == self._req_id:
                    return

        raise RCONAuthError("Authentication timeout (no AUTH_RESPONSE)")

    def command(self, cmd: str) -> str:
        assert self._sock is not None
        self._req_id += 1
        self._sock.sendall(self._pack(self._req_id, self.SERVERDATA_EXECCOMMAND, cmd))

        chunks: List[str] = []
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                rid, ptype, payload = self._recv_packet()
            except socket.timeout:
                break
            if rid == -1:
                raise RCONAuthError("Authentication failed")
            if rid != self._req_id:
                continue
            if ptype == self.SERVERDATA_RESPONSE_VALUE:
                chunks.append(payload)
        return "".join(chunks).strip()


def get_rcon_client_factory() -> Callable[[str, int, str, float], Any]:
    """
    Preferred: pip install rcon (conqp/rcon). API:
      from rcon.source import Client
      with Client(host, port, passwd='pw') as c: c.run('cmd', 'args')
    """
    try:
        from rcon.source import Client as SourceClient  # type: ignore

        class _Adapter:
            def __init__(self, host: str, port: int, password: str, timeout: float):
                self.host = host
                self.port = int(port)
                self.password = password
                self.timeout = float(timeout)
                self._c: Optional[SourceClient] = None

            def __enter__(self) -> "_Adapter":
                # conqp/rcon uses passwd=..., no authenticate() method
                self._c = SourceClient(self.host, self.port, passwd=self.password, timeout=self.timeout)
                self._c.__enter__()  # open socket + auth
                return self

            def __exit__(self, exc_type, exc, tb) -> None:
                try:
                    if self._c:
                        self._c.__exit__(exc_type, exc, tb)
                finally:
                    self._c = None

            def command(self, cmd: str) -> str:
                assert self._c is not None
                parts = shlex.split(cmd)
                if not parts:
                    return ""
                return str(self._c.run(*parts))

        return lambda h, p, pw, t: _Adapter(h, p, pw, t)
    except Exception:
        return lambda h, p, pw, t: BuiltinRCONClient(h, p, pw, t)


# =============================================================================
# SERVER OPS
# =============================================================================

def ark_server_exe(server_dir: Path) -> Path:
    return server_dir / "ShooterGame" / "Binaries" / "Win64" / "ArkAscendedServer.exe"


def server_saved_dir(server_dir: Path) -> Path:
    return server_dir / "ShooterGame" / "Saved"


def server_config_dir(server_dir: Path) -> Path:
    return server_dir / "ShooterGame" / "Saved" / "Config" / "WindowsServer"


def build_server_command(cfg: AppConfig) -> List[str]:
    exe = ark_server_exe(Path(cfg.server_dir))
    map_name = (cfg.map_name or "").strip()
    if not map_name:
        raise ValueError("Map name is required")

    session = (cfg.server_name or "").replace('"', "").strip() or DEFAULT_SERVER_NAME

    url_args = [
        f"{map_name}?listen",
        f"SessionName={session}",
        f"Port={int(cfg.port)}",
        f"QueryPort={int(cfg.query_port)}",
        f"MaxPlayers={int(cfg.max_players)}",
    ]

    if cfg.alt_save_directory_name.strip():
        url_args.append(f"AltSaveDirectoryName={cfg.alt_save_directory_name.strip()}")

    url = "?".join(url_args)

    flags: List[str] = []
    flags.append("-UseBattlEye" if cfg.enable_battleye else "-NoBattlEye")

    if cfg.automanaged_mods:
        flags.append("-automanagedmods")

    mods = cfg.normalized_mods()
    if mods:
        flags.append(f"-mods={mods}")

    # Cluster
    if cfg.cluster_enable:
        cid = cfg.cluster_id.strip()
        if not cid:
            raise ValueError("Enable Cluster requires Cluster ID.")
        flags.append(f"-clusterid={cid}")

    if cfg.cluster_custom_path_enable:
        p = cfg.cluster_dir_override.strip()
        if not p:
            raise ValueError("Enable Cluster Custom Path requires a valid path.")
        flags.append(f"-ClusterDirOverride={p}")

    if cfg.no_transfer_from_filtering:
        flags.append("-NoTransferFromFiltering")

    # Dino mode (mutual exclusive)
    if cfg.dino_mode.strip():
        flags.append(f"-{cfg.dino_mode.strip()}")

    # Logs
    if cfg.log_servergamelog:
        flags.append("-servergamelog")
    if cfg.log_servergamelogincludetribelogs:
        flags.append("-servergamelogincludetribelogs")
    if cfg.log_serverrconoutputtribelogs:
        flags.append("-ServerRCONOutputTribeLogs")

    # Mechanics / Performance
    if cfg.mech_disablecustomcosmetics:
        flags.append("-DisableCustomCosmetics")
    if cfg.mech_autodestroystructures:
        flags.append("-AutoDestroyStructures")
    if cfg.mech_forcerespawndinos:
        flags.append("-ForceRespawnDinos")
    if cfg.mech_nowildbabies:
        flags.append("-NoWildBabies")
    if cfg.mech_forceallowcaveflyers:
        flags.append("-ForceAllowCaveFlyers")
    if cfg.mech_disabledinonetrangescaling:
        flags.append("-disabledinonetrangescaling")
    if cfg.mech_unstasisdinoobstructioncheck:
        flags.append("-UnstasisDinoObstructionCheck")
    if cfg.mech_alwaystickdedicatedskeletalmeshes:
        flags.append("-AlwaysTickDedicatedSkeletalMeshes")
    if cfg.mech_disablecharactertracker:
        flags.append("-disableCharacterTracker")
    if cfg.mech_useservernetspeedcheck:
        flags.append("-UseServerNetSpeedCheck")
    if cfg.mech_stasiskeepcontrollers:
        flags.append("-StasisKeepControllers")
    if cfg.mech_ignoredupeditems:
        flags.append("-ignoredupeditems")

    return [str(exe), url, *flags]


# =============================================================================
# STAGING / BASELINE
# =============================================================================

def ensure_baseline(app_base: Path, server_dir: Path, logger: logging.Logger) -> Path:
    baseline_root = app_base / BASELINE_DIR_NAME
    ensure_dir(baseline_root)

    key = str(server_dir).replace(":", "").replace("\\", "_").replace("/", "_")
    base = baseline_root / key
    ensure_dir(base)

    src_gus = server_dir / GAMEUSERSETTINGS_REL
    src_game = server_dir / GAME_INI_REL

    if src_gus.exists() and not (base / "GameUserSettings.ini").exists():
        shutil.copy2(src_gus, base / "GameUserSettings.ini")
        logger.info("Baseline created: GameUserSettings.ini")
    if src_game.exists() and not (base / "Game.ini").exists():
        shutil.copy2(src_game, base / "Game.ini")
        logger.info("Baseline created: Game.ini")

    return base


def staging_paths(app_base: Path, server_dir: Path) -> Tuple[Path, Path]:
    staging_root = app_base / STAGING_DIR_NAME
    ensure_dir(staging_root)
    key = str(server_dir).replace(":", "").replace("\\", "_").replace("/", "_")
    root = staging_root / key
    ensure_dir(root)
    return root / "GameUserSettings.ini", root / "Game.ini"


def apply_staging_to_server(app_base: Path, server_dir: Path, logger: logging.Logger) -> None:
    stage_gus, stage_game = staging_paths(app_base, server_dir)
    dest_gus = server_dir / GAMEUSERSETTINGS_REL
    dest_game = server_dir / GAME_INI_REL

    if stage_gus.exists():
        ensure_dir(dest_gus.parent)
        shutil.copy2(stage_gus, dest_gus)
        logger.info("Applied staging: GameUserSettings.ini")

    if stage_game.exists():
        ensure_dir(dest_game.parent)
        shutil.copy2(stage_game, dest_game)
        logger.info("Applied staging: Game.ini")


def restore_baseline_to_server(app_base: Path, server_dir: Path, logger: logging.Logger) -> None:
    base = ensure_baseline(app_base, server_dir, logger)
    src_gus = base / "GameUserSettings.ini"
    src_game = base / "Game.ini"

    dest_gus = server_dir / GAMEUSERSETTINGS_REL
    dest_game = server_dir / GAME_INI_REL

    if src_gus.exists():
        ensure_dir(dest_gus.parent)
        shutil.copy2(src_gus, dest_gus)
        logger.info("Restored baseline: GameUserSettings.ini")

    if src_game.exists():
        ensure_dir(dest_game.parent)
        shutil.copy2(src_game, dest_game)
        logger.info("Restored baseline: Game.ini")


def ensure_required_server_settings(cfg: AppConfig, app_base: Path, server_dir: Path, logger: logging.Logger) -> None:
    ensure_dir((server_dir / GAMEUSERSETTINGS_REL).parent)

    # Prefer editing the staging copy if it exists (keeps UI consistent)
    stage_gus, _ = staging_paths(app_base, server_dir)
    src = stage_gus if stage_gus.exists() else (server_dir / GAMEUSERSETTINGS_REL)

    doc = read_ini(src)
    sec = "ServerSettings"

    # Always write passwords and RCON settings into INI (not cmdline)
    doc.set(sec, "ServerAdminPassword", (cfg.admin_password or "").strip())
    doc.set(sec, "ServerPassword", (cfg.join_password or "").strip())

    if cfg.enable_rcon:
        doc.set(sec, "RCONEnabled", "True")
        doc.set(sec, "RCONPort", str(int(cfg.rcon_port)))
    else:
        doc.set(sec, "RCONEnabled", "False")

    write_ini(stage_gus, doc)
    logger.info("Staged ServerSettings into GameUserSettings.ini (Admin/Join/RCON).")


# =============================================================================
# BACKUP
# =============================================================================

def backup_server(cfg: AppConfig, app_base: Path, logger: logging.Logger) -> Optional[Path]:
    server_dir = Path(cfg.server_dir)
    saved = server_saved_dir(server_dir)
    if not saved.exists():
        logger.info("Backup skipped: Saved folder not found.")
        return None

    target_dir = Path(cfg.backup_dir.strip()) if cfg.backup_dir.strip() else (app_base / BACKUP_DIR_NAME)
    ensure_dir(target_dir)

    name = f"ASA_Backup_{now_ts()}.zip"
    out_zip = target_dir / name

    include_paths = [saved]
    if cfg.backup_include_configs:
        include_paths.append(server_config_dir(server_dir))

    logger.info(f"Creating backup: {out_zip}")

    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for root in include_paths:
            root = root.resolve()
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if path.is_dir():
                    continue
                arc = path.relative_to(server_dir.resolve())
                z.write(path, arcname=str(arc))

    logger.info("Backup completed.")

    try:
        keep = max(1, int(cfg.backup_retention))
        zips = sorted(target_dir.glob("ASA_Backup_*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in zips[keep:]:
            try:
                old.unlink()
                logger.info(f"Retention: deleted {old.name}")
            except Exception:
                pass
    except Exception:
        pass

    return out_zip


# =============================================================================
# GUI LOGGING
# =============================================================================

class TkTextHandler(logging.Handler):
    def __init__(self, text: tk.Text):
        super().__init__()
        self._text = text

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)

        def append() -> None:
            self._text.configure(state="normal")
            self._text.insert("end", msg + "\n")
            self._text.see("end")
            self._text.configure(state="disabled")

        try:
            self._text.after(0, append)
        except Exception:
            pass


def build_logger(log_dir: Path, text_widget: tk.Text) -> logging.Logger:
    ensure_dir(log_dir)
    logger = logging.getLogger("asa_manager")
    logger.setLevel(LOG_LEVEL)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")

    h_gui = TkTextHandler(text_widget)
    h_gui.setLevel(LOG_LEVEL)
    h_gui.setFormatter(fmt)
    logger.addHandler(h_gui)

    h_file = logging.FileHandler(log_dir / LOG_FILE_NAME, encoding="utf-8")
    h_file.setLevel(LOG_LEVEL)
    h_file.setFormatter(fmt)
    logger.addHandler(h_file)

    return logger


# =============================================================================
# APP
# =============================================================================

class ServerManagerApp:
    @staticmethod
    def static_app_base() -> Path:
        base = app_data_dir()
        ensure_dir(base)
        return base

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_NAME)
        self.root.minsize(1220, 780)

        self.app_base = self.static_app_base()
        self.config_path = self.app_base / "config.json"
        self.log_dir = self.app_base / LOG_DIR_NAME
        self.store = ConfigStore(self.config_path)
        self.cfg = self.store.load()

        self._busy = False
        self._busy_lock = threading.Lock()

        self._server_proc: Optional[subprocess.Popen] = None
        self._server_proc_lock = threading.Lock()
        self._stop_log_reader = threading.Event()

        self._autosave_after_id: Optional[str] = None
        self._autosave_guard = False

        self._auto_update_thread: Optional[threading.Thread] = None
        self._auto_update_stop = threading.Event()

        self._rcon_factory = get_rcon_client_factory()

        # INI editor state
        self._ini_loaded_target: Optional[str] = None  # "gus" | "game"
        self._ini_doc: Optional[IniDocument] = None
        self._ini_items_index: Dict[str, Tuple[str, str]] = {}
        self._ini_apply_after_id: Optional[str] = None

        self._init_vars()
        self._build_layout()

        self.logger = build_logger(self.log_dir, self.txt_log)
        self._write_banner()

        self._autosave_guard = True
        self._apply_cfg_to_vars(self.cfg)
        self._autosave_guard = False

        self._sync_map_mode()
        self._hook_autosave()
        self._refresh_buttons()
        self._sync_auto_update_scheduler()

    # ---------------------------------------------------------------------
    # Vars
    # ---------------------------------------------------------------------
    def _init_vars(self) -> None:
        m = self.root

        # Paths
        self.var_steamcmd_dir = tk.StringVar(master=m)
        self.var_server_dir = tk.StringVar(master=m)

        # Server
        self.var_map_preset = tk.StringVar(master=m)
        self.var_map_custom = tk.StringVar(master=m)
        self.var_server_name = tk.StringVar(master=m)

        self.var_port = tk.StringVar(master=m)
        self.var_query_port = tk.StringVar(master=m)
        self.var_max_players = tk.StringVar(master=m)

        self.var_join_password = tk.StringVar(master=m)
        self.var_admin_password = tk.StringVar(master=m)

        self.var_enable_battleye = tk.BooleanVar(master=m)
        self.var_automanaged_mods = tk.BooleanVar(master=m)
        self.var_validate_on_update = tk.BooleanVar(master=m)

        # RCON
        self.var_enable_rcon = tk.BooleanVar(master=m)
        self.var_rcon_host = tk.StringVar(master=m)
        self.var_rcon_port = tk.StringVar(master=m)

        # Backup
        self.var_backup_on_stop = tk.BooleanVar(master=m)
        self.var_backup_dir = tk.StringVar(master=m)
        self.var_backup_retention = tk.StringVar(master=m)
        self.var_backup_include_configs = tk.BooleanVar(master=m)

        # Auto update
        self.var_auto_update_restart = tk.BooleanVar(master=m)
        self.var_auto_update_interval_min = tk.StringVar(master=m)

        # Status
        self.var_status = tk.StringVar(master=m)

        # Advanced args
        self.var_cluster_enable = tk.BooleanVar(master=m)
        self.var_cluster_id = tk.StringVar(master=m)
        self.var_cluster_custom_path_enable = tk.BooleanVar(master=m)
        self.var_cluster_dir_override = tk.StringVar(master=m)
        self.var_no_transfer_from_filtering = tk.BooleanVar(master=m)
        self.var_alt_save_directory_name = tk.StringVar(master=m)

        self.var_dino_mode = tk.StringVar(master=m)

        self.var_log_servergamelog = tk.BooleanVar(master=m)
        self.var_log_servergamelogincludetribelogs = tk.BooleanVar(master=m)
        self.var_log_serverrconoutputtribelogs = tk.BooleanVar(master=m)

        self.var_m_disablecustomcosmetics = tk.BooleanVar(master=m)
        self.var_m_autodestroystructures = tk.BooleanVar(master=m)
        self.var_m_forcerespawndinos = tk.BooleanVar(master=m)
        self.var_m_nowildbabies = tk.BooleanVar(master=m)
        self.var_m_forceallowcaveflyers = tk.BooleanVar(master=m)
        self.var_m_disabledinonetrangescaling = tk.BooleanVar(master=m)
        self.var_m_unstasisdinoobstructioncheck = tk.BooleanVar(master=m)
        self.var_m_alwaystickdedicatedskeletalmeshes = tk.BooleanVar(master=m)
        self.var_m_disablecharactertracker = tk.BooleanVar(master=m)
        self.var_m_useservernetspeedcheck = tk.BooleanVar(master=m)
        self.var_m_stasiskeepcontrollers = tk.BooleanVar(master=m)
        self.var_m_ignoredupeditems = tk.BooleanVar(master=m)

        # RCON UX
        self.var_rcon_cmd = tk.StringVar(master=m)
        self.var_rcon_saved = tk.StringVar(master=m)

        # INI UX
        self.var_ini_filter = tk.StringVar(master=m)
        self.var_ini_key = tk.StringVar(master=m)
        self.var_ini_section = tk.StringVar(master=m)
        self.var_ini_value = tk.StringVar(master=m)
        self.var_ini_bool = tk.StringVar(master=m)
        self.var_ini_scale = tk.DoubleVar(master=m)

    # ---------------------------------------------------------------------
    # Layout
    # ---------------------------------------------------------------------
    def _build_layout(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        paned = ttk.PanedWindow(self.root, orient="vertical")
        paned.grid(row=0, column=0, sticky="nsew")

        top = ttk.Frame(paned, padding=10)
        bottom = ttk.Frame(paned, padding=10)
        paned.add(top, weight=4)
        paned.add(bottom, weight=2)

        top.columnconfigure(0, weight=1)
        top.rowconfigure(0, weight=1)

        self.nb = ttk.Notebook(top)
        self.nb.grid(row=0, column=0, sticky="nsew")

        self.tab_server = ttk.Frame(self.nb, padding=10)
        self.tab_adv = ttk.Frame(self.nb, padding=10)
        self.tab_rcon = ttk.Frame(self.nb, padding=10)
        self.tab_ini = ttk.Frame(self.nb, padding=10)

        self.nb.add(self.tab_server, text="Server")
        self.nb.add(self.tab_adv, text="Advanced Start Args")
        self.nb.add(self.tab_rcon, text="RCON")
        self.nb.add(self.tab_ini, text="INI Editor")

        # ---------------- Server tab ----------------
        self.tab_server.columnconfigure(0, weight=1)
        self.tab_server.columnconfigure(1, weight=1)

        vcmd = (self.root.register(self._validate_digits), "%P")

        lf_paths = ttk.LabelFrame(self.tab_server, text="Paths", padding=10)
        lf_paths.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        lf_paths.columnconfigure(1, weight=1)
        lf_paths.columnconfigure(4, weight=1)

        ttk.Label(lf_paths, text="SteamCMD Directory").grid(row=0, column=0, sticky="w")
        ttk.Entry(lf_paths, textvariable=self.var_steamcmd_dir).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(lf_paths, text="Browse", command=self._browse_steamcmd).grid(row=0, column=2)

        ttk.Label(lf_paths, text="Server Install Directory").grid(row=0, column=3, sticky="w", padx=(18, 0))
        ttk.Entry(lf_paths, textvariable=self.var_server_dir).grid(row=0, column=4, sticky="ew", padx=6)
        ttk.Button(lf_paths, text="Browse", command=self._browse_server_dir).grid(row=0, column=5)

        lf_server = ttk.LabelFrame(self.tab_server, text="Server Settings", padding=10)
        lf_server.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        lf_server.columnconfigure(1, weight=1)

        lf_ops = ttk.LabelFrame(self.tab_server, text="Operations", padding=10)
        lf_ops.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        lf_ops.columnconfigure(1, weight=1)

        ttk.Label(lf_server, text="Map Preset").grid(row=0, column=0, sticky="w")
        self.cmb_map = ttk.Combobox(
            lf_server,
            textvariable=self.var_map_preset,
            state="readonly",
            values=[*MAP_PRESETS, MAP_CUSTOM_SENTINEL],
        )
        self.cmb_map.grid(row=0, column=1, sticky="ew", padx=6)
        self.cmb_map.bind("<<ComboboxSelected>>", lambda e: self._sync_map_mode())

        ttk.Label(lf_server, text="Custom Map Name").grid(row=1, column=0, sticky="w")
        self.ent_map_custom = ttk.Entry(lf_server, textvariable=self.var_map_custom)
        self.ent_map_custom.grid(row=1, column=1, sticky="ew", padx=6)

        ttk.Label(lf_server, text="Server Name").grid(row=2, column=0, sticky="w")
        ttk.Entry(lf_server, textvariable=self.var_server_name).grid(row=2, column=1, sticky="ew", padx=6)

        ttk.Label(lf_server, text="Port").grid(row=3, column=0, sticky="w")
        ttk.Entry(lf_server, textvariable=self.var_port, validate="key", validatecommand=vcmd).grid(row=3, column=1, sticky="ew", padx=6)

        ttk.Label(lf_server, text="Query Port").grid(row=4, column=0, sticky="w")
        ttk.Entry(lf_server, textvariable=self.var_query_port, validate="key", validatecommand=vcmd).grid(row=4, column=1, sticky="ew", padx=6)

        ttk.Label(lf_server, text="Max Players").grid(row=5, column=0, sticky="w")
        ttk.Entry(lf_server, textvariable=self.var_max_players, validate="key", validatecommand=vcmd).grid(row=5, column=1, sticky="ew", padx=6)

        ttk.Label(lf_server, text="Join Password").grid(row=6, column=0, sticky="w")
        ttk.Entry(lf_server, textvariable=self.var_join_password).grid(row=6, column=1, sticky="ew", padx=6)

        ttk.Label(lf_server, text="Admin Password (RCON/Admin)").grid(row=7, column=0, sticky="w")
        ttk.Entry(lf_server, textvariable=self.var_admin_password).grid(row=7, column=1, sticky="ew", padx=6)

        # Mods as multi-line list + horizontal scrollbar under field
        ttk.Label(lf_server, text="Mods (comma separated)").grid(row=8, column=0, sticky="nw", pady=(6, 0))
        mods_frame = ttk.Frame(lf_server)
        mods_frame.grid(row=8, column=1, sticky="ew", padx=6, pady=(6, 0))
        mods_frame.columnconfigure(0, weight=1)

        self.txt_mods = tk.Text(mods_frame, height=4, wrap="none")
        self.txt_mods.grid(row=0, column=0, sticky="ew")

        xscroll = ttk.Scrollbar(mods_frame, orient="horizontal", command=self.txt_mods.xview)
        xscroll.grid(row=1, column=0, sticky="ew", pady=(2, 0))
        self.txt_mods.configure(xscrollcommand=xscroll.set)

        # Options
        ttk.Checkbutton(lf_ops, text="Enable BattlEye", variable=self.var_enable_battleye).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(lf_ops, text="Automanaged Mods", variable=self.var_automanaged_mods).grid(row=1, column=0, sticky="w")
        ttk.Checkbutton(lf_ops, text="Enable RCON", variable=self.var_enable_rcon).grid(row=2, column=0, sticky="w")

        ttk.Label(lf_ops, text="RCON Host").grid(row=3, column=0, sticky="w")
        ttk.Entry(lf_ops, textvariable=self.var_rcon_host).grid(row=3, column=1, sticky="ew", padx=6)

        ttk.Label(lf_ops, text="RCON Port").grid(row=4, column=0, sticky="w")
        ttk.Entry(lf_ops, textvariable=self.var_rcon_port, validate="key", validatecommand=vcmd).grid(row=4, column=1, sticky="ew", padx=6)

        ttk.Checkbutton(lf_ops, text="Validate on Update", variable=self.var_validate_on_update).grid(row=5, column=0, sticky="w", pady=(8, 0))

        ttk.Separator(lf_ops).grid(row=6, column=0, columnspan=2, sticky="ew", pady=10)
        ttk.Checkbutton(lf_ops, text="Backup on Stop", variable=self.var_backup_on_stop).grid(row=7, column=0, sticky="w")

        ttk.Label(lf_ops, text="Backup Directory").grid(row=8, column=0, sticky="w")
        ttk.Entry(lf_ops, textvariable=self.var_backup_dir).grid(row=8, column=1, sticky="ew", padx=6)
        ttk.Button(lf_ops, text="Browse", command=self._browse_backup_dir).grid(row=8, column=2, padx=(6, 0))

        ttk.Label(lf_ops, text="Retention (zip count)").grid(row=9, column=0, sticky="w")
        ttk.Entry(lf_ops, textvariable=self.var_backup_retention, validate="key", validatecommand=vcmd).grid(row=9, column=1, sticky="ew", padx=6)
        ttk.Checkbutton(lf_ops, text="Include Configs", variable=self.var_backup_include_configs).grid(row=10, column=0, sticky="w")

        ttk.Separator(lf_ops).grid(row=11, column=0, columnspan=2, sticky="ew", pady=10)
        ttk.Checkbutton(
            lf_ops,
            text="Auto Update & Restart",
            variable=self.var_auto_update_restart,
            command=self._sync_auto_update_scheduler
        ).grid(row=12, column=0, sticky="w")
        ttk.Label(lf_ops, text="Interval (minutes)").grid(row=13, column=0, sticky="w")
        ttk.Entry(lf_ops, textvariable=self.var_auto_update_interval_min, validate="key", validatecommand=vcmd).grid(row=13, column=1, sticky="ew", padx=6)

        actions = ttk.Frame(self.tab_server, padding=(5, 10))
        actions.grid(row=2, column=0, columnspan=2, sticky="ew")
        actions.columnconfigure(9, weight=1)

        self.btn_first_install = ttk.Button(actions, text="First Install", command=self.first_install)
        self.btn_update_validate = ttk.Button(actions, text="Update / Validate", command=self.update_validate)
        self.btn_update_restart = ttk.Button(actions, text="Update & Restart (Safe)", command=self.update_and_restart_safe)
        self.btn_start = ttk.Button(actions, text="Start Server", command=self.start_server)
        self.btn_stop = ttk.Button(actions, text="Stop Server (Safe)", command=self.stop_server_safe)
        self.btn_backup_now = ttk.Button(actions, text="Backup Now", command=self.backup_now)
        self.btn_open_app = ttk.Button(actions, text="Open App Folder", command=lambda: open_folder(self.app_base))
        self.btn_open_server_cfg = ttk.Button(actions, text="Open Server Config", command=self.open_server_config_dir)

        self.btn_first_install.grid(row=0, column=0, padx=5)
        self.btn_update_validate.grid(row=0, column=1, padx=5)
        self.btn_update_restart.grid(row=0, column=2, padx=5)
        self.btn_start.grid(row=0, column=3, padx=5)
        self.btn_stop.grid(row=0, column=4, padx=5)
        self.btn_backup_now.grid(row=0, column=5, padx=5)
        self.btn_open_app.grid(row=0, column=6, padx=5)
        self.btn_open_server_cfg.grid(row=0, column=7, padx=5)

        ttk.Label(actions, textvariable=self.var_status, anchor="e").grid(row=0, column=9, sticky="e")

        # ---------------- Advanced Start Args tab ----------------
        self.tab_adv.columnconfigure(0, weight=1)
        self.tab_adv.columnconfigure(1, weight=1)

        lf_cluster = ttk.LabelFrame(self.tab_adv, text="Cluster Configuration", padding=10)
        lf_cluster.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        lf_cluster.columnconfigure(1, weight=1)

        ttk.Checkbutton(lf_cluster, text="Enable Cluster", variable=self.var_cluster_enable).grid(row=0, column=0, sticky="w")
        ttk.Label(lf_cluster, text="Cluster ID").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(lf_cluster, textvariable=self.var_cluster_id).grid(row=1, column=1, sticky="ew", padx=6, pady=(6, 0))

        ttk.Checkbutton(lf_cluster, text="NoTransferFromFiltering", variable=self.var_no_transfer_from_filtering).grid(row=2, column=0, sticky="w", pady=(8, 0))

        ttk.Checkbutton(lf_cluster, text="Enable Cluster Custom Path", variable=self.var_cluster_custom_path_enable).grid(row=3, column=0, sticky="w", pady=(8, 0))
        ttk.Label(lf_cluster, text="ClusterDirOverride Path").grid(row=4, column=0, sticky="w", pady=(6, 0))
        path_row = ttk.Frame(lf_cluster)
        path_row.grid(row=4, column=1, sticky="ew", padx=6, pady=(6, 0))
        path_row.columnconfigure(0, weight=1)
        ttk.Entry(path_row, textvariable=self.var_cluster_dir_override).grid(row=0, column=0, sticky="ew")
        ttk.Button(path_row, text="Browse", command=self._browse_cluster_dir).grid(row=0, column=1, padx=(6, 0))

        ttk.Label(lf_cluster, text="AltSaveDirectoryName (optional, per instance)").grid(row=5, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(lf_cluster, textvariable=self.var_alt_save_directory_name).grid(row=5, column=1, sticky="ew", padx=6, pady=(8, 0))

        lf_dinos = ttk.LabelFrame(self.tab_adv, text="Dinosaur Settings (mutual exclusive)", padding=10)
        lf_dinos.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

        dino_opts = [
            ("Default", ""),
            ("No Dinos", "NoDinos"),
            ("No Dinos Except Forced Spawn", "NoDinosExceptForcedSpawn"),
            ("No Dinos Except Streaming Spawn", "NoDinosExceptStreamingSpawn"),
            ("No Dinos Except Manual Spawn", "NoDinosExceptManualSpawn"),
            ("No Dinos Except Water Spawn", "NoDinosExceptWaterSpawn"),
        ]
        for i, (label, val) in enumerate(dino_opts):
            ttk.Radiobutton(lf_dinos, text=label, variable=self.var_dino_mode, value=val).grid(row=i, column=0, sticky="w")

        lf_logs = ttk.LabelFrame(self.tab_adv, text="Logs", padding=10)
        lf_logs.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        ttk.Checkbutton(lf_logs, text="servergamelog", variable=self.var_log_servergamelog).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(lf_logs, text="servergamelogincludetribelogs", variable=self.var_log_servergamelogincludetribelogs).grid(row=1, column=0, sticky="w")
        ttk.Checkbutton(lf_logs, text="ServerRCONOutputTribeLogs", variable=self.var_log_serverrconoutputtribelogs).grid(row=2, column=0, sticky="w")

        lf_mech = ttk.LabelFrame(self.tab_adv, text="Mechanics / Performance", padding=10)
        lf_mech.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)

        mech_items = [
            ("DisableCustomCosmetics", self.var_m_disablecustomcosmetics),
            ("AutoDestroyStructures", self.var_m_autodestroystructures),
            ("ForceRespawnDinos", self.var_m_forcerespawndinos),
            ("NoWildBabies", self.var_m_nowildbabies),
            ("ForceAllowCaveFlyers", self.var_m_forceallowcaveflyers),
            ("disabledinonetrangescaling", self.var_m_disabledinonetrangescaling),
            ("UnstasisDinoObstructionCheck", self.var_m_unstasisdinoobstructioncheck),
            ("AlwaysTickDedicatedSkeletalMeshes", self.var_m_alwaystickdedicatedskeletalmeshes),
            ("disableCharacterTracker", self.var_m_disablecharactertracker),
            ("UseServerNetSpeedCheck", self.var_m_useservernetspeedcheck),
            ("StasisKeepControllers", self.var_m_stasiskeepcontrollers),
            ("ignoredupeditems", self.var_m_ignoredupeditems),
        ]
        for i, (label, var) in enumerate(mech_items):
            ttk.Checkbutton(lf_mech, text=label, variable=var).grid(row=i // 2, column=i % 2, sticky="w", padx=(0, 14), pady=2)

        # ---------------- RCON tab ----------------
        self.tab_rcon.columnconfigure(0, weight=1)

        lf_rcon = ttk.LabelFrame(self.tab_rcon, text="RCON", padding=10)
        lf_rcon.grid(row=0, column=0, sticky="ew")
        lf_rcon.columnconfigure(1, weight=1)

        ttk.Label(lf_rcon, text="Saved Commands").grid(row=0, column=0, sticky="w")
        self.cmb_rcon_saved = ttk.Combobox(lf_rcon, textvariable=self.var_rcon_saved, state="readonly", values=[])
        self.cmb_rcon_saved.grid(row=0, column=1, sticky="ew", padx=6)
        self.cmb_rcon_saved.bind("<<ComboboxSelected>>", lambda e: self.var_rcon_cmd.set(self.var_rcon_saved.get()))

        ttk.Label(lf_rcon, text="Command").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.ent_rcon_cmd = ttk.Entry(lf_rcon, textvariable=self.var_rcon_cmd)
        self.ent_rcon_cmd.grid(row=1, column=1, sticky="ew", padx=6, pady=(8, 0))
        self.ent_rcon_cmd.bind("<Return>", lambda e: self.send_rcon())

        self.btn_rcon_send = ttk.Button(lf_rcon, text="Send", command=self.send_rcon)
        self.btn_rcon_send.grid(row=1, column=2, pady=(8, 0))

        btn_row = ttk.Frame(lf_rcon)
        btn_row.grid(row=2, column=1, sticky="w", padx=6, pady=(10, 0))
        ttk.Button(btn_row, text="Save Command", command=self._rcon_save_current).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(btn_row, text="Remove Selected", command=self._rcon_remove_selected).grid(row=0, column=1)

        ttk.Label(self.tab_rcon, text="Responses are written to the shared Console.").grid(row=1, column=0, sticky="w", pady=(8, 0))

        # ---------------- INI Editor tab ----------------
        self.tab_ini.columnconfigure(0, weight=2)
        self.tab_ini.columnconfigure(1, weight=1)
        self.tab_ini.rowconfigure(1, weight=1)

        ini_top = ttk.Frame(self.tab_ini)
        ini_top.grid(row=0, column=0, columnspan=2, sticky="ew")
        ini_top.columnconfigure(1, weight=1)

        ttk.Label(ini_top, text="Target").grid(row=0, column=0, sticky="w")
        self.lbl_ini_target = ttk.Label(ini_top, text="(not loaded)")
        self.lbl_ini_target.grid(row=0, column=1, sticky="w", padx=6)

        ttk.Button(ini_top, text="Load GameUserSettings.ini", command=self.load_gameusersettings).grid(row=0, column=2, padx=4)
        ttk.Button(ini_top, text="Load Game.ini", command=self.load_game_ini).grid(row=0, column=3, padx=4)
        ttk.Button(ini_top, text="Open Staged File", command=self.open_loaded_ini).grid(row=0, column=4, padx=4)

        ttk.Label(ini_top, text="Filter").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ent_filter = ttk.Entry(ini_top, textvariable=self.var_ini_filter)
        ent_filter.grid(row=1, column=1, sticky="ew", padx=6, pady=(6, 0))
        ent_filter.bind("<KeyRelease>", lambda e: self._ini_refresh_tree())

        tree_frame = ttk.Frame(self.tab_ini)
        tree_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        self.tree_ini = ttk.Treeview(tree_frame, columns=("value",), show="tree headings")
        self.tree_ini.heading("#0", text="Section / Key")
        self.tree_ini.heading("value", text="Value")
        self.tree_ini.column("value", width=420, anchor="w")
        self.tree_ini.grid(row=0, column=0, sticky="nsew")

        vs_tree = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_ini.yview)
        self.tree_ini.configure(yscrollcommand=vs_tree.set)
        vs_tree.grid(row=0, column=1, sticky="ns")

        self.tree_ini.bind("<<TreeviewSelect>>", lambda e: self._ini_on_select())

        editor = ttk.LabelFrame(self.tab_ini, text="Edit", padding=10)
        editor.grid(row=1, column=1, sticky="nsew")
        editor.columnconfigure(1, weight=1)

        ttk.Label(editor, text="Section").grid(row=0, column=0, sticky="w")
        ttk.Entry(editor, textvariable=self.var_ini_section, state="readonly").grid(row=0, column=1, sticky="ew", padx=6)

        ttk.Label(editor, text="Key").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(editor, textvariable=self.var_ini_key, state="readonly").grid(row=1, column=1, sticky="ew", padx=6, pady=(6, 0))

        self.row_value_label = ttk.Label(editor, text="Value")
        self.row_value_label.grid(row=2, column=0, sticky="w", pady=(10, 0))

        # Value widgets
        self.ent_ini_value = ttk.Entry(editor, textvariable=self.var_ini_value)
        self.cmb_ini_bool = ttk.Combobox(editor, textvariable=self.var_ini_bool, state="readonly", values=["True", "False"])

        self.ent_ini_value.grid(row=2, column=1, sticky="ew", padx=6, pady=(10, 0))
        self.cmb_ini_bool.grid_forget()

        # Slider + ticks
        self.scale_ini = ttk.Scale(editor, variable=self.var_ini_scale, from_=0.0, to=10.0, command=self._ini_scale_changed)
        self.scale_ini.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(10, 0))

        self.canvas_ticks = tk.Canvas(editor, height=14, highlightthickness=0)
        self.canvas_ticks.grid(row=4, column=0, columnspan=2, sticky="ew")

        ttk.Label(
            editor,
            text="Edits are staged. They are applied into the server folder on Start.\n"
                 "On Stop (Safe) the baseline is restored into the server folder.",
            wraplength=360
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(12, 0))

        # Auto-apply bindings (INI)
        self.ent_ini_value.bind("<KeyRelease>", lambda e: self._ini_schedule_apply())
        self.cmb_ini_bool.bind("<<ComboboxSelected>>", lambda e: self._ini_schedule_apply())

        # ---------------- Console (bottom) ----------------
        bottom.columnconfigure(0, weight=1)
        bottom.rowconfigure(0, weight=1)

        lf_console = ttk.LabelFrame(bottom, text="Console", padding=5)
        lf_console.grid(row=0, column=0, sticky="nsew")
        lf_console.columnconfigure(0, weight=1)
        lf_console.rowconfigure(0, weight=1)

        self.txt_log = tk.Text(lf_console, height=12, wrap="word", state="disabled")
        vs = ttk.Scrollbar(lf_console, orient="vertical", command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=vs.set)
        self.txt_log.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")

    # ---------------------------------------------------------------------
    # Validation
    # ---------------------------------------------------------------------
    def _validate_digits(self, proposed: str) -> bool:
        return proposed == "" or proposed.isdigit()

    # ---------------------------------------------------------------------
    # Config mapping
    # ---------------------------------------------------------------------
    def _mods_text_set(self, csv: str) -> None:
        self.txt_mods.delete("1.0", "end")
        self.txt_mods.insert("end", (csv or "").strip())

    def _mods_text_get(self) -> str:
        # User may paste CSV or newline-separated => always normalize to CSV
        raw = self.txt_mods.get("1.0", "end").strip()
        if not raw:
            return ""
        items: List[str] = []
        for line in raw.replace("\r", "\n").split("\n"):
            for tok in line.split(","):
                t = tok.strip()
                if t:
                    items.append(t)
        return ",".join(items)

    def _apply_cfg_to_vars(self, cfg: AppConfig) -> None:
        self.var_steamcmd_dir.set(cfg.steamcmd_dir)
        self.var_server_dir.set(cfg.server_dir)

        if cfg.map_name in MAP_PRESETS:
            self.var_map_preset.set(cfg.map_name)
            self.var_map_custom.set(cfg.map_name)
        else:
            self.var_map_preset.set(MAP_CUSTOM_SENTINEL)
            self.var_map_custom.set(cfg.map_name)

        self.var_server_name.set(cfg.server_name)
        self.var_port.set(str(cfg.port))
        self.var_query_port.set(str(cfg.query_port))
        self.var_max_players.set(str(cfg.max_players))

        self.var_join_password.set(cfg.join_password)
        self.var_admin_password.set(cfg.admin_password)

        self.var_enable_battleye.set(cfg.enable_battleye)
        self.var_automanaged_mods.set(cfg.automanaged_mods)
        self.var_validate_on_update.set(cfg.validate_on_update)

        self._mods_text_set(cfg.mods)

        self.var_enable_rcon.set(cfg.enable_rcon)
        self.var_rcon_host.set(cfg.rcon_host)
        self.var_rcon_port.set(str(cfg.rcon_port))

        self.var_backup_on_stop.set(cfg.backup_on_stop)
        self.var_backup_dir.set(cfg.backup_dir)
        self.var_backup_retention.set(str(cfg.backup_retention))
        self.var_backup_include_configs.set(cfg.backup_include_configs)

        self.var_auto_update_restart.set(cfg.auto_update_restart)
        self.var_auto_update_interval_min.set(str(cfg.auto_update_interval_min))

        self.var_cluster_enable.set(cfg.cluster_enable)
        self.var_cluster_id.set(cfg.cluster_id)
        self.var_cluster_custom_path_enable.set(cfg.cluster_custom_path_enable)
        self.var_cluster_dir_override.set(cfg.cluster_dir_override)
        self.var_no_transfer_from_filtering.set(cfg.no_transfer_from_filtering)
        self.var_alt_save_directory_name.set(cfg.alt_save_directory_name)

        self.var_dino_mode.set(cfg.dino_mode)

        self.var_log_servergamelog.set(cfg.log_servergamelog)
        self.var_log_servergamelogincludetribelogs.set(cfg.log_servergamelogincludetribelogs)
        self.var_log_serverrconoutputtribelogs.set(cfg.log_serverrconoutputtribelogs)

        self.var_m_disablecustomcosmetics.set(cfg.mech_disablecustomcosmetics)
        self.var_m_autodestroystructures.set(cfg.mech_autodestroystructures)
        self.var_m_forcerespawndinos.set(cfg.mech_forcerespawndinos)
        self.var_m_nowildbabies.set(cfg.mech_nowildbabies)
        self.var_m_forceallowcaveflyers.set(cfg.mech_forceallowcaveflyers)
        self.var_m_disabledinonetrangescaling.set(cfg.mech_disabledinonetrangescaling)
        self.var_m_unstasisdinoobstructioncheck.set(cfg.mech_unstasisdinoobstructioncheck)
        self.var_m_alwaystickdedicatedskeletalmeshes.set(cfg.mech_alwaystickdedicatedskeletalmeshes)
        self.var_m_disablecharactertracker.set(cfg.mech_disablecharactertracker)
        self.var_m_useservernetspeedcheck.set(cfg.mech_useservernetspeedcheck)
        self.var_m_stasiskeepcontrollers.set(cfg.mech_stasiskeepcontrollers)
        self.var_m_ignoredupeditems.set(cfg.mech_ignoredupeditems)

        self._rcon_refresh_saved(cfg)

    def _collect_vars_to_cfg(self) -> AppConfig:
        cfg = AppConfig()

        cfg.steamcmd_dir = self.var_steamcmd_dir.get().strip() or DEFAULT_STEAMCMD_DIR
        cfg.server_dir = self.var_server_dir.get().strip() or DEFAULT_SERVER_DIR

        cfg.map_name = self.var_map_custom.get().strip() or DEFAULT_MAP
        cfg.server_name = self.var_server_name.get().strip() or DEFAULT_SERVER_NAME

        cfg.port = safe_int(self.var_port.get(), DEFAULT_PORT) or DEFAULT_PORT
        cfg.query_port = safe_int(self.var_query_port.get(), DEFAULT_QUERY_PORT) or DEFAULT_QUERY_PORT
        cfg.max_players = safe_int(self.var_max_players.get(), DEFAULT_MAX_PLAYERS) or DEFAULT_MAX_PLAYERS

        cfg.join_password = (self.var_join_password.get() or "").strip()
        cfg.admin_password = (self.var_admin_password.get() or "").strip()

        cfg.enable_battleye = bool(self.var_enable_battleye.get())
        cfg.automanaged_mods = bool(self.var_automanaged_mods.get())
        cfg.validate_on_update = bool(self.var_validate_on_update.get())

        cfg.mods = self._mods_text_get()

        cfg.enable_rcon = bool(self.var_enable_rcon.get())
        cfg.rcon_host = self.var_rcon_host.get().strip() or DEFAULT_RCON_HOST
        cfg.rcon_port = safe_int(self.var_rcon_port.get(), DEFAULT_RCON_PORT) or DEFAULT_RCON_PORT

        cfg.backup_on_stop = bool(self.var_backup_on_stop.get())
        cfg.backup_dir = self.var_backup_dir.get().strip()
        cfg.backup_retention = safe_int(self.var_backup_retention.get(), 20) or 20
        cfg.backup_include_configs = bool(self.var_backup_include_configs.get())

        cfg.auto_update_restart = bool(self.var_auto_update_restart.get())
        cfg.auto_update_interval_min = safe_int(self.var_auto_update_interval_min.get(), 360) or 360

        cfg.cluster_enable = bool(self.var_cluster_enable.get())
        cfg.cluster_id = self.var_cluster_id.get().strip()
        cfg.cluster_custom_path_enable = bool(self.var_cluster_custom_path_enable.get())
        cfg.cluster_dir_override = self.var_cluster_dir_override.get().strip()
        cfg.no_transfer_from_filtering = bool(self.var_no_transfer_from_filtering.get())
        cfg.alt_save_directory_name = self.var_alt_save_directory_name.get().strip()

        cfg.dino_mode = self.var_dino_mode.get().strip()

        cfg.log_servergamelog = bool(self.var_log_servergamelog.get())
        cfg.log_servergamelogincludetribelogs = bool(self.var_log_servergamelogincludetribelogs.get())
        cfg.log_serverrconoutputtribelogs = bool(self.var_log_serverrconoutputtribelogs.get())

        cfg.mech_disablecustomcosmetics = bool(self.var_m_disablecustomcosmetics.get())
        cfg.mech_autodestroystructures = bool(self.var_m_autodestroystructures.get())
        cfg.mech_forcerespawndinos = bool(self.var_m_forcerespawndinos.get())
        cfg.mech_nowildbabies = bool(self.var_m_nowildbabies.get())
        cfg.mech_forceallowcaveflyers = bool(self.var_m_forceallowcaveflyers.get())
        cfg.mech_disabledinonetrangescaling = bool(self.var_m_disabledinonetrangescaling.get())
        cfg.mech_unstasisdinoobstructioncheck = bool(self.var_m_unstasisdinoobstructioncheck.get())
        cfg.mech_alwaystickdedicatedskeletalmeshes = bool(self.var_m_alwaystickdedicatedskeletalmeshes.get())
        cfg.mech_disablecharactertracker = bool(self.var_m_disablecharactertracker.get())
        cfg.mech_useservernetspeedcheck = bool(self.var_m_useservernetspeedcheck.get())
        cfg.mech_stasiskeepcontrollers = bool(self.var_m_stasiskeepcontrollers.get())
        cfg.mech_ignoredupeditems = bool(self.var_m_ignoredupeditems.get())

        # RCON saved commands
        cfg.rcon_saved_commands = self.cfg.rcon_saved_commands[:] if isinstance(self.cfg.rcon_saved_commands, list) else []
        if not cfg.rcon_saved_commands:
            cfg.rcon_saved_commands = ["SaveWorld", "DoExit", "ListPlayers", "DestroyWildDinos"]

        self._validate_cfg(cfg)
        return cfg

    def _validate_cfg(self, cfg: AppConfig) -> None:
        if not cfg.steamcmd_dir.strip():
            raise ValueError("SteamCMD directory is required.")
        if not cfg.server_dir.strip():
            raise ValueError("Server directory is required.")
        if not cfg.map_name.strip():
            raise ValueError("Map name is required.")

        for name, p in [("Port", cfg.port), ("QueryPort", cfg.query_port), ("RCONPort", cfg.rcon_port)]:
            if not (1 <= int(p) <= 65535):
                raise ValueError(f"{name} out of range (1..65535).")

        if not (1 <= int(cfg.max_players) <= 255):
            raise ValueError("MaxPlayers out of range (1..255).")

        if cfg.auto_update_interval_min < 10:
            raise ValueError("Auto update interval must be >= 10 minutes.")

    def _hook_autosave(self) -> None:
        def on_change(*_: Any) -> None:
            if self._autosave_guard:
                return
            self._schedule_autosave()

        vars_to_watch = [
            self.var_steamcmd_dir, self.var_server_dir,
            self.var_map_preset, self.var_map_custom, self.var_server_name,
            self.var_port, self.var_query_port, self.var_max_players,
            self.var_join_password, self.var_admin_password,
            self.var_enable_battleye, self.var_automanaged_mods, self.var_validate_on_update,
            self.var_enable_rcon, self.var_rcon_host, self.var_rcon_port,
            self.var_backup_on_stop, self.var_backup_dir, self.var_backup_retention, self.var_backup_include_configs,
            self.var_auto_update_restart, self.var_auto_update_interval_min,
            self.var_cluster_enable, self.var_cluster_id, self.var_cluster_custom_path_enable, self.var_cluster_dir_override,
            self.var_no_transfer_from_filtering, self.var_alt_save_directory_name,
            self.var_dino_mode,
            self.var_log_servergamelog, self.var_log_servergamelogincludetribelogs, self.var_log_serverrconoutputtribelogs,
            self.var_m_disablecustomcosmetics, self.var_m_autodestroystructures, self.var_m_forcerespawndinos,
            self.var_m_nowildbabies, self.var_m_forceallowcaveflyers, self.var_m_disabledinonetrangescaling,
            self.var_m_unstasisdinoobstructioncheck, self.var_m_alwaystickdedicatedskeletalmeshes,
            self.var_m_disablecharactertracker, self.var_m_useservernetspeedcheck, self.var_m_stasiskeepcontrollers,
            self.var_m_ignoredupeditems,
        ]
        for v in vars_to_watch:
            try:
                v.trace_add("write", on_change)
            except Exception:
                pass

        self.txt_mods.bind("<KeyRelease>", lambda e: (None if self._autosave_guard else self._schedule_autosave()))

    def _schedule_autosave(self) -> None:
        if self._autosave_after_id:
            try:
                self.root.after_cancel(self._autosave_after_id)
            except Exception:
                pass
        self._autosave_after_id = self.root.after(AUTOSAVE_DEBOUNCE_MS, self._autosave)

    def _autosave(self) -> None:
        self._autosave_after_id = None
        if self._autosave_guard:
            return
        try:
            self.cfg = self._collect_vars_to_cfg()
            self.store.save(self.cfg)
            self._set_status("Auto-saved")
        except Exception as e:
            self.logger.info(f"Autosave skipped: {e}")
            self._set_status(f"Config invalid: {e}")

        self._sync_auto_update_scheduler()

    # ---------------------------------------------------------------------
    # Busy / State
    # ---------------------------------------------------------------------
    def _set_busy(self, busy: bool) -> None:
        with self._busy_lock:
            self._busy = busy
        self._refresh_buttons()

    def _is_busy(self) -> bool:
        with self._busy_lock:
            return self._busy

    def _is_server_running(self) -> bool:
        with self._server_proc_lock:
            p = self._server_proc
        return p is not None and p.poll() is None

    def _refresh_buttons(self) -> None:
        busy = self._is_busy()
        running = self._is_server_running()

        self.btn_first_install.configure(state=("disabled" if busy else "normal"))
        self.btn_update_validate.configure(state=("disabled" if busy else "normal"))
        self.btn_update_restart.configure(state=("disabled" if busy else "normal"))

        self.btn_start.configure(state=("disabled" if busy or running else "normal"))
        self.btn_stop.configure(state=("disabled" if busy or not running else "normal"))
        self.btn_backup_now.configure(state=("disabled" if busy else "normal"))

        self.btn_rcon_send.configure(state=("disabled" if busy else "normal"))

        if running:
            self._set_status("Server: RUNNING")
        else:
            if not busy and not self.var_status.get().startswith("Config invalid"):
                self._set_status("Ready")

    def _run_task(self, name: str, fn: Callable[[], None]) -> None:
        if self._is_busy():
            return

        def worker() -> None:
            self._set_busy(True)
            try:
                self.logger.info(f"=== {name} started ===")
                fn()
                self.logger.info(f"=== {name} completed ===")
            except Exception as e:
                self.logger.error(f"{name} failed: {e}")
                try:
                    messagebox.showerror(name, str(e))
                except Exception:
                    pass
            finally:
                self._set_busy(False)

        threading.Thread(target=worker, daemon=True).start()

    # ---------------------------------------------------------------------
    # UX
    # ---------------------------------------------------------------------
    def _set_status(self, text: str) -> None:
        self.var_status.set(text)

    def _write_banner(self) -> None:
        self.logger.info(f"{APP_NAME} started | Admin={is_admin()} | Config={self.config_path}")
        self.logger.info(f"Logs: {self.log_dir / LOG_FILE_NAME}")
        self._set_status("Ready")

    def _sync_map_mode(self) -> None:
        choice = self.var_map_preset.get()
        if choice == MAP_CUSTOM_SENTINEL:
            self.ent_map_custom.configure(state="normal")
        else:
            self.var_map_custom.set(choice)
            self.ent_map_custom.configure(state="disabled")

    # ---------------------------------------------------------------------
    # Browsers
    # ---------------------------------------------------------------------
    def _browse_steamcmd(self) -> None:
        p = filedialog.askdirectory(title="Select SteamCMD directory")
        if p:
            self.var_steamcmd_dir.set(p)

    def _browse_server_dir(self) -> None:
        p = filedialog.askdirectory(title="Select ARK server install directory")
        if p:
            self.var_server_dir.set(p)

    def _browse_backup_dir(self) -> None:
        p = filedialog.askdirectory(title="Select backup target directory")
        if p:
            self.var_backup_dir.set(p)

    def _browse_cluster_dir(self) -> None:
        p = filedialog.askdirectory(title="Select ClusterDirOverride directory")
        if p:
            self.var_cluster_dir_override.set(p)

    def open_server_config_dir(self) -> None:
        d = server_config_dir(Path(self.cfg.server_dir))
        open_folder(d)

    # ---------------------------------------------------------------------
    # Dependencies
    # ---------------------------------------------------------------------
    def _ensure_dependencies_first_install(self, logger: logging.Logger) -> None:
        v = vc14_x64_version()
        if v:
            logger.info(f"VC++ v14 x64 OK (Version={v})")
        else:
            logger.info("VC++ v14 x64 missing -> installing...")
            install_vcredist(logger)

        # DirectX legacy: always install (requested)
        logger.info("DirectX legacy -> installing (forced).")
        install_directx_web(logger)

    # ---------------------------------------------------------------------
    # First Install / Update Validate
    # ---------------------------------------------------------------------
    def first_install(self) -> None:
        def job() -> None:
            self.cfg = self._collect_vars_to_cfg()
            self.store.save(self.cfg)

            if not is_admin():
                self.logger.info("Warning: Not running as Administrator. Installs may fail.")

            self._ensure_dependencies_first_install(self.logger)

            steamcmd_exe = ensure_steamcmd(Path(self.cfg.steamcmd_dir), self.logger)
            steamcmd_update_server(steamcmd_exe, Path(self.cfg.server_dir), self.logger, validate=False)

            exe = ark_server_exe(Path(self.cfg.server_dir))
            self.logger.info(f"Server executable: {exe if exe.exists() else 'NOT FOUND'}")

        self._run_task("First Install", job)

    def update_validate(self) -> None:
        def job() -> None:
            self.cfg = self._collect_vars_to_cfg()
            self.store.save(self.cfg)

            steamcmd_exe = ensure_steamcmd(Path(self.cfg.steamcmd_dir), self.logger)
            steamcmd_update_server(steamcmd_exe, Path(self.cfg.server_dir), self.logger, validate=True)

        self._run_task("Update / Validate", job)

    # ---------------------------------------------------------------------
    # Start / Stop / RCON
    # ---------------------------------------------------------------------
    def _stage_required_configs_for_start(self) -> None:
        server_dir = Path(self.cfg.server_dir)
        ensure_baseline(self.app_base, server_dir, self.logger)
        ensure_required_server_settings(self.cfg, self.app_base, server_dir, self.logger)

    def start_server(self) -> None:
        def job() -> None:
            self.cfg = self._collect_vars_to_cfg()
            self.store.save(self.cfg)

            server_dir = Path(self.cfg.server_dir)
            exe = ark_server_exe(server_dir)
            if not exe.exists():
                raise FileNotFoundError(f"Server EXE not found: {exe}")

            self._stage_required_configs_for_start()
            apply_staging_to_server(self.app_base, server_dir, self.logger)

            cmd = build_server_command(self.cfg)
            self.logger.info("Starting server...")
            self.logger.info(" ".join(cmd))

            with self._server_proc_lock:
                if self._server_proc and self._server_proc.poll() is None:
                    raise RuntimeError("Server already running")

                self._stop_log_reader.clear()
                self._server_proc = subprocess.Popen(
                    cmd,
                    cwd=str(exe.parent),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                )

            threading.Thread(target=self._server_log_reader, daemon=True).start()
            self.root.after(0, self._refresh_buttons)

        self._run_task("Start Server", job)

    def _server_log_reader(self) -> None:
        with self._server_proc_lock:
            p = self._server_proc
        if not p or not p.stdout:
            return

        try:
            for line in p.stdout:
                if self._stop_log_reader.is_set():
                    break

                # Reduce noisy analytics chatter (user-facing UX)
                if "GameAnalytics" in line or "Couldn't resolve host name" in line:
                    continue

                self.logger.info(line.rstrip())
        except Exception as e:
            self.logger.info(f"Log reader stopped: {e}")
        finally:
            try:
                code = p.poll()
                if code is not None:
                    self.logger.info(f"Server exited with code {code}")
            except Exception:
                pass
            self.root.after(0, self._refresh_buttons)

    def _rcon_try(self, cmd: str, timeout: float = 4.0, retry_window_sec: int = 15) -> str:
        if not self.cfg.enable_rcon:
            raise RuntimeError("RCON disabled in config.")
        if not (self.cfg.admin_password or "").strip():
            raise RuntimeError("Admin password is empty.")
        start = time.time()
        last_err: Optional[Exception] = None
        while time.time() - start < retry_window_sec:
            try:
                client = self._rcon_factory(self.cfg.rcon_host, int(self.cfg.rcon_port), self.cfg.admin_password, timeout)
                with client as c:
                    return str(c.command(cmd))
            except Exception as e:
                last_err = e
                time.sleep(0.5)
        raise RuntimeError(str(last_err) if last_err else "RCON failed")

    def send_rcon(self) -> None:
        cmd = self.var_rcon_cmd.get().strip()
        if not cmd:
            return

        def job() -> None:
            self.cfg = self._collect_vars_to_cfg()
            self.store.save(self.cfg)

            self.logger.info(f"RCON> {cmd}")
            out = self._rcon_try(cmd, timeout=5.0)
            self.logger.info(out if out else "(no response)")

            if cmd not in self.cfg.rcon_saved_commands:
                self.cfg.rcon_saved_commands.append(cmd)
                self.store.save(self.cfg)
                self._rcon_refresh_saved(self.cfg)

            self.var_rcon_cmd.set("")

        self._run_task("RCON", job)

    def _rcon_refresh_saved(self, cfg: AppConfig) -> None:
        vals = cfg.rcon_saved_commands[:] if isinstance(cfg.rcon_saved_commands, list) else []
        self.cmb_rcon_saved.configure(values=vals)

    def _rcon_save_current(self) -> None:
        cmd = self.var_rcon_cmd.get().strip()
        if not cmd:
            return
        if cmd not in self.cfg.rcon_saved_commands:
            self.cfg.rcon_saved_commands.append(cmd)
            self.store.save(self.cfg)
            self._rcon_refresh_saved(self.cfg)
            self.var_rcon_saved.set(cmd)

    def _rcon_remove_selected(self) -> None:
        sel = self.var_rcon_saved.get().strip()
        if not sel:
            return
        try:
            self.cfg.rcon_saved_commands = [c for c in self.cfg.rcon_saved_commands if c != sel]
            self.store.save(self.cfg)
            self._rcon_refresh_saved(self.cfg)
            self.var_rcon_saved.set("")
        except Exception:
            pass

    def stop_server_safe(self) -> None:
        def job() -> None:
            self.cfg = self._collect_vars_to_cfg()
            self.store.save(self.cfg)

            with self._server_proc_lock:
                p = self._server_proc

            if not p or p.poll() is not None:
                self.logger.info("Server not running.")
                return

            if self.cfg.enable_rcon:
                try:
                    self.logger.info("RCON: SaveWorld")
                    _ = self._rcon_try("SaveWorld", timeout=6.0)
                except Exception as e:
                    self.logger.info(f"RCON SaveWorld failed: {e}")

                try:
                    self.logger.info("RCON: DoExit")
                    _ = self._rcon_try("DoExit", timeout=6.0)
                except Exception as e:
                    self.logger.info(f"RCON DoExit failed -> terminate fallback: {e}")

            t_end = time.time() + 20
            while time.time() < t_end and p.poll() is None:
                time.sleep(0.5)

            if p.poll() is None:
                self.logger.info("Terminating server process...")
                self._stop_log_reader.set()
                p.terminate()
                try:
                    p.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    self.logger.info("Killing server process...")
                    p.kill()
                    p.wait(timeout=5)

            with self._server_proc_lock:
                self._server_proc = None

            self.logger.info("Server stopped.")

            if self.cfg.backup_on_stop:
                backup_server(self.cfg, self.app_base, self.logger)

            restore_baseline_to_server(self.app_base, Path(self.cfg.server_dir), self.logger)

            self.root.after(0, self._refresh_buttons)

        self._run_task("Stop Server", job)

    def update_and_restart_safe(self) -> None:
        def job() -> None:
            self.cfg = self._collect_vars_to_cfg()
            self.store.save(self.cfg)

            if self._is_server_running():
                self.logger.info("Server running -> performing safe stop before update.")
                self._stop_server_safe_inline()

            steamcmd_exe = ensure_steamcmd(Path(self.cfg.steamcmd_dir), self.logger)
            steamcmd_update_server(steamcmd_exe, Path(self.cfg.server_dir), self.logger, validate=bool(self.cfg.validate_on_update))

            self.logger.info("Restarting server after update...")
            self._start_server_inline()

        self._run_task("Update & Restart", job)

    def _stop_server_safe_inline(self) -> None:
        with self._server_proc_lock:
            p = self._server_proc

        if not p or p.poll() is not None:
            return

        if self.cfg.enable_rcon:
            try:
                self.logger.info("RCON: SaveWorld")
                _ = self._rcon_try("SaveWorld", timeout=6.0)
            except Exception as e:
                self.logger.info(f"RCON SaveWorld failed: {e}")

            try:
                self.logger.info("RCON: DoExit")
                _ = self._rcon_try("DoExit", timeout=6.0)
            except Exception as e:
                self.logger.info(f"RCON DoExit failed -> terminate fallback: {e}")

        t_end = time.time() + 20
        while time.time() < t_end and p.poll() is None:
            time.sleep(0.5)

        if p.poll() is None:
            self.logger.info("Terminating server process...")
            self._stop_log_reader.set()
            p.terminate()
            try:
                p.wait(timeout=12)
            except subprocess.TimeoutExpired:
                self.logger.info("Killing server process...")
                p.kill()
                p.wait(timeout=5)

        with self._server_proc_lock:
            self._server_proc = None

        self.logger.info("Server stopped (inline).")

        if self.cfg.backup_on_stop:
            backup_server(self.cfg, self.app_base, self.logger)

        restore_baseline_to_server(self.app_base, Path(self.cfg.server_dir), self.logger)

    def _start_server_inline(self) -> None:
        server_dir = Path(self.cfg.server_dir)
        exe = ark_server_exe(server_dir)
        if not exe.exists():
            raise FileNotFoundError(f"Server EXE not found: {exe}")

        self._stage_required_configs_for_start()
        apply_staging_to_server(self.app_base, server_dir, self.logger)

        cmd = build_server_command(self.cfg)
        self.logger.info("Starting server (inline)...")
        self.logger.info(" ".join(cmd))

        with self._server_proc_lock:
            self._stop_log_reader.clear()
            self._server_proc = subprocess.Popen(
                cmd,
                cwd=str(exe.parent),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

        threading.Thread(target=self._server_log_reader, daemon=True).start()
        self.root.after(0, self._refresh_buttons)

    def backup_now(self) -> None:
        def job() -> None:
            self.cfg = self._collect_vars_to_cfg()
            self.store.save(self.cfg)
            backup_server(self.cfg, self.app_base, self.logger)

        self._run_task("Backup", job)

    # ---------------------------------------------------------------------
    # Auto Update Loop
    # ---------------------------------------------------------------------
    def _sync_auto_update_scheduler(self) -> None:
        try:
            self.cfg = self._collect_vars_to_cfg()
            self.store.save(self.cfg)
        except Exception:
            return

        enabled = bool(self.cfg.auto_update_restart)
        if enabled and (self._auto_update_thread is None or not self._auto_update_thread.is_alive()):
            self._auto_update_stop.clear()
            self._auto_update_thread = threading.Thread(target=self._auto_update_loop, daemon=True)
            self._auto_update_thread.start()
            self.logger.info("Auto Update & Restart scheduler enabled.")
        elif not enabled and self._auto_update_thread is not None:
            self._auto_update_stop.set()
            self.logger.info("Auto Update & Restart scheduler disabled.")

    def _auto_update_loop(self) -> None:
        while not self._auto_update_stop.is_set():
            interval = max(10, int(self.cfg.auto_update_interval_min))
            for _ in range(interval):
                if self._auto_update_stop.is_set():
                    return
                time.sleep(60)

            if self._auto_update_stop.is_set():
                return

            if self._is_busy():
                self.logger.info("Auto update skipped: app is busy.")
                continue

            self.logger.info("Auto update trigger reached -> Update & Restart (Safe).")
            self.root.after(0, self.update_and_restart_safe)

    # ---------------------------------------------------------------------
    # INI Editor
    # ---------------------------------------------------------------------
    def _ini_target_paths(self) -> Tuple[Path, Path]:
        server_dir = Path(self.cfg.server_dir)
        stage_gus, stage_game = staging_paths(self.app_base, server_dir)
        live_gus = server_dir / GAMEUSERSETTINGS_REL
        live_game = server_dir / GAME_INI_REL
        return (stage_gus if stage_gus.exists() else live_gus,
                stage_game if stage_game.exists() else live_game)

    def load_gameusersettings(self) -> None:
        self.cfg = self._collect_vars_to_cfg()
        self.store.save(self.cfg)
        server_dir = Path(self.cfg.server_dir)
        ensure_baseline(self.app_base, server_dir, self.logger)
        self._ini_loaded_target = "gus"
        src, _ = self._ini_target_paths()
        self._ini_doc = read_ini(src)
        self.lbl_ini_target.configure(text=f"GameUserSettings.ini (editing staged copy if present)")
        self._ini_refresh_tree()

    def load_game_ini(self) -> None:
        self.cfg = self._collect_vars_to_cfg()
        self.store.save(self.cfg)
        server_dir = Path(self.cfg.server_dir)
        ensure_baseline(self.app_base, server_dir, self.logger)
        self._ini_loaded_target = "game"
        _, src = self._ini_target_paths()
        self._ini_doc = read_ini(src)
        self.lbl_ini_target.configure(text=f"Game.ini (editing staged copy if present)")
        self._ini_refresh_tree()

    def open_loaded_ini(self) -> None:
        if not self._ini_loaded_target:
            return
        src_gus, src_game = self._ini_target_paths()
        open_file(src_gus if self._ini_loaded_target == "gus" else src_game)

    def _ini_refresh_tree(self) -> None:
        self.tree_ini.delete(*self.tree_ini.get_children())
        self._ini_items_index.clear()
        if not self._ini_doc:
            return

        data = self._ini_doc.get()
        filt = (self.var_ini_filter.get() or "").strip().lower()

        for section in sorted(data.keys(), key=lambda s: s.lower()):
            sec_iid = self.tree_ini.insert("", "end", text=f"[{section}]", values=("",))
            keys = data[section]
            inserted_any = False
            for key in sorted(keys.keys(), key=lambda s: s.lower()):
                val = keys[key]
                if filt and (filt not in section.lower() and filt not in key.lower() and filt not in str(val).lower()):
                    continue
                iid = self.tree_ini.insert(sec_iid, "end", text=key, values=(val,))
                self._ini_items_index[iid] = (section, key)
                inserted_any = True
            if inserted_any:
                self.tree_ini.item(sec_iid, open=True)

    def _ini_on_select(self) -> None:
        sel = self.tree_ini.selection()
        if not sel:
            return
        iid = sel[0]
        if iid not in self._ini_items_index:
            return
        section, key = self._ini_items_index[iid]
        assert self._ini_doc is not None
        val = self._ini_doc.get().get(section, {}).get(key, "")

        self.var_ini_section.set(section)
        self.var_ini_key.set(key)

        t = self._detect_value_type(str(val))
        if t == "bool":
            self.ent_ini_value.grid_forget()
            self.cmb_ini_bool.grid(row=2, column=1, sticky="ew", padx=6, pady=(10, 0))
            self.var_ini_bool.set("True" if str(val).strip().lower() == "true" else "False")
            self.scale_ini.configure(state="disabled")
            self.canvas_ticks.delete("all")
        else:
            self.cmb_ini_bool.grid_forget()
            self.ent_ini_value.grid(row=2, column=1, sticky="ew", padx=6, pady=(10, 0))
            self.var_ini_value.set(str(val))

            if t in ("int", "float"):
                lo, hi = self._guess_numeric_range(str(val))
                self.scale_ini.configure(from_=lo, to=hi, state="normal")
                try:
                    self.var_ini_scale.set(float(val))
                except Exception:
                    self.var_ini_scale.set(float(lo))
                self._draw_ticks(lo, hi)
            else:
                self.scale_ini.configure(state="disabled")
                self.canvas_ticks.delete("all")

    def _detect_value_type(self, s: str) -> str:
        v = s.strip()
        if v.lower() in ("true", "false"):
            return "bool"
        try:
            int(v)
            return "int"
        except Exception:
            pass
        try:
            float(v)
            return "float"
        except Exception:
            return "str"

    def _guess_numeric_range(self, s: str) -> Tuple[float, float]:
        try:
            v = float(s)
        except Exception:
            return (0.0, 10.0)
        if -2.0 <= v <= 2.0:
            return (-5.0, 5.0)
        if 0.0 <= v <= 5.0:
            return (0.0, 10.0)
        if 0.0 <= v <= 100.0:
            return (0.0, 200.0)
        return (min(v * 0.5, v - 1.0), max(v * 1.5, v + 1.0))

    def _draw_ticks(self, lo: float, hi: float) -> None:
        self.canvas_ticks.delete("all")
        try:
            w = self.canvas_ticks.winfo_width()
            if w <= 1:
                self.root.after(50, lambda: self._draw_ticks(lo, hi))
                return
        except Exception:
            return

        w = self.canvas_ticks.winfo_width()
        h = int(self.canvas_ticks["height"])
        n = 11  # 10 segments
        for i in range(n):
            x = int((w - 2) * (i / (n - 1))) + 1
            tick_h = 10 if i in (0, n - 1) or i == (n - 1) // 2 else 6
            self.canvas_ticks.create_line(x, h, x, h - tick_h)

    def _ini_scale_changed(self, _=None) -> None:
        section = self.var_ini_section.get().strip()
        key = self.var_ini_key.get().strip()
        if not section or not key:
            return
        # Keep entry synced and auto-apply
        cur = self.var_ini_value.get().strip()
        t = self._detect_value_type(cur)
        if t == "int":
            self.var_ini_value.set(str(int(round(self.var_ini_scale.get()))))
        elif t == "float":
            self.var_ini_value.set(f"{self.var_ini_scale.get():.6f}".rstrip("0").rstrip("."))
        self._ini_schedule_apply()

    def _ini_schedule_apply(self) -> None:
        if self._ini_apply_after_id:
            try:
                self.root.after_cancel(self._ini_apply_after_id)
            except Exception:
                pass
        self._ini_apply_after_id = self.root.after(INI_APPLY_DEBOUNCE_MS, self._ini_apply_now)

    def _ini_apply_now(self) -> None:
        self._ini_apply_after_id = None
        if not self._ini_doc or not self._ini_loaded_target:
            return

        section = self.var_ini_section.get().strip()
        key = self.var_ini_key.get().strip()
        if not section or not key:
            return

        val = ""
        if self.cmb_ini_bool.winfo_ismapped():
            val = self.var_ini_bool.get().strip()
        else:
            val = self.var_ini_value.get()

        self._ini_doc.set(section, key, val)

        server_dir = Path(self.cfg.server_dir)
        stage_gus, stage_game = staging_paths(self.app_base, server_dir)

        if self._ini_loaded_target == "gus":
            write_ini(stage_gus, self._ini_doc)
        else:
            write_ini(stage_game, self._ini_doc)

        self._ini_refresh_tree()
        self._set_status("INI staged")

    # ---------------------------------------------------------------------
    # Misc
    # ---------------------------------------------------------------------
    def backup_now(self) -> None:
        def job() -> None:
            self.cfg = self._collect_vars_to_cfg()
            self.store.save(self.cfg)
            backup_server(self.cfg, self.app_base, self.logger)

        self._run_task("Backup", job)


# =============================================================================
# ENTRYPOINT
# =============================================================================

def launch_gui() -> None:
    set_windows_appusermodel_id(APP_USERMODEL_ID)

    root = tk.Tk()

    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass

    apply_window_icon(root)

    if os.name == "nt" and not is_admin():
        try:
            if messagebox.askyesno(
                "Administrator rights recommended",
                "This app installs dependencies and manages server files.\n"
                "Run as Administrator for full functionality.\n\n"
                "Relaunch with admin rights now?"
            ):
                if relaunch_as_admin():
                    root.destroy()
                    return
        except Exception:
            pass

    _ = ServerManagerApp(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
