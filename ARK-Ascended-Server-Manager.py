# ARK: Survival Ascended Dedicated Server Manager (Windows)

from __future__ import annotations

import ctypes
import copy
import hashlib
import json
import logging
import os
import shlex
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import zipfile
from dataclasses import asdict, dataclass, field, fields
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
AMAZON_ROOT_CA1_URL: str = "https://www.amazontrust.com/repository/AmazonRootCA1.cer"
AMAZON_R2M02_URL: str = "https://crt.r2m02.amazontrust.com/r2m02.cer"

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

# DirectX legacy detection (requested: combine registry + legacy DLL presence)
DIRECTX_LEGACY_DLLS = [
    "d3dx9_43.dll",
    "d3dx10_43.dll",
    "d3dx11_43.dll",
    "d3dcompiler_43.dll",
    "xinput1_3.dll",
]


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


def safe_int(s: Any, default: int) -> int:
    try:
        return int(str(s).strip())
    except Exception:
        return default


def safe_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        t = v.strip().lower()
        if t in ("1", "true", "yes", "y", "on"):
            return True
        if t in ("0", "false", "no", "n", "off"):
            return False
    return default


def file_sha256(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 256), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    ensure_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding=encoding, newline="") as f:
        f.write(text)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(str(tmp), str(path))


def atomic_write_bytes(path: Path, data: bytes) -> None:
    ensure_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(str(tmp), str(path))


def open_folder(path: Path) -> None:
    ensure_dir(path)
    try:
        os.startfile(str(path))
    except Exception:
        pass


def open_in_explorer(path: Path, select_file: bool = True) -> None:
    """
    Windows: open Explorer and select file (best UX).
    Fallback: open folder/file via os.startfile.
    """
    try:
        if os.name == "nt":
            if select_file and path.exists() and path.is_file():
                subprocess.Popen(["explorer.exe", "/select,", str(path)])
                return
            # Open folder
            target = path if path.is_dir() else path.parent
            ensure_dir(target)
            subprocess.Popen(["explorer.exe", str(target)])
            return

        # non-Windows fallback
        if path.is_dir():
            open_folder(path)
        else:
            if path.exists():
                os.startfile(str(path))  # type: ignore[attr-defined]
    except Exception:
        pass


def _find_powershell() -> Optional[str]:
    """
    Returns an available PowerShell executable name (powershell.exe or pwsh).
    We keep this conservative to stay compatible with standard Windows installs.
    """
    if os.name != "nt":
        return None

    candidates = ["powershell.exe", "powershell", "pwsh.exe", "pwsh"]
    for c in candidates:
        try:
            p = subprocess.run(["where", c], capture_output=True, text=True)
            if p.returncode == 0:
                return c
        except Exception:
            continue
    return "powershell.exe"


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


def run_and_stream_collect(cmd: List[str], logger: logging.Logger, cwd: Optional[Path] = None) -> Tuple[int, str]:
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
    lines: List[str] = []
    for line in p.stdout:
        s = line.rstrip()
        lines.append(s)
        logger.info(s)
    code = p.wait()
    return code, "\n".join(lines)


def server_key_from_dir(server_dir: Path) -> str:
    return str(server_dir).replace(":", "").replace("\\", "_").replace("/", "_")


# =============================================================================
# DOWNLOAD
# =============================================================================

def _urllib_download_ssl(url: str, dest: Path, logger: logging.Logger, timeout: int = DOWNLOAD_TIMEOUT_SEC) -> None:
    ensure_dir(dest.parent)
    logger.info(f"Downloading: {url}")

    ctx = ssl.create_default_context()
    try:
        import certifi  # type: ignore
        ctx.load_verify_locations(cafile=certifi.where())
    except Exception:
        pass

    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=timeout, context=ctx) as r:
        data = r.read()
    if not data:
        raise RuntimeError("Empty download response")
    atomic_write_bytes(dest, data)
    logger.info(f"Saved: {dest}")


def _bits_download(url: str, dest: Path, logger: logging.Logger) -> None:
    if os.name != "nt":
        raise RuntimeError("BITS download is only supported on Windows.")

    ps_exe = _find_powershell()
    if not ps_exe:
        raise RuntimeError("PowerShell not found; cannot use BITS download.")

    ensure_dir(dest.parent)

    ps = (
        "Import-Module BitsTransfer -ErrorAction Stop; "
        f"Start-BitsTransfer -Source '{url}' -Destination '{str(dest)}' -Priority Foreground -ErrorAction Stop"
    )
    cmd = [ps_exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps]
    code = run_and_stream(cmd, logger)
    if code != 0 or not dest.exists() or dest.stat().st_size == 0:
        raise RuntimeError(f"BITS download failed (exit={code}): {url}")

    logger.info(f"Saved: {dest}")


def download_file_with_certutil_fallback(url: str, dest: Path, logger: logging.Logger) -> None:
    """
    Legacy function name kept for compatibility.
    New behavior:
      - Windows: try BITS first (enterprise-safe), then urllib SSL.
      - Non-Windows: urllib SSL only.
    """
    last_err: Optional[Exception] = None

    if os.name == "nt":
        try:
            _bits_download(url, dest, logger)
            return
        except Exception as e:
            last_err = e
            logger.info(f"BITS download failed: {e} -> fallback to urllib/ssl.")

    try:
        _urllib_download_ssl(url, dest, logger)
        return
    except Exception as e:
        last_err = e
        logger.info(f"Download failed via urllib/ssl: {e}")

    if os.name == "nt":
        try:
            logger.info("Retrying via BITS as last resort...")
            _bits_download(url, dest, logger)
            return
        except Exception as e:
            last_err = e

    raise RuntimeError(f"Failed to download: {url} -> {last_err}")


# =============================================================================
# CONFIG
# =============================================================================

@dataclass
class AppConfig:
    schema_version: int = 5

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
    backup_dir: str = ""  # empty => appdata/backups
    backup_retention: int = 20
    backup_include_configs: bool = False

    auto_update_restart: bool = False
    auto_update_interval_min: int = 360

    # certificate install
    install_optional_certificates: bool = True

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


@dataclass
class ConfigLoadResult:
    cfg: AppConfig
    migrated: bool
    warnings: List[str]


class ConfigStore:
    """
    - Defaults + JSON overlay (typed)
    - Keeps unknown keys for forward compatibility
    - Atomic writes
    - Optional migration (schema_version bump / missing keys)
    """

    def __init__(self, path: Path):
        self.path = path
        self._extra: Dict[str, Any] = {}

    def load(self) -> ConfigLoadResult:
        cfg = AppConfig()
        migrated = False
        warnings: List[str] = []

        if not self.path.exists():
            migrated = True  # first-run: create file later
            return ConfigLoadResult(cfg=cfg, migrated=migrated, warnings=warnings)

        try:
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Config root is not a JSON object")
        except Exception as e:
            # quarantine corrupt config
            try:
                bad = self.path.with_name(f"config.corrupt.{now_ts()}.json")
                shutil.copy2(self.path, bad)
                warnings.append(f"Config was corrupt -> copied to: {bad}")
            except Exception:
                warnings.append("Config was corrupt -> could not copy quarantine file")
            migrated = True
            return ConfigLoadResult(cfg=cfg, migrated=migrated, warnings=warnings)

        known = {f.name: f for f in fields(AppConfig)}
        self._extra = {k: v for k, v in data.items() if k not in known}

        # overlay known fields with type safety
        for name, fdef in known.items():
            if name not in data:
                continue
            v = data.get(name)
            try:
                cur = getattr(cfg, name)
                if isinstance(cur, bool):
                    setattr(cfg, name, safe_bool(v, cur))
                elif isinstance(cur, int):
                    setattr(cfg, name, safe_int(v, cur))
                elif isinstance(cur, list):
                    setattr(cfg, name, v if isinstance(v, list) else cur)
                else:
                    setattr(cfg, name, v if isinstance(v, type(cur)) else str(v))
            except Exception:
                pass

        # normalize list field
        if not isinstance(cfg.rcon_saved_commands, list):
            cfg.rcon_saved_commands = ["SaveWorld", "DoExit", "ListPlayers", "DestroyWildDinos"]

        # schema migration
        current_schema = AppConfig().schema_version
        if safe_int(getattr(cfg, "schema_version", 0), 0) != current_schema:
            cfg.schema_version = current_schema
            migrated = True

        # missing keys = migrated (ensures new fields get written to disk)
        for name in known.keys():
            if name not in data:
                migrated = True
                break

        return ConfigLoadResult(cfg=cfg, migrated=migrated, warnings=warnings)

    def save(self, cfg: AppConfig) -> None:
        ensure_dir(self.path.parent)
        base = asdict(cfg)

        # forward-compat: keep unknown keys
        for k, v in self._extra.items():
            if k not in base:
                base[k] = v

        atomic_write_text(self.path, json.dumps(base, indent=2), encoding="utf-8")


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


def directx_registry_present() -> bool:
    if winreg is None:
        return False
    try:
        with reg_open_key_64(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\DirectX"):
            return True
    except Exception:
        return False


def has_directx_legacy(min_hits: int = 3) -> bool:
    if os.name != "nt":
        return False
    windir = os.environ.get("WINDIR", r"C:\Windows")
    candidates = [
        Path(windir) / "System32",
        Path(windir) / "SysWOW64",
    ]
    hits = 0
    for folder in candidates:
        for dll in DIRECTX_LEGACY_DLLS:
            if (folder / dll).exists():
                hits += 1
    return hits >= min_hits


def install_vcredist(logger: logging.Logger) -> None:
    temp = Path(os.environ.get("TEMP", str(Path.home() / "AppData/Local/Temp")))
    exe = temp / "vc_redist.x64.exe"
    download_file_with_certutil_fallback(VC_REDIST_X64_URL, exe, logger)
    code = run_and_stream([str(exe), "/install", "/passive", "/norestart"], logger)
    logger.info(f"VC++ installer exit code: {code}")


def install_directx_web(logger: logging.Logger) -> None:
    temp = Path(os.environ.get("TEMP", str(Path.home() / "AppData/Local/Temp")))
    exe = temp / "dxwebsetup.exe"
    download_file_with_certutil_fallback(DXWEBSETUP_URL, exe, logger)
    code = run_and_stream([str(exe), "/Q"], logger)
    logger.info(f"DirectX web installer exit code: {code}")


def install_asa_certificates(logger: logging.Logger) -> None:
    """
    - Downloads AmazonRootCA1 + r2m02 and imports them into Windows cert store.
    - Implemented via PowerShell Import-Certificate (NOT certutil) to avoid Defender/ASR download heuristics.
    """
    if os.name != "nt":
        logger.info("Certificate install skipped: only supported on Windows.")
        return

    ps_exe = _find_powershell()
    if not ps_exe:
        raise RuntimeError("PowerShell not found; cannot import certificates.")

    temp = Path(os.environ.get("TEMP", str(Path.home() / "AppData/Local/Temp")))
    root_path = temp / "AmazonRootCA1.cer"
    r2m02_path = temp / "r2m02.cer"

    download_file_with_certutil_fallback(AMAZON_ROOT_CA1_URL, root_path, logger)
    download_file_with_certutil_fallback(AMAZON_R2M02_URL, r2m02_path, logger)

    if is_admin():
        root_store = r"Cert:\LocalMachine\Root"
        ca_store = r"Cert:\LocalMachine\CA"
        logger.info("Certificate import: admin -> LocalMachine store.")
    else:
        root_store = r"Cert:\CurrentUser\Root"
        ca_store = r"Cert:\CurrentUser\CA"
        logger.info("Certificate import: non-admin -> CurrentUser store.")

    def import_cert(cer_path: Path, store: str) -> None:
        ps = (
            f"Import-Certificate -FilePath '{str(cer_path)}' -CertStoreLocation '{store}' "
            "| Out-Null"
        )
        cmd = [ps_exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps]
        code = run_and_stream(cmd, logger)
        if code != 0:
            raise RuntimeError(f"Import-Certificate failed (exit={code}) for {cer_path.name} -> {store}")

    logger.info("Installing certificates: AmazonRootCA1 -> Root, r2m02 -> CA")
    import_cert(root_path, root_store)
    import_cert(r2m02_path, ca_store)
    logger.info("Certificates installed/updated successfully.")


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
            try:
                run_and_stream_collect([str(c), "+quit"], logger, cwd=c.parent)
            except Exception as e:
                logger.info(f"SteamCMD bootstrap warning (ignored): {e}")
            return c

    zip_path = steamcmd_dir / "steamcmd.zip"
    download_file_with_certutil_fallback(STEAMCMD_ZIP_URL, zip_path, logger)
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(steamcmd_dir)
    try:
        zip_path.unlink(missing_ok=True)  # type: ignore[arg-type]
    except Exception:
        pass

    for c in candidates:
        if c.exists():
            try:
                run_and_stream_collect([str(c), "+quit"], logger, cwd=c.parent)
            except Exception as e:
                logger.info(f"SteamCMD bootstrap warning (ignored): {e}")
            return c

    raise FileNotFoundError(f"steamcmd.exe not found after extraction in: {steamcmd_dir}")


def steamcmd_update_server(steamcmd_exe: Path, server_dir: Path, logger: logging.Logger, validate: bool) -> None:
    ensure_dir(server_dir)

    base_cmd = [
        str(steamcmd_exe),
        "+@ShutdownOnFailedCommand", "1",
        "+@NoPromptForPassword", "1",
        "+force_install_dir", str(server_dir),
        "+login", "anonymous",
        "+app_update", str(APP_ID),
    ]
    if validate:
        base_cmd.append("validate")
    base_cmd.append("+quit")

    code, out = run_and_stream_collect(base_cmd, logger, cwd=steamcmd_exe.parent)

    if code == 7 or "Missing configuration" in out:
        logger.info("SteamCMD returned code 7 / Missing configuration (first-run bootstrap). Retrying once...")
        time.sleep(2)
        code, out = run_and_stream_collect(base_cmd, logger, cwd=steamcmd_exe.parent)

    if code != 0:
        raise RuntimeError(f"SteamCMD exited with code {code}")


# =============================================================================
# INI (order-preserving, duplicate-key aware)
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

    def is_effectively_empty(self) -> bool:
        for l in self.lines:
            if l.kind == "kv":
                return False
            if l.kind == "section":
                # sections alone are still "empty enough" (common corruption case is almost empty file)
                continue
        # if only comments/whitespace, it's empty
        return True

    def kv_entries_by_section(self) -> Dict[str, List[Tuple[int, str, str]]]:
        """
        Returns section -> list of (line_index, key, value) in original order.
        Duplicate keys are preserved.
        """
        out: Dict[str, List[Tuple[int, str, str]]] = {}
        for idx, line in enumerate(self.lines):
            if line.kind == "kv":
                out.setdefault(line.section, []).append((idx, line.key, line.value))
        return out

    def get_last_value_map(self) -> Dict[str, Dict[str, str]]:
        """
        Convenience map (last-value wins). Only used for diff/merge.
        """
        data: Dict[str, Dict[str, str]] = {}
        for line in self.lines:
            if line.kind == "kv":
                data.setdefault(line.section, {})[line.key] = line.value
        return data

    def ensure_section(self, section: str) -> None:
        section = section.strip()
        if not section:
            return
        if any(l.kind == "section" and l.section == section for l in self.lines):
            return

        if self.lines and not self.lines[-1].raw.endswith("\n"):
            self.lines[-1].raw += "\n"
        self.lines.append(IniLine(kind="other", raw="\n"))
        self.lines.append(IniLine(kind="section", raw=f"[{section}]\n", section=section))

    def set(self, section: str, key: str, value: str) -> None:
        """
        Set key in section:
        - If key exists (any occurrence), update the FIRST occurrence (stable, conservative).
        - Else, append as new kv line at end of section.
        """
        section = section.strip()
        key = key.strip()
        value = str(value)

        if not section or not key:
            return

        self.ensure_section(section)

        for l in self.lines:
            if l.kind == "kv" and l.section == section and l.key.lower() == key.lower():
                nl = "\r\n" if l.raw.endswith("\r\n") else ("\n" if l.raw.endswith("\n") else "\n")
                l.key = key
                l.value = value
                l.raw = f"{key}={value}{nl}"
                return

        self.append_kv(section, key, value)

    def append_kv(self, section: str, key: str, value: str) -> int:
        """
        Always append a new kv line (duplicate keys allowed).
        Returns inserted line index.
        """
        section = section.strip()
        key = key.strip()
        value = str(value)

        if not section or not key:
            return -1

        self.ensure_section(section)

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
        return insert_at

    def update_value_at(self, line_index: int, value: str) -> None:
        if not (0 <= line_index < len(self.lines)):
            return
        l = self.lines[line_index]
        if l.kind != "kv":
            return
        nl = "\r\n" if l.raw.endswith("\r\n") else ("\n" if l.raw.endswith("\n") else "\n")
        l.value = str(value)
        l.raw = f"{l.key}={l.value}{nl}"

    def delete_at(self, line_index: int) -> None:
        if not (0 <= line_index < len(self.lines)):
            return
        if self.lines[line_index].kind != "kv":
            return
        self.lines.pop(line_index)

    def to_text(self) -> str:
        return "".join(l.raw for l in self.lines)


def read_ini(path: Path) -> IniDocument:
    if not path.exists():
        return IniDocument.parse("")
    return IniDocument.parse(path.read_text(encoding="utf-8", errors="ignore"))


def write_ini(path: Path, doc: IniDocument) -> None:
    atomic_write_text(path, doc.to_text(), encoding="utf-8")


def three_way_merge_ini(base: IniDocument, staged: IniDocument, upstream: IniDocument) -> IniDocument:
    """
    3-way merge on last-value maps (safe for ARK style):
    - compute changes from base -> staged
    - apply those changes onto upstream
    NOTE: deletions are not propagated (conservative, avoids accidental removal).
    """
    base_map = base.get_last_value_map()
    staged_map = staged.get_last_value_map()
    up_doc = upstream  # mutate upstream doc

    for sec, kvs in staged_map.items():
        for key, staged_val in kvs.items():
            base_val = base_map.get(sec, {}).get(key, None)
            if base_val is None or staged_val != base_val:
                up_doc.set(sec, key, staged_val)

    return up_doc


@dataclass
class IniStagePaths:
    target_name: str  # "gus" | "game"
    live: Path
    baseline: Path
    stage: Path
    stage_base: Path
    stage_meta: Path


def ini_stage_paths(app_base: Path, server_dir: Path, target: str) -> IniStagePaths:
    key = server_key_from_dir(server_dir)

    live_gus = server_dir / GAMEUSERSETTINGS_REL
    live_game = server_dir / GAME_INI_REL

    baseline_root = app_base / BASELINE_DIR_NAME / key
    baseline_gus = baseline_root / "GameUserSettings.ini"
    baseline_game = baseline_root / "Game.ini"

    stage_gus, stage_game = staging_paths(app_base, server_dir)

    if target == "gus":
        stage = stage_gus
        live = live_gus
        baseline = baseline_gus
        stage_base = stage_gus.with_suffix(".base.ini")
        stage_meta = stage_gus.with_suffix(".meta.json")
    else:
        stage = stage_game
        live = live_game
        baseline = baseline_game
        stage_base = stage_game.with_suffix(".base.ini")
        stage_meta = stage_game.with_suffix(".meta.json")

    return IniStagePaths(
        target_name=target,
        live=live,
        baseline=baseline,
        stage=stage,
        stage_base=stage_base,
        stage_meta=stage_meta,
    )


def ensure_ini_staging_synced(paths: IniStagePaths, server_running: bool, logger: Optional[logging.Logger] = None) -> None:
    """
    Guarantees:
    - stage exists and is not trivially empty/corrupt
    - stage includes latest upstream keys (via 3-way merge)
    Upstream source decision:
    - if server running: use baseline (if exists) else live
    - if server not running: use live (if exists) else baseline
    """
    ensure_dir(paths.stage.parent)

    def log(msg: str) -> None:
        if logger:
            logger.info(msg)

    upstream = None
    if server_running:
        upstream = paths.baseline if paths.baseline.exists() else paths.live
    else:
        upstream = paths.live if paths.live.exists() else paths.baseline

    upstream_exists = upstream.exists() if upstream is not None else False

    if not paths.stage.exists():
        if upstream_exists:
            shutil.copy2(upstream, paths.stage)
            shutil.copy2(upstream, paths.stage_base)
            log(f"INI staging created from upstream: {paths.stage.name}")
        else:
            write_ini(paths.stage, IniDocument.parse(""))
            write_ini(paths.stage_base, IniDocument.parse(""))
            log(f"INI staging created empty: {paths.stage.name}")

        meta = {
            "created": now_ts(),
            "upstream_path": str(upstream) if upstream else "",
            "upstream_hash": file_sha256(upstream) if upstream else "",
        }
        try:
            atomic_write_text(paths.stage_meta, json.dumps(meta, indent=2), encoding="utf-8")
        except Exception:
            pass
        return

    # repair corrupt/empty stage (your exact bug)
    try:
        stage_doc = read_ini(paths.stage)
        if paths.stage.stat().st_size == 0 or stage_doc.is_effectively_empty():
            if upstream_exists:
                shutil.copy2(upstream, paths.stage)
                shutil.copy2(upstream, paths.stage_base)
                log(f"INI staging repaired from upstream: {paths.stage.name}")
            else:
                write_ini(paths.stage, IniDocument.parse(""))
                write_ini(paths.stage_base, IniDocument.parse(""))
                log(f"INI staging repaired as empty: {paths.stage.name}")
            return
    except Exception:
        # if anything goes sideways, rebuild from upstream
        if upstream_exists:
            shutil.copy2(upstream, paths.stage)
            shutil.copy2(upstream, paths.stage_base)
            log(f"INI staging force-repaired from upstream: {paths.stage.name}")
        return

    # ensure stage_base exists
    if not paths.stage_base.exists():
        if upstream_exists:
            shutil.copy2(upstream, paths.stage_base)
            log(f"INI stage base created from upstream: {paths.stage_base.name}")
        else:
            shutil.copy2(paths.stage, paths.stage_base)
            log(f"INI stage base created from stage: {paths.stage_base.name}")

    # merge if upstream changed since last base snapshot
    if upstream_exists:
        upstream_hash = file_sha256(upstream)
        base_hash = file_sha256(paths.stage_base)
        if upstream_hash and base_hash and upstream_hash != base_hash:
            base_doc = read_ini(paths.stage_base)
            staged_doc = read_ini(paths.stage)
            upstream_doc = read_ini(upstream)
            merged = three_way_merge_ini(base_doc, staged_doc, upstream_doc)
            write_ini(paths.stage, merged)
            shutil.copy2(upstream, paths.stage_base)

            meta = {
                "last_merge": now_ts(),
                "upstream_path": str(upstream),
                "upstream_hash": upstream_hash,
                "base_hash_before": base_hash,
            }
            try:
                atomic_write_text(paths.stage_meta, json.dumps(meta, indent=2), encoding="utf-8")
            except Exception:
                pass

            log(f"INI staging merged with upstream changes: {paths.stage.name}")


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
                self._c = SourceClient(self.host, self.port, passwd=self.password, timeout=self.timeout)
                self._c.__enter__()
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

    if cfg.dino_mode.strip():
        flags.append(f"-{cfg.dino_mode.strip()}")

    if cfg.log_servergamelog:
        flags.append("-servergamelog")
    if cfg.log_servergamelogincludetribelogs:
        flags.append("-servergamelogincludetribelogs")
    if cfg.log_serverrconoutputtribelogs:
        flags.append("-ServerRCONOutputTribeLogs")

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

def ensure_baseline(app_base: Path, server_dir: Path, logger: logging.Logger, refresh: bool = True) -> Path:
    """
    Enterprise fix:
    - Baseline must reflect the *current* live INIs right before staging is applied.
    - refresh=True overwrites baseline if live exists (safe & correct for Stop Safe restore).
    """
    baseline_root = app_base / BASELINE_DIR_NAME
    ensure_dir(baseline_root)

    key = server_key_from_dir(server_dir)
    base = baseline_root / key
    ensure_dir(base)

    src_gus = server_dir / GAMEUSERSETTINGS_REL
    src_game = server_dir / GAME_INI_REL

    dst_gus = base / "GameUserSettings.ini"
    dst_game = base / "Game.ini"

    if src_gus.exists() and (refresh or not dst_gus.exists()):
        shutil.copy2(src_gus, dst_gus)
        logger.info("Baseline updated: GameUserSettings.ini")
    if src_game.exists() and (refresh or not dst_game.exists()):
        shutil.copy2(src_game, dst_game)
        logger.info("Baseline updated: Game.ini")

    return base


def staging_paths(app_base: Path, server_dir: Path) -> Tuple[Path, Path]:
    staging_root = app_base / STAGING_DIR_NAME
    ensure_dir(staging_root)
    key = server_key_from_dir(server_dir)
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
    base_root = app_base / BASELINE_DIR_NAME / server_key_from_dir(server_dir)
    src_gus = base_root / "GameUserSettings.ini"
    src_game = base_root / "Game.ini"

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

    # guarantee staged INI is healthy + synced
    paths = ini_stage_paths(app_base, server_dir, "gus")
    ensure_ini_staging_synced(paths, server_running=False, logger=logger)

    doc = read_ini(paths.stage)
    sec = "ServerSettings"

    doc.set(sec, "ServerAdminPassword", (cfg.admin_password or "").strip())
    doc.set(sec, "ServerPassword", (cfg.join_password or "").strip())

    if cfg.enable_rcon:
        doc.set(sec, "RCONEnabled", "True")
        doc.set(sec, "RCONPort", str(int(cfg.rcon_port)))
    else:
        doc.set(sec, "RCONEnabled", "False")

    write_ini(paths.stage, doc)
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
        load_res = self.store.load()
        self.cfg = load_res.cfg
        self._config_migrated = load_res.migrated
        self._config_warnings = load_res.warnings

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
        self._ini_items_index: Dict[str, int] = {}  # tree iid -> IniDocument line_index
        self._ini_apply_after_id: Optional[str] = None
        self._ini_selected_line_idx: Optional[int] = None
        self._ini_paths_current: Optional[IniStagePaths] = None

        self._init_vars()
        self._build_layout()

        self.logger = build_logger(self.log_dir, self.txt_log)
        self._write_banner()

        # log config warnings + write migrated config once
        for w in self._config_warnings:
            self.logger.info(f"[CONFIG] {w}")
        if self._config_migrated:
            try:
                self.store.save(self.cfg)
                self.logger.info("[CONFIG] Migrated/initialized config saved.")
            except Exception as e:
                self.logger.info(f"[CONFIG] Save after migration failed: {e}")

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

        self.var_steamcmd_dir = tk.StringVar(master=m)
        self.var_server_dir = tk.StringVar(master=m)

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

        self.var_enable_rcon = tk.BooleanVar(master=m)
        self.var_rcon_host = tk.StringVar(master=m)
        self.var_rcon_port = tk.StringVar(master=m)

        self.var_backup_on_stop = tk.BooleanVar(master=m)
        self.var_backup_dir = tk.StringVar(master=m)
        self.var_backup_retention = tk.StringVar(master=m)
        self.var_backup_include_configs = tk.BooleanVar(master=m)

        self.var_auto_update_restart = tk.BooleanVar(master=m)
        self.var_auto_update_interval_min = tk.StringVar(master=m)

        self.var_install_optional_certificates = tk.BooleanVar(master=m)

        self.var_status = tk.StringVar(master=m)

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

        self.var_rcon_cmd = tk.StringVar(master=m)
        self.var_rcon_saved = tk.StringVar(master=m)

        # INI editor vars
        self.var_ini_filter = tk.StringVar(master=m)
        self.var_ini_key = tk.StringVar(master=m)
        self.var_ini_section = tk.StringVar(master=m)
        self.var_ini_value = tk.StringVar(master=m)
        self.var_ini_bool = tk.StringVar(master=m)
        self.var_ini_scale = tk.DoubleVar(master=m)

        # INI "add line" vars
        self.var_ini_add_section = tk.StringVar(master=m)
        self.var_ini_add_key = tk.StringVar(master=m)
        self.var_ini_add_value = tk.StringVar(master=m)

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
        ttk.Entry(lf_paths)  # no-op placeholder removed intentionally
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

        ttk.Label(lf_server, text="Mods (comma separated)").grid(row=8, column=0, sticky="nw", pady=(6, 0))
        mods_frame = ttk.Frame(lf_server)
        mods_frame.grid(row=8, column=1, sticky="ew", padx=6, pady=(6, 0))
        mods_frame.columnconfigure(0, weight=1)

        self.txt_mods = tk.Text(mods_frame, height=4, wrap="none")
        self.txt_mods.grid(row=0, column=0, sticky="ew")

        xscroll = ttk.Scrollbar(mods_frame, orient="horizontal", command=self.txt_mods.xview)
        xscroll.grid(row=1, column=0, sticky="ew", pady=(2, 0))
        self.txt_mods.configure(xscrollcommand=xscroll.set)

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

        ttk.Separator(lf_ops).grid(row=14, column=0, columnspan=2, sticky="ew", pady=10)
        ttk.Checkbutton(
            lf_ops,
            text="Install certificates",
            variable=self.var_install_optional_certificates
        ).grid(row=15, column=0, sticky="w")

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
        self.tab_ini.rowconfigure(2, weight=1)

        ini_top = ttk.Frame(self.tab_ini)
        ini_top.grid(row=0, column=0, columnspan=2, sticky="ew")
        ini_top.columnconfigure(1, weight=1)

        ttk.Label(ini_top, text="Target").grid(row=0, column=0, sticky="w")
        self.lbl_ini_target = ttk.Label(ini_top, text="(not loaded)")
        self.lbl_ini_target.grid(row=0, column=1, sticky="w", padx=6)

        ttk.Button(ini_top, text="Load GameUserSettings.ini", command=self.load_gameusersettings).grid(row=0, column=2, padx=4)
        ttk.Button(ini_top, text="Load Game.ini", command=self.load_game_ini).grid(row=0, column=3, padx=4)
        ttk.Button(ini_top, text="Open Live + Staging", command=self.open_loaded_ini).grid(row=0, column=4, padx=4)
        ttk.Button(ini_top, text="Resync from Upstream", command=self._ini_resync_from_upstream).grid(row=0, column=5, padx=4)

        ttk.Label(ini_top, text="Filter").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ent_filter = ttk.Entry(ini_top, textvariable=self.var_ini_filter)
        ent_filter.grid(row=1, column=1, sticky="ew", padx=6, pady=(6, 0))
        ent_filter.bind("<KeyRelease>", lambda e: self._ini_refresh_tree())

        tree_frame = ttk.Frame(self.tab_ini)
        tree_frame.grid(row=2, column=0, sticky="nsew", padx=(0, 10))
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

        editor = ttk.LabelFrame(self.tab_ini, text="Edit Selected Line", padding=10)
        editor.grid(row=2, column=1, sticky="nsew")
        editor.columnconfigure(1, weight=1)

        ttk.Label(editor, text="Section").grid(row=0, column=0, sticky="w")
        ttk.Entry(editor, textvariable=self.var_ini_section, state="readonly").grid(row=0, column=1, sticky="ew", padx=6)

        ttk.Label(editor, text="Key").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(editor, textvariable=self.var_ini_key, state="readonly").grid(row=1, column=1, sticky="ew", padx=6, pady=(6, 0))

        ttk.Label(editor, text="Value").grid(row=2, column=0, sticky="w", pady=(10, 0))

        self.ent_ini_value = ttk.Entry(editor, textvariable=self.var_ini_value)
        self.cmb_ini_bool = ttk.Combobox(editor, textvariable=self.var_ini_bool, state="readonly", values=["True", "False"])

        self.ent_ini_value.grid(row=2, column=1, sticky="ew", padx=6, pady=(10, 0))
        self.cmb_ini_bool.grid_forget()

        self.scale_ini = ttk.Scale(editor, variable=self.var_ini_scale, from_=0.0, to=10.0, command=self._ini_scale_changed)
        self.scale_ini.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(10, 0))

        self.canvas_ticks = tk.Canvas(editor, height=14, highlightthickness=0)
        self.canvas_ticks.grid(row=4, column=0, columnspan=2, sticky="ew")

        btn_line = ttk.Frame(editor)
        btn_line.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        ttk.Button(btn_line, text="Delete Selected Line", command=self._ini_delete_selected).grid(row=0, column=0, sticky="w")

        ttk.Label(
            editor,
            text="Edits are staged and auto-saved.\n"
                 "On Start: staging is copied into the server folder.\n"
                 "On Stop (Safe): baseline is restored into the server folder.",
            wraplength=360
        ).grid(row=6, column=0, columnspan=2, sticky="w", pady=(12, 0))

        self.ent_ini_value.bind("<KeyRelease>", lambda e: self._ini_schedule_apply())
        self.cmb_ini_bool.bind("<<ComboboxSelected>>", lambda e: self._ini_schedule_apply())

        add_box = ttk.LabelFrame(self.tab_ini, text="Add / Append Line", padding=10)
        add_box.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        add_box.columnconfigure(1, weight=1)
        add_box.columnconfigure(3, weight=1)

        ttk.Label(add_box, text="Section").grid(row=0, column=0, sticky="w")
        ttk.Entry(add_box, textvariable=self.var_ini_add_section).grid(row=0, column=1, sticky="ew", padx=6)

        ttk.Label(add_box, text="Key").grid(row=0, column=2, sticky="w")
        ttk.Entry(add_box, textvariable=self.var_ini_add_key).grid(row=0, column=3, sticky="ew", padx=6)

        ttk.Label(add_box, text="Value").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(add_box, textvariable=self.var_ini_add_value).grid(row=1, column=1, columnspan=3, sticky="ew", padx=6, pady=(6, 0))

        add_btns = ttk.Frame(add_box)
        add_btns.grid(row=2, column=1, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Button(add_btns, text="Append Line (duplicate keys allowed)", command=self._ini_append_line).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(add_btns, text="Set/Replace First Occurrence", command=self._ini_set_line).grid(row=0, column=1)

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

        self.var_install_optional_certificates.set(bool(cfg.install_optional_certificates))

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
        """
        Enterprise fix:
        - Start from current self.cfg (deepcopy) so newly added config fields
          (or fields not yet bound to UI) are not lost on autosave.
        """
        cfg = copy.deepcopy(self.cfg) if isinstance(self.cfg, AppConfig) else AppConfig()
        cfg.schema_version = AppConfig().schema_version

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

        cfg.install_optional_certificates = bool(self.var_install_optional_certificates.get())

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

        if not isinstance(cfg.rcon_saved_commands, list) or not cfg.rcon_saved_commands:
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
            self.var_install_optional_certificates,
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
    # Dependencies (First Install)
    # ---------------------------------------------------------------------
    def _ensure_dependencies_first_install(self, logger: logging.Logger) -> None:
        v = vc14_x64_version()
        if v:
            logger.info(f"VC++ v14 x64 OK (Version={v})")
        else:
            logger.info("VC++ v14 x64 missing -> installing...")
            install_vcredist(logger)

        dx_reg = directx_registry_present()
        dx_legacy = has_directx_legacy()

        if dx_reg and dx_legacy:
            logger.info("DirectX legacy OK (registry + legacy DLLs detected)")
        else:
            logger.info(f"DirectX check: registry_present={dx_reg} legacy_dlls_present={dx_legacy} -> installing DirectX websetup...")
            install_directx_web(logger)

            if has_directx_legacy():
                logger.info("DirectX legacy OK (post-install)")
            else:
                logger.info("DirectX legacy still not detected after install. No reinstall loop. Check %WINDIR%\\Logs\\DirectX.log if needed.")

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

            if bool(self.cfg.install_optional_certificates):
                install_asa_certificates(self.logger)
            else:
                self.logger.info("Optional certificate install disabled (default).")

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

        # baseline MUST be refreshed right before applying staging
        ensure_baseline(self.app_base, server_dir, self.logger, refresh=True)

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
    # INI Editor (Enterprise)
    # ---------------------------------------------------------------------
    def _ini_load_target(self, target: str) -> None:
        self.cfg = self._collect_vars_to_cfg()
        self.store.save(self.cfg)

        server_dir = Path(self.cfg.server_dir)

        # Ensure baseline exists (but do not refresh here; editor should be non-destructive)
        ensure_dir(self.app_base / BASELINE_DIR_NAME / server_key_from_dir(server_dir))

        paths = ini_stage_paths(self.app_base, server_dir, target)

        # Critical: staging must sync from upstream (baseline if server running)
        ensure_ini_staging_synced(paths, server_running=self._is_server_running(), logger=self.logger)

        self._ini_loaded_target = target
        self._ini_paths_current = paths
        self._ini_doc = read_ini(paths.stage)

        if target == "gus":
            self.lbl_ini_target.configure(text=f"Editing STAGED GameUserSettings.ini  |  {paths.stage}")
        else:
            self.lbl_ini_target.configure(text=f"Editing STAGED Game.ini  |  {paths.stage}")

        # prefill add-section with current selection (or common default)
        if not self.var_ini_add_section.get().strip():
            self.var_ini_add_section.set("ServerSettings")

        self._ini_refresh_tree()

    def load_gameusersettings(self) -> None:
        self._ini_load_target("gus")

    def load_game_ini(self) -> None:
        self._ini_load_target("game")

    def open_loaded_ini(self) -> None:
        """
        Requirement:
        - Open Explorer for BOTH Live and Staging locations (file selected).
        """
        if not self._ini_paths_current:
            return
        paths = self._ini_paths_current
        open_in_explorer(paths.stage, select_file=True)
        open_in_explorer(paths.live, select_file=True)

    def _ini_resync_from_upstream(self) -> None:
        if not self._ini_paths_current:
            return
        ensure_ini_staging_synced(self._ini_paths_current, server_running=self._is_server_running(), logger=self.logger)
        self._ini_doc = read_ini(self._ini_paths_current.stage)
        self._ini_refresh_tree()
        self._set_status("INI resynced")

    def _ini_refresh_tree(self) -> None:
        self.tree_ini.delete(*self.tree_ini.get_children())
        self._ini_items_index.clear()

        if not self._ini_doc:
            return

        kv_by_section = self._ini_doc.kv_entries_by_section()
        filt = (self.var_ini_filter.get() or "").strip().lower()

        idx_to_iid: Dict[int, str] = {}
        selected_idx = self._ini_selected_line_idx

        # preserve insertion order
        for section, entries in kv_by_section.items():
            # filter entries
            visible: List[Tuple[int, str, str]] = []
            for idx, key, val in entries:
                hay = f"{section}\n{key}\n{val}".lower()
                if filt and filt not in hay:
                    continue
                visible.append((idx, key, val))

            if not visible:
                continue

            sec_iid = self.tree_ini.insert("", "end", text=f"[{section}]", values=("",))
            self.tree_ini.item(sec_iid, open=True)

            # count duplicates for display
            counts: Dict[str, int] = {}
            totals: Dict[str, int] = {}
            for _, k, _ in entries:
                totals[k.lower()] = totals.get(k.lower(), 0) + 1

            for idx, key, val in visible:
                k_l = key.lower()
                counts[k_l] = counts.get(k_l, 0) + 1
                label = key if totals.get(k_l, 0) <= 1 else f"{key} [{counts[k_l]}]"
                iid = self.tree_ini.insert(sec_iid, "end", text=label, values=(val,))
                self._ini_items_index[iid] = idx
                idx_to_iid[idx] = iid

        # restore selection if possible
        if selected_idx is not None and selected_idx in idx_to_iid:
            iid = idx_to_iid[selected_idx]
            try:
                self.tree_ini.selection_set(iid)
                self.tree_ini.see(iid)
            except Exception:
                pass

    def _ini_on_select(self) -> None:
        sel = self.tree_ini.selection()
        if not sel:
            return
        iid = sel[0]
        if iid not in self._ini_items_index:
            return
        idx = self._ini_items_index[iid]
        assert self._ini_doc is not None

        if not (0 <= idx < len(self._ini_doc.lines)):
            return
        line = self._ini_doc.lines[idx]
        if line.kind != "kv":
            return

        self._ini_selected_line_idx = idx
        self.var_ini_section.set(line.section)
        self.var_ini_key.set(line.key)

        # also prefill "add line" section with current section
        if line.section.strip():
            self.var_ini_add_section.set(line.section)

        val = line.value
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
        n = 11
        for i in range(n):
            x = int((w - 2) * (i / (n - 1))) + 1
            tick_h = 10 if i in (0, n - 1) or i == (n - 1) // 2 else 6
            self.canvas_ticks.create_line(x, h, x, h - tick_h)

    def _ini_scale_changed(self, _=None) -> None:
        if self._ini_selected_line_idx is None:
            return
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
        if not self._ini_doc or not self._ini_loaded_target or not self._ini_paths_current:
            return
        if self._ini_selected_line_idx is None:
            return

        if self.cmb_ini_bool.winfo_ismapped():
            val = self.var_ini_bool.get().strip()
        else:
            val = self.var_ini_value.get()

        self._ini_doc.update_value_at(self._ini_selected_line_idx, val)
        write_ini(self._ini_paths_current.stage, self._ini_doc)

        self._ini_refresh_tree()
        self._set_status("INI staged")

    def _ini_append_line(self) -> None:
        if not self._ini_doc or not self._ini_paths_current:
            return
        sec = self.var_ini_add_section.get().strip()
        key = self.var_ini_add_key.get().strip()
        val = self.var_ini_add_value.get()

        if not sec or not key:
            messagebox.showerror("INI", "Section and Key are required.")
            return

        idx = self._ini_doc.append_kv(sec, key, val)
        if idx < 0:
            return

        write_ini(self._ini_paths_current.stage, self._ini_doc)
        self._ini_selected_line_idx = idx
        self._ini_refresh_tree()
        self._set_status("INI line appended")

    def _ini_set_line(self) -> None:
        if not self._ini_doc or not self._ini_paths_current:
            return
        sec = self.var_ini_add_section.get().strip()
        key = self.var_ini_add_key.get().strip()
        val = self.var_ini_add_value.get()

        if not sec or not key:
            messagebox.showerror("INI", "Section and Key are required.")
            return

        self._ini_doc.set(sec, key, val)
        write_ini(self._ini_paths_current.stage, self._ini_doc)
        self._ini_refresh_tree()
        self._set_status("INI key set")

    def _ini_delete_selected(self) -> None:
        if not self._ini_doc or not self._ini_paths_current:
            return
        if self._ini_selected_line_idx is None:
            return

        idx = self._ini_selected_line_idx
        self._ini_doc.delete_at(idx)
        write_ini(self._ini_paths_current.stage, self._ini_doc)

        self._ini_selected_line_idx = None
        self.var_ini_section.set("")
        self.var_ini_key.set("")
        self.var_ini_value.set("")
        self.var_ini_bool.set("")
        self._ini_refresh_tree()
        self._set_status("INI line deleted")


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
