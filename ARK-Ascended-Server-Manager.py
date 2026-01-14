# ARK: Survival Ascended Dedicated Server Manager (Windows)
from __future__ import annotations

import base64
import contextlib
import ctypes
import copy
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from ctypes import wintypes
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import font as tkfont
from tkinter import ttk
import uuid

try:
    import winreg  # type: ignore
except Exception:
    winreg = None

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# =============================================================================
# GLOBALS
# =============================================================================

APP_NAME = "ARK: Survival Ascended Server Manager"
APP_USERMODEL_ID = "Ch4r0ne.ARKASAManager"

ARK_ASA_APP_ID = 2430930  # ASA Dedicated Server AppID

STEAMCMD_ZIP_URL = "https://steamcdn-a.akamaihd.net/client/installer/steamcmd.zip"
VC_REDIST_X64_URL = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
DXWEBSETUP_URL = "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe"

AMAZON_ROOT_CA1_URL = "https://www.amazontrust.com/repository/AmazonRootCA1.cer"
AMAZON_R2M02_URL = "https://crt.r2m02.amazontrust.com/r2m02.cer"

DEFAULT_STEAMCMD_DIR = r"C:\GameServer\SteamCMD"
DEFAULT_SERVER_DIR = r"C:\GameServer\ARK-Survival-Ascended-Server"

DEFAULT_MAP = "TheIsland_WP"
DEFAULT_SERVER_NAME = "default"
DEFAULT_PORT = 7777
DEFAULT_QUERY_PORT = 27015
DEFAULT_MAX_PLAYERS = 70

DEFAULT_RCON_HOST = "127.0.0.1"
DEFAULT_RCON_PORT = 27020

DOWNLOAD_TIMEOUT_SEC = 180
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
SERVERS_DIR_NAME = "servers"
LOCKS_DIR_NAME = "locks"
GLOBAL_CONFIG_NAME = "global.json"
LEGACY_CONFIG_NAME = "config.json"
SERVER_CONFIG_NAME = "server.json"
DISCORD_STATE_FILE_NAME = "discord_state.json"

LOG_LEVEL = logging.INFO

DIRECTX_LEGACY_DLLS = [
    "d3dx9_43.dll",
    "d3dx10_43.dll",
    "d3dx11_43.dll",
    "d3dcompiler_43.dll",
    "xinput1_3.dll",
]

GAMEUSERSETTINGS_REL = Path(r"ShooterGame\Saved\Config\WindowsServer\GameUserSettings.ini")
GAME_INI_REL = Path(r"ShooterGame\Saved\Config\WindowsServer\Game.ini")

THEME_COLORS = {
    "bg": "#f5f7fb",
    "surface": "#ffffff",
    "border": "#d7deea",
    "text": "#1f2937",
    "muted": "#6b7280",
    "accent": "#2563eb",
    "accent_dark": "#1d4ed8",
    "accent_light": "#e6eefc",
    "console_bg": "#0b1220",
    "console_fg": "#e2e8f0",
    "console_select": "#1e293b",
}

# =============================================================================
# PATH / ICON HELPERS
# =============================================================================

def resource_path(relative: str) -> str:
    base = getattr(sys, "_MEIPASS", None)  # type: ignore[name-defined]
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


def _set_tk_window_icon_from_ico(root: tk.Tk, ico_path: str) -> None:
    """
    Ensures icon is applied for the actual window (WM_SETICON), not only Tk metadata.
    This fixes cases where taskbar/window still shows generic icon.
    """
    if os.name != "nt":
        return

    try:
        hwnd = root.winfo_id()
        user32 = ctypes.windll.user32

        WM_SETICON = 0x0080
        ICON_SMALL = 0
        ICON_BIG = 1
        IMAGE_ICON = 1
        LR_LOADFROMFILE = 0x0010
        LR_DEFAULTSIZE = 0x0040

        hicon_small = user32.LoadImageW(None, ico_path, IMAGE_ICON, 16, 16, LR_LOADFROMFILE)
        hicon_big = user32.LoadImageW(None, ico_path, IMAGE_ICON, 32, 32, LR_LOADFROMFILE | LR_DEFAULTSIZE)

        if hicon_small:
            user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, hicon_small)
        if hicon_big:
            user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, hicon_big)
    except Exception:
        pass


def _set_tk_window_icon_from_exe(root: tk.Tk) -> None:
    """
    Fallback: Extract icon from the running EXE (PyInstaller onefile) and apply via WM_SETICON.
    """
    if os.name != "nt":
        return
    try:
        hwnd = root.winfo_id()
        user32 = ctypes.windll.user32
        shell32 = ctypes.windll.shell32

        WM_SETICON = 0x0080
        ICON_SMALL = 0
        ICON_BIG = 1

        exe_path = os.path.abspath(sys.executable)  # type: ignore[name-defined]

        large = (ctypes.c_void_p * 1)()
        small = (ctypes.c_void_p * 1)()

        n = shell32.ExtractIconExW(exe_path, 0, large, small, 1)
        if n <= 0:
            return

        if small[0]:
            user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, small[0])
        if large[0]:
            user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, large[0])
    except Exception:
        pass


def apply_window_icon(root: tk.Tk) -> None:
    """
    Priority:
      1) assets/app.ico (when running from sources or bundled as data)
      2) icon extracted from sys.executable (PyInstaller --icon)
    """
    ico = resource_path(r"assets\app.ico")
    try:
        if Path(ico).exists():
            root.iconbitmap(ico)
            _set_tk_window_icon_from_ico(root, ico)
        else:
            _set_tk_window_icon_from_exe(root)
    except Exception:
        _set_tk_window_icon_from_exe(root)


def configure_modern_theme(root: tk.Tk) -> None:
    style = ttk.Style()
    if "clam" in style.theme_names():
        style.theme_use("clam")

    default_font = tkfont.nametofont("TkDefaultFont")
    default_font.configure(family="Segoe UI", size=10)
    tkfont.nametofont("TkTextFont").configure(family="Segoe UI", size=10)
    tkfont.nametofont("TkHeadingFont").configure(family="Segoe UI Semibold", size=10)

    theme = THEME_COLORS
    root.configure(bg=theme["bg"])

    style.configure(
        ".",
        background=theme["bg"],
        foreground=theme["text"],
        bordercolor=theme["border"],
        lightcolor=theme["border"],
        darkcolor=theme["border"],
        troughcolor=theme["bg"],
        focuscolor=theme["accent"],
        borderwidth=1,
    )

    style.configure("TFrame", background=theme["bg"])
    style.configure("TLabel", background=theme["bg"], foreground=theme["text"])
    style.configure("TSeparator", background=theme["border"])

    style.configure("TLabelframe", background=theme["bg"], bordercolor=theme["border"])
    style.configure(
        "TLabelframe.Label",
        background=theme["bg"],
        foreground=theme["text"],
        font=("Segoe UI Semibold", 10),
    )

    style.configure(
        "TButton",
        background=theme["surface"],
        foreground=theme["text"],
        padding=(12, 6),
        relief="flat",
        borderwidth=1,
    )
    style.map(
        "TButton",
        background=[
            ("active", theme["accent_light"]),
            ("pressed", theme["accent_light"]),
            ("disabled", theme["bg"]),
        ],
        foreground=[("disabled", theme["muted"])],
    )

    style.configure(
        "TEntry",
        fieldbackground=theme["surface"],
        foreground=theme["text"],
        padding=4,
    )
    style.configure(
        "TCombobox",
        fieldbackground=theme["surface"],
        background=theme["surface"],
        foreground=theme["text"],
        padding=4,
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", theme["surface"])],
        foreground=[("readonly", theme["text"])],
        selectbackground=[("readonly", theme["accent_light"])],
    )

    style.configure("TCheckbutton", background=theme["bg"], foreground=theme["text"])
    style.configure("TRadiobutton", background=theme["bg"], foreground=theme["text"])
    style.configure("TScale", background=theme["bg"], troughcolor=theme["border"])

    style.configure("TNotebook", background=theme["bg"], borderwidth=0)
    style.configure(
        "TNotebook.Tab",
        background=theme["bg"],
        foreground=theme["muted"],
        padding=(14, 8),
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", theme["surface"])],
        foreground=[("selected", theme["text"])],
    )

    style.configure(
        "Treeview",
        background=theme["surface"],
        fieldbackground=theme["surface"],
        foreground=theme["text"],
        rowheight=24,
        bordercolor=theme["border"],
    )
    style.map(
        "Treeview",
        background=[("selected", theme["accent"])],
        foreground=[("selected", "#ffffff")],
    )
    style.configure(
        "Treeview.Heading",
        background=theme["bg"],
        foreground=theme["text"],
        relief="flat",
        padding=(8, 6),
    )

    style.configure(
        "Vertical.TScrollbar",
        background=theme["border"],
        troughcolor=theme["bg"],
        arrowcolor=theme["text"],
    )
    style.configure(
        "Horizontal.TScrollbar",
        background=theme["border"],
        troughcolor=theme["bg"],
        arrowcolor=theme["text"],
    )


def configure_dpi_awareness() -> None:
    if os.name != "nt":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def apply_tk_scaling(root: tk.Tk) -> None:
    try:
        dpi = root.winfo_fpixels("1i")
        scaling = max(1.0, dpi / 72.0)
        root.tk.call("tk", "scaling", scaling)
    except Exception:
        pass


def _scaled_dimension(root: tk.Tk, size: int) -> int:
    try:
        scaling = float(root.tk.call("tk", "scaling"))
    except Exception:
        scaling = 1.0
    return max(1, int(size * scaling))


def apply_min_window_size(root: tk.Tk, width: int, height: int) -> None:
    scaled_w = _scaled_dimension(root, width)
    scaled_h = _scaled_dimension(root, height)
    screen_w = root.winfo_screenwidth()
    screen_h = root.winfo_screenheight()
    root.minsize(min(scaled_w, screen_w), min(scaled_h, screen_h))


def apply_initial_window_geometry(root: tk.Tk, width: int, height: int) -> None:
    scaled_w = _scaled_dimension(root, width)
    scaled_h = _scaled_dimension(root, height)
    screen_w = root.winfo_screenwidth()
    screen_h = root.winfo_screenheight()
    target_w = min(scaled_w, int(screen_w * 0.95))
    target_h = min(scaled_h, int(screen_h * 0.9))
    root.geometry(f"{target_w}x{target_h}")

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
        exe = sys.executable  # type: ignore[name-defined]
        params = " ".join([f'"{a}"' for a in sys.argv[1:]])  # type: ignore[name-defined]
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return int(rc) > 32
    except Exception:
        return False


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def now_ts() -> str:
    return time.strftime("%Y-%m-%d_%H-%M-%S")


def format_duration(total_seconds: int) -> str:
    seconds = max(0, int(total_seconds))
    mins, sec = divmod(seconds, 60)
    hrs, mins = divmod(mins, 60)
    days, hrs = divmod(hrs, 24)
    if days > 0:
        return f"{days}d {hrs}h {mins}m"
    if hrs > 0:
        return f"{hrs}h {mins}m"
    return f"{mins}m {sec}s"


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
        os.startfile(str(path))  # type: ignore[attr-defined]
    except Exception:
        pass


def open_in_explorer(path: Path, select_file: bool = True) -> None:
    try:
        if os.name == "nt":
            if select_file and path.exists() and path.is_file():
                subprocess.Popen(["explorer.exe", "/select,", str(path)], creationflags=CREATE_NO_WINDOW)
                return
            target = path if path.is_dir() else path.parent
            ensure_dir(target)
            subprocess.Popen(["explorer.exe", str(target)], creationflags=CREATE_NO_WINDOW)
            return
    except Exception:
        pass


def _find_powershell() -> Optional[str]:
    if os.name != "nt":
        return None
    candidates = ["powershell.exe", "powershell", "pwsh.exe", "pwsh"]
    for c in candidates:
        try:
            p = subprocess.run(["where", c], capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
            if p.returncode == 0:
                return c
        except Exception:
            continue
    return "powershell.exe"


def _is_writable_dir(p: Path) -> bool:
    try:
        ensure_dir(p)
        t = p / f".write_test_{os.getpid()}_{int(time.time())}"
        t.write_text("ok", encoding="utf-8")
        t.unlink()
        return True
    except Exception:
        return False


def _portable_base_dir() -> Path:
    try:
        if getattr(sys, "frozen", False):  # type: ignore[name-defined]
            return Path(sys.executable).resolve().parent  # type: ignore[name-defined]
        return Path(__file__).resolve().parent
    except Exception:
        return Path.cwd()


def _programdata_base() -> Optional[Path]:
    if os.name != "nt":
        return None
    base = os.getenv("PROGRAMDATA") or r"C:\ProgramData"
    return Path(base) / APPDATA_DIR_NAME


def _appdata_base() -> Path:
    base = os.getenv("APPDATA") or str(Path.home())
    return Path(base) / APPDATA_DIR_NAME


def resolve_storage_root() -> Path:
    if os.name != "nt":
        user = _appdata_base()
        if _is_writable_dir(user):
            return user
        portable = _portable_base_dir() / APPDATA_DIR_NAME
        ensure_dir(portable)
        return portable

    shared = _programdata_base()
    if not shared:
        user = _appdata_base()
        if _is_writable_dir(user):
            return user
        portable = _portable_base_dir() / APPDATA_DIR_NAME
        ensure_dir(portable)
        return portable

    try:
        ensure_dir(shared)
    except Exception:
        user = _appdata_base()
        if _is_writable_dir(user):
            return user
        portable = _portable_base_dir() / APPDATA_DIR_NAME
        ensure_dir(portable)
        return portable

    if _is_writable_dir(shared):
        return shared

    if is_admin():
        ensure_programdata_acl(shared)
        if _is_writable_dir(shared):
            return shared

    raise PermissionError(
        f"Shared storage at {shared} is not writable. Admin rights are required to initialize shared storage."
    )


def ensure_programdata_acl(shared_root: Path, logger: Optional[logging.Logger] = None) -> None:
    if os.name != "nt" or not is_admin():
        return
    try:
        ensure_dir(shared_root)
        cmd = ["icacls", str(shared_root), "/grant", "Users:(OI)(CI)M", "/T", "/C"]
        subprocess.run(cmd, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        if logger:
            logger.info(f"Shared storage ACL ensured: {shared_root}")
    except Exception as e:
        if logger:
            logger.info(f"Shared storage ACL could not be ensured: {e}")


def run_quiet(cmd: List[str], cwd: Optional[Path] = None) -> Tuple[int, str]:
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
        return p.returncode, out.strip()
    except Exception as e:
        return 1, str(e)


def stream_process_output(
    cmd: List[str],
    logger: logging.Logger,
    cwd: Optional[Path] = None,
    timeout_s: int = 0,
    log_prefix: str = "",
) -> Tuple[int, str]:
    """
    Streams stdout/stderr live into logger (GUI + file) AND returns full combined output.
    Handles SteamCMD progress that uses carriage returns (\r).
    """
    logger.info(" ".join(cmd))
    p = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    assert p.stdout is not None

    start = time.time()
    buf = b""
    collected: List[str] = []
    last_line = ""
    last_emit_t = 0.0

    def emit(line: str) -> None:
        nonlocal last_line, last_emit_t
        s = line.strip("\r\n")
        if not s:
            return
        # light throttle for rapidly updating progress lines
        now = time.time()
        if s == last_line and (now - last_emit_t) < 0.25:
            return
        last_line = s
        last_emit_t = now
        msg = f"{log_prefix}{s}" if log_prefix else s
        collected.append(msg)
        logger.info(msg)

    while True:
        if timeout_s > 0 and (time.time() - start) > timeout_s:
            try:
                p.kill()
            except Exception:
                pass
            emit("Process timeout -> killed.")
            break

        chunk = p.stdout.read(4096)
        if not chunk:
            break

        buf += chunk
        # split on \n or \r to capture progress updates
        while True:
            m = re.search(br"[\r\n]", buf)
            if not m:
                break
            idx = m.start()
            line = buf[:idx]
            sep = buf[idx:idx+1]
            buf = buf[idx+1:]
            try:
                emit(line.decode("utf-8", errors="replace"))
            except Exception:
                pass
            if sep == b"\r":
                continue

    if buf:
        try:
            emit(buf.decode("utf-8", errors="replace"))
        except Exception:
            pass

    code = p.wait()
    return code, "\n".join(collected)


def server_root(app_base: Path, server_id: str) -> Path:
    return app_base / SERVERS_DIR_NAME / server_id


def server_config_path(app_base: Path, server_id: str) -> Path:
    return server_root(app_base, server_id) / SERVER_CONFIG_NAME


def server_lock_path(app_base: Path, server_id: str) -> Path:
    return server_root(app_base, server_id) / LOCKS_DIR_NAME / "server.lock"


def global_lock_path(app_base: Path) -> Path:
    return app_base / LOCKS_DIR_NAME / "global.lock"


def server_discord_state_path(app_base: Path, server_id: str) -> Path:
    return server_root(app_base, server_id) / DISCORD_STATE_FILE_NAME

# =============================================================================
# DOWNLOAD (urllib only)
# =============================================================================

def download_file(url: str, dest: Path, logger: logging.Logger, timeout: int = DOWNLOAD_TIMEOUT_SEC) -> None:
    ensure_dir(dest.parent)
    logger.info(f"Downloading: {url}")

    ctx = ssl.create_default_context()
    try:
        import certifi  # type: ignore
        ctx.load_verify_locations(cafile=certifi.where())
    except Exception:
        pass

    req = Request(url, headers={"User-Agent": "ARK-ASA-Manager/1.0"})
    with urlopen(req, timeout=timeout, context=ctx) as r:
        data = r.read()

    if not data:
        raise RuntimeError("Empty download response")

    atomic_write_bytes(dest, data)
    logger.info(f"Saved: {dest}")

# =============================================================================
# DPAPI (Discord secrets)
# =============================================================================

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob_from_bytes(data: bytes) -> DATA_BLOB:
    buf = (ctypes.c_byte * len(data)).from_buffer_copy(data)
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))


def dpapi_encrypt(plain: str) -> str:
    if os.name != "nt":
        raise RuntimeError("DPAPI is only available on Windows.")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    data_in = _blob_from_bytes(plain.encode("utf-8"))
    data_out = DATA_BLOB()
    flags = 0x4  # CRYPTPROTECT_LOCAL_MACHINE

    if not crypt32.CryptProtectData(ctypes.byref(data_in), None, None, None, None, flags, ctypes.byref(data_out)):
        raise RuntimeError("DPAPI encrypt failed.")

    try:
        out = ctypes.string_at(data_out.pbData, data_out.cbData)
        return base64.b64encode(out).decode("ascii")
    finally:
        kernel32.LocalFree(data_out.pbData)


def dpapi_decrypt(enc_b64: str) -> str:
    if os.name != "nt":
        raise RuntimeError("DPAPI is only available on Windows.")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    raw = base64.b64decode(enc_b64.encode("ascii"))
    data_in = _blob_from_bytes(raw)
    data_out = DATA_BLOB()

    if not crypt32.CryptUnprotectData(ctypes.byref(data_in), None, None, None, None, 0, ctypes.byref(data_out)):
        raise RuntimeError("DPAPI decrypt failed.")

    try:
        out = ctypes.string_at(data_out.pbData, data_out.cbData)
        return out.decode("utf-8", errors="replace")
    finally:
        kernel32.LocalFree(data_out.pbData)

# =============================================================================
# CONFIG
# =============================================================================

@dataclass
class ServerRef:
    id: str
    display_name: str
    server_dir: str


@dataclass
class GlobalConfig:
    schema_version: int = 1
    steamcmd_dir: str = DEFAULT_STEAMCMD_DIR
    last_selected_server_id: str = ""
    servers: List[ServerRef] = field(default_factory=list)


@dataclass
class AppConfig:
    schema_version: int = 10
    server_dir: str = DEFAULT_SERVER_DIR

    map_name: str = DEFAULT_MAP
    server_name: str = DEFAULT_SERVER_NAME

    port: int = DEFAULT_PORT
    query_port: int = DEFAULT_QUERY_PORT
    max_players: int = DEFAULT_MAX_PLAYERS

    server_platform: str = ""  # e.g. "PC+XSX+WINGDK" (moved to Advanced tab)

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
    backup_dir: str = ""
    backup_retention: int = 20
    backup_include_configs: bool = False

    auto_update_restart: bool = False
    auto_update_interval_min: int = 360

    install_optional_certificates: bool = True  # enforced True

    # Console noise filter (GUI only)
    hide_gameanalytics_console_logs: bool = True

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

    dino_mode: str = ""

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

    custom_start_args: str = ""

    discord_enable: bool = False
    discord_webhook_url: str = ""
    discord_webhook_url_enc: str = ""
    discord_poll_interval_sec: int = 300
    discord_notify_start: bool = True
    discord_notify_stop: bool = True
    discord_notify_join: bool = True
    discord_notify_leave: bool = False
    discord_notify_crash: bool = True
    discord_include_player_id: bool = False
    discord_mention_mode: str = "name"
    discord_mention_map_json: str = ""

    def normalized_mods(self) -> str:
        raw = (self.mods or "").strip()
        if not raw:
            return ""
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        return ",".join(parts)


@dataclass
class ConfigLoadResult:
    cfg: AppConfig
    migrated: bool
    warnings: List[str]

@dataclass
class GlobalConfigLoadResult:
    cfg: GlobalConfig
    migrated: bool
    warnings: List[str]


class ServerConfigStore:
    def __init__(self, path: Path, lock_path: Path):
        self.path = path
        self.lock_path = lock_path
        self._extra: Dict[str, Any] = {}

    def load(self) -> ConfigLoadResult:
        cfg = AppConfig()
        migrated = False
        warnings: List[str] = []

        if not self.path.exists():
            migrated = True
            return ConfigLoadResult(cfg=cfg, migrated=migrated, warnings=warnings)

        try:
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Config root is not a JSON object")
        except Exception as e:
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

        cfg.install_optional_certificates = True

        enc_webhook = (cfg.discord_webhook_url_enc or "").strip()
        if enc_webhook:
            try:
                cfg.discord_webhook_url = dpapi_decrypt(enc_webhook)
            except Exception:
                cfg.discord_webhook_url = ""
                warnings.append("Discord webhook could not be decrypted. Please re-enter the URL.")

        if not isinstance(cfg.rcon_saved_commands, list):
            cfg.rcon_saved_commands = ["SaveWorld", "DoExit", "ListPlayers", "DestroyWildDinos"]

        current_schema = AppConfig().schema_version
        if safe_int(getattr(cfg, "schema_version", 0), 0) != current_schema:
            cfg.schema_version = current_schema
            migrated = True

        for name in known.keys():
            if name not in data:
                migrated = True
                break

        return ConfigLoadResult(cfg=cfg, migrated=migrated, warnings=warnings)

    def save(self, cfg: AppConfig) -> None:
        with exclusive_file_lock(self.lock_path):
            ensure_dir(self.path.parent)
            base = asdict(cfg)
            webhook_raw = (cfg.discord_webhook_url or "").strip()
            if webhook_raw:
                try:
                    base["discord_webhook_url_enc"] = dpapi_encrypt(webhook_raw)
                except Exception as exc:
                    raise RuntimeError(f"Failed to encrypt Discord webhook URL: {exc}") from exc
            else:
                base["discord_webhook_url_enc"] = ""
            base["discord_webhook_url"] = ""
            for k, v in self._extra.items():
                if k not in base:
                    base[k] = v
            if self.path.exists():
                try:
                    bak = self.path.with_name(f"server.bak.{now_ts()}.json")
                    shutil.copy2(self.path, bak)
                except Exception:
                    pass
            atomic_write_text(self.path, json.dumps(base, indent=2), encoding="utf-8")

    def save_new(self, cfg: AppConfig) -> None:
        with exclusive_file_lock(self.lock_path):
            if self.path.exists():
                raise FileExistsError(str(self.path))
            ensure_dir(self.path.parent)
            base = asdict(cfg)
            atomic_write_text(self.path, json.dumps(base, indent=2), encoding="utf-8")


class GlobalConfigStore:
    def __init__(self, path: Path, lock_path: Path):
        self.path = path
        self.lock_path = lock_path
        self._extra: Dict[str, Any] = {}

    def load(self) -> GlobalConfigLoadResult:
        cfg = GlobalConfig()
        migrated = False
        warnings: List[str] = []

        if not self.path.exists():
            migrated = True
            return GlobalConfigLoadResult(cfg=cfg, migrated=migrated, warnings=warnings)

        try:
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Global config root is not a JSON object")
        except Exception as e:
            try:
                bad = self.path.with_name(f"global.corrupt.{now_ts()}.json")
                shutil.copy2(self.path, bad)
                warnings.append(f"Global config was corrupt -> copied to: {bad}")
            except Exception:
                warnings.append("Global config was corrupt -> could not copy quarantine file")
            migrated = True
            return GlobalConfigLoadResult(cfg=cfg, migrated=migrated, warnings=warnings)

        known = {"schema_version", "steamcmd_dir", "last_selected_server_id", "servers"}
        self._extra = {k: v for k, v in data.items() if k not in known}

        cfg.schema_version = safe_int(data.get("schema_version", cfg.schema_version), cfg.schema_version)
        cfg.steamcmd_dir = str(data.get("steamcmd_dir") or cfg.steamcmd_dir)
        cfg.last_selected_server_id = str(data.get("last_selected_server_id") or "")

        servers_raw = data.get("servers")
        if isinstance(servers_raw, list):
            for item in servers_raw:
                if not isinstance(item, dict):
                    continue
                sid = str(item.get("id") or "").strip()
                sdir = str(item.get("server_dir") or "").strip()
                if not sid or not sdir:
                    continue
                name = str(item.get("display_name") or sid).strip()
                cfg.servers.append(ServerRef(id=sid, display_name=name, server_dir=sdir))
        else:
            migrated = True

        if cfg.schema_version != GlobalConfig().schema_version:
            cfg.schema_version = GlobalConfig().schema_version
            migrated = True

        return GlobalConfigLoadResult(cfg=cfg, migrated=migrated, warnings=warnings)

    def save(self, cfg: GlobalConfig) -> None:
        with exclusive_file_lock(self.lock_path):
            ensure_dir(self.path.parent)
            base = asdict(cfg)
            for k, v in self._extra.items():
                if k not in base:
                    base[k] = v
            if self.path.exists():
                try:
                    bak = self.path.with_name(f"global.bak.{now_ts()}.json")
                    shutil.copy2(self.path, bak)
                except Exception:
                    pass
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


def has_directx_legacy(min_hits: int = 1) -> bool:
    if os.name != "nt":
        return False
    windir = os.environ.get("WINDIR", r"C:\Windows")
    candidates = [Path(windir) / "System32", Path(windir) / "SysWOW64"]
    hits = 0
    for folder in candidates:
        for dll in DIRECTX_LEGACY_DLLS:
            if (folder / dll).exists():
                hits += 1
    return hits >= min_hits


def install_vcredist(logger: logging.Logger) -> None:
    temp = Path(os.environ.get("TEMP", str(Path.home() / "AppData/Local/Temp")))
    exe = temp / "vc_redist.x64.exe"
    download_file(VC_REDIST_X64_URL, exe, logger)
    code, _ = stream_process_output([str(exe), "/install", "/passive", "/norestart"], logger)
    logger.info(f"VC++ installer exit code: {code}")


def install_directx_web(logger: logging.Logger) -> None:
    temp = Path(os.environ.get("TEMP", str(Path.home() / "AppData/Local/Temp")))
    exe = temp / "dxwebsetup.exe"
    download_file(DXWEBSETUP_URL, exe, logger)
    code, _ = stream_process_output([str(exe), "/Q"], logger)
    logger.info(f"DirectX web installer exit code: {code}")


def install_asa_certificates(logger: logging.Logger) -> None:
    """
    Mandatory:
    - Downloads AmazonRootCA1 + r2m02 and imports into Windows cert store.
    - PowerShell Import-Certificate (Defender friendlier than certutil).
    """
    if os.name != "nt":
        logger.info("Certificate install skipped: only supported on Windows.")
        return

    ps_exe = _find_powershell()
    if not ps_exe:
        raise RuntimeError("PowerShell not found; cannot import certificates.")

    temp = Path(os.environ.get("TEMP", str(Path.home() / "AppData/Local/Temp")))
    root_path = temp / f"AmazonRootCA1_{os.getpid()}.cer"
    r2m02_path = temp / f"r2m02_{os.getpid()}.cer"

    download_file(AMAZON_ROOT_CA1_URL, root_path, logger)
    download_file(AMAZON_R2M02_URL, r2m02_path, logger)

    if is_admin():
        root_store = r"Cert:\LocalMachine\Root"
        ca_store = r"Cert:\LocalMachine\CA"
        logger.info("Certificate import: LocalMachine store.")
    else:
        root_store = r"Cert:\CurrentUser\Root"
        ca_store = r"Cert:\CurrentUser\CA"
        logger.info("Certificate import: CurrentUser store (non-admin).")

    def import_cert(cer_path: Path, store: str) -> None:
        ps = f"Import-Certificate -FilePath '{str(cer_path)}' -CertStoreLocation '{store}' | Out-Null"
        code, out = run_quiet([ps_exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps])
        if code != 0:
            msg = out.splitlines()[-1].strip() if out else "unknown Import-Certificate error"
            raise RuntimeError(f"Import-Certificate failed for {cer_path.name} -> {store}: {msg}")

    logger.info("Installing certificates: AmazonRootCA1 -> Root, r2m02 -> CA")
    import_cert(root_path, root_store)
    import_cert(r2m02_path, ca_store)
    logger.info("Certificates installed/updated successfully.")

    try:
        root_path.unlink(missing_ok=True)  # type: ignore[arg-type]
        r2m02_path.unlink(missing_ok=True)  # type: ignore[arg-type]
    except Exception:
        pass

# =============================================================================
# SteamCMD canonical path + lock + runscript
# =============================================================================

@contextlib.contextmanager
def exclusive_file_lock(lock_path: Path, timeout_s: int = 900, poll_s: float = 0.25):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock_path, "a+", encoding="utf-8")
    start = time.time()

    if os.name == "nt":
        import msvcrt
        while True:
            try:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                if time.time() - start > timeout_s:
                    raise TimeoutError(f"Timeout waiting for lock: {lock_path}")
                time.sleep(poll_s)
        try:
            yield
        finally:
            try:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            finally:
                fh.close()
    else:
        try:
            yield
        finally:
            fh.close()


def resolve_steamcmd_exe(steamcmd_root: str) -> Path:
    root = Path(steamcmd_root)
    candidates = [
        root / "steamcmd.exe",
        root / "SteamCMD" / "steamcmd.exe",
        root / "steamcmd" / "steamcmd.exe",
    ]
    for p in candidates:
        if p.is_file():
            return p
    return candidates[0]


def safe_extract_zip(zip_path: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_real = dest_dir.resolve()

    with zipfile.ZipFile(zip_path, "r") as zf:
        for zi in zf.infolist():
            if zi.is_dir():
                continue
            target = (dest_dir / zi.filename).resolve()
            if not str(target).startswith(str(dest_real)):
                raise RuntimeError(f"Blocked unsafe zip path: {zi.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(zi, "r") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)


def ensure_steamcmd(steamcmd_root: str, logger: logging.Logger) -> Path:
    exe = resolve_steamcmd_exe(steamcmd_root)
    root = exe.parent
    ensure_dir(root)

    if exe.is_file():
        # verify it boots at least once
        code, _ = stream_process_output([str(exe), "+quit"], logger, cwd=root, log_prefix="[SteamCMD] ")
        if code in (0, 7, 8):
            # SteamCMD can return 7/8 during first bootstrap/self-update; treat as OK.
            if code != 0:
                logger.warning("[SteamCMD] boot returned exit=%s (bootstrap/self-update).", code)
            return exe
        logger.warning("[SteamCMD] steamcmd.exe exists but boot returned code=%s -> reinstalling", code)

    zip_path = root / "steamcmd.zip"
    try:
        if zip_path.exists():
            zip_path.unlink()
    except Exception:
        pass

    download_file(STEAMCMD_ZIP_URL, zip_path, logger)
    safe_extract_zip(zip_path, root)
    try:
        zip_path.unlink()
    except Exception:
        pass

    exe = resolve_steamcmd_exe(str(root))
    if not exe.is_file():
        raise FileNotFoundError(f"SteamCMD extraction failed: steamcmd.exe not found in {root}")

    # final boot (SteamCMD may self-update/bootstrap on first run and return non-zero transiently)
    code, _ = stream_process_output([str(exe), "+quit"], logger, cwd=root, log_prefix="[SteamCMD] ")
    if code != 0:
        # IMPORTANT: do NOT hard-fail here. Update/Validate succeeds moments later because SteamCMD stabilizes.
        # Also use f-string to avoid any logger %-formatting argument mismatch.
        logger.warning(f"[SteamCMD] boot returned exit={code} after fresh install (bootstrap/self-update). Continuing...")

    return exe


def unstick_install_dir(install_dir: Path, app_id: int, logger: logging.Logger) -> bool:
    steamapps = install_dir / "steamapps"
    manifest = steamapps / f"appmanifest_{app_id}.acf"
    downloading = steamapps / "downloading" / str(app_id)
    tempdir = steamapps / "temp"

    changed = False
    if manifest.exists():
        backup_dir = steamapps / "_repair_backup"
        backup_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        target = backup_dir / f"appmanifest_{app_id}.acf.{ts}.bak"
        try:
            os.chmod(manifest, stat.S_IWRITE)
        except Exception:
            pass
        shutil.move(str(manifest), str(target))
        logger.warning("[SteamCMD] Moved stale manifest -> %s", target)
        changed = True

    for p in [downloading, tempdir]:
        if p.exists():
            try:
                shutil.rmtree(p, ignore_errors=True)
                logger.warning("[SteamCMD] Removed stale folder -> %s", p)
                changed = True
            except Exception:
                pass

    return changed

def steamcmd_output_has_fatal(out: str) -> bool:
    """
    SteamCMD sometimes exits 0 but prints error text (rare).
    We treat the run as failed if strong fatal markers are present.
    """
    if not out:
        return False

    fatal_patterns = [
        r"\bERROR!\b",
        r"\bFAILED\b",
        r"Failed to install app",
        r"Invalid Password",
        r"No subscription",
        r"Login Failure",
        r"Timed out",
        r"Disk write failure",
        r"Missing file privileges",
    ]
    for pat in fatal_patterns:
        if re.search(pat, out, re.IGNORECASE):
            return True
    return False


def steamcmd_verify_install(install_dir: Path, app_id: int) -> bool:
    """
    Minimal verification that an update actually produced artifacts.
    """
    manifest = install_dir / "steamapps" / f"appmanifest_{app_id}.acf"
    exe = install_dir / "ShooterGame" / "Binaries" / "Win64" / "ArkAscendedServer.exe"
    return manifest.exists() or exe.exists()

def steamcmd_app_update(
    logger: logging.Logger,
    steamcmd_exe: Path,
    install_dir: Path,
    app_id: int,
    validate: bool,
    lock_root: Path,
    retries: int = 2,
) -> None:
    install_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_root / "locks" / "steamcmd.lock"

    with exclusive_file_lock(lock_path):
        # Warm-up (updates steamcmd itself / creates initial files)
        stream_process_output(
            [str(steamcmd_exe), "+quit"],
            logger,
            cwd=steamcmd_exe.parent,
            log_prefix="[SteamCMD] ",
        )

        for attempt in range(1, retries + 2):
            script_lines = [
                "@ShutdownOnFailedCommand 1",
                "@NoPromptForPassword 1",
                f'force_install_dir "{install_dir}"',
                "login anonymous",
                f"app_update {app_id}" + (" validate" if validate else ""),
                "quit",
                "",
            ]
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", encoding="utf-8") as tf:
                tf.write("\n".join(script_lines))
                script_path = Path(tf.name)

            try:
                code, out = stream_process_output(
                    [str(steamcmd_exe), "+runscript", str(script_path)],
                    logger,
                    cwd=steamcmd_exe.parent,
                    log_prefix="[SteamCMD] ",
                )
            finally:
                try:
                    script_path.unlink()
                except Exception:
                    pass

            # --------- NEW SUCCESS LOGIC ----------
            # ExitCode 0 is the primary success signal.
            # We only treat it as failure if strong fatal markers appear AND no install artifacts exist.
            if code == 0:
                if steamcmd_output_has_fatal(out) and not steamcmd_verify_install(install_dir, app_id):
                    logger.warning("[SteamCMD] exit=0 but fatal markers found and install not verified -> retrying.")
                else:
                    # Optional verification (keeps first install stable)
                    if steamcmd_verify_install(install_dir, app_id):
                        logger.info("[SteamCMD] app_update successful (verified).")
                        return

                    # On some systems, manifest/exe might appear slightly delayed -> short retry window
                    logger.warning("[SteamCMD] exit=0 but install not yet verified -> short wait and re-check.")
                    time.sleep(2.0)
                    if steamcmd_verify_install(install_dir, app_id):
                        logger.info("[SteamCMD] app_update successful (verified after delay).")
                        return

                    # Still not verified -> do one more attempt if available
                    if attempt < (retries + 1):
                        logger.warning("[SteamCMD] not verified yet -> retrying (attempt %s/%s).", attempt, retries + 1)
                        time.sleep(2.0 * attempt)
                        continue

                    raise RuntimeError("SteamCMD exit=0 but install could not be verified (no manifest/exe).")

            # --------- RETRYABLE FAILURES ----------
            retryable = False
            if code in (7, 8) or re.search(r"state is 0x6 after update job", out or "", re.IGNORECASE):
                retryable = True
                changed = unstick_install_dir(install_dir, app_id, logger)
                logger.warning(
                    "[SteamCMD] Retryable failure (exit=%s), self-heal changed=%s, attempt %s/%s",
                    code, changed, attempt, retries + 1
                )

            if code == 3221225477:
                retryable = True
                logger.warning("[SteamCMD] Crash (3221225477) -> reinstall SteamCMD + retry.")
                _ = ensure_steamcmd(str(steamcmd_exe.parent), logger)

            if retryable and attempt <= retries:
                time.sleep(3.0 * attempt)
                continue

            # --------- HARD FAIL ----------
            tail = "\n".join((out or "").splitlines()[-35:])
            raise RuntimeError(f"SteamCMD failed (exit={code}). Last output:\n{tail}")

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
                continue
        return True

    def kv_entries_by_section(self) -> Dict[str, List[Tuple[int, str, str]]]:
        out: Dict[str, List[Tuple[int, str, str]]] = {}
        for idx, line in enumerate(self.lines):
            if line.kind == "kv":
                out.setdefault(line.section, []).append((idx, line.key, line.value))
        return out

    def get_last_value_map(self) -> Dict[str, Dict[str, str]]:
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
    base_map = base.get_last_value_map()
    staged_map = staged.get_last_value_map()
    up_doc = upstream

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


def staging_paths(app_base: Path, server_id: str) -> Tuple[Path, Path]:
    root = server_root(app_base, server_id) / STAGING_DIR_NAME
    ensure_dir(root)
    return root / "GameUserSettings.ini", root / "Game.ini"


def ini_stage_paths(app_base: Path, server_id: str, server_dir: Path, target: str) -> IniStagePaths:
    live_gus = server_dir / GAMEUSERSETTINGS_REL
    live_game = server_dir / GAME_INI_REL

    baseline_root = server_root(app_base, server_id) / BASELINE_DIR_NAME
    baseline_gus = baseline_root / "GameUserSettings.ini"
    baseline_game = baseline_root / "Game.ini"

    stage_gus, stage_game = staging_paths(app_base, server_id)

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
    ensure_dir(paths.stage.parent)

    def log(msg: str) -> None:
        if logger:
            logger.info(msg)

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
        if upstream_exists:
            shutil.copy2(upstream, paths.stage)
            shutil.copy2(upstream, paths.stage_base)
            log(f"INI staging force-repaired from upstream: {paths.stage.name}")
        return

    if not paths.stage_base.exists():
        if upstream_exists:
            shutil.copy2(upstream, paths.stage_base)
            log(f"INI stage base created from upstream: {paths.stage_base.name}")
        else:
            shutil.copy2(paths.stage, paths.stage_base)
            log(f"INI stage base created from stage: {paths.stage_base.name}")

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

class RCONError(Exception):
    ...


class RCONAuthError(RCONError):
    ...


class RCONConnectionError(RCONError):
    ...


class RCONProtocolError(RCONError):
    ...


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
# DISCORD NOTIFICATIONS
# =============================================================================

def utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def validate_discord_webhook_url(url: str) -> None:
    cleaned = (url or "").strip()
    if not cleaned:
        raise ValueError("Discord webhook URL is empty.")

    parsed = urlparse(cleaned)
    if parsed.scheme.lower() != "https":
        raise ValueError("Discord webhook must use https://")

    host = (parsed.hostname or "").lower()
    allowed_hosts = {"discord.com", "ptb.discord.com", "canary.discord.com", "discordapp.com"}
    if host not in allowed_hosts:
        raise ValueError("Webhook host must be a Discord domain.")

    path = parsed.path or ""
    if not re.match(r"^/api/webhooks/\d+/.+", path):
        raise ValueError("Webhook path must look like /api/webhooks/<id>/<token>.")


def redact_webhook(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or "discord.com"
        match = re.match(r"^/api/webhooks/(\d+)/", parsed.path or "")
        webhook_id = match.group(1) if match else "unknown"
        return f"https://{host}/api/webhooks/{webhook_id}/[REDACTED]"
    except Exception:
        return "[REDACTED]"


class DiscordWebhookClient:
    def __init__(self, webhook_url: str, logger: logging.Logger, timeout: float = 8.0):
        self.webhook_url = webhook_url.strip()
        validate_discord_webhook_url(self.webhook_url)
        self.logger = logger
        self.timeout = timeout

    def post(self, payload: Dict[str, Any]) -> None:
        if not self.webhook_url:
            self.logger.info("[Discord] Webhook URL missing; send skipped.")
            return

        ctx = ssl.create_default_context()
        try:
            import certifi  # type: ignore
            ctx.load_verify_locations(cafile=certifi.where())
        except Exception:
            pass

        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "ARK-ASA-Manager/1.0"}

        def send_once() -> int:
            req = Request(self.webhook_url, data=data, headers=headers, method="POST")
            with urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return int(getattr(resp, "status", resp.getcode()))

        try:
            status = send_once()
            if status in (200, 204):
                return
            self.logger.info(f"[Discord] Webhook returned status {status}")
        except HTTPError as e:
            if int(getattr(e, "code", 0)) == 429:
                retry_after = e.headers.get("Retry-After") if e.headers else None
                try:
                    delay = float(retry_after) if retry_after else 0.0
                except Exception:
                    delay = 0.0
                if delay > 0:
                    self.logger.info(f"[Discord] Rate limited. Retrying in {delay:.1f}s.")
                    time.sleep(delay)
                try:
                    status = send_once()
                    if status not in (200, 204):
                        self.logger.info(f"[Discord] Webhook returned status {status} after retry.")
                except Exception as retry_err:
                    self.logger.info(
                        f"[Discord] Webhook retry failed ({redact_webhook(self.webhook_url)}): "
                        f"{type(retry_err).__name__}"
                    )
            else:
                self.logger.info(f"[Discord] Webhook error ({redact_webhook(self.webhook_url)}): HTTP {e.code}")
        except Exception as e:
            self.logger.info(
                f"[Discord] Webhook error ({redact_webhook(self.webhook_url)}): {type(e).__name__}"
            )


class PlayerListProvider:
    def __init__(self, rcon_fn: Callable[[str, float], str], logger: logging.Logger):
        self.rcon_fn = rcon_fn
        self.logger = logger
        self._patterns = [
            re.compile(r"^\s*\d+\.\s*(?P<name>.+?)[,;]\s*(?P<id>\d{6,20})\s*$"),
            re.compile(r"^\s*(?P<id>\d{6,20})\s*[,;]\s*(?P<name>.+?)\s*$"),
            re.compile(r"^\s*(?P<name>.+?)\s*[,;]\s*(?P<id>\d{6,20})\b.*$"),
        ]

    def get_players(self) -> Dict[str, Dict[str, str]]:
        raw = self.rcon_fn("ListPlayers", 6.0)
        if not raw:
            return {}

        players: Dict[str, Dict[str, str]] = {}
        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        for line in lines:
            if line.lower().startswith("player") and "count" in line.lower():
                continue
            if "no players" in line.lower():
                continue

            cleaned = re.sub(r"^\s*\d+\.\s*", "", line).strip()
            name = ""
            player_id = ""
            for pat in self._patterns:
                m = pat.match(cleaned)
                if m:
                    name = m.group("name").strip()
                    player_id = m.group("id").strip()
                    break

            if not player_id:
                m = re.search(r"\d{6,20}", cleaned)
                if m:
                    player_id = m.group(0)
                    name = cleaned.replace(player_id, "").strip(" ,;-")

            if not name:
                name = cleaned

            if player_id:
                key = player_id
            else:
                key = hashlib.sha1(name.encode("utf-8", errors="ignore")).hexdigest()

            players[key] = {"name": name, "id": player_id, "raw": line}

        return players


class DiscordStateStore:
    def __init__(self, state_path: Path, logger: logging.Logger):
        self.path = state_path
        self.logger = logger

    def load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except Exception as e:
            self.logger.info(f"[Discord] Failed to read state: {e}")
            return {}

    def save(self, state: Dict[str, Any]) -> None:
        try:
            ensure_dir(self.path.parent)
            atomic_write_text(self.path, json.dumps(state, indent=2), encoding="utf-8")
        except Exception as e:
            self.logger.info(f"[Discord] Failed to save state: {e}")


class DiscordNotificationCoordinator:
    ERROR_THROTTLE_SEC = 3600

    def __init__(self, state_path: Path, server_id: str, logger: logging.Logger, rcon_fn: Callable[[str, float], str]):
        self.server_id = server_id
        self.logger = logger
        self.state_store = DiscordStateStore(state_path, logger)
        self.player_provider = PlayerListProvider(rcon_fn, logger)
        self._cfg: Optional[AppConfig] = None
        self._webhook: Optional[DiscordWebhookClient] = None
        self._state_lock = threading.Lock()
        self._poll_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._server_instance_id: Optional[str] = None
        self._stop_requested = False

    def update_config(self, cfg: AppConfig) -> None:
        self._cfg = cfg
        if cfg.discord_enable and cfg.discord_webhook_url.strip():
            try:
                self._webhook = DiscordWebhookClient(cfg.discord_webhook_url, self.logger, timeout=8.0)
            except ValueError as exc:
                self._webhook = None
                self.logger.info(f"[Discord] Webhook URL invalid: {exc}")
        else:
            self._webhook = None
        if not (cfg.discord_notify_join or cfg.discord_notify_leave):
            self.stop_polling()

    @property
    def state_dir(self) -> Path:
        return self.state_store.path.parent

    def request_stop(self) -> None:
        self._stop_requested = True

    def start_instance(self, cfg: AppConfig, pid: int) -> None:
        self.update_config(cfg)
        instance_id = f"{utc_now_iso()}_pid{pid}"
        self._server_instance_id = instance_id
        self._stop_requested = False
        with self._state_lock:
            state = self.state_store.load()
            state["server_instance_id"] = instance_id
            state["server_started_ts"] = time.time()
            self.state_store.save(state)
        self._notify_start(cfg)

    def notify_stop(self, cfg: AppConfig, requested: bool, exit_code: Optional[int] = None) -> None:
        self.update_config(cfg)
        if requested:
            self._notify_stop(cfg)
        else:
            if self._stop_requested:
                return
            self._notify_crash(cfg, exit_code)

    def start_polling(self, cfg: AppConfig) -> None:
        self.update_config(cfg)
        if not cfg.discord_enable:
            return
        if not (cfg.discord_notify_join or cfg.discord_notify_leave):
            return
        if self._poll_thread and self._poll_thread.is_alive():
            return
        if not cfg.enable_rcon:
            return
        if not self._webhook:
            return
        self._stop_event.clear()
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def stop_polling(self) -> None:
        self._stop_event.set()

    def send_test(self, cfg: AppConfig) -> None:
        self.update_config(cfg)
        if not self._webhook:
            self.logger.info("[Discord] Webhook not configured; test skipped.")
            return
        payload = {
            "embeds": [
                {
                    "title": "🔔 Discord webhook test",
                    "description": "The ARK ASA Server Manager webhook is configured correctly.",
                    "color": 0x3498DB,
                    "timestamp": utc_now_iso(),
                    "footer": {"text": "ARK ASA Server Manager"},
                }
            ]
        }
        self._webhook.post(payload)

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            cfg = self._cfg
            if cfg:
                interval = max(60, int(cfg.discord_poll_interval_sec))
                self._poll_once(cfg)
            else:
                interval = 60

            deadline = time.time() + interval
            while time.time() < deadline:
                if self._stop_event.is_set():
                    return
                time.sleep(1)

    def _poll_once(self, cfg: AppConfig) -> None:
        if not cfg.discord_enable:
            return
        if not cfg.enable_rcon:
            return
        if not self._webhook:
            return

        try:
            current = self.player_provider.get_players()
        except Exception as e:
            self.logger.info(f"[Discord] RCON ListPlayers failed: {e}")
            self._maybe_notify_error(cfg, e)
            return

        with self._state_lock:
            state = self.state_store.load()
            previous = state.get("last_players", {})
            if not isinstance(previous, dict):
                previous = {}

            current_ids = set(current.keys())
            previous_ids = set(previous.keys())
            joined_ids = current_ids - previous_ids
            left_ids = previous_ids - current_ids

            if cfg.discord_notify_join and joined_ids:
                self._notify_player_change(cfg, current, joined_ids, joined=True)
            if cfg.discord_notify_leave and left_ids:
                self._notify_player_change(cfg, previous, left_ids, joined=False)

            state["last_players"] = current
            state["last_error_hash"] = ""
            state["last_error_notify_ts"] = 0
            self.state_store.save(state)

    def _load_mention_map(self, cfg: AppConfig) -> Dict[str, str]:
        raw = (cfg.discord_mention_map_json or "").strip()
        if not raw:
            return {}

        data: Dict[str, str] = {}
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                data = {str(k): str(v) for k, v in parsed.items()}
                return data
        except Exception:
            pass

        try:
            path = Path(raw)
            if path.exists() and path.is_file():
                parsed = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(parsed, dict):
                    data = {str(k): str(v) for k, v in parsed.items()}
        except Exception as e:
            self.logger.info(f"[Discord] Failed to load mention map: {e}")

        return data

    def _format_player_mention(self, cfg: AppConfig, player: Dict[str, str], mapping: Optional[Dict[str, str]] = None) -> str:
        name = player.get("name") or "Unknown"
        mode = (cfg.discord_mention_mode or "name").strip().lower()
        if mode == "none":
            return name
        if mode == "mapping":
            mapping = mapping if mapping is not None else self._load_mention_map(cfg)
            key = player.get("id") or ""
            target = mapping.get(key) if key else None
            if not target:
                target = mapping.get(name)
            if target:
                return f"<@{target}>"
        return f"**{name}**"

    def _server_context_fields(self, cfg: AppConfig) -> List[Dict[str, Any]]:
        mods = cfg.normalized_mods()
        mods_display = mods.split(",") if mods else []
        if len(mods_display) > 5:
            mods_display = mods_display[:5] + ["..."]

        return [
            {"name": "Server", "value": cfg.server_name or "default", "inline": True},
            {"name": "Map", "value": cfg.map_name or DEFAULT_MAP, "inline": True},
            {"name": "Game Port", "value": str(int(cfg.port)), "inline": True},
            {"name": "Query Port", "value": str(int(cfg.query_port)), "inline": True},
            {"name": "Max Players", "value": str(int(cfg.max_players)), "inline": True},
            {"name": "Mods", "value": ", ".join(mods_display) if mods_display else "None", "inline": False},
        ]

    def _notify_start(self, cfg: AppConfig) -> None:
        if not cfg.discord_notify_start or not self._webhook:
            return
        if not self._server_instance_id:
            return

        with self._state_lock:
            state = self.state_store.load()
            if state.get("last_start_sent_instance") == self._server_instance_id:
                return
            state["last_start_sent_instance"] = self._server_instance_id
            self.state_store.save(state)

        payload = {
            "embeds": [
                {
                    "title": "🟢 Server started",
                    "description": f"{cfg.server_name or 'default'} is now online.",
                    "color": 0x2ECC71,
                    "fields": self._server_context_fields(cfg),
                    "timestamp": utc_now_iso(),
                    "footer": {"text": "ARK ASA Server Manager"},
                }
            ]
        }
        self._webhook.post(payload)

    def _notify_stop(self, cfg: AppConfig) -> None:
        if not cfg.discord_notify_stop or not self._webhook:
            return
        if not self._server_instance_id:
            return

        with self._state_lock:
            state = self.state_store.load()
            if state.get("last_stop_sent_instance") == self._server_instance_id:
                return
            state["last_stop_sent_instance"] = self._server_instance_id
            self.state_store.save(state)

        payload = {
            "embeds": [
                {
                    "title": "🛑 Server stopped",
                    "description": f"{cfg.server_name or 'default'} has been stopped.",
                    "color": 0xE74C3C,
                    "fields": self._stop_fields(state),
                    "timestamp": utc_now_iso(),
                    "footer": {"text": "ARK ASA Server Manager"},
                }
            ]
        }
        self._webhook.post(payload)

    def _notify_crash(self, cfg: AppConfig, exit_code: Optional[int]) -> None:
        if not cfg.discord_notify_crash or not self._webhook:
            return
        if not self._server_instance_id:
            return

        with self._state_lock:
            state = self.state_store.load()
            if state.get("last_crash_sent_instance") == self._server_instance_id:
                return
            state["last_crash_sent_instance"] = self._server_instance_id
            self.state_store.save(state)

        fields = self._stop_fields(state)
        if exit_code is not None:
            fields.append({"name": "Exit Code", "value": str(exit_code), "inline": True})

        payload = {
            "embeds": [
                {
                    "title": "💥 Server exited",
                    "description": f"{cfg.server_name or 'default'} exited unexpectedly.",
                    "color": 0xF39C12,
                    "fields": fields,
                    "timestamp": utc_now_iso(),
                    "footer": {"text": "ARK ASA Server Manager"},
                }
            ]
        }
        self._webhook.post(payload)

    def _stop_fields(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        fields: List[Dict[str, Any]] = []
        started = state.get("server_started_ts")
        if isinstance(started, (int, float)):
            uptime = max(0, int(time.time() - float(started)))
            fields.append({"name": "Uptime", "value": format_duration(uptime), "inline": True})
        return fields

    def _notify_player_change(
        self,
        cfg: AppConfig,
        player_data: Dict[str, Dict[str, str]],
        player_ids: set,
        joined: bool,
    ) -> None:
        if not self._webhook:
            return
        title = "✅ Player joined" if joined else "👋 Player left"
        color = 0x2ECC71 if joined else 0x95A5A6

        mapping = self._load_mention_map(cfg) if cfg.discord_mention_mode == "mapping" else None
        mentions = [self._format_player_mention(cfg, player_data[player_id], mapping) for player_id in player_ids]
        online_now = len(player_data) if joined else max(0, len(player_data) - len(player_ids))

        if len(mentions) > 5:
            description = "\n".join(mentions)
            embed = {
                "title": title,
                "description": description,
                "color": color,
                "fields": [{"name": "Online now", "value": str(online_now), "inline": True}],
                "timestamp": utc_now_iso(),
                "footer": {"text": "ARK ASA Server Manager"},
            }
            self._webhook.post({"embeds": [embed]})
            return

        for player_id in player_ids:
            player = player_data[player_id]
            mention = self._format_player_mention(cfg, player, mapping)
            fields = [{"name": "Online now", "value": str(online_now), "inline": True}]
            if cfg.discord_include_player_id and player.get("id"):
                fields.append({"name": "Player ID", "value": player["id"], "inline": True})
            embed = {
                "title": title,
                "description": f"{mention} {'joined' if joined else 'left'} the server.",
                "color": color,
                "fields": fields,
                "timestamp": utc_now_iso(),
                "footer": {"text": "ARK ASA Server Manager"},
            }
            self._webhook.post({"embeds": [embed]})

    def _maybe_notify_error(self, cfg: AppConfig, error: Exception) -> None:
        if not self._webhook:
            return

        # --- PATCH: RCON Discord notify
        STAGE_INTERVAL_SEC = 300
        REQUIRED_STAGES = 3
        STALE_RESET_SEC = 900
        POST_NOTIFY_THROTTLE_SEC = 1800

        now = time.time()
        with self._state_lock:
            state = self.state_store.load()

            last_notify = state.get("rcon_last_notify_ts", 0)
            if isinstance(last_notify, (int, float)) and now - float(last_notify) < POST_NOTIFY_THROTTLE_SEC:
                return

            last_seen = state.get("rcon_last_seen_ts", 0)
            if isinstance(last_seen, (int, float)) and now - float(last_seen) > STALE_RESET_SEC:
                state.pop("rcon_stage_count", None)
                state.pop("rcon_stage_last_ts", None)

            state["rcon_last_seen_ts"] = now

            stage_count = int(state.get("rcon_stage_count", 0) or 0)
            stage_last_ts = float(state.get("rcon_stage_last_ts", 0) or 0)

            if stage_count == 0:
                state["rcon_stage_count"] = 1
                state["rcon_stage_last_ts"] = now
                self.state_store.save(state)
                return

            if now - stage_last_ts < STAGE_INTERVAL_SEC:
                self.state_store.save(state)
                return

            stage_count += 1
            state["rcon_stage_count"] = stage_count
            state["rcon_stage_last_ts"] = now

            if stage_count < REQUIRED_STAGES:
                self.state_store.save(state)
                return

            state["rcon_last_notify_ts"] = now
            state.pop("rcon_stage_count", None)
            state.pop("rcon_stage_last_ts", None)
            self.state_store.save(state)

        err_hash = hashlib.sha1(str(error).encode("utf-8", errors="ignore")).hexdigest()
        now = time.time()
        with self._state_lock:
            state = self.state_store.load()
            last_hash = state.get("last_error_hash", "")
            last_ts = state.get("last_error_notify_ts", 0)
            if err_hash == last_hash and isinstance(last_ts, (int, float)) and now - float(last_ts) < self.ERROR_THROTTLE_SEC:
                return
            state["last_error_hash"] = err_hash
            state["last_error_notify_ts"] = now
            self.state_store.save(state)

        payload = {
            "embeds": [
                {
                    "title": "⚠️ RCON polling error",
                    "description": str(error),
                    "color": 0xE67E22,
                    "timestamp": utc_now_iso(),
                    "footer": {"text": "ARK ASA Server Manager"},
                }
            ]
        }
        self._webhook.post(payload)

# =============================================================================
# SERVER OPS
# =============================================================================

def ark_server_exe(server_dir: Path) -> Path:
    return server_dir / "ShooterGame" / "Binaries" / "Win64" / "ArkAscendedServer.exe"


def server_saved_dir(server_dir: Path) -> Path:
    return server_dir / "ShooterGame" / "Saved"


def server_config_dir(server_dir: Path) -> Path:
    return server_dir / "ShooterGame" / "Saved" / "Config" / "WindowsServer"


def split_custom_start_args(raw: str) -> List[str]:
    cleaned = (raw or "").strip()
    if not cleaned:
        return []
    try:
        parts = shlex.split(cleaned, posix=False)
    except ValueError:
        parts = cleaned.split()
    return [p for p in parts if p]


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
    ]

    if cfg.server_platform.strip():
        url_args.append(f"ServerPlatform={cfg.server_platform.strip()}")

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
        
    flags.append(f"-WinLiveMaxPlayers={int(cfg.max_players)}")

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

    flags.extend(split_custom_start_args(cfg.custom_start_args))

    return [str(exe), url, *flags]

# =============================================================================
# BASELINE / STAGING APPLY
# =============================================================================

def ensure_baseline(app_base: Path, server_id: str, server_dir: Path, logger: logging.Logger, refresh: bool = True) -> Path:
    base = server_root(app_base, server_id) / BASELINE_DIR_NAME
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


def apply_staging_to_server(app_base: Path, server_id: str, server_dir: Path, logger: logging.Logger) -> None:
    stage_gus, stage_game = staging_paths(app_base, server_id)
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


def restore_baseline_to_server(app_base: Path, server_id: str, server_dir: Path, logger: logging.Logger) -> None:
    base_root = server_root(app_base, server_id) / BASELINE_DIR_NAME
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


def ensure_required_server_settings(
    cfg: AppConfig,
    app_base: Path,
    server_id: str,
    server_dir: Path,
    logger: logging.Logger,
) -> None:
    ensure_dir((server_dir / GAMEUSERSETTINGS_REL).parent)

    # Stage GUS
    paths_gus = ini_stage_paths(app_base, server_id, server_dir, "gus")
    ensure_ini_staging_synced(paths_gus, server_running=False, logger=logger)
    doc_gus = read_ini(paths_gus.stage)

    # Password/RCON in [ServerSettings]
    sec_server = "ServerSettings"
    doc_gus.set(sec_server, "ServerAdminPassword", (cfg.admin_password or "").strip())
    doc_gus.set(sec_server, "ServerPassword", (cfg.join_password or "").strip())

    if cfg.enable_rcon:
        doc_gus.set(sec_server, "RCONEnabled", "True")
        doc_gus.set(sec_server, "RCONPort", str(int(cfg.rcon_port)))
    else:
        doc_gus.set(sec_server, "RCONEnabled", "False")

    # SessionSettings
    sec_session = "/Script/Engine.GameSession"
    doc_gus.set(sec_session, "SessionName", (cfg.server_name or DEFAULT_SERVER_NAME).strip())
    doc_gus.set(sec_session, "MaxPlayers", str(int(cfg.max_players)))

    write_ini(paths_gus.stage, doc_gus)
    logger.info("Staged GameUserSettings.ini (Admin/Join/RCON/SessionName/MaxPlayers).")

    # Stage Game.ini (critical for MaxPlayers)
    paths_game = ini_stage_paths(app_base, server_id, server_dir, "game")
    ensure_ini_staging_synced(paths_game, server_running=False, logger=logger)
    doc_game = read_ini(paths_game.stage)

    doc_game.set("/Script/Engine.GameSession", "MaxPlayers", str(int(cfg.max_players)))
    write_ini(paths_game.stage, doc_game)
    logger.info("Staged Game.ini (/Script/Engine.GameSession MaxPlayers).")

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
        self._drop_predicate: Callable[[str], bool] = lambda _msg: False

    def set_drop_predicate(self, pred: Callable[[str], bool]) -> None:
        self._drop_predicate = pred or (lambda _msg: False)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            raw_msg = record.getMessage()
            if self._drop_predicate(raw_msg):
                return
        except Exception:
            pass

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


def build_logger(log_dir: Path, text_widget: tk.Text) -> Tuple[logging.Logger, TkTextHandler]:
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

    return logger, h_gui

# =============================================================================
# APP
# =============================================================================

class ServerManagerApp:
    def __init__(self, root: tk.Tk, app_base: Path):
        self.root = root
        self.root.title(APP_NAME)
        apply_min_window_size(self.root, 1220, 780)

        self.app_base = app_base
        self.global_config_path = self.app_base / GLOBAL_CONFIG_NAME
        self.log_dir = self.app_base / LOG_DIR_NAME

        self.global_store = GlobalConfigStore(self.global_config_path, global_lock_path(self.app_base))
        global_res = self.global_store.load()
        self.global_cfg = global_res.cfg
        self._global_migrated = global_res.migrated
        self._global_warnings = global_res.warnings

        self.active_server_id: str = ""
        self.server_store: Optional[ServerConfigStore] = None
        self.cfg = AppConfig()
        self._server_migrated = False
        self._server_warnings: List[str] = []

        self._initialize_profiles()

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

        # -------------------------
        # RCON FIX (runtime snapshot)
        # Prevents "Authentication failed" when user edits AdminPassword/Host/Port in GUI
        # while the server is already running (server still uses the old values).
        # -------------------------
        self._runtime_rcon_host: Optional[str] = None
        self._runtime_rcon_port: Optional[int] = None
        self._runtime_rcon_password: Optional[str] = None

        self._discord_coordinator: Optional[DiscordNotificationCoordinator] = None
        self._discord_server_id: Optional[str] = None

        # Console noise filter state (GUI only)
        self._suppress_ga_console: bool = True

        # INI editor state
        self._ini_loaded_target: Optional[str] = None
        self._ini_doc: Optional[IniDocument] = None
        self._ini_items_index: Dict[str, int] = {}
        self._ini_apply_after_id: Optional[str] = None
        self._ini_selected_line_idx: Optional[int] = None
        self._ini_paths_current: Optional[IniStagePaths] = None

        self._server_id_order: List[str] = []

        self._init_vars()
        self._build_layout()
        self._apply_text_theme()
        self.root.after(0, self._apply_text_theme)
        self._refresh_server_selector(self.active_server_id)

        self.logger, self._gui_log_handler = build_logger(self.log_dir, self.txt_log)
        self._gui_log_handler.set_drop_predicate(self._drop_console_message)
        self._sync_console_log_filter_state()
        self._write_banner()

        shared = _programdata_base()
        if shared:
            ensure_programdata_acl(shared, self.logger)

        for w in self._global_warnings:
            self.logger.info(f"[CONFIG] {w}")
        for w in self._server_warnings:
            self.logger.info(f"[CONFIG] {w}")
        if self._global_migrated:
            try:
                self.global_store.save(self.global_cfg)
                self.logger.info("[CONFIG] Migrated/initialized global config saved.")
            except Exception as e:
                self.logger.info(f"[CONFIG] Save after global migration failed: {e}")
        if self._server_migrated and self.server_store:
            try:
                self.server_store.save(self.cfg)
                self.logger.info("[CONFIG] Migrated/initialized server config saved.")
            except Exception as e:
                self.logger.info(f"[CONFIG] Save after server migration failed: {e}")

        self._autosave_guard = True
        self._apply_global_cfg_to_vars(self.global_cfg)
        self._apply_cfg_to_vars(self.cfg)
        self._autosave_guard = False

        self._sync_map_mode()
        self._hook_autosave()
        self._refresh_buttons()
        self._sync_auto_update_scheduler()

    # ---------------------------------------------------------------------
    # Profile / config init
    # ---------------------------------------------------------------------
    def _initialize_profiles(self) -> None:
        legacy_path = self.app_base / LEGACY_CONFIG_NAME
        if not self.global_config_path.exists() and legacy_path.exists():
            self._migrate_legacy_config(legacy_path)
            return

        if not self.global_cfg.servers:
            self._create_default_server_profile()
            return

        self._select_active_server_from_global()

    def _migrate_legacy_config(self, legacy_path: Path) -> None:
        try:
            raw = json.loads(legacy_path.read_text(encoding="utf-8"))
        except Exception:
            raw = {}

        steamcmd_dir = str(raw.get("steamcmd_dir") or DEFAULT_STEAMCMD_DIR) if isinstance(raw, dict) else DEFAULT_STEAMCMD_DIR

        legacy_store = ServerConfigStore(legacy_path, self.app_base / LOCKS_DIR_NAME / "legacy.lock")
        legacy_res = legacy_store.load()
        self._server_warnings.extend(legacy_res.warnings)

        server_cfg = legacy_res.cfg
        server_id = str(uuid.uuid4())
        server_dir = server_cfg.server_dir or DEFAULT_SERVER_DIR
        display_name = server_cfg.server_name or "Server 1"

        server_ref = ServerRef(id=server_id, display_name=display_name, server_dir=server_dir)
        self.global_cfg = GlobalConfig(
            steamcmd_dir=steamcmd_dir,
            last_selected_server_id=server_id,
            servers=[server_ref],
        )
        self._global_migrated = True

        server_cfg.server_dir = server_dir
        server_store = ServerConfigStore(server_config_path(self.app_base, server_id), server_lock_path(self.app_base, server_id))
        try:
            server_store.save_new(server_cfg)
            self._server_migrated = True
        except FileExistsError:
            existing = server_store.load()
            server_cfg = existing.cfg
            self._server_migrated = existing.migrated
            self._server_warnings.extend(existing.warnings)

        self.server_store = server_store
        self.cfg = server_cfg
        self.active_server_id = server_id

    def _create_default_server_profile(self) -> None:
        server_id = str(uuid.uuid4())
        cfg = AppConfig()
        server_ref = ServerRef(id=server_id, display_name="Server 1", server_dir=cfg.server_dir)
        self.global_cfg.servers.append(server_ref)
        self.global_cfg.last_selected_server_id = server_id
        self._global_migrated = True

        self.server_store = ServerConfigStore(server_config_path(self.app_base, server_id), server_lock_path(self.app_base, server_id))
        try:
            self.server_store.save_new(cfg)
            self._server_migrated = True
        except FileExistsError:
            pass
        self.cfg = cfg
        self.active_server_id = server_id

    def _select_active_server_from_global(self) -> None:
        server_ids = [ref.id for ref in self.global_cfg.servers]
        if not server_ids:
            self._create_default_server_profile()
            return

        selected = self.global_cfg.last_selected_server_id
        if selected not in server_ids:
            selected = server_ids[0]
            self.global_cfg.last_selected_server_id = selected
            self._global_migrated = True

        self.active_server_id = selected
        self._load_active_server_config(selected)

    def _load_active_server_config(self, server_id: str) -> None:
        ref = self._server_ref_by_id(server_id)
        if not ref:
            self._create_default_server_profile()
            return

        store = ServerConfigStore(server_config_path(self.app_base, server_id), server_lock_path(self.app_base, server_id))
        res = store.load()
        cfg = res.cfg
        self._server_migrated = res.migrated
        self._server_warnings = res.warnings

        if ref.server_dir:
            cfg.server_dir = ref.server_dir
        elif cfg.server_dir:
            ref.server_dir = cfg.server_dir
            self._global_migrated = True

        self.server_store = store
        self.cfg = cfg

    def _server_ref_by_id(self, server_id: str) -> Optional[ServerRef]:
        for ref in self.global_cfg.servers:
            if ref.id == server_id:
                return ref
        return None

    def _server_dir_in_use(self, server_dir: str, exclude_id: Optional[str] = None) -> bool:
        for ref in self.global_cfg.servers:
            if exclude_id and ref.id == exclude_id:
                continue
            if ref.server_dir.strip().lower() == server_dir.strip().lower():
                return True
        return False

    def _udp_port_free(self, port: int, host: str = "0.0.0.0") -> bool:
        if not (1 <= port <= 65535):
            return False
        try:
            with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                else:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                sock.bind((host, port))
            return True
        except OSError:
            return False

    def _tcp_port_free(self, port: int, host: str = "0.0.0.0") -> bool:
        if not (1 <= port <= 65535):
            return False
        try:
            with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                else:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                sock.bind((host, port))
                sock.listen(1)
            return True
        except OSError:
            return False

    def _read_profile_ports(self, server_id: str) -> Tuple[Optional[int], Optional[int], Optional[int]]:
        try:
            cfg_path = server_config_path(self.app_base, server_id)
            if not cfg_path.exists():
                return None, None, None

            data = json.loads(cfg_path.read_text(encoding="utf-8"))

            def _get_int(*keys: str) -> Optional[int]:
                for key in keys:
                    value = data.get(key)
                    if isinstance(value, int):
                        return value
                    if isinstance(value, str) and value.isdigit():
                        return int(value)
                return None

            game = _get_int("port", "game_port", "gamePort")
            query = _get_int("query_port", "queryPort")
            rcon = _get_int("rcon_port", "rconPort")
            return game, query, rcon
        except Exception:
            return None, None, None

    def _collect_used_ports(self, ignore_server_id: Optional[str] = None) -> Set[int]:
        used: Set[int] = set()
        for ref in getattr(self.global_cfg, "servers", []):
            sid = getattr(ref, "id", None)
            if not sid or sid == ignore_server_id:
                continue
            game, query, rcon = self._read_profile_ports(sid)
            for port in (game, query, rcon):
                if isinstance(port, int):
                    used.add(port)
        return used

    def auto_assign_ports(
        self,
        cfg: AppConfig,
        *,
        stride: int = 10,
        max_tries: int = 200,
        ignore_server_id: Optional[str] = None,
    ) -> Tuple[int, int, int]:
        used = self._collect_used_ports(ignore_server_id=ignore_server_id)

        base_game = int(getattr(cfg, "port", 0) or DEFAULT_PORT)
        base_query = int(getattr(cfg, "query_port", 0) or DEFAULT_QUERY_PORT)
        base_rcon = int(getattr(cfg, "rcon_port", 0) or DEFAULT_RCON_PORT)

        def _block_ok(game: int, query: int, rcon: int) -> bool:
            if game in used or query in used or rcon in used:
                return False
            if len({game, query, rcon}) != 3:
                return False
            if not self._udp_port_free(game):
                return False
            if not self._udp_port_free(query):
                return False
            if not self._tcp_port_free(rcon):
                return False
            return True

        if _block_ok(base_game, base_query, base_rcon):
            cfg.port = base_game
            cfg.query_port = base_query
            cfg.rcon_port = base_rcon
            return base_game, base_query, base_rcon

        for n in range(1, max_tries + 1):
            game = base_game + n * stride
            query = base_query + n * stride
            rcon = base_rcon + n * stride

            if max(game, query, rcon) > 65535:
                break

            if _block_ok(game, query, rcon):
                cfg.port = game
                cfg.query_port = query
                cfg.rcon_port = rcon
                return game, query, rcon

        raise RuntimeError(
            "No free port block found "
            f"(base={base_game}/{base_query}/{base_rcon}, stride={stride}, tries={max_tries})."
        )

    def _save_active_server_config(self, cfg: AppConfig) -> None:
        if not self.server_store:
            raise RuntimeError("Server config store not initialized.")

        ref = self._server_ref_by_id(self.active_server_id)
        if not ref:
            raise RuntimeError("Active server profile is missing.")

        if self._server_dir_in_use(cfg.server_dir, exclude_id=self.active_server_id):
            # Shared install directory across profiles is allowed.
            # Ensure ports are unique per profile.
            pass

        self.server_store.save(cfg)
        if ref and ref.server_dir != cfg.server_dir:
            ref.server_dir = cfg.server_dir
            self.global_store.save(self.global_cfg)

    def _save_global_config(self, cfg: Optional[GlobalConfig] = None) -> None:
        self.global_cfg = cfg or self.global_cfg
        self.global_store.save(self.global_cfg)

    # ---------------------------------------------------------------------
    # Profile actions
    # ---------------------------------------------------------------------
    def _refresh_server_selector(self, selected_id: Optional[str] = None) -> None:
        refs = self.global_cfg.servers
        self._server_id_order = [ref.id for ref in refs]
        labels = [ref.display_name or ref.id for ref in refs]
        try:
            self.cmb_server_profile.configure(values=labels)
        except Exception:
            pass

        if not refs:
            self.var_server_profile.set("")
            return

        target_id = selected_id or self.active_server_id or refs[0].id
        if target_id not in self._server_id_order:
            target_id = refs[0].id

        idx = self._server_id_order.index(target_id)
        try:
            self.cmb_server_profile.current(idx)
        except Exception:
            self.var_server_profile.set(labels[idx])

    def _on_server_profile_selected(self) -> None:
        try:
            idx = self.cmb_server_profile.current()
        except Exception:
            return
        if idx < 0 or idx >= len(getattr(self, "_server_id_order", [])):
            return
        server_id = self._server_id_order[idx]
        self._switch_server_profile(server_id)

    def _switch_server_profile(self, server_id: str) -> None:
        if server_id == self.active_server_id:
            return
        if self._is_server_running():
            messagebox.showwarning("Server running", "Stop the server before switching profiles.")
            self._refresh_server_selector(self.active_server_id)
            return

        try:
            self.cfg = self._collect_vars_to_cfg()
            self._save_active_server_config(self.cfg)
            self.global_cfg = self._collect_vars_to_global_cfg()
            self._save_global_config(self.global_cfg)
        except Exception as e:
            messagebox.showerror("Switch profile", str(e))
            self._refresh_server_selector(self.active_server_id)
            return

        self.active_server_id = server_id
        self.global_cfg.last_selected_server_id = server_id
        self._save_global_config(self.global_cfg)

        self._load_active_server_config(server_id)
        self._autosave_guard = True
        self._apply_cfg_to_vars(self.cfg)
        self._autosave_guard = False
        self._sync_map_mode()
        self._reset_ini_state()

    def _add_server_profile(self) -> None:
        display_name = simpledialog.askstring("New Server Profile", "Display name:", initialvalue="New Server")
        if not display_name:
            return

        new_dir = filedialog.askdirectory(
            title="Select ARK server install directory for this NEW profile",
            mustexist=False,
        )
        if not new_dir:
            return

        new_dir = str(Path(new_dir).resolve())

        if self._server_dir_in_use(new_dir):
            ok = messagebox.askyesno(
                "New Server Profile",
                "This server install directory is already used by another profile.\n"
                "Use the same install directory anyway (shared install)?\n\n"
                "Note: Make sure each profile uses unique ports.",
            )
            if not ok:
                return


        try:
            cfg = self._collect_vars_to_cfg()
        except Exception:
            cfg = AppConfig()

        cfg.server_dir = new_dir
        cfg.server_name = display_name.strip() or cfg.server_name or DEFAULT_SERVER_NAME

        try:
            self.auto_assign_ports(cfg, stride=10, max_tries=300)
        except Exception as e:
            messagebox.showerror("New Server Profile", f"Port auto-detection failed: {e}")
            return

        server_id = str(uuid.uuid4())
        new_store = ServerConfigStore(server_config_path(self.app_base, server_id), server_lock_path(self.app_base, server_id))
        try:
            new_store.save_new(cfg)
        except FileExistsError:
            messagebox.showerror("New Server Profile", "Refusing to overwrite an existing server config.")
            return

        self.global_cfg.servers.append(ServerRef(id=server_id, display_name=display_name.strip(), server_dir=cfg.server_dir))
        self.global_cfg.last_selected_server_id = server_id
        self._save_global_config(self.global_cfg)

        self.active_server_id = server_id
        self.server_store = new_store
        self.cfg = cfg
        self._refresh_server_selector(server_id)
        self._autosave_guard = True
        self._apply_cfg_to_vars(self.cfg)
        self._autosave_guard = False
        self._reset_ini_state()

    def _rename_server_profile(self) -> None:
        ref = self._server_ref_by_id(self.active_server_id)
        if not ref:
            return
        new_name = simpledialog.askstring("Rename Server Profile", "Display name:", initialvalue=ref.display_name)
        if not new_name:
            return
        ref.display_name = new_name.strip()
        self._save_global_config(self.global_cfg)
        self._refresh_server_selector(self.active_server_id)

    def _remove_server_profile(self) -> None:
        if self._is_server_running():
            messagebox.showwarning("Remove Profile", "Stop the server before removing a profile.")
            return
        if len(self.global_cfg.servers) <= 1:
            messagebox.showwarning("Remove Profile", "At least one server profile must exist.")
            return
        ref = self._server_ref_by_id(self.active_server_id)
        if not ref:
            return
        if not messagebox.askyesno(
            "Remove Profile",
            f"Remove profile '{ref.display_name}'?\nFiles on disk will be kept.",
        ):
            return

        self.global_cfg.servers = [r for r in self.global_cfg.servers if r.id != ref.id]
        self.active_server_id = self.global_cfg.servers[0].id
        self.global_cfg.last_selected_server_id = self.active_server_id
        self._save_global_config(self.global_cfg)

        self._load_active_server_config(self.active_server_id)
        self._refresh_server_selector(self.active_server_id)
        self._autosave_guard = True
        self._apply_cfg_to_vars(self.cfg)
        self._autosave_guard = False
        self._reset_ini_state()

    def _reset_ini_state(self) -> None:
        self._ini_loaded_target = None
        self._ini_paths_current = None
        self._ini_doc = None
        self._ini_items_index = {}
        try:
            self.lbl_ini_target.configure(text="(not loaded)")
        except Exception:
            pass

    # ---------------------------------------------------------------------
    # Console filter (GUI only)
    # ---------------------------------------------------------------------
    def _sync_console_log_filter_state(self) -> None:
        try:
            self._suppress_ga_console = bool(self.var_hide_gameanalytics_console_logs.get())
        except Exception:
            self._suppress_ga_console = True

    def _drop_console_message(self, message: str) -> bool:
        # Only affects GUI console (Tk handler). File log stays complete.
        if not getattr(self, "_suppress_ga_console", False):
            return False

        s = (message or "").strip()
        if not s:
            return False

        # Hide GameAnalytics spam (all severities)
        if "GameAnalytics" in s:
            return True
        if "api.gameanalytics.com" in s:
            return True

        return False

    # ---------------------------------------------------------------------
    # RCON FIX helpers
    # ---------------------------------------------------------------------
    def _capture_runtime_rcon(self, cfg: AppConfig) -> None:
        # Capture values used to start the *running* server.
        self._runtime_rcon_host = (cfg.rcon_host or DEFAULT_RCON_HOST).strip()
        self._runtime_rcon_port = int(cfg.rcon_port)
        self._runtime_rcon_password = str(cfg.admin_password or "")

    def _clear_runtime_rcon(self) -> None:
        self._runtime_rcon_host = None
        self._runtime_rcon_port = None
        self._runtime_rcon_password = None

    # ---------------------------------------------------------------------
    # Discord helpers
    # ---------------------------------------------------------------------
    def _discord_get_coordinator(self) -> DiscordNotificationCoordinator:
        server_id = self.active_server_id
        if not self._discord_coordinator or self._discord_server_id != server_id:
            self._discord_coordinator = DiscordNotificationCoordinator(
                server_discord_state_path(self.app_base, server_id),
                server_id,
                self.logger,
                lambda cmd, timeout: self._rcon_try(cmd, timeout=timeout),
            )
            self._discord_server_id = server_id
        self._discord_coordinator.update_config(self.cfg)
        return self._discord_coordinator

    def _discord_update_config(self) -> None:
        if self._discord_coordinator:
            self._discord_coordinator.update_config(self.cfg)

    def _discord_start_notifications(self, pid: int) -> None:
        if not self.cfg.discord_enable:
            return
        coordinator = self._discord_get_coordinator()
        coordinator.start_instance(self.cfg, pid)
        coordinator.start_polling(self.cfg)

    def _discord_request_stop(self) -> None:
        if not self.cfg.discord_enable:
            return
        coordinator = self._discord_get_coordinator()
        coordinator.request_stop()

    def _discord_stop_notifications(self, requested: bool, exit_code: Optional[int] = None) -> None:
        if not self.cfg.discord_enable:
            return
        coordinator = self._discord_get_coordinator()
        coordinator.notify_stop(self.cfg, requested=requested, exit_code=exit_code)
        coordinator.stop_polling()

    def _discord_send_test(self) -> None:
        def job() -> None:
            self.cfg = self._collect_vars_to_cfg()
            self._save_active_server_config(self.cfg)
            coordinator = self._discord_get_coordinator()
            coordinator.send_test(self.cfg)

        self._run_task("Discord Test", job)

    def _discord_open_state_folder(self) -> None:
        try:
            cfg = self._collect_vars_to_cfg()
        except Exception:
            cfg = self.cfg
        server_id = self.active_server_id
        path = server_discord_state_path(self.app_base, server_id)
        open_in_explorer(path, select_file=True)

    # ---------------------------------------------------------------------
    # Vars
    # ---------------------------------------------------------------------
    def _init_vars(self) -> None:
        m = self.root

        self.var_server_profile = tk.StringVar(master=m)
        self.var_steamcmd_dir = tk.StringVar(master=m)
        self.var_server_dir = tk.StringVar(master=m)

        self.var_map_preset = tk.StringVar(master=m)
        self.var_map_custom = tk.StringVar(master=m)
        self.var_server_name = tk.StringVar(master=m)

        self.var_port = tk.StringVar(master=m)
        self.var_query_port = tk.StringVar(master=m)
        self.var_max_players = tk.StringVar(master=m)

        # moved to Advanced tab
        self.var_server_platform_crossplay = tk.BooleanVar(master=m)

        self.var_join_password = tk.StringVar(master=m)
        self.var_admin_password = tk.StringVar(master=m)

        self.var_enable_battleye = tk.BooleanVar(master=m)
        self.var_automanaged_mods = tk.BooleanVar(master=m)
        self.var_validate_on_update = tk.BooleanVar(master=m)

        self.var_enable_rcon = tk.BooleanVar(master=m)
        self.var_rcon_host = tk.StringVar(master=m)
        self.var_rcon_port = tk.StringVar(master=m)

        self.var_discord_enable = tk.BooleanVar(master=m)
        self.var_discord_webhook_url = tk.StringVar(master=m)
        self.var_discord_poll_interval_min = tk.StringVar(master=m)
        self.var_discord_notify_start = tk.BooleanVar(master=m)
        self.var_discord_notify_stop = tk.BooleanVar(master=m)
        self.var_discord_notify_join = tk.BooleanVar(master=m)
        self.var_discord_notify_leave = tk.BooleanVar(master=m)
        self.var_discord_notify_crash = tk.BooleanVar(master=m)
        self.var_discord_include_player_id = tk.BooleanVar(master=m)
        self.var_discord_mention_mode = tk.StringVar(master=m)
        self.var_discord_mention_map_json = tk.StringVar(master=m)

        self.var_backup_on_stop = tk.BooleanVar(master=m)
        self.var_backup_dir = tk.StringVar(master=m)
        self.var_backup_retention = tk.StringVar(master=m)
        self.var_backup_include_configs = tk.BooleanVar(master=m)

        self.var_auto_update_restart = tk.BooleanVar(master=m)
        self.var_auto_update_interval_min = tk.StringVar(master=m)

        # Hide GameAnalytics spam (console only)
        self.var_hide_gameanalytics_console_logs = tk.BooleanVar(master=m)

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

        self.var_custom_start_args = tk.StringVar(master=m)

        self.var_rcon_cmd = tk.StringVar(master=m)
        self.var_rcon_saved = tk.StringVar(master=m)

        self.var_ini_filter = tk.StringVar(master=m)
        self.var_ini_key = tk.StringVar(master=m)
        self.var_ini_section = tk.StringVar(master=m)
        self.var_ini_value = tk.StringVar(master=m)
        self.var_ini_bool = tk.StringVar(master=m)
        self.var_ini_scale = tk.DoubleVar(master=m)

        self.var_ini_add_section = tk.StringVar(master=m)
        self.var_ini_add_key = tk.StringVar(master=m)
        self.var_ini_add_value = tk.StringVar(master=m)

    # ---------------------------------------------------------------------
    # Layout
    # ---------------------------------------------------------------------
    def _build_layout(self) -> None:
        theme = THEME_COLORS
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        self.paned = ttk.PanedWindow(self.root, orient="vertical")
        self.paned.grid(row=0, column=0, sticky="nsew")

        top = ttk.Frame(self.paned, padding=10)
        bottom = ttk.Frame(self.paned, padding=10)
        self.paned.add(top, weight=5)
        self.paned.add(bottom, weight=1)

        top.columnconfigure(0, weight=1)
        top.rowconfigure(0, weight=1)

        self.nb = ttk.Notebook(top)
        self.nb.grid(row=0, column=0, sticky="nsew")

        self.tab_server = ttk.Frame(self.nb, padding=10)
        self.tab_adv = ttk.Frame(self.nb, padding=10)
        self.tab_rcon = ttk.Frame(self.nb, padding=10)
        self.tab_discord = ttk.Frame(self.nb, padding=10)
        self.tab_ini = ttk.Frame(self.nb, padding=10)

        self.nb.add(self.tab_server, text="Server")
        self.nb.add(self.tab_adv, text="Advanced Start Args")
        self.nb.add(self.tab_rcon, text="RCON")
        self.nb.add(self.tab_discord, text="Discord")
        self.nb.add(self.tab_ini, text="INI Editor")

        # ---------------- Server tab ----------------
        self.tab_server.columnconfigure(0, weight=1)
        self.tab_server.columnconfigure(1, weight=1)

        vcmd = (self.root.register(self._validate_digits), "%P")

        lf_profiles = ttk.LabelFrame(self.tab_server, text="Server Profiles", padding=10)
        lf_profiles.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        lf_profiles.columnconfigure(1, weight=1)

        ttk.Label(lf_profiles, text="Active Server").grid(row=0, column=0, sticky="w")
        self.cmb_server_profile = ttk.Combobox(
            lf_profiles,
            textvariable=self.var_server_profile,
            state="readonly",
            values=[],
        )
        self.cmb_server_profile.grid(row=0, column=1, sticky="ew", padx=6)
        self.cmb_server_profile.bind("<<ComboboxSelected>>", lambda e: self._on_server_profile_selected())

        profile_actions = ttk.Frame(lf_profiles)
        profile_actions.grid(row=0, column=2, sticky="e")
        ttk.Button(profile_actions, text="Add", command=self._add_server_profile).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(profile_actions, text="Rename", command=self._rename_server_profile).grid(row=0, column=1, padx=(0, 6))
        ttk.Button(profile_actions, text="Remove", command=self._remove_server_profile).grid(row=0, column=2)

        lf_paths = ttk.LabelFrame(self.tab_server, text="Paths", padding=10)
        lf_paths.grid(row=1, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        lf_paths.columnconfigure(1, weight=1)
        lf_paths.columnconfigure(4, weight=1)

        ttk.Label(lf_paths, text="SteamCMD Directory").grid(row=0, column=0, sticky="w")
        ttk.Entry(lf_paths, textvariable=self.var_steamcmd_dir).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(lf_paths, text="Browse", command=self._browse_steamcmd).grid(row=0, column=2)

        ttk.Label(lf_paths, text="Server Install Directory").grid(row=0, column=3, sticky="w", padx=(18, 0))
        ttk.Entry(lf_paths, textvariable=self.var_server_dir).grid(row=0, column=4, sticky="ew", padx=6)
        ttk.Button(lf_paths, text="Browse", command=self._browse_server_dir).grid(row=0, column=5)

        lf_server = ttk.LabelFrame(self.tab_server, text="Server Settings", padding=10)
        lf_server.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)
        lf_server.columnconfigure(1, weight=1)

        lf_ops = ttk.LabelFrame(self.tab_server, text="Operations", padding=10)
        lf_ops.grid(row=2, column=1, sticky="nsew", padx=5, pady=5)
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

        self.txt_mods = tk.Text(
            mods_frame,
            height=4,
            wrap="none",
            background=theme["surface"],
            foreground=theme["text"],
            insertbackground=theme["text"],
            selectbackground=theme["accent_light"],
            highlightthickness=1,
            highlightbackground=theme["border"],
            highlightcolor=theme["accent"],
        )
        self.txt_mods.grid(row=0, column=0, sticky="ew")

        xscroll = ttk.Scrollbar(mods_frame, orient="horizontal", command=self.txt_mods.xview)
        xscroll.grid(row=1, column=0, sticky="ew", pady=(2, 0))
        self.txt_mods.configure(xscrollcommand=xscroll.set)

        ttk.Label(lf_server, text="Custom Server Arguments (optional)").grid(row=9, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(lf_server, textvariable=self.var_custom_start_args).grid(row=9, column=1, sticky="ew", padx=6, pady=(8, 0))
        ttk.Label(lf_server, text="Example: -Parameter1 -Parameter2").grid(row=10, column=1, sticky="w", padx=6, pady=(2, 0))

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

        ttk.Checkbutton(
            lf_ops,
            text="Hide GameAnalytics debug spam (console only)",
            variable=self.var_hide_gameanalytics_console_logs,
            command=self._sync_console_log_filter_state,
        ).grid(row=14, column=0, columnspan=3, sticky="w", pady=(10, 0))

        actions = ttk.Frame(self.tab_server, padding=(5, 10))
        actions.grid(row=3, column=0, columnspan=2, sticky="ew")
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

        # moved: ServerPlatform
        lf_platform = ttk.LabelFrame(self.tab_adv, text="Platform / Crossplay", padding=10)
        lf_platform.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        ttk.Checkbutton(
            lf_platform,
            text='ServerPlatform: PC+XSX+WINGDK',
            variable=self.var_server_platform_crossplay
        ).grid(row=0, column=0, sticky="w")

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
        lf_logs.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        ttk.Checkbutton(lf_logs, text="servergamelog", variable=self.var_log_servergamelog).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(lf_logs, text="servergamelogincludetribelogs", variable=self.var_log_servergamelogincludetribelogs).grid(row=1, column=0, sticky="w")
        ttk.Checkbutton(lf_logs, text="ServerRCONOutputTribeLogs", variable=self.var_log_serverrconoutputtribelogs).grid(row=2, column=0, sticky="w")

        lf_mech = ttk.LabelFrame(self.tab_adv, text="Mechanics / Performance", padding=10)
        lf_mech.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)

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

        # ---------------- Discord tab ----------------
        self.tab_discord.columnconfigure(0, weight=1)

        lf_discord = ttk.LabelFrame(self.tab_discord, text="Discord Webhooks", padding=10)
        lf_discord.grid(row=0, column=0, sticky="ew")
        lf_discord.columnconfigure(1, weight=1)

        ttk.Checkbutton(lf_discord, text="Enable Discord notifications", variable=self.var_discord_enable).grid(
            row=0, column=0, columnspan=2, sticky="w"
        )

        ttk.Label(lf_discord, text="Webhook URL").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(lf_discord, textvariable=self.var_discord_webhook_url).grid(row=1, column=1, sticky="ew", padx=6, pady=(6, 0))

        ttk.Label(lf_discord, text="Poll interval (minutes)").grid(row=2, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(lf_discord, textvariable=self.var_discord_poll_interval_min).grid(row=2, column=1, sticky="w", padx=6, pady=(6, 0))

        notify_frame = ttk.LabelFrame(self.tab_discord, text="Notifications", padding=10)
        notify_frame.grid(row=1, column=0, sticky="ew", pady=(10, 0))

        ttk.Checkbutton(notify_frame, text="Server start", variable=self.var_discord_notify_start).grid(row=0, column=0, sticky="w", padx=(0, 14))
        ttk.Checkbutton(notify_frame, text="Server stop", variable=self.var_discord_notify_stop).grid(row=0, column=1, sticky="w", padx=(0, 14))
        ttk.Checkbutton(notify_frame, text="Server crash/exit", variable=self.var_discord_notify_crash).grid(row=0, column=2, sticky="w")

        ttk.Checkbutton(notify_frame, text="Player join", variable=self.var_discord_notify_join).grid(row=1, column=0, sticky="w", padx=(0, 14))
        ttk.Checkbutton(notify_frame, text="Player leave", variable=self.var_discord_notify_leave).grid(row=1, column=1, sticky="w", padx=(0, 14))
        ttk.Checkbutton(
            notify_frame,
            text="Include player IDs (advanced)",
            variable=self.var_discord_include_player_id,
        ).grid(row=2, column=0, sticky="w", padx=(0, 14), pady=(6, 0))

        mention_frame = ttk.LabelFrame(self.tab_discord, text="Mentions", padding=10)
        mention_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        mention_frame.columnconfigure(1, weight=1)

        ttk.Label(mention_frame, text="Mention mode").grid(row=0, column=0, sticky="w")
        self.cmb_discord_mention_mode = ttk.Combobox(
            mention_frame,
            textvariable=self.var_discord_mention_mode,
            state="readonly",
            values=["name", "mapping", "none"],
            width=14,
        )
        self.cmb_discord_mention_mode.grid(row=0, column=1, sticky="w", padx=6)

        ttk.Label(mention_frame, text="Mention map (JSON or file path)").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(mention_frame, textvariable=self.var_discord_mention_map_json).grid(row=1, column=1, sticky="ew", padx=6, pady=(6, 0))

        discord_btns = ttk.Frame(self.tab_discord)
        discord_btns.grid(row=3, column=0, sticky="w", pady=(10, 0))
        ttk.Button(discord_btns, text="Send Test", command=self._discord_send_test).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(discord_btns, text="Open State Folder", command=self._discord_open_state_folder).grid(row=0, column=1)

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

        self.txt_log = tk.Text(
            lf_console,
            height=12,
            wrap="word",
            state="disabled",
            background=theme["console_bg"],
            foreground=theme["console_fg"],
            insertbackground=theme["console_fg"],
            selectbackground=theme["console_select"],
            highlightthickness=1,
            highlightbackground=theme["border"],
            highlightcolor=theme["accent"],
            font=tkfont.nametofont("TkFixedFont"),
        )
        vs = ttk.Scrollbar(lf_console, orient="vertical", command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=vs.set)
        self.txt_log.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")

        self.root.after(0, self._initialize_paned_layout)

    def _initialize_paned_layout(self) -> None:
        try:
            self.root.update_idletasks()
            height = self.root.winfo_height()
            if height > 1:
                self.paned.sashpos(0, int(height * 0.75))
        except Exception:
            pass

    def _apply_text_theme(self) -> None:
        theme = THEME_COLORS
        self.txt_mods.configure(
            background=theme["surface"],
            foreground=theme["text"],
            insertbackground=theme["text"],
            selectbackground=theme["accent_light"],
            highlightthickness=1,
            highlightbackground=theme["border"],
            highlightcolor=theme["accent"],
        )
        self.txt_log.configure(
            background=theme["console_bg"],
            foreground=theme["console_fg"],
            insertbackground=theme["console_fg"],
            selectbackground=theme["console_select"],
            highlightthickness=1,
            highlightbackground=theme["border"],
            highlightcolor=theme["accent"],
            font=tkfont.nametofont("TkFixedFont"),
        )
        self.canvas_ticks.configure(background=theme["bg"])

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

    def _apply_global_cfg_to_vars(self, cfg: GlobalConfig) -> None:
        self.var_steamcmd_dir.set(cfg.steamcmd_dir)

    def _apply_cfg_to_vars(self, cfg: AppConfig) -> None:
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

        self.var_server_platform_crossplay.set(cfg.server_platform.strip() == "PC+XSX+WINGDK")

        self.var_join_password.set(cfg.join_password)
        self.var_admin_password.set(cfg.admin_password)

        self.var_enable_battleye.set(cfg.enable_battleye)
        self.var_automanaged_mods.set(cfg.automanaged_mods)
        self.var_validate_on_update.set(cfg.validate_on_update)

        self._mods_text_set(cfg.mods)

        self.var_enable_rcon.set(cfg.enable_rcon)
        self.var_rcon_host.set(cfg.rcon_host)
        self.var_rcon_port.set(str(cfg.rcon_port))

        self.var_discord_enable.set(cfg.discord_enable)
        self.var_discord_webhook_url.set(cfg.discord_webhook_url)
        poll_min = max(1, int(int(cfg.discord_poll_interval_sec) / 60)) if cfg.discord_poll_interval_sec else 5
        self.var_discord_poll_interval_min.set(str(poll_min))
        self.var_discord_notify_start.set(cfg.discord_notify_start)
        self.var_discord_notify_stop.set(cfg.discord_notify_stop)
        self.var_discord_notify_join.set(cfg.discord_notify_join)
        self.var_discord_notify_leave.set(cfg.discord_notify_leave)
        self.var_discord_notify_crash.set(cfg.discord_notify_crash)
        self.var_discord_include_player_id.set(cfg.discord_include_player_id)
        self.var_discord_mention_mode.set(cfg.discord_mention_mode or "name")
        self.var_discord_mention_map_json.set(cfg.discord_mention_map_json)

        self.var_backup_on_stop.set(cfg.backup_on_stop)
        self.var_backup_dir.set(cfg.backup_dir)
        self.var_backup_retention.set(str(cfg.backup_retention))
        self.var_backup_include_configs.set(cfg.backup_include_configs)

        self.var_auto_update_restart.set(cfg.auto_update_restart)
        self.var_auto_update_interval_min.set(str(cfg.auto_update_interval_min))

        self.var_hide_gameanalytics_console_logs.set(bool(cfg.hide_gameanalytics_console_logs))
        self._sync_console_log_filter_state()

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

        self.var_custom_start_args.set(cfg.custom_start_args)

        self._rcon_refresh_saved(cfg)

    def _collect_vars_to_cfg(self) -> AppConfig:
        cfg = copy.deepcopy(self.cfg) if isinstance(self.cfg, AppConfig) else AppConfig()
        cfg.schema_version = AppConfig().schema_version
        cfg.server_dir = self.var_server_dir.get().strip() or DEFAULT_SERVER_DIR

        cfg.map_name = self.var_map_custom.get().strip() or DEFAULT_MAP
        cfg.server_name = self.var_server_name.get().strip() or DEFAULT_SERVER_NAME

        cfg.port = safe_int(self.var_port.get(), DEFAULT_PORT) or DEFAULT_PORT
        cfg.query_port = safe_int(self.var_query_port.get(), DEFAULT_QUERY_PORT) or DEFAULT_QUERY_PORT
        cfg.max_players = safe_int(self.var_max_players.get(), DEFAULT_MAX_PLAYERS) or DEFAULT_MAX_PLAYERS

        cfg.server_platform = "PC+XSX+WINGDK" if bool(self.var_server_platform_crossplay.get()) else ""

        # RCON FIX NOTE: keep mapping strict - JoinPassword != AdminPassword
        cfg.join_password = (self.var_join_password.get() or "").strip()
        cfg.admin_password = (self.var_admin_password.get() or "").strip()

        cfg.enable_battleye = bool(self.var_enable_battleye.get())
        cfg.automanaged_mods = bool(self.var_automanaged_mods.get())
        cfg.validate_on_update = bool(self.var_validate_on_update.get())

        cfg.mods = self._mods_text_get()

        cfg.enable_rcon = bool(self.var_enable_rcon.get())
        cfg.rcon_host = self.var_rcon_host.get().strip() or DEFAULT_RCON_HOST
        cfg.rcon_port = safe_int(self.var_rcon_port.get(), DEFAULT_RCON_PORT) or DEFAULT_RCON_PORT

        cfg.discord_enable = bool(self.var_discord_enable.get())
        cfg.discord_webhook_url = self.var_discord_webhook_url.get().strip()
        poll_min = safe_int(self.var_discord_poll_interval_min.get(), 5) or 5
        cfg.discord_poll_interval_sec = max(60, int(poll_min) * 60)
        cfg.discord_notify_start = bool(self.var_discord_notify_start.get())
        cfg.discord_notify_stop = bool(self.var_discord_notify_stop.get())
        cfg.discord_notify_join = bool(self.var_discord_notify_join.get())
        cfg.discord_notify_leave = bool(self.var_discord_notify_leave.get())
        cfg.discord_notify_crash = bool(self.var_discord_notify_crash.get())
        cfg.discord_include_player_id = bool(self.var_discord_include_player_id.get())
        cfg.discord_mention_mode = (self.var_discord_mention_mode.get() or "name").strip().lower()
        cfg.discord_mention_map_json = self.var_discord_mention_map_json.get().strip()
        if cfg.discord_mention_mode not in ("name", "mapping", "none"):
            cfg.discord_mention_mode = "name"

        cfg.backup_on_stop = bool(self.var_backup_on_stop.get())
        cfg.backup_dir = self.var_backup_dir.get().strip()
        cfg.backup_retention = safe_int(self.var_backup_retention.get(), 20) or 20
        cfg.backup_include_configs = bool(self.var_backup_include_configs.get())

        cfg.auto_update_restart = bool(self.var_auto_update_restart.get())
        cfg.auto_update_interval_min = safe_int(self.var_auto_update_interval_min.get(), 360) or 360

        cfg.hide_gameanalytics_console_logs = bool(self.var_hide_gameanalytics_console_logs.get())

        cfg.install_optional_certificates = True

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

        cfg.custom_start_args = self.var_custom_start_args.get().strip()

        if not isinstance(cfg.rcon_saved_commands, list) or not cfg.rcon_saved_commands:
            cfg.rcon_saved_commands = ["SaveWorld", "DoExit", "ListPlayers", "DestroyWildDinos"]

        self._validate_cfg(cfg)
        return cfg

    def _collect_vars_to_global_cfg(self) -> GlobalConfig:
        cfg = copy.deepcopy(self.global_cfg) if isinstance(self.global_cfg, GlobalConfig) else GlobalConfig()
        cfg.schema_version = GlobalConfig().schema_version
        cfg.steamcmd_dir = self.var_steamcmd_dir.get().strip() or DEFAULT_STEAMCMD_DIR
        self._validate_global_cfg(cfg)
        return cfg

    def _validate_cfg(self, cfg: AppConfig) -> None:
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

    def _validate_global_cfg(self, cfg: GlobalConfig) -> None:
        if not cfg.steamcmd_dir.strip():
            raise ValueError("SteamCMD directory is required.")

    def _hook_autosave(self) -> None:
        def on_change(*_: Any) -> None:
            if self._autosave_guard:
                return
            self._schedule_autosave()

        vars_to_watch = [
            self.var_steamcmd_dir, self.var_server_dir,
            self.var_map_preset, self.var_map_custom, self.var_server_name,
            self.var_port, self.var_query_port, self.var_max_players,
            self.var_server_platform_crossplay,
            self.var_join_password, self.var_admin_password,
            self.var_enable_battleye, self.var_automanaged_mods, self.var_validate_on_update,
            self.var_enable_rcon, self.var_rcon_host, self.var_rcon_port,
            self.var_discord_enable, self.var_discord_webhook_url, self.var_discord_poll_interval_min,
            self.var_discord_notify_start, self.var_discord_notify_stop, self.var_discord_notify_join,
            self.var_discord_notify_leave, self.var_discord_notify_crash, self.var_discord_include_player_id,
            self.var_discord_mention_mode, self.var_discord_mention_map_json,
            self.var_backup_on_stop, self.var_backup_dir, self.var_backup_retention, self.var_backup_include_configs,
            self.var_auto_update_restart, self.var_auto_update_interval_min,
            self.var_hide_gameanalytics_console_logs,
            self.var_cluster_enable, self.var_cluster_id, self.var_cluster_custom_path_enable, self.var_cluster_dir_override,
            self.var_no_transfer_from_filtering, self.var_alt_save_directory_name,
            self.var_dino_mode,
            self.var_log_servergamelog, self.var_log_servergamelogincludetribelogs, self.var_log_serverrconoutputtribelogs,
            self.var_m_disablecustomcosmetics, self.var_m_autodestroystructures, self.var_m_forcerespawndinos,
            self.var_m_nowildbabies, self.var_m_forceallowcaveflyers, self.var_m_disabledinonetrangescaling,
            self.var_m_unstasisdinoobstructioncheck, self.var_m_alwaystickdedicatedskeletalmeshes,
            self.var_m_disablecharactertracker, self.var_m_useservernetspeedcheck, self.var_m_stasiskeepcontrollers,
            self.var_m_ignoredupeditems,
            self.var_custom_start_args,
        ]
        for v in vars_to_watch:
            try:
                v.trace_add("write", on_change)
            except Exception:
                pass

        self.txt_mods.bind("<KeyRelease>", lambda e: (None if self._autosave_guard else self._schedule_autosave()))

        try:
            self.var_hide_gameanalytics_console_logs.trace_add("write", lambda *_: self._sync_console_log_filter_state())
        except Exception:
            pass

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
            self._save_active_server_config(self.cfg)
            self.global_cfg = self._collect_vars_to_global_cfg()
            self.global_store.save(self.global_cfg)
            self._set_status("Auto-saved")
        except Exception as e:
            self.logger.info(f"Autosave skipped: {e}")
            self._set_status(f"Config invalid: {e}")

        self._sync_auto_update_scheduler()
        self._discord_update_config()

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

    def _ui(self, fn: Callable[[], None]) -> None:
        try:
            self.root.after(0, fn)
        except Exception:
            pass

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
                self._ui(lambda: messagebox.showerror(name, str(e)))
            finally:
                self._set_busy(False)

        threading.Thread(target=worker, daemon=True).start()

    # ---------------------------------------------------------------------
    # UX
    # ---------------------------------------------------------------------
    def _set_status(self, text: str) -> None:
        self.var_status.set(text)

    def _write_banner(self) -> None:
        server_cfg_path = server_config_path(self.app_base, self.active_server_id)
        self.logger.info(
            f"{APP_NAME} started | Admin={is_admin()} | GlobalConfig={self.global_config_path} | ServerConfig={server_cfg_path}"
        )
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
                logger.info("DirectX legacy DLLs still not detected after install (this can be normal).")

    # ---------------------------------------------------------------------
    # First Install / Update Validate
    # ---------------------------------------------------------------------
    def first_install(self) -> None:
        def job() -> None:
            self.cfg = self._collect_vars_to_cfg()
            self._save_active_server_config(self.cfg)

            shared = _programdata_base()
            if shared:
                ensure_programdata_acl(shared, self.logger)

            if not is_admin():
                self.logger.info("Warning: Not running as Administrator. Installs may fail.")

            self._ensure_dependencies_first_install(self.logger)
            install_asa_certificates(self.logger)

            steamcmd_exe = ensure_steamcmd(self.global_cfg.steamcmd_dir, self.logger)

            steamcmd_app_update(
                logger=self.logger,
                steamcmd_exe=steamcmd_exe,
                install_dir=Path(self.cfg.server_dir),
                app_id=ARK_ASA_APP_ID,
                validate=False,
                lock_root=self.app_base,
                retries=2,
            )

            exe = ark_server_exe(Path(self.cfg.server_dir))
            self.logger.info(f"Server executable: {exe if exe.exists() else 'NOT FOUND'}")

        self._run_task("First Install", job)

    def update_validate(self) -> None:
        def job() -> None:
            self.cfg = self._collect_vars_to_cfg()
            self._save_active_server_config(self.cfg)

            shared = _programdata_base()
            steamcmd_exe = ensure_steamcmd(self.global_cfg.steamcmd_dir, self.logger)

            steamcmd_app_update(
                logger=self.logger,
                steamcmd_exe=steamcmd_exe,
                install_dir=Path(self.cfg.server_dir),
                app_id=ARK_ASA_APP_ID,
                validate=True,
                lock_root=self.app_base,
                retries=2,
            )

        self._run_task("Update / Validate", job)

    # ---------------------------------------------------------------------
    # Start / Stop / RCON
    # ---------------------------------------------------------------------
    def _stage_required_configs_for_start(self) -> None:
        server_dir = Path(self.cfg.server_dir)
        ensure_baseline(self.app_base, self.active_server_id, server_dir, self.logger, refresh=True)
        ensure_required_server_settings(self.cfg, self.app_base, self.active_server_id, server_dir, self.logger)

    def start_server(self) -> None:
        def job() -> None:
            self.cfg = self._collect_vars_to_cfg()
            self._save_active_server_config(self.cfg)

            server_dir = Path(self.cfg.server_dir)
            exe = ark_server_exe(server_dir)
            if not exe.exists():
                raise FileNotFoundError(f"Server EXE not found: {exe}")

            if self.cfg.enable_rcon and not (self.cfg.admin_password or "").strip():
                raise RuntimeError("Admin/RCON password is empty. Set 'Admin Password (RCON/Admin)' before starting.")

            self._stage_required_configs_for_start()
            apply_staging_to_server(self.app_base, self.active_server_id, server_dir, self.logger)

            # RCON FIX: capture *runtime* values used to start this server instance
            self._capture_runtime_rcon(self.cfg)

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
                    creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                pid = self._server_proc.pid

            threading.Thread(target=self._server_log_reader, daemon=True).start()
            if pid is not None:
                self._discord_start_notifications(pid)
            self._ui(self._refresh_buttons)

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
                self.logger.info(line.rstrip())
        except Exception as e:
            self.logger.info(f"Log reader stopped: {e}")
        finally:
            code: Optional[int] = None
            try:
                code = p.poll()
                if code is not None:
                    self.logger.info(f"Server exited with code {code}")
            except Exception:
                pass

            # RCON FIX: server is gone -> runtime snapshot is no longer valid
            self._clear_runtime_rcon()

            self._discord_stop_notifications(requested=False, exit_code=code)

            self._ui(self._refresh_buttons)

    def _rcon_try(self, cmd: str, timeout: float = 4.0, retry_window_sec: int = 15) -> str:
        if not self.cfg.enable_rcon:
            raise RuntimeError("RCON disabled in config.")

        # RCON FIX:
        # If server is running, always use the runtime snapshot captured at Start.
        # This prevents "Authentication failed" when GUI values changed after start.
        if self._is_server_running() and self._runtime_rcon_password is not None:
            host = (self._runtime_rcon_host or DEFAULT_RCON_HOST).strip()
            port = int(self._runtime_rcon_port or DEFAULT_RCON_PORT)
            password = self._runtime_rcon_password
        else:
            host = (self.cfg.rcon_host or DEFAULT_RCON_HOST).strip()
            port = int(self.cfg.rcon_port)
            password = (self.cfg.admin_password or "").strip()

        if not password:
            raise RuntimeError("Admin password is empty.")

        start = time.time()
        last_err: Optional[Exception] = None
        while time.time() - start < retry_window_sec:
            try:
                client = self._rcon_factory(host, port, password, timeout)
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
            self._save_active_server_config(self.cfg)

            self.logger.info(f"RCON> {cmd}")
            out = self._rcon_try(cmd, timeout=5.0)
            self.logger.info(out if out else "(no response)")

            if cmd not in self.cfg.rcon_saved_commands:
                self.cfg.rcon_saved_commands.append(cmd)
                self._save_active_server_config(self.cfg)
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
            self._save_active_server_config(self.cfg)
            self._rcon_refresh_saved(self.cfg)
            self.var_rcon_saved.set(cmd)

    def _rcon_remove_selected(self) -> None:
        sel = self.var_rcon_saved.get().strip()
        if not sel:
            return
        try:
            self.cfg.rcon_saved_commands = [c for c in self.cfg.rcon_saved_commands if c != sel]
            self._save_active_server_config(self.cfg)
            self._rcon_refresh_saved(self.cfg)
            self.var_rcon_saved.set("")
        except Exception:
            pass

    def _stop_server_impl(self, inline: bool) -> None:
        with self._server_proc_lock:
            p = self._server_proc

        if not p or p.poll() is not None:
            if not inline:
                self.logger.info("Server not running.")
            # RCON FIX: ensure snapshot cleared if process already ended
            self._clear_runtime_rcon()
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

        # RCON FIX: server stopped -> snapshot invalid
        self._clear_runtime_rcon()

        self.logger.info("Server stopped.")

        if self.cfg.backup_on_stop:
            backup_server(self.cfg, self.app_base, self.logger)

        restore_baseline_to_server(self.app_base, self.active_server_id, Path(self.cfg.server_dir), self.logger)
        if not inline:
            self._ui(self._refresh_buttons)

    def stop_server_safe(self) -> None:
        def job() -> None:
            self.cfg = self._collect_vars_to_cfg()
            self._save_active_server_config(self.cfg)
            was_running = self._is_server_running()
            if was_running:
                self._discord_request_stop()
            self._stop_server_impl(inline=False)
            if was_running:
                self._discord_stop_notifications(requested=True)

        self._run_task("Stop Server", job)

    def update_and_restart_safe(self) -> None:
        def job() -> None:
            self.cfg = self._collect_vars_to_cfg()
            self._save_active_server_config(self.cfg)

            if self._is_server_running():
                self.logger.info("Server running -> performing safe stop before update.")
                self._discord_request_stop()
                self._stop_server_impl(inline=True)
                self._discord_stop_notifications(requested=True)

            shared = _programdata_base()
            steamcmd_exe = ensure_steamcmd(self.global_cfg.steamcmd_dir, self.logger)

            steamcmd_app_update(
                logger=self.logger,
                steamcmd_exe=steamcmd_exe,
                install_dir=Path(self.cfg.server_dir),
                app_id=ARK_ASA_APP_ID,
                validate=bool(self.cfg.validate_on_update),
                lock_root=self.app_base,
                retries=2,
            )

            self.logger.info("Restarting server after update...")
            self._start_server_inline()

        self._run_task("Update & Restart", job)

    def _start_server_inline(self) -> None:
        server_dir = Path(self.cfg.server_dir)
        exe = ark_server_exe(server_dir)
        if not exe.exists():
            raise FileNotFoundError(f"Server EXE not found: {exe}")

        if self.cfg.enable_rcon and not (self.cfg.admin_password or "").strip():
            raise RuntimeError("Admin/RCON password is empty. Set 'Admin Password (RCON/Admin)' before starting.")

        self._stage_required_configs_for_start()
        apply_staging_to_server(self.app_base, self.active_server_id, server_dir, self.logger)

        # RCON FIX: capture runtime values for this running instance
        self._capture_runtime_rcon(self.cfg)

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
                creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            pid = self._server_proc.pid

        threading.Thread(target=self._server_log_reader, daemon=True).start()
        if pid is not None:
            self._discord_start_notifications(pid)
        self._ui(self._refresh_buttons)

    def backup_now(self) -> None:
        def job() -> None:
            self.cfg = self._collect_vars_to_cfg()
            self._save_active_server_config(self.cfg)
            backup_server(self.cfg, self.app_base, self.logger)

        self._run_task("Backup", job)

    # ---------------------------------------------------------------------
    # Auto Update Loop
    # ---------------------------------------------------------------------
    def _sync_auto_update_scheduler(self) -> None:
        try:
            self.cfg = self._collect_vars_to_cfg()
            self._save_active_server_config(self.cfg)
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
            self._ui(self.update_and_restart_safe)

    # ---------------------------------------------------------------------
    # INI Editor
    # ---------------------------------------------------------------------
    def _ini_load_target(self, target: str) -> None:
        self.cfg = self._collect_vars_to_cfg()
        self._save_active_server_config(self.cfg)

        server_dir = Path(self.cfg.server_dir)
        ensure_dir(server_root(self.app_base, self.active_server_id) / BASELINE_DIR_NAME)

        paths = ini_stage_paths(self.app_base, self.active_server_id, server_dir, target)
        ensure_ini_staging_synced(paths, server_running=self._is_server_running(), logger=self.logger)

        self._ini_loaded_target = target
        self._ini_paths_current = paths
        self._ini_doc = read_ini(paths.stage)

        if target == "gus":
            self.lbl_ini_target.configure(text=f"Editing STAGED GameUserSettings.ini  |  {paths.stage}")
        else:
            self.lbl_ini_target.configure(text=f"Editing STAGED Game.ini  |  {paths.stage}")

        if not self.var_ini_add_section.get().strip():
            self.var_ini_add_section.set("ServerSettings")

        self._ini_refresh_tree()

    def load_gameusersettings(self) -> None:
        self._ini_load_target("gus")

    def load_game_ini(self) -> None:
        self._ini_load_target("game")

    def open_loaded_ini(self) -> None:
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

        for section, entries in kv_by_section.items():
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
    configure_dpi_awareness()

    root = tk.Tk()
    apply_tk_scaling(root)
    configure_modern_theme(root)
    apply_initial_window_geometry(root, 1220, 780)

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

    try:
        app_base = resolve_storage_root()
        ensure_dir(app_base)
    except PermissionError as e:
        if os.name == "nt" and not is_admin():
            try:
                if messagebox.askyesno(
                    "Shared storage requires admin",
                    f"{e}\n\nRelaunch with admin rights to initialize shared storage?",
                ):
                    if relaunch_as_admin():
                        root.destroy()
                        return
            except Exception:
                pass
        messagebox.showerror("Storage unavailable", str(e))
        root.destroy()
        return

    _ = ServerManagerApp(root, app_base)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
