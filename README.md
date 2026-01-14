# ARK: Survival Ascended Server Manager (Windows)

[![Discord](https://img.shields.io/badge/Discord-%237289DA.svg?logo=discord&logoColor=white)](https://discord.gg/7tvmSdXcEH)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/github/license/Ch4r0ne/ARK-Ascended-Server-Manager)
![Stars](https://img.shields.io/github/stars/Ch4r0ne/ARK-Ascended-Server-Manager?style=flat)
![Issues](https://img.shields.io/github/issues/Ch4r0ne/ARK-Ascended-Server-Manager)
![Last Commit](https://img.shields.io/github/last-commit/Ch4r0ne/ARK-Ascended-Server-Manager)
[![Downloads](https://img.shields.io/github/downloads/Ch4r0ne/ARK-Ascended-Server-Manager/total)](https://github.com/Ch4r0ne/ARK-Ascended-Server-Manager/releases)

**GUI manager** for **ARK: Survival Ascended Dedicated Servers** on **Windows**.  
Built for **safe operations**, **reliable RCON**, and a clean **staging-based configuration workflow**.

> Not affiliated with Studio Wildcard / Snail Games.

## Preview

![Server Tab](docs/img/ASA_Server_Manager_Preview_2.png)

---

## Highlights

### First Install Automation (Admin recommended)
- Installs prerequisites:
  - Visual C++ 2015–2022 Redistributable (x64)
  - DirectX Legacy Runtime (web installer)
  - Amazon certificates (helps on hardened hosts / strict TLS chains)
- Installs SteamCMD automatically
- Downloads / updates the ASA dedicated server via SteamCMD

### Safe Start / Stop
- Deterministic start-line generation (map, ports, session, mods, BattleEye, RCON, cluster, advanced flags)
- Safe stop sequence:
  - `SaveWorld` → `DoExit`

### Reliable RCON
- Uses Python `rcon` (Source RCON) when available
- Built-in RCON fallback (same UI, same behavior)
- Saved commands + fast execution
- Output written into the shared Console

### INI Editor (Staging Workflow)
- User-friendly editing:
  - booleans via `True/False` selector
  - numeric values via slider + tick marks
  - changes are staged automatically (debounced)
- On **Start**: staged configs are applied into the server directory
- On **Stop (Safe)**: baseline is restored into the server directory (staged edits remain for next start)

![Server Tab](docs/img/ASA_Server_Manager_Preview_5.png)

### Advanced Start Arguments (Grouped)
- Cluster configuration
- Dino modes (mutual exclusive)
- Logs
- Mechanics / performance flags

### Backups + Retention
- Optional backup on stop
- Zip retention policy
- Optional “include configs” mode

### Auto Update & Restart
- Interval-based update/validate + safe restart
- Skips triggers while the app is busy

---

## Installation

### Option A: EXE (recommended)
1. Download the latest release from **Releases**
2. Run `ARK-ASA-Manager.exe`
3. Click **First Install** once (**run as Administrator** for full functionality)
4. Configure server settings
5. Click **Start Server**

### Option B: Build EXE
```powershell
pyinstaller --noconfirm --clean --onefile --windowed `
  --name "ARK-ASA-Manager" `
  --icon ".\assets\app.ico" `
  --add-data ".\assets;assets" `
  --collect-all rcon `
  ".\ARK-Ascended-Server-Manager.py"
```
---

## Usage

### Recommended flow
1. **First Install**
2. Configure **Paths**, **Server Settings**, **Operations**
3. Optional: adjust **Advanced Start Args**
4. Optional: adjust INI values in **INI Editor**
5. **Start Server**
6. Use **RCON** for admin commands and operations
7. **Stop Server (Safe)** (optional backup + baseline restore)

### Multi-instance hosting
- Use unique ports per instance (game/query/RCON)
- Use `AltSaveDirectoryName` per instance to keep saves separated
- If you run clusters, keep cluster IDs consistent across instances that should transfer

---

## Configuration Model

### Staging + Baseline
This manager separates *edit time* and *runtime*:

- **Baseline**
  - created once from the server’s original INIs
  - used to restore a known-good state on stop
- **Staging**
  - your edits are written here
  - applied to the server folder on start

This avoids “half-edited live INIs” and allows safe rollback without losing your intended changes.

### Backups + Retention
- Backups are stored as zip files (Saved folder + optional Config folder)
- Retention deletes older zips beyond the configured limit

---

## Networking

Typical defaults (depends on your config):
- **Game Port (UDP):** `7777`
- **Query Port (UDP):** `27015`
- **RCON Port (TCP):** `27020` (only if RCON enabled)

### Router / NAT (Port Forwarding)
Forward ports to the server host:
- `7777/UDP`
- `27015/UDP`
- `27020/TCP` (optional, only for RCON)

### Windows Firewall (PowerShell)
```powershell
New-NetFirewallRule -DisplayName "ARK ASA Game Port (UDP 7777)"   -Direction Inbound -Action Allow -Protocol UDP -LocalPort 7777
New-NetFirewallRule -DisplayName "ARK ASA Query Port (UDP 27015)" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 27015
```

### Validate listening ports
```powershell
netstat -aon | findstr :7777
netstat -aon | findstr :27015
netstat -aon | findstr :27020
```

---

## Security

### RCON
Do **not** expose RCON to the public internet.

Use one of:
- LAN-only access
- VPN
- strict firewall allow-listing (admin IPs only)

### Credentials
- Keep your Admin/Join password private
- Avoid committing `config.json` to public

---

## Troubleshooting

### “First Install” fails
Run the EXE **as Administrator**. Installers and certificate store writes may fail without elevation.

---

## Dependencies

The manager may download or use:
- SteamCMD: https://steamcdn-a.akamaihd.net/client/installer/steamcmd.zip
- VC++ Redistributable (x64): https://aka.ms/vs/17/release/vc_redist.x64.exe
- DirectX Runtime Web Installer: https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe
- Amazon certificates:
  - https://www.amazontrust.com/repository/AmazonRootCA1.cer
  - https://crt.r2m02.amazontrust.com/r2m02.cer
- Python RCON: https://pypi.org/project/rcon/

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Ch4r0ne/ARK-Ascended-Server-Manager&type=date&legend=bottom-right)](https://www.star-history.com/#Ch4r0ne/ARK-Ascended-Server-Manager&type=date&legend=bottom-right)


