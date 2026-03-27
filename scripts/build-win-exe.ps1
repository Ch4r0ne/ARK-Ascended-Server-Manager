Param(
  [string]$Name = "ARK-ASA-Manager"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Push-Location -LiteralPath (Split-Path -Parent $MyInvocation.MyCommand.Path)
try {
  $repoRoot = Resolve-Path ".."
  Set-Location $repoRoot

  # Ensure Python and PyInstaller
  $py = Get-Command python -ErrorAction SilentlyContinue
  if (-not $py) {
    Write-Error "python not found in PATH"
  }
  python -m pip install --upgrade pip > $null
  python -m pip install --upgrade pyinstaller > $null

  # Clean previous builds
  if (Test-Path build) { Remove-Item -Recurse -Force build }
  if (Test-Path dist)  { Remove-Item -Recurse -Force dist }

  # Windows uses ';' separator in --add-data
  $cmd = @(
    "pyinstaller",
    "--noconfirm",
    "--clean",
    "--onefile",
    "--windowed",
    "--name", $Name,
    "--icon", ".\assets\app.ico",
    "--add-data", ".\assets;assets",
    ".\ARK-Ascended-Server-Manager.py"
  )

  Write-Host "Building $Name.exe ..."
  & $cmd

  $exe = Join-Path "dist" "$Name.exe"
  if (-not (Test-Path $exe)) {
    Write-Error "Build failed: $exe not found"
  }
  Write-Host "Built: $exe"
}
finally {
  Pop-Location
}

