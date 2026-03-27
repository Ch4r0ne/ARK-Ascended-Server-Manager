Param(
  [string]$Name = "ARK-ASA-Manager"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Push-Location -LiteralPath (Split-Path -Parent $MyInvocation.MyCommand.Path)
try {
  $repoRoot = Resolve-Path ".."
  Set-Location $repoRoot

  Write-Host "========================================" -ForegroundColor Cyan
  Write-Host "Building $Name" -ForegroundColor Cyan
  Write-Host "========================================" -ForegroundColor Cyan
  Write-Host "Working directory: $(Get-Location)" -ForegroundColor Gray

  # 检查 Python
  $py = Get-Command python -ErrorAction SilentlyContinue
  if (-not $py) {
    Write-Error "python not found in PATH. Please install Python and add it to PATH."
  }
  Write-Host "Python: $($py.Source)" -ForegroundColor Gray

  # 安装/升级依赖
  Write-Host "Installing dependencies..." -ForegroundColor Yellow
  python -m pip install --upgrade pip > $null
  python -m pip install --upgrade pyinstaller > $null

  # 安装项目依赖（如果有 requirements.txt）
  if (Test-Path "requirements.txt") {
    Write-Host "Installing project dependencies from requirements.txt..." -ForegroundColor Yellow
    python -m pip install -r requirements.txt > $null
  }

  # 清理之前的构建
  Write-Host "Cleaning previous builds..." -ForegroundColor Yellow
  if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
  if (Test-Path "dist")  { Remove-Item -Recurse -Force "dist" }
  if (Test-Path "$Name.spec") { Remove-Item -Force "$Name.spec" }

  # 验证必要文件是否存在
  $scriptPath = ".\ARK-Ascended-Server-Manager.py"
  $iconPath = ".\assets\app.ico"
  $assetsPath = ".\assets"

  if (-not (Test-Path $scriptPath)) {
    Write-Error "Script not found: $scriptPath"
  }
  if (-not (Test-Path $iconPath)) {
    Write-Error "Icon not found: $iconPath"
  }
  if (-not (Test-Path $assetsPath)) {
    Write-Error "Assets directory not found: $assetsPath"
  }

  # 构建命令（数组方式避免分号解析问题）
  $cmd = @(
    "pyinstaller",
    "--noconfirm",
    "--clean",
    "--onefile",
    "--windowed",
    "--name", $Name,
    "--icon", $iconPath,
    "--add-data", ".\assets;assets",
    $scriptPath
  )

  Write-Host "Running PyInstaller..." -ForegroundColor Yellow
  Write-Host "Command: $($cmd -join ' ')" -ForegroundColor Gray

  # 执行构建
  $startTime = Get-Date
  & $cmd
  $endTime = Get-Date
  $duration = $endTime - $startTime

  # 验证输出
  $exe = Join-Path "dist" "$Name.exe"
  if (-not (Test-Path $exe)) {
    Write-Error "Build failed: $exe not found"
  }

  # 输出构建信息
  Write-Host "========================================" -ForegroundColor Green
  Write-Host "Build completed successfully!" -ForegroundColor Green
  Write-Host "========================================" -ForegroundColor Green
  Write-Host "Output: $exe" -ForegroundColor Green
  Write-Host "Size: $([math]::Round((Get-Item $exe).Length / 1MB, 2)) MB" -ForegroundColor Gray
  Write-Host "Duration: $($duration.Minutes)m $($duration.Seconds)s" -ForegroundColor Gray
  Write-Host "========================================" -ForegroundColor Green

}
catch {
  Write-Host "========================================" -ForegroundColor Red
  Write-Host "Build failed!" -ForegroundColor Red
  Write-Host "========================================" -ForegroundColor Red
  Write-Error $_.Exception.Message
  throw
}
finally {
  Pop-Location
}