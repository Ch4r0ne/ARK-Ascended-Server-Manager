#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="${1:-ARK-ASA-Manager}"

if command -v docker >/dev/null 2>&1; then
  echo "Using Docker to build Windows .exe ($NAME) ..."
  # Image provides Wine + PyInstaller targeting Windows
  IMAGE="cdrx/pyinstaller-windows:python3"
  docker pull "$IMAGE" >/dev/null
  docker run --rm -v "$PWD":/src "$IMAGE" \
    /bin/bash -lc \
    "cd /src && \
     rm -rf build dist && \
     pyinstaller --noconfirm --clean --onefile --windowed \
       --name \"$NAME\" \
       --icon ./assets/app.ico \
       --add-data ./assets:assets \
       ./ARK-Ascended-Server-Manager.py"
  if [[ -f "dist/${NAME}.exe" ]]; then
    echo "Built: dist/${NAME}.exe"
    exit 0
  else
    echo "Build failed: dist/${NAME}.exe not found" >&2
    exit 1
  fi
else
  echo "Docker not found. Cannot cross-compile to Windows .exe on macOS/Linux." >&2
  echo "Install Docker and re-run this script." >&2
  exit 2
fi

