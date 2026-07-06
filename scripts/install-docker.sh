#!/usr/bin/env bash
# RocketLogAI one-click Docker install (Linux / macOS)
# Usage: ./scripts/install-docker.sh [INSTALL_DIR]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="$(dirname "$SCRIPT_DIR")"

INSTALL_DIR="${1:-}"

echo ""
echo "RocketLogAI Docker Install"
echo "=========================="
echo "Uses Python 3.12 inside the container (no local Python required)."
echo ""

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Docker not found. Install Docker first."
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker daemon is not running."
    exit 1
fi

if [ -z "$INSTALL_DIR" ]; then
    read -r -p "Install directory for config and data (default: ~/logsentinel): " INSTALL_DIR
fi
INSTALL_DIR="${INSTALL_DIR:-$HOME/logsentinel}"
mkdir -p "$INSTALL_DIR/data"

echo ""
echo "[1/5] Copying Docker files..."
for f in Dockerfile docker-compose.yml pyproject.toml requirements.txt example-config.yaml; do
    [ -f "$SOURCE_ROOT/$f" ] && cp -f "$SOURCE_ROOT/$f" "$INSTALL_DIR/"
done
cp -r "$SOURCE_ROOT/logsentinel" "$INSTALL_DIR/"
cp -r "$SOURCE_ROOT/templates" "$INSTALL_DIR/"
cp -r "$SOURCE_ROOT/scripts" "$INSTALL_DIR/"

if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
    cp "$INSTALL_DIR/example-config.yaml" "$INSTALL_DIR/config.yaml"
    echo "Created config.yaml from example-config.yaml"
fi
echo "docker" > "$INSTALL_DIR/.install-type"

if [ -f "$SOURCE_ROOT/scripts/rla_cleanup.py" ]; then
    echo "Cleaning install folder..."
    python3 "$SOURCE_ROOT/scripts/rla_cleanup.py" "$INSTALL_DIR" --source "$SOURCE_ROOT" --fix
fi

echo ""
echo "[2/5] Backing up any existing data (if present)..."
python3 "$SOURCE_ROOT/scripts/rla_backup.py" "$INSTALL_DIR" --label pre-docker 2>/dev/null || true

echo ""
echo "[3/5] Building Docker image (Python 3.12)..."
(cd "$INSTALL_DIR" && docker compose build)

echo ""
echo "[4/5] Starting container..."
(cd "$INSTALL_DIR" && docker compose up -d)

echo ""
echo "[5/5] Done!"
echo ""
echo "RocketLogAI is running in Docker."
echo "  Web UI:  http://localhost:8787"
echo "  Data:    $INSTALL_DIR/data"
echo "  Config:  $INSTALL_DIR/config.yaml"
echo ""
echo "Default login: admin / admin (change immediately in the UI)"
echo ""
echo "Useful commands (run from install directory):"
echo "  docker compose logs -f"
echo "  docker compose down"
echo "  docker compose up -d --build   # after upgrades"
echo ""