#!/usr/bin/env bash
# RocketLogAI Upgrade Script (Linux / macOS / WSL)
# Run this from a *new* RocketLogAI-*-Installer directory (or source tree)
# to upgrade an existing installation in-place.
#
# Usage:
#   ./scripts/upgrade.sh [TARGET_INSTALL_DIR]
#
# It will:
#   - Detect docker vs native venv install
#   - Stop the service / container
#   - Copy updated code (logsentinel/, templates/, scripts/)
#   - Re-install Python package (preserves venv)
#   - Preserve your config.yaml and data/
#   - Restart
#
# Always backup first! (especially data/logsentinel.db and config.yaml)

set -e

echo "🔄 RocketLogAI Upgrade"
echo "======================"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SOURCE_ROOT="$(dirname "$SCRIPT_DIR")"   # the new installer / source dir

TARGET_DIR="${1:-}"

if [ -z "$TARGET_DIR" ]; then
    echo "Enter path to your existing RocketLogAI installation (e.g. /opt/logsentinel or ~/logsentinel or the dir with docker-compose.yml):"
    read -r TARGET_DIR
fi

if [ ! -d "$TARGET_DIR" ]; then
    echo "ERROR: Target directory does not exist: $TARGET_DIR"
    exit 1
fi

echo "Upgrading: $TARGET_DIR"
echo "Using new code from: $SOURCE_ROOT"
echo

# Detect type of install
IS_DOCKER=false
if [ -f "$TARGET_DIR/docker-compose.yml" ] || [ -f "$TARGET_DIR/../docker-compose.yml" ]; then
    IS_DOCKER=true
    echo "[detected] Docker Compose installation"
fi

if [ "$IS_DOCKER" = true ]; then
    echo
    echo "[1/4] Stopping Docker service..."
    (cd "$TARGET_DIR" && docker compose down) || (cd "$TARGET_DIR/.." && docker compose down) || true

    echo
    echo "[2/4] Copying updated application files (Docker will rebuild)..."
    # For docker we usually just need the source in the build context.
    # If user mounted or has the files next to compose, copy them.
    if [ -d "$TARGET_DIR/logsentinel" ]; then
        cp -r "$SOURCE_ROOT/logsentinel" "$TARGET_DIR/"
    fi
    if [ -d "$TARGET_DIR/templates" ]; then
        cp -r "$SOURCE_ROOT/templates" "$TARGET_DIR/"
    fi
    cp -f "$SOURCE_ROOT/Dockerfile" "$TARGET_DIR/" 2>/dev/null || true
    cp -f "$SOURCE_ROOT/docker-compose.yml" "$TARGET_DIR/" 2>/dev/null || true
    cp -f "$SOURCE_ROOT/pyproject.toml" "$TARGET_DIR/" 2>/dev/null || true
    cp -f "$SOURCE_ROOT/requirements.txt" "$TARGET_DIR/" 2>/dev/null || true
    cp -f "$SOURCE_ROOT/example-config.yaml" "$TARGET_DIR/" 2>/dev/null || true

    echo
    echo "[3/4] Rebuilding Docker image..."
    (cd "$TARGET_DIR" && docker compose build --no-cache) || (cd "$TARGET_DIR/.." && docker compose build --no-cache)

    echo
    echo "[4/4] Starting upgraded container..."
    (cd "$TARGET_DIR" && docker compose up -d) || (cd "$TARGET_DIR/.." && docker compose up -d)

    echo
    echo "✅ Docker upgrade complete!"
    echo "   Run: docker compose logs -f rocketlogai"
    exit 0
fi

# === Native (venv) upgrade ===
echo
echo "[1/5] Stopping service if running (systemd)..."
if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl stop rocketlogai 2>/dev/null || true
    # Also try common names
    sudo systemctl stop logsentinel 2>/dev/null || true
fi

# Try to find venv
VENV_DIR="$TARGET_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "Looking for venv in common locations..."
    for cand in "$TARGET_DIR" "$TARGET_DIR/.." "$HOME/logsentinel" "/opt/logsentinel"; do
        if [ -d "$cand/.venv" ]; then
            VENV_DIR="$cand/.venv"
            TARGET_DIR="$cand"
            echo "Found venv at $VENV_DIR"
            break
        fi
    done
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "ERROR: Could not find .venv in $TARGET_DIR"
    echo "Please activate your venv manually and run the pip upgrade step yourself."
    exit 1
fi

echo
echo "[2/5] Copying updated code into $TARGET_DIR ..."
cp -r "$SOURCE_ROOT/logsentinel" "$TARGET_DIR/"
cp -r "$SOURCE_ROOT/templates" "$TARGET_DIR/"
cp -f "$SOURCE_ROOT/pyproject.toml" "$TARGET_DIR/" 2>/dev/null || true
cp -f "$SOURCE_ROOT/requirements.txt" "$TARGET_DIR/" 2>/dev/null || true
cp -f "$SOURCE_ROOT/example-config.yaml" "$TARGET_DIR/" 2>/dev/null || true
cp -r "$SOURCE_ROOT/scripts" "$TARGET_DIR/" 2>/dev/null || true

# Clean pycache
find "$TARGET_DIR" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
find "$TARGET_DIR" -name '*.pyc' -delete 2>/dev/null || true

echo
echo "[3/5] Activating venv and upgrading Python package..."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

pip install --upgrade pip setuptools wheel
cd "$TARGET_DIR"
pip install -e ".[web]" --upgrade

# Belt-and-suspenders for any new deps in web extras
pip install fastapi uvicorn[standard] jinja2 itsdangerous bcrypt pyotp qrcode rich click pyyaml openai geoip2 requests ldap3 python-multipart 2>/dev/null || true

echo
echo "[4/5] Updating launcher scripts (if present)..."
cat > "$TARGET_DIR/start-rocketlogai.sh" << 'EOF'
#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
source .venv/bin/activate
echo "Starting RocketLogAI..."
logsentinel run --web
EOF
chmod +x "$TARGET_DIR/start-rocketlogai.sh" 2>/dev/null || true

echo
echo "[5/5] Restarting service..."
if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl daemon-reload 2>/dev/null || true
    if systemctl is-enabled rocketlogai >/dev/null 2>&1; then
        sudo systemctl restart rocketlogai || true
    elif systemctl is-enabled logsentinel >/dev/null 2>&1; then
        sudo systemctl restart logsentinel || true
    else
        echo "No systemd service found or enabled. Start manually with:"
        echo "   cd $TARGET_DIR && ./start-rocketlogai.sh"
    fi
else
    echo "Start manually:"
    echo "   cd $TARGET_DIR && ./start-rocketlogai.sh"
fi

echo
echo "✅ Upgrade complete!"
echo
echo "Important:"
echo "  - Your config.yaml and data/ were left untouched."
echo "  - New features (Daily Briefing at /daily, Ollama fixes, improved config UI) are now active."
echo "  - If you use systemd, you may want to review /etc/systemd/system/rocketlogai.service"
echo "  - Check logs: journalctl -u rocketlogai -f   (or docker logs)"
echo
echo "Open the web UI and verify everything works (especially LLM connection)."
echo