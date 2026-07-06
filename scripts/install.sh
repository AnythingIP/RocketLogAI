#!/usr/bin/env bash
# RocketLogAI one-click installer for Linux / macOS / WSL
# Run from the RocketLogAI repo root (or extracted v2.0 installer directory)

set -e

echo "🚀 RocketLogAI v2.0 Installer"
echo "=============================="

# Determine where this script lives (source of truth for files to copy)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SOURCE_ROOT="$(dirname "$SCRIPT_DIR")"   # parent of scripts/ = the installer root

INSTALL_DIR="${1:-$HOME/logsentinel}"

echo "Installing to: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

echo
echo "[1/6] Selecting Python (recommended: 3.12) ..."
SELECTOR="$SOURCE_ROOT/scripts/rla_python.py"
if [ ! -f "$SELECTOR" ]; then
    echo "ERROR: missing scripts/rla_python.py"
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3.10 or newer is required."
    exit 1
fi
PY_JSON="$(python3 "$SELECTOR" --ask)"
mapfile -t PYTHON_LAUNCHER < <(python3 -c "import json,sys; print('\n'.join(json.loads(sys.argv[1])['command']))" "$PY_JSON")
echo "Selected $(python3 -c "import json,sys; print(json.loads(sys.argv[1])['version'])" "$PY_JSON")"

if [ -f "$INSTALL_DIR/config.yaml" ]; then
    echo
    echo "[1.5/6] Existing install detected - backing up first..."
    python3 "$SOURCE_ROOT/scripts/rla_backup.py" "$INSTALL_DIR" --label pre-install || true
fi

# Auto-install required system packages on Debian/Ubuntu (makes one-click work on fresh servers)
if command -v apt-get >/dev/null 2>&1; then
    MISSING_PACKAGES=""
    if ! dpkg -s python3-venv >/dev/null 2>&1; then
        MISSING_PACKAGES="$MISSING_PACKAGES python3-venv"
    fi
    if ! dpkg -s python3-dev >/dev/null 2>&1; then
        MISSING_PACKAGES="$MISSING_PACKAGES python3-dev"
    fi
    if ! dpkg -s build-essential >/dev/null 2>&1; then
        MISSING_PACKAGES="$MISSING_PACKAGES build-essential"
    fi

    if [ -n "$MISSING_PACKAGES" ]; then
        echo ""
        echo "Some required system packages are missing. Installing them now..."
        echo "You may be prompted for your sudo password."
        sudo apt-get update -qq
        sudo apt-get install -y $MISSING_PACKAGES
        echo "System packages installed."
    fi
fi

# Create virtual environment
echo
echo "[2/6] Creating virtual environment..."
if ! "${PYTHON_LAUNCHER[@]}" -m venv "$INSTALL_DIR/.venv"; then
    echo ""
    echo "ERROR: Failed to create virtual environment even after installing system packages."
    echo "Please run this manually and then re-run the installer:"
    echo "    sudo apt install python3-venv python3-dev build-essential"
    exit 1
fi

# shellcheck disable=SC1091
source "$INSTALL_DIR/.venv/bin/activate"

echo
echo "[3/6] Copying RocketLogAI source into install directory..."

# Use portable cp instead of rsync (many minimal systems don't have rsync)
cp -r "$SOURCE_ROOT/logsentinel" "$INSTALL_DIR/"
cp -r "$SOURCE_ROOT/templates" "$INSTALL_DIR/"
cp "$SOURCE_ROOT/pyproject.toml" "$INSTALL_DIR/"
cp "$SOURCE_ROOT/requirements.txt" "$INSTALL_DIR/" 2>/dev/null || true
cp "$SOURCE_ROOT/example-config.yaml" "$INSTALL_DIR/" 2>/dev/null || true

# Copy scripts and docs
cp -r "$SOURCE_ROOT/scripts" "$INSTALL_DIR/" 2>/dev/null || true
cp "$SOURCE_ROOT/INSTALL.md" "$INSTALL_DIR/" 2>/dev/null || true
cp "$SOURCE_ROOT/README.md" "$INSTALL_DIR/" 2>/dev/null || true

# Clean any pycache that might have been copied
find "$INSTALL_DIR" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
find "$INSTALL_DIR" -name '*.pyc' -delete 2>/dev/null || true

echo
echo "[4/6] Installing dependencies (this may take a minute)..."
pip install --upgrade pip wheel "setuptools>=65,<81"

cd "$INSTALL_DIR"

# Install the package with web + v2 extras
pip install ".[web,v2]"
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
fi

# Open Interpreter with conflict-safe install (Rust not required for core; OI installed with --no-deps fallback)
echo "Installing AI Assistant extras (open-interpreter + cryptography)..."
pip install "setuptools>=65,<81" 2>/dev/null || true
if ! pip install "open-interpreter>=0.2.0" cryptography 2>/dev/null; then
    echo "Full open-interpreter install failed; trying minimal install..."
    pip install --no-deps open-interpreter cryptography 2>/dev/null || true
fi

# systemd service generation (Linux only)
if [ -d /etc/systemd/system ] && [ "$(uname -s)" = "Linux" ]; then
    SERVICE_FILE="/etc/systemd/system/rocketlogai.service"
    if [ ! -f "$SERVICE_FILE" ]; then
        echo "Generating systemd service template at $INSTALL_DIR/rocketlogai.service ..."
        cat > "$INSTALL_DIR/rocketlogai.service" << EOFSVC
[Unit]
Description=RocketLogAI v2 Syslog Security Platform
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/.venv/bin/logsentinel run --web
Restart=on-failure
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOFSVC
        echo "To enable: sudo cp $INSTALL_DIR/rocketlogai.service $SERVICE_FILE && sudo systemctl enable --now rocketlogai"
    fi
fi

# One more safety pass for common web + security deps
pip install fastapi uvicorn[standard] jinja2 itsdangerous bcrypt pyotp qrcode rich click pyyaml openai geoip2 requests ldap3 python-multipart cryptography 2>/dev/null || true

echo "native" > "$INSTALL_DIR/.install-type"

echo
echo "[5/6] Creating launcher scripts..."

cat > "$INSTALL_DIR/start-rocketlogai.sh" << 'EOF'
#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
source .venv/bin/activate
echo "Starting RocketLogAI..."
echo "Web UI addresses will be shown below (HTTP and HTTPS if enabled)."
echo
logsentinel run --web
EOF
chmod +x "$INSTALL_DIR/start-rocketlogai.sh"

echo
echo "[6/6] Cleaning install folder..."
if [ -f "$SOURCE_ROOT/scripts/rla_cleanup.py" ]; then
    python3 "$SOURCE_ROOT/scripts/rla_cleanup.py" "$INSTALL_DIR" --source "$SOURCE_ROOT" --fix
fi

echo ""
echo "Done!"
echo "Tip: Run ./scripts/setup.sh anytime for install, upgrade, Docker, or repair."
echo ""
echo "Installation complete!"
echo
echo "Next steps:"
echo "  1. cd $INSTALL_DIR"
echo "  2. cp example-config.yaml config.yaml"
echo "  3. Edit config.yaml (especially the llm: section for your model or Microsoft 365 Copilot)"
echo "  4. ./start-rocketlogai.sh"
echo "  5. Open the web UI and change the default admin/admin password immediately"
echo
echo "RocketLogAI v2.0 includes:"
echo "  - Unified AI Brain (MCP server, vector DB/RAG, conversation memory)"
echo "  - RocketRemediate (dry-run, approval, backup, rollback)"
echo "  - RocketShield (WAF + AV on decrypted traffic, parental controls)"
echo "  - RocketAI Mobile API (QR pairing, local-first sync)"
echo "  - UEBA anomaly detection, full audit logging, Prometheus metrics"
echo "  - Organization tasks, per-section config saves, Helm chart"
echo "Install full extras: pip install -e '.[web,ai,v2]'"
echo
echo "To run as a systemd service later, see the notes in INSTALL.md"
echo
