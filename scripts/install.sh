#!/usr/bin/env bash
# RocketLogAI one-click installer for Linux / macOS / WSL
# Run this from the extracted RocketLogAI-v1.3-Installer directory (or current source)

set -e

echo "🚀 RocketLogAI Installer"
echo "========================"

# Determine where this script lives (source of truth for files to copy)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SOURCE_ROOT="$(dirname "$SCRIPT_DIR")"   # parent of scripts/ = the installer root

INSTALL_DIR="${1:-$HOME/logsentinel}"

echo "Installing to: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

echo
echo "[1/5] Checking Python 3.10+ ..."
if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3.10 or newer is required."
    exit 1
fi
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "Found Python $PYTHON_VERSION"

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
echo "[2/5] Creating virtual environment..."
if ! python3 -m venv "$INSTALL_DIR/.venv"; then
    echo ""
    echo "ERROR: Failed to create virtual environment even after installing system packages."
    echo "Please run this manually and then re-run the installer:"
    echo "    sudo apt install python3-venv python3-dev build-essential"
    exit 1
fi

# shellcheck disable=SC1091
source "$INSTALL_DIR/.venv/bin/activate"

echo
echo "[3/5] Copying RocketLogAI source into install directory..."

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
echo "[4/5] Installing dependencies (this may take a minute)..."
pip install --upgrade pip setuptools wheel

cd "$INSTALL_DIR"

# Install the package with web extras + any requirements.txt as belt-and-suspenders
pip install ".[web]"
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
fi

# One more safety pass for common web + security deps
pip install fastapi uvicorn[standard] jinja2 itsdangerous bcrypt pyotp qrcode rich click pyyaml openai geoip2 requests ldap3 python-multipart 2>/dev/null || true

echo
echo "[5/5] Creating launcher scripts..."

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
echo "✅ Installation complete!"
echo
echo "Next steps:"
echo "  1. cd $INSTALL_DIR"
echo "  2. cp example-config.yaml config.yaml"
echo "  3. Edit config.yaml (especially the llm: section for your model or Microsoft 365 Copilot)"
echo "  4. ./start-rocketlogai.sh"
echo "  5. Open the web UI and change the default admin/admin password immediately"
echo
echo "New in v1.3: Daily Briefing (/daily) - the Operator Companion. Chat with the crew about what happened that day/shift, get context-aware scripts, and promote fixes to monitors."
echo "Also: improved Ollama support + clearer LLM config UI separating local vs cloud."
echo
echo "To run as a systemd service later, see the notes in INSTALL.md"
echo
