#!/usr/bin/env bash
# RocketLogAI installer for Linux / macOS / WSL

set -e

echo "🚀 RocketLogAI Installer"
echo "========================"

INSTALL_DIR="${1:-$HOME/logsentinel}"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo
echo "[1/4] Checking Python..."
if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3.10+ is required."
    exit 1
fi
python3 --version

echo
echo "[2/4] Creating virtual environment..."
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo
echo "[3/4] Installing with web dashboard + secure password hashing..."
pip install --upgrade pip setuptools wheel
pip install -e ".[web]"
[ -f requirements.txt ] && pip install -r requirements.txt

echo
echo "[4/4] Creating launcher..."

cat > start-rocketlogai.sh << 'EOF'
#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
source .venv/bin/activate
echo "Starting RocketLogAI..."
echo "Web UI → check the startup messages (HTTP on your web_port, HTTPS on https_port if enabled in config)"
logsentinel run --web
EOF
chmod +x start-rocketlogai.sh

echo
echo "✅ Done!"
echo
echo "Next steps:"
echo "  1. (Optional) Edit config.yaml  (set web_host, web_port, https_port, http_enabled, ssl_enabled as needed)"
echo "  2. ./start-rocketlogai.sh"
echo "  3. Change the default admin password right away (Users page in the UI)"
echo
echo "Your credentials are now stored hashed in the database."
echo "To move elsewhere later: copy the entire folder (especially the data/ directory with DB, certs, and learned data)."
echo
