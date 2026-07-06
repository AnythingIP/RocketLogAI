#!/usr/bin/env bash
# RocketLogAI Upgrade Script (Linux / macOS / WSL)
#
# Usage:
#   ./scripts/upgrade.sh [TARGET_DIR] [--native|--docker] [--fix]
#
# Run from a git-cloned RocketLogAI source directory.

set -euo pipefail

SHOW_HELP=false
INSTALL_TYPE=""
FIX=false
TARGET_DIR=""

for arg in "$@"; do
    case "$arg" in
        -h|--help) SHOW_HELP=true ;;
        --native) INSTALL_TYPE="native" ;;
        --docker) INSTALL_TYPE="docker" ;;
        --fix) FIX=true ;;
        *) TARGET_DIR="$arg" ;;
    esac
done

if [ "$SHOW_HELP" = true ]; then
    cat <<'EOF'
RocketLogAI Upgrade

Usage:
  ./scripts/upgrade.sh [TARGET_DIR] [--native|--docker] [--fix]

Options:
  --native   Force native (venv) upgrade
  --docker   Force Docker upgrade
  --fix      Run health check repair after upgrade
  --help     Show this help

Example:
  ./scripts/upgrade.sh ~/logsentinel --native --fix
EOF
    exit 0
fi

echo "RocketLogAI Upgrade"
echo "======================"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SOURCE_ROOT="$(dirname "$SCRIPT_DIR")"

if [ -z "$TARGET_DIR" ]; then
    echo "Enter path to your existing RocketLogAI installation:"
    read -r TARGET_DIR
fi

if [ ! -d "$TARGET_DIR" ]; then
    echo "ERROR: Target directory does not exist: $TARGET_DIR"
    exit 1
fi

TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"

echo "Upgrading: $TARGET_DIR"
echo "Using new code from: $SOURCE_ROOT"
echo

docker_daemon_ok() {
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

detect_install_type() {
    local dir="$1"
    if [ -f "$dir/.install-type" ]; then
        local t
        t="$(tr '[:upper:]' '[:lower:]' < "$dir/.install-type" | tr -d '[:space:]')"
        if [ "$t" = "native" ] || [ "$t" = "docker" ]; then
            echo "$t"
            return
        fi
    fi
    if [ -d "$dir/.venv" ]; then
        echo "native"
        return
    fi
    if docker_daemon_ok; then
        if docker ps -a --filter "name=rocketlogai" --format '{{.Names}}' 2>/dev/null | grep -q rocketlogai; then
            echo "docker"
            return
        fi
    fi
    if [ -f "$dir/config.yaml" ] || [ -f "$dir/data/logsentinel.db" ]; then
        echo "native"
        return
    fi
    if [ -f "$dir/docker-compose.yml" ] && docker_daemon_ok; then
        echo "docker"
        return
    fi
    echo "native"
}

copy_upgrade_files() {
    local dest="$1"
    for d in logsentinel templates scripts helm tests; do
        if [ -d "$SOURCE_ROOT/$d" ]; then
            cp -r "$SOURCE_ROOT/$d" "$dest/"
        fi
    done
    for f in pyproject.toml requirements.txt example-config.yaml Dockerfile docker-compose.yml INSTALL.md README.md; do
        [ -f "$SOURCE_ROOT/$f" ] && cp -f "$SOURCE_ROOT/$f" "$dest/"
    done
    find "$dest" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
    find "$dest" -name '*.pyc' -delete 2>/dev/null || true
}

ensure_venv() {
    local dir="$1"
    if [ -d "$dir/.venv/bin" ]; then
        return 0
    fi
    echo "No .venv found — creating one..."
    python3 -m venv "$dir/.venv"
}

install_native_package() {
    local dir="$1"
    ensure_venv "$dir"
    # shellcheck disable=SC1091
    source "$dir/.venv/bin/activate"
    pip install --upgrade pip setuptools wheel
    cd "$dir"
    pip install -e ".[web,v2,ai]" --upgrade
    pip install open-interpreter cryptography --upgrade 2>/dev/null || true
    echo "native" > "$dir/.install-type"
    cat > "$dir/start-rocketlogai.sh" << 'EOF'
#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
source .venv/bin/activate
echo "Starting RocketLogAI..."
logsentinel run --web
EOF
    chmod +x "$dir/start-rocketlogai.sh"
}

if [ -z "$INSTALL_TYPE" ]; then
    INSTALL_TYPE="$(detect_install_type "$TARGET_DIR")"
fi

echo "[detected] Install type: $INSTALL_TYPE"

if [ "$INSTALL_TYPE" = "docker" ]; then
    if ! docker_daemon_ok; then
        echo "ERROR: Docker install detected but Docker daemon is not running."
        echo "Start Docker, or re-run with --native if this is a Python install."
        exit 1
    fi

    echo
    echo "[1/3] Stopping Docker service..."
    (cd "$TARGET_DIR" && docker compose down)

    echo
    echo "[2/3] Copying updated files..."
    copy_upgrade_files "$TARGET_DIR"
    echo "docker" > "$TARGET_DIR/.install-type"

    echo
    echo "[3/3] Rebuilding and restarting container..."
    (cd "$TARGET_DIR" && docker compose build --no-cache && docker compose up -d)

    echo
    echo "Docker upgrade complete!"
else
    echo
    echo "[1/4] Stopping service if running..."
    if command -v systemctl >/dev/null 2>&1; then
        sudo systemctl stop rocketlogai 2>/dev/null || true
        sudo systemctl stop logsentinel 2>/dev/null || true
    fi
    pkill -f "logsentinel run" 2>/dev/null || true

    echo
    echo "[2/4] Copying updated code..."
    copy_upgrade_files "$TARGET_DIR"

    echo
    echo "[3/4] Installing/upgrading Python package..."
    install_native_package "$TARGET_DIR"

    echo
    echo "[4/4] Verifying installation..."
    "$TARGET_DIR/.venv/bin/python" -c "import logsentinel; print('RocketLogAI', logsentinel.__version__)"

    echo
    echo "Native upgrade complete!"
    echo
    echo "Start with:"
    echo "  cd $TARGET_DIR && ./start-rocketlogai.sh"
fi

if [ "$FIX" = true ] && [ -f "$SOURCE_ROOT/scripts/healthcheck.py" ]; then
    echo
    echo "Running health check repair..."
    python3 "$SOURCE_ROOT/scripts/healthcheck.py" "$TARGET_DIR" --fix || true
fi

echo
echo "Your config.yaml and data/ were preserved."
echo "Open http://localhost:8787 and verify the dashboard."
echo