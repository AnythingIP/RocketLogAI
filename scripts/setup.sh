#!/usr/bin/env bash
# RocketLogAI one-click setup wizard (Linux / macOS / WSL)
# Usage: ./scripts/setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="$(dirname "$SCRIPT_DIR")"

show_help() {
    cat <<'EOF'
RocketLogAI Setup Wizard

  ./scripts/setup.sh

Guides you through fresh install, Docker install, upgrade, or health check.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    show_help
    exit 0
fi

echo ""
echo "========================================"
echo "  RocketLogAI v2 Setup Wizard"
echo "========================================"
echo ""
echo "Recommended: Python 3.12 for native installs (full AI Operator support)"
echo "Docker installs use Python 3.12 inside the container automatically."
echo ""
echo "What would you like to do?"
echo "  1) Fresh install (Python / native)"
echo "  2) Fresh install (Docker)"
echo "  3) Upgrade existing installation"
echo "  4) Health check / repair"
echo "  5) Restore from backup"
echo ""
read -r -p "Enter choice [1-5] (default 1): " choice
choice="${choice:-1}"

case "$choice" in
    1)
        "$SCRIPT_DIR/install.sh"
        ;;
    2)
        "$SCRIPT_DIR/install-docker.sh"
        ;;
    3)
        read -r -p "Existing install directory (e.g. ~/logsentinel): " target
        if [ -z "$target" ]; then
            echo "ERROR: Install directory required."
            exit 1
        fi
        "$SCRIPT_DIR/upgrade.sh" "$target" --native --fix
        ;;
    4)
        read -r -p "Install directory to check (default: ~/logsentinel): " target
        target="${target:-$HOME/logsentinel}"
        "$SCRIPT_DIR/check.sh" "$target" --fix
        ;;
    5)
        read -r -p "Install directory: " target
        read -r -p "Backup folder path (under install/backups/...): " backup
        if [ -z "$target" ] || [ -z "$backup" ]; then
            echo "ERROR: Both paths required."
            exit 1
        fi
        python3 "$SCRIPT_DIR/rla_backup.py" "$target" --restore "$backup"
        ;;
    *)
        echo "Invalid choice."
        exit 1
        ;;
esac