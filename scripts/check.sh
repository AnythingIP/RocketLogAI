#!/usr/bin/env bash
# RocketLogAI Health Check (Linux / macOS / WSL)
# Usage:
#   ./scripts/check.sh [INSTALL_DIR] [--fix]

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SOURCE_ROOT="$(dirname "$SCRIPT_DIR")"
HEALTHCHECK="$SOURCE_ROOT/scripts/healthcheck.py"

INSTALL_DIR=""
FIX=false

for arg in "$@"; do
    case "$arg" in
        -h|--help)
            cat <<'EOF'
RocketLogAI Health Check

Usage:
  ./scripts/check.sh [INSTALL_DIR] [--fix]

  --fix   Attempt automatic repair (create venv, reinstall deps)
EOF
            exit 0
            ;;
        --fix) FIX=true ;;
        *) INSTALL_DIR="$arg" ;;
    esac
done

if [ -z "$INSTALL_DIR" ]; then
    if [ -f "./config.yaml" ]; then
        INSTALL_DIR="$(pwd)"
    else
        read -r -p "Enter RocketLogAI install directory (default: ~/logsentinel): " INSTALL_DIR
        INSTALL_DIR="${INSTALL_DIR:-$HOME/logsentinel}"
    fi
fi

if [ ! -f "$HEALTHCHECK" ]; then
    echo "ERROR: healthcheck.py not found at $HEALTHCHECK"
    exit 1
fi

ARGS=("$HEALTHCHECK" "$INSTALL_DIR")
if [ "$FIX" = true ]; then
    ARGS+=("--fix")
fi

python3 "${ARGS[@]}"