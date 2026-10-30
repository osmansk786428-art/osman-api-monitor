#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"
if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
elif command -v python >/dev/null 2>&1; then
    PYTHON=python
else
    echo "Python 3 is not installed." >&2
    exit 1
fi
"$PYTHON" --version
exec "$PYTHON" "$SCRIPT_DIR/api_monitor_v7.0.py"
