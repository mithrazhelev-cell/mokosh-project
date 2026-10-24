#!/usr/bin/env bash
set -euo pipefail

# Private files created by MOKOSH must never be group/world readable.
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
VENV_DIR="${MOKOSH_VENV_DIR:-$HOME/venv_sys}"

if [[ ! -x "$VENV_DIR/bin/python3" ]]; then
    printf 'MOKOSH: Python environment not found: %s\n' "$VENV_DIR" >&2
    exit 1
fi

cd "$SCRIPT_DIR"
exec "$VENV_DIR/bin/python3" "$SCRIPT_DIR/mokosh_gui.py"
