#!/usr/bin/env bash
set -e

banner() {
    local title="$1" width="${2:-80}"
    local left=$(( (width - ${#title}) / 2 ))
    printf '%*s\n' "$width" '' | tr ' ' '*'
    printf '%*s%s\n' "$left" '' "$title"
    printf '%*s\n' "$width" '' | tr ' ' '*'
}
banner "Linux installation"
echo .
if ! command -v python3 &> /dev/null; then
    echo "[!] python3 is not installed. Please install it (3.11+)."
    exit 1
fi

if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
    echo "[!] Python 3.11 or newer is required."
    exit 1
fi

if ! command -v git &> /dev/null; then
    echo "[!] git is not installed. Please install it."
    exit 1
fi

echo "[+] Creating the .venv virtual environment..."
python3 -m venv .venv

echo "[+] Installing the project and the Python tools..."
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet -e ".[dev,tools]"

echo "[+] Installing the binaries (pinned versions and SHA-256)..."
.venv/bin/securepipeline tools install --yes

echo
printf '*%.0s' $(seq 1 80); echo
echo "Installation completed successfully!"
echo "To start the tool:"
echo "  .venv/bin/securepipeline"
