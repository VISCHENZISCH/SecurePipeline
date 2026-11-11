#!/usr/bin/env bash
set -e

# Work from the repository, wherever the script is called from.
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

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

# Make the command available from any folder through ~/.local/bin.
# The scan tools are found next to the .venv Python, so a link is enough.
BIN_DIR="$HOME/.local/bin"
LINK="$BIN_DIR/securepipeline"
TARGET="$ROOT/.venv/bin/securepipeline"
mkdir -p "$BIN_DIR"
if [ -e "$LINK" ] && [ ! -L "$LINK" ]; then
    echo "[!] $LINK already exists and is not a link: left unchanged."
else
    ln -sfn "$TARGET" "$LINK"
    echo "[+] Command linked: $LINK"
fi

echo
printf '*%.0s' $(seq 1 80); echo
echo "Installation completed successfully!"
echo "To scan a project, go to its folder and start the tool:"
echo "  cd /path/to/your/project"
case ":$PATH:" in
    *":$BIN_DIR:"*)
        echo "  securepipeline"
        ;;
    *)
        echo "  $TARGET"
        echo
        echo "To type only 'securepipeline', add $BIN_DIR to your PATH:"
        echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
        ;;
esac
