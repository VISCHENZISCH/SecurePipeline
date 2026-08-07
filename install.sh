#!/usr/bin/env bash
set -e

echo "#################### SecurePipeline #####################"
echo "                    Installation Linux                   "
echo "#################### SecurePipeline #####################"

if ! command -v python3 &> /dev/null; then
    echo "[!] python3 n'est pas installé. Veuillez l'installer (3.11+)."
    exit 1
fi

if ! command -v git &> /dev/null; then
    echo "[!] git n'est pas installé. Veuillez l'installer."
    exit 1
fi

echo "[+] Création de l'environnement virtuel .venv..."
python3 -m venv .venv
source .venv/bin/activate

echo "[+] Installation du projet et des outils Python..."
pip install --upgrade pip
pip install -e .[dev]
pip install semgrep bandit pip-audit checkov

BIN_DIR=".venv/bin"

echo "[+] Téléchargement de Gitleaks..."
curl -sL "https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz" | tar -xz -C $BIN_DIR gitleaks

echo "[+] Téléchargement de Trivy..."
curl -sL "https://github.com/aquasecurity/trivy/releases/download/v0.49.1/trivy_0.49.1_Linux-64bit.tar.gz" | tar -xz -C $BIN_DIR trivy

echo "[+] Téléchargement de Hadolint..."
curl -sLo $BIN_DIR/hadolint "https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64"
chmod +x $BIN_DIR/hadolint

echo "[+] Téléchargement de kube-score..."
curl -sLo $BIN_DIR/kube-score "https://github.com/zegl/kube-score/releases/download/v1.17.0/kube-score_1.17.0_linux_amd64"
chmod +x $BIN_DIR/kube-score

echo "################### SecurePipeline ###################"
echo "Installation terminée avec succès !"
echo "Pour lancer l'outil, activez d'abord l'environnement :"
echo "  source .venv/bin/activate"
echo "  securepipeline"
