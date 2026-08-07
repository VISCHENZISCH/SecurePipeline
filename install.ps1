Write-Host "#################### SecurePipeline #####################"
Write-Host "                    Installation Windows                   "
Write-Host "#################### SecurePipeline #####################"

if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Host "[!] python n'est pas installé. Veuillez l'installer (3.11+)." -ForegroundColor Red
    exit 1
}

if (-not (Get-Command "git" -ErrorAction SilentlyContinue)) {
    Write-Host "[!] git n'est pas installé. Veuillez l'installer." -ForegroundColor Red
    exit 1
}

Write-Host "[+] Création de l'environnement virtuel .venv..." -ForegroundColor Green
python -m venv .venv
# On ajoute temporairement au PATH pour le script courant
$env:Path = "$PWD\.venv\Scripts;$env:Path"

Write-Host "[+] Installation du projet et des outils Python..." -ForegroundColor Green
python -m pip install --upgrade pip
python -m pip install -e .[dev]
python -m pip install semgrep bandit pip-audit checkov

$BinDir = "$PWD\.venv\Scripts"

Write-Host "[+] Téléchargement de Gitleaks..." -ForegroundColor Green
Invoke-WebRequest -Uri "https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_windows_x64.zip" -OutFile "$BinDir\gitleaks.zip"
Expand-Archive -Path "$BinDir\gitleaks.zip" -DestinationPath "$BinDir" -Force
Remove-Item "$BinDir\gitleaks.zip"

Write-Host "[+] Téléchargement de Trivy..." -ForegroundColor Green
Invoke-WebRequest -Uri "https://github.com/aquasecurity/trivy/releases/download/v0.49.1/trivy_0.49.1_Windows-64bit.zip" -OutFile "$BinDir\trivy.zip"
Expand-Archive -Path "$BinDir\trivy.zip" -DestinationPath "$BinDir" -Force
Remove-Item "$BinDir\trivy.zip"

Write-Host "[+] Téléchargement de Hadolint..." -ForegroundColor Green
Invoke-WebRequest -Uri "https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Windows-x86_64.exe" -OutFile "$BinDir\hadolint.exe"

Write-Host "[+] Téléchargement de kube-score..." -ForegroundColor Green
Invoke-WebRequest -Uri "https://github.com/zegl/kube-score/releases/download/v1.17.0/kube-score_1.17.0_windows_amd64.exe" -OutFile "$BinDir\kube-score.exe"

Write-Host "#################### SecurePipeline #####################"
Write-Host "Installation terminée avec succès !" -ForegroundColor Green
Write-Host "Pour lancer l'outil, activez d'abord l'environnement :"
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "  securepipeline"
