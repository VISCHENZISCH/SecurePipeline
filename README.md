# SecurePipeline

**SecurePipeline** est un outil CLI DevSecOps multi-stack, conçu pour analyser automatiquement un dépôt de code, détecter les stacks technologiques présentes et exécuter les contrôles de sécurité adaptés de manière transparente.

## Fonctionnalités

- **Détection Automatique** : Identifie la stack (Python, Node.js, PHP, Flutter, Docker, Kubernetes) sans configuration.
- **Analyse Statique (SAST)** : Utilise Semgrep et Bandit pour détecter les patterns de code dangereux.
- **Audit de Dépendances** : Scanne les vulnérabilités (CVE) via npm audit, composer audit, pip-audit et dart pub.
- **Audit d'Infrastructure (IaC)** : Linting de Dockerfile (Hadolint), scan d'images (Trivy), analyse de manifests K8s (kube-score, Checkov).
- **Détection de Secrets** : Recherche de clés API, tokens et mots de passe avec Gitleaks.
- **Intégration CI/CD** : Mode headless parfait pour GitHub Actions avec génération de rapports Markdown.
- **Interface CLI interactive** : Menu terminal léger sans dépendance d'affichage externe.

## Installation

### Via Python (Recommandé pour usage local)

```bash
# 1. Cloner le projet
git clone https://github.com/votre-org/securepipeline.git
cd securepipeline

# 2. Créer un environnement virtuel
python3 -m venv .venv
source .venv/bin/activate

# 3. Installer
pip install -e .
```

*Note : Les outils de sécurité (trivy, semgrep, gitleaks, etc.) doivent être installés sur votre système.*

### Via Docker (Recommandé pour CI/CD)

L'image Docker contient toutes les dépendances requises :

```bash
docker build -t securepipeline:latest .
docker run --rm -v $(pwd):/app securepipeline scan /app
```

## Utilisation

### Mode Interactif

Lance le menu interactif terminal :

```bash
securepipeline scan /chemin/vers/projet
```

### Mode CI/CD (Headless)

Idéal pour les pipelines automatisés. Échoue avec un code `1` si des vulnérabilités critiques sont trouvées :

```bash
securepipeline scan . --interactive=false --fail-on critical
```

*Le rapport sera généré dans `.securepipeline/reports/securepipeline-report.md`.*

## Architecture des Modules

| Stack | Outils Intégrés |
|---|---|
| **Global** | Gitleaks (Secrets) |
| **Python** | pip-audit (Dépendances), Bandit (SAST), Semgrep |
| **Node.js** | npm audit, Semgrep |
| **PHP** | composer audit, Semgrep |
| **Flutter**| dart pub outdated, Semgrep |
| **Docker** | Hadolint (Dockerfile), Trivy (Image) |
| **Kubernetes**| kube-score, Checkov |
