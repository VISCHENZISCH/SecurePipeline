# Guide d'Installation de SecurePipeline

L'installation de SecurePipeline a été entièrement automatisée. Les scripts d'installation se chargent de configurer un environnement virtuel Python et de télécharger toutes les dépendances ainsi que les binaires de sécurité externes (Trivy, Gitleaks, Hadolint, kube-score) pour qu'ils soient accessibles uniquement depuis l'environnement du projet.

## Prérequis

Avant de lancer l'installation, assurez-vous d'avoir :
- **Python 3.11+** installé et ajouté au PATH.
- **Git** installé et ajouté au PATH.

*(Note : Pour le scan d'infrastructures locales spécifiques comme Node.js ou PHP, assurez-vous d'avoir `npm` ou `php-cli` installés sur votre système).*

---

##  Installation Automatique

### Sous Linux / macOS

1. Ouvrez un terminal dans le dossier du projet.
2. Rendez le script exécutable et lancez-le :
   ```bash
   chmod +x install.sh
   ./install.sh
   ```

### Sous Windows

1. Ouvrez **PowerShell** dans le dossier du projet.
2. Exécutez le script d'installation :
   ```powershell
   .\install.ps1
   ```
   *(Si l'exécution des scripts est désactivée, lancez d'abord `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

---

##  Utilisation

L'outil installe tous les utilitaires directement dans son propre environnement virtuel pour ne pas polluer votre système. Par conséquent, vous devez **toujours activer l'environnement** avant de l'utiliser.

### 1. Activer l'environnement

**Sous Linux / macOS :**
```bash
source .venv/bin/activate
```

**Sous Windows (PowerShell) :**
```powershell
.\.venv\Scripts\Activate.ps1
```

### 2. Lancer l'outil

Une fois l'environnement activé (vous verrez un préfixe `(.venv)` dans votre terminal), lancez simplement l'outil :
```bash
securepipeline
```

> [!TIP]
> Pour quitter l'environnement virtuel après votre session, tapez la commande `deactivate`.
