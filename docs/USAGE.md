# docs/USAGE.md — Guide d'utilisation SecurePipeline

# Utilisation de SecurePipeline

SecurePipeline est un scanner de sécurité CLI multi-stack. Ce guide couvre toutes
les modalités d'utilisation : interactif, headless, Docker et CI/CD.

---

## Prérequis

Assurez-vous d'avoir suivi le guide [INSTALL.md](./INSTALL.md) et que l'environnement
virtuel est activé (`source .venv/bin/activate`).

---

## Mode Interactif (usage local)

Lance le menu terminal guidé :

```bash
securepipeline scan /chemin/vers/votre/projet
```

L'outil :
1. Détecte automatiquement les stacks présentes (Python, Node, PHP, Flutter, Docker, K8s)
2. Lance les scanners correspondants
3. Affiche le résumé dans le terminal
4. Génère un rapport dans `.securepipeline/reports/`

---

## Mode Headless (CI/CD)

Idéal pour les pipelines automatisés. Aucune interaction requise.

```bash
# Échoue avec code 1 si des vulnérabilités critiques sont trouvées
securepipeline scan . --fail-on critical

# Modifier le seuil d'échec
securepipeline scan . --fail-on high

# Choisir le format de rapport
securepipeline scan . --format markdown
securepipeline scan . --format html
securepipeline scan . --format both
```

Le rapport est écrit dans `.securepipeline/reports/securepipeline-report.md` (et/ou `.html`).

---

## Via Docker (sans installation Python locale)

```bash
# Scanner le répertoire courant
docker run --rm \
  -v "$(pwd):/project:ro" \
  -v "$(pwd)/.securepipeline:/project/.securepipeline" \
  securepipeline:latest scan /project

# Avec seuil d'échec
docker run --rm \
  -v "$(pwd):/project:ro" \
  -v "$(pwd)/.securepipeline:/project/.securepipeline" \
  securepipeline:latest scan /project --fail-on critical
```

### Via docker-compose

```bash
# Build + scan du répertoire courant
docker compose run --rm scanner

# Avec arguments personnalisés
docker compose run --rm scanner scan /project --fail-on high
```

---

## Exemples de rapports

### Résumé terminal (mode interactif)

```
╔══════════════════════════════════════════════╗
║         SecurePipeline — Résultats           ║
╠══════════════════════════════════════════════╣
║  Stacks détectées : python, docker           ║
║  Findings total   : 12                       ║
║  ├─ CRITICAL : 1                             ║
║  ├─ HIGH     : 3                             ║
║  ├─ MEDIUM   : 6                             ║
║  └─ LOW/INFO : 2                             ║
╚══════════════════════════════════════════════╝
```

### Rapport Markdown

Le rapport Markdown `.securepipeline/reports/securepipeline-report.md` contient :
- Résumé exécutif (stacks, durée, compteurs par sévérité)
- Section par scanner (pip-audit, Bandit, Semgrep, Trivy, Hadolint, Gitleaks, kube-score, Checkov, kubesec)
- Détail de chaque finding : règle, fichier, ligne, description, remédiation

---

## Codes de sortie

| Code | Signification |
|------|---------------|
| `0`  | Scan terminé sans finding au-dessus du seuil |
| `1`  | Au moins un finding au-dessus du seuil `--fail-on` |
| `2`  | Erreur critique (projet inaccessible, crash inattendu) |

---

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `SECUREPIPELINE_LOG_LEVEL` | `INFO` | Verbosité du log (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `SECUREPIPELINE_FAIL_ON` | `critical` | Seuil de sévérité pour l'exit code 1 |
| `SECUREPIPELINE_REPORT_DIR` | `.securepipeline/reports` | Répertoire de sortie des rapports |

---

## Dépannage

**"Outil X non installé, module ignoré"**
→ L'outil est absent du PATH. Relancez `./install.sh` ou installez-le manuellement.

**Aucun finding alors que des vulnérabilités sont connues**
→ Vérifiez que l'outil externe retourne bien du JSON valide :
```bash
semgrep scan --json /votre/projet
pip-audit --format json --output -
```

**Le rapport est vide**
→ Vérifiez les droits d'écriture sur `.securepipeline/reports/`.
