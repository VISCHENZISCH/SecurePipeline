# Guide DevSecOps - Bonnes Pratiques

Ce guide récapitule les bonnes pratiques fondamentales mises en place au sein du projet **SecurePipeline**, couvrant le cycle de vie DevSecOps de la création de l'image Docker au déploiement Kubernetes.

## Bonnes Pratiques Docker

1. **Images de base minimales**
   - Préférez `alpine`, `distroless` ou `-slim` (ex: `python:3.11-slim`) pour réduire la surface d'attaque.
   
2. **Utilisateur Non-Root**
   - Créez toujours un utilisateur dédié avec des droits restreints. Ne faites jamais tourner l'application en `root`.
   ```dockerfile
   RUN useradd -m appuser
   USER appuser
   ```

3. **Multi-Stage Builds**
   - Séparez l'environnement de build (contenant les compilateurs) de l'environnement d'exécution. L'image finale ne doit contenir que les binaires/dépendances nécessaires.

4. **Gestion des Secrets**
   - N'intégrez jamais de secrets dans l'image. Passez-les à l'exécution via des variables d'environnement, ou idéalement, via un gestionnaire de secrets (Vault, Kubernetes Secrets).
   - *Outil dans SecurePipeline : `trivy` et `hadolint` (vérification du Dockerfile).*

## Bonnes Pratiques Kubernetes

1. **Contextes de Sécurité (SecurityContext)**
   - Appliquez systématiquement un contexte de sécurité sur les Pods.
   ```yaml
   securityContext:
     runAsNonRoot: true
     readOnlyRootFilesystem: true
     allowPrivilegeEscalation: false
     capabilities:
       drop: ["ALL"]
   ```

2. **Limites de Ressources**
   - Définissez toujours les `requests` et `limits` pour le CPU et la RAM afin d'éviter les attaques par déni de service (DDoS) et l'épuisement des nœuds.

3. **Network Policies**
   - Mettez en place une politique réseau par défaut qui bloque tout le trafic (`DefaultDeny`), puis ouvrez explicitement les ports nécessaires.

4. **Secrets Kubernetes**
   - Ne stockez jamais de données sensibles en clair dans des ConfigMaps. Utilisez des `Secrets` (de préférence chiffrés au repos dans etcd) ou des solutions externes type ExternalSecrets.
   - *Outil dans SecurePipeline : `kube-score` et `checkov`.*

## Intégration Continue (CI/CD) Sécurisée

1. **Scan Continu (Shift-Left)**
   - Intégrez la sécurité dès le commit (via des pre-commit hooks) et à chaque Pull Request (SAST, SCA). Ne permettez pas le merge si une faille critique est détectée.
   - *Outil dans SecurePipeline : Action GitHub `.github/workflows/securepipeline.yml`.*

2. **Moindre Privilège**
   - Limitez les permissions des jetons GitHub Actions (`permissions: contents: read`).

3. **Détection de Secrets (Gitleaks)**
   - Un scan de secrets (Gitleaks) doit tourner sur tous les dépôts systématiquement. Un secret poussé sur Git doit être considéré comme compromis et révoqué immédiatement.
