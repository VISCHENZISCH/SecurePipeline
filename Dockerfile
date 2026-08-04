FROM python:3.11-slim

# Éviter les prompts lors des installations apt
ENV DEBIAN_FRONTEND=noninteractive

# Installer les dépendances systèmes de base
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    curl \
    git \
    apt-transport-https \
    gnupg \
    lsb-release \
    # Ajout d'outils requis
    npm \
    php-cli \
    composer \
    && rm -rf /var/lib/apt/lists/*

# Installer Trivy
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - \
    && echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | tee -a /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy \
    && rm -rf /var/lib/apt/lists/*

# Installer Hadolint
RUN wget -O /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 \
    && chmod +x /usr/local/bin/hadolint

# Installer Gitleaks
RUN wget -qO- https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks

# Préparer l'application
WORKDIR /app
COPY pyproject.toml README.md ./
COPY securepipeline/ securepipeline/

# Installer SecurePipeline et les dépendances Python (semgrep, bandit, etc.)
RUN pip install --no-cache-dir -e . \
    && pip install --no-cache-dir semgrep bandit pip-audit checkov

ENTRYPOINT ["securepipeline"]
CMD ["--help"]
