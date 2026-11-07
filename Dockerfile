FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends git npm php-cli composer \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY securepipeline/ securepipeline/

RUN pip install ".[tools]" \
    && securepipeline tools install --yes --bin-dir /usr/local/bin

# The mounted repository belongs to another user, which git would otherwise refuse.
RUN git config --system --add safe.directory '*' \
    && useradd --uid 1000 --create-home scanner \
    && install -d -m 1777 /cache

# HOME points to /tmp so that the container's root filesystem can stay read-only.
ENV HOME=/tmp \
    TRIVY_CACHE_DIR=/cache/trivy

USER 1000
WORKDIR /project

ENTRYPOINT ["securepipeline"]
CMD ["--help"]
