# DevSecOps guide: best practices

This guide summarizes the core practices behind **SecurePipeline**, covering the DevSecOps lifecycle from building a Docker image to deploying on Kubernetes.

## Docker best practices

1. **Minimal base images**
   - Prefer `alpine`, `distroless` or `-slim` (for example `python:3.11-slim`) to reduce the attack surface.

2. **Non-root user**
   - Always create a dedicated user with restricted rights. Never run the application as `root`.
   ```dockerfile
   RUN useradd -m appuser
   USER appuser
   ```

3. **Multi-stage builds**
   - Separate the build environment (with its compilers) from the runtime environment. The final image should contain only the required binaries and dependencies.

4. **Secret management**
   - Never bake secrets into the image. Pass them at runtime through environment variables or, ideally, a secret manager (Vault, Kubernetes Secrets).
   - *SecurePipeline tools: `trivy` and `hadolint` (Dockerfile checks).*

## Kubernetes best practices

1. **Security contexts**
   - Always apply a security context to Pods.
   ```yaml
   securityContext:
     runAsNonRoot: true
     readOnlyRootFilesystem: true
     allowPrivilegeEscalation: false
     capabilities:
       drop: ["ALL"]
   ```

2. **Resource limits**
   - Always define CPU and memory `requests` and `limits` to limit denial of service and node exhaustion.

3. **Network policies**
   - Set up a default policy that blocks all traffic (`DefaultDeny`), then explicitly open the required ports.

4. **Kubernetes secrets**
   - Never store sensitive data in plain text in ConfigMaps. Use `Secrets` (preferably encrypted at rest in etcd) or external solutions such as ExternalSecrets.
   - *SecurePipeline tools: `kube-score` and `checkov`.*

## Secure continuous integration (CI/CD)

1. **Continuous scanning (shift left)**
   - Build security in from the commit (pre-commit hooks) and on every pull request (SAST, SCA). Do not allow a merge when a critical vulnerability is detected.
   - *SecurePipeline tool: the GitHub Action in `.github/workflows/securepipeline.yml`.*

2. **Least privilege**
   - Limit GitHub Actions token permissions (`permissions: contents: read`).

3. **Secret detection (Gitleaks)**
   - A secret scan (Gitleaks) should run on every repository. A secret pushed to Git must be considered compromised and revoked immediately.
