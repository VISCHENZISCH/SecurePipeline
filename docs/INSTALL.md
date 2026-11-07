# Installation guide

The installation scripts create a virtual environment and install the project and its security tools into it. The binaries (Gitleaks, Trivy, Hadolint, kube-score, kubesec) use pinned versions and are verified with SHA-256 before being installed.

## Prerequisites

- **Python 3.11+** and **Git** on the PATH.
- Depending on the stacks to scan: `npm`, `composer` or `dart`, which these scripts do not install.

---

## Automatic installation

### Linux / macOS

```bash
./install.sh
```

### Windows

```powershell
.\install.ps1
```

*(If script execution is disabled, first run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.)*

kubesec has no Windows binary: on this system, a Kubernetes project gives an incomplete scan (code 2), unless you use `--allow-incomplete`.

---

## Usage

The tool finds the binaries of its virtual environment by itself. You can activate the environment or call the executable directly:

```bash
.venv/bin/securepipeline                  # Linux / macOS
.\.venv\Scripts\securepipeline.exe        # Windows
```

---

## Managing tools

```bash
securepipeline tools check                # Status of each tool
securepipeline tools install              # Install the missing ones
securepipeline tools install trivy        # Reinstall a specific tool
securepipeline tools install --yes --bin-dir /usr/local/bin
```

Binaries go to the active virtual environment, otherwise to `~/.local/bin`. Versions are defined in one place: [securepipeline/tools/catalog.py](../securepipeline/tools/catalog.py).

## Platforms

Binaries are available for Linux and macOS (amd64 and arm64) and Windows (amd64), with two exceptions: no Hadolint for macOS arm64, and no kubesec for Windows.
