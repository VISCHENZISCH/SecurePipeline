<h1 align="center">SecurePipeline</h1>

<p align="center">
  <strong>Multi-stack DevSecOps security scanner for your terminal and your CI.</strong>
</p>

<p align="center">
  Created by <a href="https://github.com/VISCHENZISCH"><strong>Félix TOVIGNAN</strong></a>
  ·
  <a href="https://github.com/VISCHENZISCH/SecurePipeline"><strong>VISCHENZISCH/SecurePipeline</strong></a>
</p>

<p align="center">
  <a href="https://github.com/VISCHENZISCH/SecurePipeline/stargazers"><img src="https://img.shields.io/github/stars/VISCHENZISCH/SecurePipeline?style=flat" alt="GitHub stars"></a>
  <a href="https://github.com/VISCHENZISCH/SecurePipeline/commits/main"><img src="https://img.shields.io/github/last-commit/VISCHENZISCH/SecurePipeline" alt="Last commit"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-3776AB" alt="Python 3.11+">
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-policy-brightgreen" alt="Security policy"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license"></a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/python.svg" width="36" height="36" alt="Python" title="Python">&nbsp;&nbsp;
  <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/nodedotjs.svg" width="36" height="36" alt="Node.js" title="Node.js">&nbsp;&nbsp;
  <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/php.svg" width="36" height="36" alt="PHP" title="PHP">&nbsp;&nbsp;
  <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/flutter.svg" width="36" height="36" alt="Flutter" title="Flutter">&nbsp;&nbsp;
  <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/docker.svg" width="36" height="36" alt="Docker" title="Docker">&nbsp;&nbsp;
  <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/kubernetes.svg" width="36" height="36" alt="Kubernetes" title="Kubernetes">&nbsp;&nbsp;
  <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/githubactions.svg" width="36" height="36" alt="GitHub Actions" title="GitHub Actions">
</p>

SecurePipeline detects the technologies in a repository, runs the matching security tools in parallel, and clearly reports anything it could not verify.

## Features

- **Automatic detection**: Python, Node.js, PHP, Flutter, Docker and Kubernetes, with no configuration.
- **Fast by design**: tools run in parallel, Semgrep runs once for all stacks, and dependency folders are skipped.
- **Static analysis**: Semgrep and Bandit, plus bundled rules for JavaScript/TypeScript and PHP.
- **Dependency audit**: pip-audit, npm audit, composer audit and dart pub outdated.
- **Infrastructure audit**: Hadolint, Trivy, kube-score, Checkov and kubesec.
- **Secret detection**: Gitleaks runs on every project, and secrets are redacted from reports.
- **Reliable results**: a missing or failing tool makes the scan "incomplete" instead of declaring it clean.
- **Verified tools**: binaries use pinned versions and are checked against a SHA-256 before being installed.
- **CI/CD ready**: precise exit codes, readable logs, and Markdown, HTML and JSON reports.

## Supported stacks

|                                                                            | Stack            | Tools                                                                |
| -------------------------------------------------------------------------- | ---------------- | -------------------------------------------------------------------- |
|                                                                            | **All projects** | Gitleaks                                                             |
| <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/python.svg" width="20" height="20" alt="">     | **Python**       | pip-audit, Bandit, Semgrep                                           |
| <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/nodedotjs.svg" width="20" height="20" alt="">  | **Node.js**      | npm audit, Semgrep with bundled rules                                |
| <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/php.svg" width="20" height="20" alt="">        | **PHP**          | composer audit, Semgrep with bundled rules                           |
| <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/flutter.svg" width="20" height="20" alt="">    | **Flutter**      | dart pub outdated (outdated dependencies only, no SAST or CVE audit) |
| <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/docker.svg" width="20" height="20" alt="">     | **Docker**       | Hadolint, Trivy                                                      |
| <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/kubernetes.svg" width="20" height="20" alt=""> | **Kubernetes**   | kube-score, Checkov, kubesec                                         |

Runs on
<img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/linux.svg" width="16" height="16" alt=""> Linux,
<img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/apple.svg" width="16" height="16" alt=""> macOS and
<img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/windows.svg" width="16" height="16" alt=""> Windows.
See [platform notes](https://github.com/VISCHENZISCH/SecurePipeline/blob/main/docs/INSTALL.md#platforms) for the exceptions.

## Installation

Requires Python 3.11+ and Git.

### From PyPI

[pipx](https://pipx.pypa.io/) installs SecurePipeline in its own environment, which keeps the Python tools (Semgrep, Checkov) away from your other packages:

```bash
pipx install "securepipeline[tools]"
securepipeline tools install --yes --bin-dir ~/.local/bin
```

The second command downloads the binary tools (Gitleaks, Trivy, Hadolint...) at pinned versions and checks their SHA-256.

### Linux and macOS, from source

```bash
git clone https://github.com/VISCHENZISCH/SecurePipeline.git
cd SecurePipeline
chmod +x install.sh
./install.sh
```

### Windows (PowerShell), from source

```powershell
git clone https://github.com/VISCHENZISCH/SecurePipeline.git
cd SecurePipeline
.\install.ps1
```

If PowerShell blocks the script because of its execution policy, allow it for the current session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install.ps1
```

<p align="center">
  <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/screenshots/install-start.png" width="640" alt="Installation script starting with its banner">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/screenshots/install-complete.png" width="640" alt="Installation script finishing successfully">
</p>

The script creates `.venv`, then installs the project and its tools. `npm`, `composer` and `dart` are installed separately if you need them. Details: [docs/INSTALL.md](https://github.com/VISCHENZISCH/SecurePipeline/blob/main/docs/INSTALL.md).

## Usage

### Interactive menu

On Linux and macOS:

```bash
.venv/bin/securepipeline
```

On Windows, the path uses `Scripts` instead of `bin`:

```powershell
.\.venv\Scripts\securepipeline.exe
```

The menu displays the current project, its stacks, the missing tools and the last scan summary. Press `1` to scan the current project, or `2` to scan another one right away.

### Scan progress

Each tool shows its live status, and a check mark as soon as it has run. The scan ends with a clear verdict and the number of findings per severity.

### Commands

Examples below assume that `.venv` is activated.

```bash
securepipeline scan                        # Scan the current directory
securepipeline scan /path --fail-on high   # Fail from "high" severity
securepipeline scan . --format both        # Markdown and HTML reports
securepipeline detect                      # Show stacks and planned tools
securepipeline tools check                 # Show tool status
securepipeline tools install               # Install the missing tools
```

### Exit codes

| Code | Meaning                                           |
| ---- | ------------------------------------------------- |
| `0`  | No finding at the threshold and a complete scan   |
| `1`  | At least one finding at the `--fail-on` threshold |
| `2`  | Incomplete scan (tool missing or failed) or error |

Reports are written to `.securepipeline/reports/`. Full guide: [docs/USAGE.md](https://github.com/VISCHENZISCH/SecurePipeline/blob/main/docs/USAGE.md).

> [!WARNING]
> Do not commit the `.securepipeline/` folder. The reports list the weaknesses of your project, with file paths and line numbers, and anyone who can read the repository could use them. Add it to your `.gitignore` before your next commit:
>
> ```bash
> echo ".securepipeline/" >> .gitignore
> ```
>
> If it is already committed, remove it from Git but keep your local copy with `git rm -r --cached .securepipeline`, then commit.

### Docker

```bash
docker build -t securepipeline:latest .
docker compose run --rm scanner
```

With rootless Docker: `env UID=0 GID=0 docker compose run --rm scanner`.

### <img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/githubactions.svg" width="18" height="18" alt=""> GitHub Actions

The workflow in [.github/workflows/securepipeline.yml](https://github.com/VISCHENZISCH/SecurePipeline/blob/main/.github/workflows/securepipeline.yml) runs the tests, scans the repository, uploads the reports and comments on pull requests.

## Development

```bash
pip install -e ".[dev,tools]"
pytest
ruff check .
```

## Security

To report a vulnerability, please follow the [security policy](https://github.com/VISCHENZISCH/SecurePipeline/blob/main/SECURITY.md). DevSecOps recommendations are in [docs/DEVSECOPS.md](https://github.com/VISCHENZISCH/SecurePipeline/blob/main/docs/DEVSECOPS.md).

## License

Released under the [MIT License](https://github.com/VISCHENZISCH/SecurePipeline/blob/main/LICENSE).

## Author

<img src="https://raw.githubusercontent.com/VISCHENZISCH/SecurePipeline/main/docs/assets/logos/github.svg" width="16" height="16" alt=""> **Félix TOVIGNAN**, [@VISCHENZISCH](https://github.com/VISCHENZISCH)

If SecurePipeline helps you, [star the repository](https://github.com/VISCHENZISCH/SecurePipeline).

Logos are trademarks of their respective owners. Most come from [Simple Icons](https://simpleicons.org/).
