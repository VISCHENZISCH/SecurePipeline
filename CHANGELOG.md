# Changelog

All notable changes to SecurePipeline are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

First public release.

### Added

- Automatic stack detection: Python, Node.js, PHP, Rust, Flutter, Docker and Kubernetes, at any depth of the repository, among the files git tracks.
- Rust module: OSV-Scanner for known vulnerabilities (RustSec), cargo-deny for the project's `deny.toml` policy, and Semgrep Rust rules.
- Dependency audits run in every folder that has its own manifest, such as `frontend/`. A folder that cannot be audited keeps the scan incomplete without hiding the other results.
- Static analysis with Semgrep and Bandit, with bundled rules for JavaScript/TypeScript and PHP.
- Dependency audit with pip-audit, npm audit, composer audit and dart pub outdated, with Python severities from OSV.dev.
- Infrastructure audit with Hadolint, Trivy, kube-score, Checkov and kubesec.
- Secret detection with Gitleaks on every project, with secrets redacted from reports.
- Tools run in parallel, and Semgrep runs once for all stacks.
- Each tool reports its status, so a failed or missing tool makes the scan incomplete instead of clean.
- Tool catalog with pinned versions and SHA-256 verification (`securepipeline tools install`).
- Interactive menu with a live progress panel, and a non-interactive `scan` command for CI.
- Markdown, HTML and JSON reports. The HTML report can be exported again without a new scan.
- Exit codes for CI: 1 for blocking findings, 2 for an incomplete scan.
- Docker image, docker-compose file, Kubernetes Job and GitHub Actions workflow.

[0.1.0]: https://github.com/VISCHENZISCH/SecurePipeline/releases/tag/v0.1.0
