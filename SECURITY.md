# Security Policy

SecurePipeline is maintained by [Félix TOVIGNAN](https://github.com/VISCHENZISCH). A security tool has to be trustworthy itself, so reports about its own weaknesses are welcome.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

Fixes are made on the latest version.

## Reporting a vulnerability

**Please do not open a public issue for a vulnerability.**

Report it privately through [GitHub Security Advisories](https://github.com/VISCHENZISCH/SecurePipeline/security/advisories/new).

Please include:

- the affected version or commit;
- the steps to reproduce the issue;
- the impact you observed;
- a suggested fix, if you have one.

This is a personal project, so handling is best effort. You will be credited in the advisory unless you prefer otherwise.

## Scope

In scope:

- the `securepipeline` CLI and its menu;
- the tool installer, including checksum verification;
- report generation, such as a secret left in a report or content injected through a scanned project;
- a scan that wrongly reports success when a tool failed or did not run;
- the Dockerfile, Kubernetes manifests and GitHub Actions workflow in this repository.

Out of scope:

- vulnerabilities in the third-party tools themselves (Semgrep, Trivy, Gitleaks...), which should be reported to their maintainers;
- findings reported by SecurePipeline about your own projects;
- false positives or false negatives from a third-party tool's rules.

## How SecurePipeline protects you

- **Verified downloads**: tool binaries use pinned versions and are checked against a SHA-256 before being installed.
- **Redacted secrets**: secrets found by Gitleaks are redacted and do not appear in reports.
- **No shell**: external tools run without a shell.
- **Honest results**: a missing or failing tool makes the scan incomplete (exit code `2`) instead of passing.
- **Escaped reports**: content coming from scanned projects is escaped in Markdown and HTML reports.
- **Hardened container**: the Docker image runs as a non-root user and supports a read-only root filesystem.

## Using it safely

- Reports describe the weaknesses of your project: treat them as sensitive, especially on public CI runs.
- Scans send data to third parties: Semgrep downloads its rules from semgrep.dev, and pip-audit, npm audit, composer audit and OSV.dev receive dependency or vulnerability identifiers.
- A clean scan does not prove that a project is secure. It only means that the tools that ran found nothing at the chosen threshold.
