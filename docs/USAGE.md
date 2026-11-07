# Using SecurePipeline

SecurePipeline is a multi-stack security CLI. This guide covers the interactive menu, the commands, Docker and CI/CD.

Prerequisite: follow [INSTALL.md](./INSTALL.md).

---

## Interactive menu

```bash
securepipeline
```

The top of the menu shows the current project, its stacks, the missing tools and the last scan summary. The project starts as the current directory. **Scan another project** asks for a path, scans it right away and makes it the current project.

| Key | Action |
|---|---|
| `1` | Scan this project |
| `2` | Scan another project |
| `3` | View last results |
| `4` | Export HTML report (from the last results, without a new scan) |
| `5` | Check / install tools |
| `6` | List scan modules |
| `7` | Scan settings (threshold, report format, parallelism) |
| `8` | Help and CI/CD |
| `u` | Update SecurePipeline |
| `q` | Quit |

Type a command right after a `!` to run it, for example `!ls` or `!git status`. It runs without a shell, so pipes, redirections and built-ins such as `cd` are not available.

The menu uses the terminal's alternate screen, like `vim` or `htop`: quitting restores your terminal as it was, without menu copies in the history. Scan results print on the normal screen, so you can scroll through them, and they remain visible after you quit. The ASCII logo needs at least 78 columns, and terminals shorter than 24 lines stay on the normal screen so that you can scroll up to the top of the menu.

---

## Commands

| Command | Purpose |
|---|---|
| `securepipeline scan [PATH]` | Scan a project (current directory by default) |
| `securepipeline detect [PATH]` | Show the stacks and planned tools |
| `securepipeline tools check` | Show tool status |
| `securepipeline tools install [TOOLS]` | Install the missing tools, or the named ones |
| `securepipeline modules` | List the scan modules |

### `scan` options

| Option | Default | Purpose |
|---|---|---|
| `--fail-on critical\|high\|medium\|low` | `critical` | Severity from which the scan fails |
| `--format md\|markdown\|html\|both` | `md` | Report format |
| `--report-dir DIR` | `.securepipeline/reports` | Report directory, relative to the project |
| `-j`, `--jobs N` | based on CPU, 8 at most | Tools to run in parallel |
| `--allow-incomplete` | off | Do not fail when a tool is missing or fails |
| `--all` | off | Print all findings, not just the first 20 |
| `-q`, `--quiet` | off | Print the verdict only |

---

## Exit codes

| Code | Meaning |
|------|---------------|
| `0`  | No finding at the threshold and a complete scan |
| `1`  | At least one finding at the `--fail-on` threshold |
| `2`  | Incomplete scan, invalid argument or report that cannot be written |
| `130` | Scan interrupted (Ctrl-C) |

Code `1` takes precedence over code `2`: a blocking finding is reported even if another tool failed.

---

## Tool status

| Status | Meaning | Makes the scan incomplete |
|---|---|---|
| No findings, or N findings | The tool worked | No |
| Nothing to scan | No target for this tool (no Dockerfile...) | No |
| Skipped | Tool missing, or target that cannot be audited (no lockfile...) | Yes |
| Error | Failure, timeout or unreadable output | Yes |

---

## Reports

The `.securepipeline/reports/` directory contains:

- `securepipeline-report.md` and/or `securepipeline-report.html`, depending on `--format`;
- `securepipeline-report.json`, always written, which the menu reads back to show the last results and generate the HTML without a new scan.

Each report includes the summary, the scan coverage (the result of each tool) and the details of the findings. Secrets are redacted: only their location and type are kept.

---

## Docker

```bash
docker build -t securepipeline:latest .

docker run --rm --user "$(id -u):$(id -g)" \
  -v "$(pwd):/project:ro" \
  -v "$(pwd)/.securepipeline/reports:/project/.securepipeline/reports" \
  securepipeline:latest scan /project --fail-on critical
```

With docker-compose (read-only container, Trivy cache kept between scans):

```bash
docker compose run --rm scanner
docker compose run --rm scanner scan /project --fail-on high
```

With rootless Docker, container UID 0 is your user: use `--user 0:0` or `env UID=0 GID=0 docker compose run --rm scanner`.

The image does not include `dart`: a Flutter project gives an incomplete scan there, unless you use `--allow-incomplete`.

---

## CI/CD

```bash
securepipeline scan . --fail-on critical --format both
```

GitHub Actions example: [.github/workflows/securepipeline.yml](../.github/workflows/securepipeline.yml).

---

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SECUREPIPELINE_FAIL_ON` | `critical` | Same as `--fail-on` |
| `SECUREPIPELINE_FORMAT` | `md` | Same as `--format` |
| `SECUREPIPELINE_REPORT_DIR` | `.securepipeline/reports` | Same as `--report-dir` |
| `SECUREPIPELINE_LOG_LEVEL` | `WARNING` | Internal log verbosity |
| `NO_COLOR` | not set | Disable colors |
| `FORCE_COLOR` | not set | Force colors, even outside a terminal |

---

## Troubleshooting

**A tool shows "not installed"**
Run `securepipeline tools install`. `npm`, `composer` and `dart` are installed separately.

**`npm` or `composer` is skipped because of a missing lockfile**
Generate and commit `package-lock.json` or `composer.lock`. yarn and pnpm are not audited.

**`pip-audit` is skipped**
The tool audits `requirements.txt` or `pyproject.toml`. A project with only `setup.py` or a `Pipfile` is not audited.

**A Python dependency shows "Unknown severity"**
OSV.dev did not respond or does not know this severity: the vulnerability defaults to MEDIUM.

**`semgrep` fails**
The registry rules require network access to semgrep.dev.
