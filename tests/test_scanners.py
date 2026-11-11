"""Scanner tests: generated commands, errors and output parsing."""

import json
import shutil
import subprocess  # nosec B404 - builds a throwaway git repository

import pytest

from securepipeline.core.models import Finding, Severity
from securepipeline.scanners import docker as docker_scanner
from securepipeline.scanners import flutter as flutter_scanner
from securepipeline.scanners import kubernetes as k8s_scanner
from securepipeline.scanners import leaks as secrets_scanner
from securepipeline.scanners import node as node_scanner
from securepipeline.scanners import php as php_scanner
from securepipeline.scanners import python as python_scanner
from securepipeline.scanners import rust as rust_scanner
from securepipeline.scanners import semgrep as semgrep_scanner
from securepipeline.scanners.base import (
    CheckSkipped,
    NothingToScan,
    PartialScan,
    ToolError,
    audit_dirs,
    load_json,
)
from securepipeline.utils.process import CommandResult


def fake_runner(monkeypatch, module, stdout="", code=0, stderr=""):
    """Replace run_command and return the list of received commands."""
    calls = []

    def run(command, **_kwargs):
        calls.append(command)
        return CommandResult(command, code, stdout, stderr)

    monkeypatch.setattr(module, "run_command", run)
    return calls


def test_load_json_rejects_unexpected_return_code():
    with pytest.raises(ToolError, match="registry unreachable"):
        load_json(CommandResult(["x"], 7, "{}", "warning\nregistry unreachable\n"))


def test_load_json_rejects_invalid_json():
    with pytest.raises(ToolError, match="invalid JSON"):
        load_json(CommandResult(["x"], 0, "not json"))


def test_load_json_rejects_timeout():
    with pytest.raises(ToolError, match="Timed out"):
        load_json(CommandResult(["x"], -1, stderr="Timed out after 5s", timed_out=True))


def test_gitleaks_redacts_and_uses_no_git_outside_repository(monkeypatch, tmp_path):
    def run(command, **_kwargs):
        report = command[command.index("--report-path") + 1]
        with open(report, "w", encoding="utf-8") as handle:
            json.dump([], handle)
        calls.append(command)
        return CommandResult(command, 0)

    calls = []
    monkeypatch.setattr(secrets_scanner, "run_command", run)
    secrets_scanner.SecretsScanner()._run(tmp_path)
    assert "--redact" in calls[0]
    assert "--no-git" in calls[0]
    assert not list(tmp_path.iterdir()), "the project must not be modified"


def test_gitleaks_keeps_history_scan_in_repository(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()

    def run(command, **_kwargs):
        calls.append(command)
        with open(command[command.index("--report-path") + 1], "w", encoding="utf-8") as handle:
            handle.write("[]")
        return CommandResult(command, 0)

    calls = []
    monkeypatch.setattr(secrets_scanner, "run_command", run)
    secrets_scanner.SecretsScanner()._run(tmp_path)
    assert "--no-git" not in calls[0]


def test_gitleaks_failure_is_an_error(monkeypatch, tmp_path):
    fake_runner(monkeypatch, secrets_scanner, code=1, stderr="fatal: boom")
    with pytest.raises(ToolError, match="fatal: boom"):
        secrets_scanner.SecretsScanner()._run(tmp_path)


def test_gitleaks_finding_never_contains_the_secret():
    finding = secrets_scanner.parse_leak({
        "RuleID": "aws", "Description": "AWS", "File": "a", "StartLine": 2,
        "Match": "AKIASECRET", "Secret": "AKIASECRET", "Commit": "abcdef123456",  # nosec B105 - fake secret
    })
    assert finding.severity is Severity.CRITICAL
    assert "AKIASECRET" not in json.dumps(vars(finding), default=str)


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
def test_gitleaks_detects_secret_outside_repository(tmp_path, fake_aws_key):
    (tmp_path / "creds.txt").write_text(f'aws_access_key_id = "{fake_aws_key}"\n')
    findings = secrets_scanner.SecretsScanner()._run(tmp_path)
    assert findings
    assert fake_aws_key not in repr(findings)


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
def test_gitleaks_detects_secret_in_git_history(tmp_path, fake_aws_key):
    git = ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", "-C", str(tmp_path)]
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)  # nosec B603 B607 - test repository
    (tmp_path / "creds.txt").write_text(f'aws_access_key_id = "{fake_aws_key}"\n')
    subprocess.run([*git, "add", "."], check=True)  # nosec B603 - test repository
    subprocess.run([*git, "commit", "-qm", "x"], check=True)  # nosec B603 - test repository
    assert secrets_scanner.SecretsScanner()._run(tmp_path)


def test_pip_audit_targets_requirements(monkeypatch, tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    calls = fake_runner(monkeypatch, python_scanner, json.dumps({"dependencies": []}))
    python_scanner.PythonScanner()._run_pip_audit(tmp_path)
    assert str(tmp_path / "requirements.txt") in calls[0]


def test_pip_audit_targets_the_project_not_the_environment(monkeypatch, tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    calls = fake_runner(monkeypatch, python_scanner, json.dumps({"dependencies": []}))
    python_scanner.PythonScanner()._run_pip_audit(tmp_path)
    assert calls[0][-1] == str(tmp_path)


def test_pip_audit_without_manifest_is_skipped(tmp_path):
    (tmp_path / "setup.py").write_text("")
    with pytest.raises(CheckSkipped):
        python_scanner.PythonScanner()._run_pip_audit(tmp_path)


def test_pip_audit_uses_fetched_severity_and_flags_unknown():
    data = {"dependencies": [{"name": "a", "version": "1", "vulns": [
        {"id": "V1", "fix_versions": ["2"], "description": "d"},
        {"id": "V2", "fix_versions": [], "description": "d"},
    ]}]}
    known, unknown = python_scanner.parse_pip_audit(data, {"V1": Severity.CRITICAL})
    assert known.severity is Severity.CRITICAL
    assert "Upgrade to: 2" in known.remediation
    assert unknown.severity is Severity.MEDIUM
    assert "Unknown severity" in unknown.description


def test_osv_lookup_prefers_github_advisory(monkeypatch):
    urls = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b'{"database_specific": {"severity": "HIGH"}}'

    def urlopen(url, **_kwargs):
        urls.append(url)
        return Response()

    monkeypatch.setattr(python_scanner.urllib.request, "urlopen", urlopen)
    label = python_scanner._lookup_severity({"id": "PYSEC-1", "aliases": ["CVE-1", "GHSA-x"]})
    assert label == "HIGH"
    assert urls[0].endswith("/GHSA-x")


def test_osv_lookup_survives_network_failure(monkeypatch):
    def urlopen(*_args, **_kwargs):
        raise OSError("offline")

    monkeypatch.setattr(python_scanner.urllib.request, "urlopen", urlopen)
    assert python_scanner._lookup_severity({"id": "V"}) is None


def test_bandit_excludes_environments(monkeypatch, tmp_path):
    calls = fake_runner(monkeypatch, python_scanner, json.dumps({"results": []}))
    python_scanner.PythonScanner()._run_bandit(tmp_path)
    assert "*/.venv/*" in calls[0][calls[0].index("-x") + 1]


def test_bandit_ignores_assert_only_in_tests(monkeypatch, tmp_path):
    issue = {"test_id": "B101", "issue_severity": "LOW", "issue_confidence": "HIGH"}
    results = [
        {**issue, "filename": "tests/test_app.py"},
        {**issue, "filename": "pkg/conftest.py"},
        {**issue, "filename": "pkg/api_test.py"},
        {**issue, "filename": "app/service.py"},
        {**issue, "test_id": "B105", "filename": "tests/test_app.py"},
    ]
    fake_runner(monkeypatch, python_scanner, json.dumps({"results": results}))
    findings = python_scanner.PythonScanner()._run_bandit(tmp_path)
    assert [(f.rule_id, f.file_path) for f in findings] == [
        ("B101", "app/service.py"),
        ("B105", "tests/test_app.py"),
    ]


def test_bandit_promotes_certain_high_to_critical():
    findings = python_scanner.parse_bandit({"results": [
        {"issue_severity": "HIGH", "issue_confidence": "HIGH"},
        {"issue_severity": "HIGH", "issue_confidence": "LOW"},
    ]})
    assert [f.severity for f in findings] == [Severity.CRITICAL, Severity.HIGH]


def test_semgrep_groups_all_configs_in_one_command(monkeypatch, tmp_path):
    calls = fake_runner(monkeypatch, semgrep_scanner, json.dumps({"results": []}))
    semgrep_scanner.SemgrepScanner(["python", "php"])._run(tmp_path)
    assert len(calls) == 1
    assert "p/python" in calls[0]
    assert "p/php" in calls[0]


def test_semgrep_invalid_config_is_an_error(monkeypatch, tmp_path):
    fake_runner(monkeypatch, semgrep_scanner, json.dumps({"results": []}), code=7)
    with pytest.raises(ToolError):
        semgrep_scanner.SemgrepScanner(["python"])._run(tmp_path)


def test_semgrep_without_rules_has_nothing_to_scan(tmp_path):
    with pytest.raises(NothingToScan):
        semgrep_scanner.SemgrepScanner(["flutter"])._run(tmp_path)


def test_semgrep_parser_flattens_multiline_message():
    findings = semgrep_scanner.parse_semgrep({"results": [{
        "check_id": "a.b.rule", "path": "x.py", "start": {"line": 4},
        "extra": {"message": "line one\nline two", "severity": "ERROR"},
    }]})
    assert findings[0].title == "line one line two"
    assert findings[0].rule_id == "rule"
    assert findings[0].severity is Severity.HIGH


def test_npm_needs_a_lockfile(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    with pytest.raises(CheckSkipped):
        node_scanner.NodeScanner()._run_npm_audit(tmp_path)


def test_npm_error_payload_is_an_error(monkeypatch, tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    fake_runner(monkeypatch, node_scanner, json.dumps({"error": {"summary": "registry down"}}), code=1)
    with pytest.raises(ToolError, match="registry down"):
        node_scanner.NodeScanner()._run_npm_audit(tmp_path)


def test_npm_parser():
    findings = node_scanner.parse_npm_audit({"vulnerabilities": {
        "lodash": {
            "severity": "moderate", "range": "<4", "fixAvailable": True,
            "via": [{"title": "Pollution", "url": "https://github.com/advisories/GHSA-abc"}],
        },
        "app": {"severity": "high", "range": "*", "fixAvailable": False, "via": ["lodash"]},
    }})
    assert findings[0].rule_id == "GHSA-abc"
    assert findings[0].severity is Severity.MEDIUM
    assert findings[1].description == "Via: lodash"


def test_composer_needs_a_lockfile(tmp_path):
    (tmp_path / "composer.json").write_text("{}")
    with pytest.raises(CheckSkipped):
        php_scanner.PhpScanner()._run_composer_audit(tmp_path)


def test_composer_accepts_empty_php_array():
    assert php_scanner.parse_composer_audit({"advisories": []}) == []


@pytest.mark.parametrize("entries", [
    [{"advisoryId": "A", "title": "T", "severity": "high", "cve": "CVE-1"}],
    {"0": {"advisoryId": "A", "title": "T", "severity": "high", "cve": "CVE-1"}},
])
def test_composer_parser(entries):
    findings = php_scanner.parse_composer_audit({"advisories": {"vendor/pkg": entries}})
    assert findings[0].severity is Severity.HIGH
    assert "CVE-1" in findings[0].description


def test_dart_parser_handles_unresolved_versions():
    findings = flutter_scanner.parse_pub_outdated({"packages": [
        {"package": "a", "current": None, "latest": {"version": "2.0.0"}},
        {"package": "b", "current": {"version": "1.0.0"}, "latest": {"version": "1.0.0"}},
        {"package": "c", "current": {"version": "1.0.0"}, "latest": None},
    ]})
    assert [f.title for f in findings] == ["Outdated dependency: a"]


def test_docker_scanner_info():
    scanner = docker_scanner.DockerScanner()
    assert scanner.info().name == "Docker"
    assert scanner.info().stack == "docker"
    assert scanner.tools_required == ["hadolint", "trivy"]


def test_hadolint_lints_all_dockerfiles_at_once(monkeypatch, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM x")
    (tmp_path / "Dockerfile.dockerignore").write_text("")
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "Dockerfile.prod").write_text("FROM x")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "Dockerfile").write_text("FROM x")
    calls = fake_runner(monkeypatch, docker_scanner, "[]")
    docker_scanner.DockerScanner()._run_hadolint(tmp_path)
    assert len(calls) == 1
    assert calls[0][3:] == ["Dockerfile", "svc/Dockerfile.prod"]


def test_hadolint_without_dockerfile_has_nothing_to_scan(tmp_path):
    with pytest.raises(NothingToScan):
        docker_scanner.DockerScanner()._run_hadolint(tmp_path)


def test_trivy_uses_current_flags(monkeypatch, tmp_path):
    calls = fake_runner(monkeypatch, docker_scanner, json.dumps({"Results": None}))
    assert docker_scanner.DockerScanner()._run_trivy(tmp_path) == []
    assert "--scanners" in calls[0]
    assert "--security-checks" not in calls[0]


def test_trivy_parser():
    findings = docker_scanner.parse_trivy({"Results": [{
        "Target": "Dockerfile",
        "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "p", "Severity": "CRITICAL", "FixedVersion": "2"}],
        "Misconfigurations": [{"ID": "DS-1", "Severity": "HIGH", "CauseMetadata": {"StartLine": 3}}],
    }]})
    assert [f.severity for f in findings] == [Severity.CRITICAL, Severity.HIGH]
    assert findings[1].line == 3


def test_hadolint_parser_has_text_description():
    findings = docker_scanner.parse_hadolint([
        {"code": "DL1", "message": "m", "level": "error", "file": "Dockerfile", "line": 2, "column": 1},
    ])
    assert findings[0].severity is Severity.HIGH
    assert findings[0].description == ""


def test_find_manifests_uses_paths_relative_to_project(tmp_path):
    # The parent directory is called k8s: that must not select everything.
    root = tmp_path / "k8s" / "projet"
    (root / "config").mkdir(parents=True)
    (root / "config" / "app.yaml").write_text("apiVersion: v1\n")
    (root / "k8s").mkdir()
    (root / "k8s" / "ok.yaml").write_text("apiVersion: v1\n")
    (root / "k8s" / "empty.yaml").write_text("")
    (root / "k8s" / "other.yml").write_text("key: value\n")
    (root / "helm" / "templates").mkdir(parents=True)
    (root / "helm" / "templates" / "tpl.yaml").write_text("apiVersion: {{ .Values.v }}\n")
    assert k8s_scanner.find_manifests(root) == ["k8s/ok.yaml"]


def test_k8s_without_manifest_has_nothing_to_scan(tmp_path):
    with pytest.raises(NothingToScan):
        k8s_scanner.KubernetesScanner()._run_kube_score(tmp_path)


def test_kube_score_ignores_skipped_and_passing_checks():
    def check(grade, skipped=False, check_id="c"):
        return {"grade": grade, "skipped": skipped, "check": {"id": check_id, "name": "N"}, "comments": None}

    findings = k8s_scanner.parse_kube_score([{
        "object_name": "app",
        "file_name": "k8s/a.yaml",
        "file_row": 1,
        "checks": [check(10), check(1, skipped=True), check(0, skipped=True), check(1, check_id="crit"), check(5, check_id="warn")],
    }])
    assert [(f.rule_id, f.severity) for f in findings] == [("crit", Severity.HIGH), ("warn", Severity.MEDIUM)]


def test_checkov_parser():
    findings = k8s_scanner.parse_checkov({"results": {"failed_checks": [
        {"check_id": "CKV_1", "check_name": "N", "severity": None, "file_path": "/k8s/a.yaml", "file_line_range": [4, 9], "guideline": None},
    ]}})
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].file_path == "k8s/a.yaml"
    assert findings[0].line == 4


def test_checkov_empty_result_has_no_results_key():
    assert k8s_scanner.parse_checkov({"passed": 0, "failed": 0}) == []


def test_kubesec_parser():
    findings = k8s_scanner.parse_kubesec([{"scoring": {
        "critical": [{"id": "A", "selector": "s", "reason": "r"}],
        "advise": [{"id": "B", "selector": "s", "reason": "r"}],
    }}], "a.yaml")
    assert [f.severity for f in findings] == [Severity.HIGH, Severity.LOW]


def test_kubesec_unsupported_kind_is_not_an_error(monkeypatch, tmp_path):
    (tmp_path / "k8s").mkdir()
    (tmp_path / "k8s" / "svc.yaml").write_text("apiVersion: v1\nkind: Service\n")
    payload = json.dumps([{"valid": True, "message": "not supported", "scoring": {}}])
    fake_runner(monkeypatch, k8s_scanner, payload, code=2)
    assert k8s_scanner.KubernetesScanner()._run_kubesec(tmp_path) == []


# Folders at any depth --------------------------------------------------------

def test_audit_dirs_prefixes_paths_with_the_folder(tmp_path):
    (tmp_path / "web").mkdir()
    findings = audit_dirs(
        tmp_path, [tmp_path, tmp_path / "web"],
        lambda d: [Finding("R", "t", Severity.LOW, "package-lock.json")],
    )
    assert [f.file_path for f in findings] == ["package-lock.json", "web/package-lock.json"]


def test_audit_dirs_keeps_findings_of_the_folders_it_could_audit(tmp_path):
    def audit(directory):
        if directory.name == "web":
            raise CheckSkipped("lockfile missing")
        return [Finding("R", "t", Severity.LOW, "x")]

    (tmp_path / "web").mkdir()
    with pytest.raises(PartialScan, match="web: lockfile missing") as error:
        audit_dirs(tmp_path, [tmp_path, tmp_path / "web"], audit)
    assert len(error.value.findings) == 1


def test_audit_dirs_skips_when_no_folder_could_be_audited(tmp_path):
    with pytest.raises(CheckSkipped) as error:
        audit_dirs(tmp_path, [tmp_path], lambda _d: (_ for _ in ()).throw(CheckSkipped("no lockfile")))
    assert not isinstance(error.value, PartialScan)


def test_npm_audit_runs_in_each_frontend_folder(monkeypatch, tmp_path):
    for folder in ("frontend", "admin"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "package.json").write_text("{}")
        (tmp_path / folder / "package-lock.json").write_text("{}")
    calls = []

    def run(command, cwd=None, **_kwargs):
        calls.append(cwd)
        return CommandResult(command, 0, json.dumps({"vulnerabilities": {}}))

    monkeypatch.setattr(node_scanner, "run_command", run)
    node_scanner.NodeScanner()._run_npm_audit(tmp_path)
    assert calls == [tmp_path / "admin", tmp_path / "frontend"]


# Rust --------------------------------------------------------------------------

OSV_OUTPUT = {"results": [{"source": {"path": "/p/Cargo.lock", "type": "lockfile"}, "packages": [
    {
        "package": {"name": "quick-xml", "version": "0.31.0", "ecosystem": "crates.io"},
        "groups": [{"ids": ["RUSTSEC-2026-0194"], "max_severity": "7.5"}],
        "vulnerabilities": [{
            "id": "RUSTSEC-2026-0194", "summary": "Denial of service", "aliases": ["CVE-2026-1"],
            "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.37.0"}]}],
                          "database_specific": {"informational": None}}],
        }],
    },
    {
        "package": {"name": "basic-toml", "version": "0.1.10", "ecosystem": "crates.io"},
        "groups": [{"ids": ["RUSTSEC-2026-0374"], "max_severity": ""}],
        "vulnerabilities": [{
            "id": "RUSTSEC-2026-0374", "summary": "basic-toml is unmaintained",
            "affected": [{"ranges": [], "database_specific": {"informational": "unmaintained"}}],
        }],
    },
]}]}


def test_osv_scanner_rates_by_cvss_and_flags_unmaintained_crates():
    findings = {f.rule_id: f for f in rust_scanner.parse_osv_scanner(OSV_OUTPUT)}
    assert findings["RUSTSEC-2026-0194"].severity == Severity.HIGH
    assert findings["RUSTSEC-2026-0194"].remediation == "Upgrade quick-xml to 0.37.0"
    assert findings["RUSTSEC-2026-0374"].severity == Severity.LOW
    assert "[unmaintained]" in findings["RUSTSEC-2026-0374"].description


def test_osv_scanner_reads_the_lockfile_only(monkeypatch, tmp_path):
    (tmp_path / "Cargo.toml").write_text("")
    (tmp_path / "Cargo.lock").write_text("")
    calls = fake_runner(monkeypatch, rust_scanner, json.dumps({"results": []}), code=1)
    rust_scanner.RustScanner()._run_osv_scanner(tmp_path)
    assert calls[0][-2:] == ["--lockfile", str(tmp_path / "Cargo.lock")]


def test_osv_scanner_needs_a_cargo_lock(tmp_path):
    (tmp_path / "Cargo.toml").write_text("")
    with pytest.raises(CheckSkipped, match="Cargo.lock missing"):
        rust_scanner.RustScanner()._run_osv_scanner(tmp_path)


def test_cargo_deny_only_runs_with_a_project_policy(tmp_path):
    (tmp_path / "Cargo.toml").write_text("")
    with pytest.raises(NothingToScan, match="no deny.toml"):
        rust_scanner.RustScanner()._run_cargo_deny(tmp_path)


def test_cargo_deny_never_rewrites_the_lockfile_or_repeats_advisories(monkeypatch, tmp_path):
    for name in ("Cargo.toml", "Cargo.lock", "deny.toml"):
        (tmp_path / name).write_text("")
    monkeypatch.setattr(rust_scanner.shutil, "which", lambda _name: "/usr/bin/cargo")
    calls = fake_runner(monkeypatch, rust_scanner)
    rust_scanner.RustScanner()._run_cargo_deny(tmp_path)
    assert "--locked" in calls[0]
    assert "advisories" not in calls[0]


def test_cargo_deny_parses_diagnostics():
    output = "\n".join([
        json.dumps({"type": "diagnostic", "fields": {
            "severity": "error", "code": "rejected", "message": "license GPL-3.0 rejected",
            "labels": [{"line": 12, "span": "foo 1.0"}]}}),
        json.dumps({"type": "summary", "fields": {}}),
        "not json",
    ])
    [finding] = rust_scanner.parse_cargo_deny(output)
    assert (finding.rule_id, finding.severity, finding.line) == ("cargo-deny/rejected", Severity.HIGH, 12)


def test_cargo_deny_reports_the_error_line_not_the_usage_hint(monkeypatch, tmp_path):
    for name in ("Cargo.toml", "Cargo.lock", "deny.toml"):
        (tmp_path / name).write_text("")
    monkeypatch.setattr(rust_scanner.shutil, "which", lambda _name: "/usr/bin/cargo")
    fake_runner(monkeypatch, rust_scanner, code=2,
                stderr="error: unexpected argument '--config' found\n\nFor more information, try '--help'.\n")
    with pytest.raises(ToolError, match="unexpected argument"):
        rust_scanner.RustScanner()._run_cargo_deny(tmp_path)
