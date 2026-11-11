"""Registry of the scan modules."""

from securepipeline.scanners.base import BaseScanner
from securepipeline.scanners.docker import DockerScanner
from securepipeline.scanners.flutter import FlutterScanner
from securepipeline.scanners.kubernetes import KubernetesScanner
from securepipeline.scanners.leaks import SecretsScanner
from securepipeline.scanners.node import NodeScanner
from securepipeline.scanners.php import PhpScanner
from securepipeline.scanners.python import PythonScanner
from securepipeline.scanners.rust import RustScanner
from securepipeline.scanners.semgrep import REGISTRY_RULESETS, SemgrepScanner

STACK_SCANNERS: dict[str, type[BaseScanner]] = {
    "python":  PythonScanner,
    "node":    NodeScanner,
    "php":     PhpScanner,
    "rust":    RustScanner,
    "flutter": FlutterScanner,
    "docker":  DockerScanner,
    "k8s":     KubernetesScanner,
}


def get_scanners_for_stacks(stacks: list[str]) -> list[BaseScanner]:
    """Return the scanners to run for the detected stacks.

    Gitleaks always runs, even without a known stack. Semgrep runs once, with the
    rules of every detected stack.
    """
    scanners: list[BaseScanner] = [
        STACK_SCANNERS[stack]() for stack in stacks if stack in STACK_SCANNERS
    ]
    if any(stack in REGISTRY_RULESETS for stack in stacks):
        scanners.append(SemgrepScanner(stacks))
    scanners.append(SecretsScanner())
    return scanners


def all_scanners() -> list[BaseScanner]:
    return [*(cls() for cls in STACK_SCANNERS.values()), SemgrepScanner(), SecretsScanner()]


__all__ = [
    "STACK_SCANNERS",
    "BaseScanner",
    "all_scanners",
    "get_scanners_for_stacks",
]
