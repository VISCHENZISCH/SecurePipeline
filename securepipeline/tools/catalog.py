"""Single source of tool versions and checksums.

install.sh, install.ps1, the Dockerfile and the CI all go through
`securepipeline tools install`, so this file is the only one to update.
"""

from dataclasses import dataclass, field

PIP_TOOLS = {
    "pip-audit": ("pip-audit>=2.7,<3", "Python dependency audit"),
    "bandit": ("bandit>=1.7,<2", "Python static analysis"),
    "semgrep": ("semgrep>=1.70,<2", "Multi-language static analysis"),
    "checkov": ("checkov>=3.2,<4", "Kubernetes manifest scan"),
}


@dataclass(frozen=True)
class Asset:
    filename: str
    sha256: str


@dataclass(frozen=True)
class BinaryTool:
    name: str
    description: str
    base_url: str
    assets: dict[str, Asset] = field(default_factory=dict)


GITHUB = "https://github.com"

BINARY_TOOLS = (
    BinaryTool(
        "gitleaks", "Secret detection",
        f"{GITHUB}/gitleaks/gitleaks/releases/download/v8.18.2",
        {
            "linux-amd64": Asset("gitleaks_8.18.2_linux_x64.tar.gz", "6298c9235dfc9278c14b28afd9b7fa4e6f4a289cb1974bd27949fc1e9122bdee"),
            "linux-arm64": Asset("gitleaks_8.18.2_linux_arm64.tar.gz", "4df25683f95b9e1dbb8cc71dac74d10067b8aba221e7f991e01cafa05bcbd030"),
            "darwin-amd64": Asset("gitleaks_8.18.2_darwin_x64.tar.gz", "b2dc4f853128062856273d422e2f29791a036641c1655feb83192078970fbfc0"),
            "darwin-arm64": Asset("gitleaks_8.18.2_darwin_arm64.tar.gz", "7be53fa77d7ec10cb8a7085d6ebcf375d55dd4c71f2cf6e7e6bf11554847a095"),
            "windows-amd64": Asset("gitleaks_8.18.2_windows_x64.zip", "aa19543417c668b15e89b3357413099d81a75029a8ebbaec5034b7c8cc33c7e5"),
        },
    ),
    BinaryTool(
        "hadolint", "Dockerfile lint",
        f"{GITHUB}/hadolint/hadolint/releases/download/v2.12.0",
        {
            "linux-amd64": Asset("hadolint-Linux-x86_64", "56de6d5e5ec427e17b74fa48d51271c7fc0d61244bf5c90e828aab8362d55010"),
            "linux-arm64": Asset("hadolint-Linux-arm64", "5798551bf19f33951881f15eb238f90aef023f11e7ec7e9f4c37961cb87c5df6"),
            "darwin-amd64": Asset("hadolint-Darwin-x86_64", "2a5b7afcab91645c39a7cebefcd835b865f7488e69be24567f433dfc3d41cd27"),
            "windows-amd64": Asset("hadolint-Windows-x86_64.exe", "ed89a156290e15452276b2b4c84efa688a5183d3b578bfaec7cfdf986f0632a8"),
        },
    ),
    BinaryTool(
        "trivy", "CVEs and misconfigurations (filesystem)",
        f"{GITHUB}/aquasecurity/trivy/releases/download/v0.76.2",
        {
            "linux-amd64": Asset("trivy_0.76.2_Linux-64bit.tar.gz", "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf"),
            "linux-arm64": Asset("trivy_0.76.2_Linux-ARM64.tar.gz", "ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3"),
            "darwin-amd64": Asset("trivy_0.76.2_macOS-64bit.tar.gz", "e08bb9ea449ecf66c6bfb03cbb8697c503ff33d35fc585c9747e3eaeb7ed4c7b"),
            "darwin-arm64": Asset("trivy_0.76.2_macOS-ARM64.tar.gz", "ae7ea358326960406b703c77b2ac490190797d80b306b5b50c2a27221da0a5b8"),
            "windows-amd64": Asset("trivy_0.76.2_windows-64bit.zip", "691f737a7e5566a673c3a74dab9160552ec32101e953b659e5c77443d16dddb6"),
        },
    ),
    BinaryTool(
        "kube-score", "Kubernetes manifest lint",
        f"{GITHUB}/zegl/kube-score/releases/download/v1.18.0",
        {
            "linux-amd64": Asset("kube-score_1.18.0_linux_amd64", "06e9860646fac6f808d5dbff0b920a73afc8949ca090cf4ac032034a5aacac22"),
            "linux-arm64": Asset("kube-score_1.18.0_linux_arm64", "7401bbc64ad02dce3f8a50002a75962e82b0ec3d95ac3175bc1c188919230585"),
            "darwin-amd64": Asset("kube-score_1.18.0_darwin_amd64", "2240f1ac66740c90cdb3d5286d7fb044db13ad597c2615d22e0b1e668227c864"),
            "darwin-arm64": Asset("kube-score_1.18.0_darwin_arm64", "8013c9d5005606320f1956fd60dce2761de76d3e72db0c9cbe5cc2f2a55b629f"),
            "windows-amd64": Asset("kube-score_1.18.0_windows_amd64.exe", "16557c68c32738b63616c7e0102534b562f34b36f3a8ec1d8a74281934970583"),
        },
    ),
    BinaryTool(
        "kubesec", "Kubernetes security score",
        f"{GITHUB}/controlplaneio/kubesec/releases/download/v2.13.0",
        {
            "linux-amd64": Asset("kubesec_linux_amd64.tar.gz", "8bf8aca56c257e2612cb11d956f45ff94166a4558e30a8f3db76d97c4237c89d"),
            "linux-arm64": Asset("kubesec_linux_arm64.tar.gz", "3b4d43e66c9148e32b25ee7acaaec6e767590b2117c58d5ebc33ee9b2b06de88"),
            "darwin-amd64": Asset("kubesec_darwin_amd64.tar.gz", "4ae95a7f69deb6e56a95e5ab1ab8cbf460f22a4633e9ae164fcb1ad029fae4da"),
            "darwin-arm64": Asset("kubesec_darwin_arm64.tar.gz", "f2ff4c805572077077ce467a2c1faef8f4afd104353aa890059a9f7e8b4c3a41"),
        },
    ),
)

BINARIES_BY_NAME = {tool.name: tool for tool in BINARY_TOOLS}


def tool_descriptions() -> dict[str, str]:
    """Return {tool: description} for every installable tool."""
    binaries = {tool.name: tool.description for tool in BINARY_TOOLS}
    return {**{name: description for name, (_, description) in PIP_TOOLS.items()}, **binaries}
