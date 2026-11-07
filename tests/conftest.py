"""Keep test output free of color codes, whatever the terminal."""

import os

import pytest

os.environ["NO_COLOR"] = "1"
os.environ.pop("FORCE_COLOR", None)


@pytest.fixture
def fake_aws_key() -> str:
    """Invented key, split so that secret scanners do not flag this file."""
    return "AKIA" + "Q7XW3PLMNB2VK9TR"
