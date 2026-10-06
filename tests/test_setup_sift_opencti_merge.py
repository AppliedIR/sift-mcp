"""A setup-sift re-run that adds opencti-mcp to an existing gateway.yaml writes
the URL and token the wizard collected.

The merge path added the entry with no OpenCTI settings at all. The answers
reach the merge on fd 3, never in argv or the environment. Blank answers give
the same ${VAR} placeholders as a new config. Runs the installer's own block in
tmp_path, with a dummy token.
"""

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()
_start = SCRIPT.rindex(
    'if [[ -f "$GATEWAY_CONFIG" ]]; then',
    0,
    SCRIPT.index("Existing gateway config found"),
)
_end = SCRIPT.index("MERGE_EOF\n", SCRIPT.index("<< 'MERGE_EOF'", _start)) + len(
    "MERGE_EOF\n"
)
MERGE = SCRIPT[_start:_end] + "fi\n"

EXISTING = {
    "backends": {
        "sift-mcp": {"type": "stdio", "command": "python", "args": ["-m", "sift_mcp"]},
    }
}


def _merge(tmp_path, url, token):
    config = tmp_path / "gateway.yaml"
    config.write_text(yaml.safe_dump(EXISTING))
    body = "\n".join(
        [
            "set -euo pipefail",
            'info() { echo "INFO $*"; }',
            f'GATEWAY_CONFIG="{config}"; VENV_PYTHON="{sys.executable}"',
            f'INSTALL_OPENCTI=true; OPENCTI_URL="{url}"; OPENCTI_TOKEN="{token}"',
            MERGE,
        ]
    )
    p = subprocess.run(
        ["bash", "-c", body],
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert p.returncode == 0, p.stdout + p.stderr
    return yaml.safe_load(config.read_text())["backends"]["opencti-mcp"]["env"]


def test_a_merged_opencti_entry_carries_the_wizards_url_and_token(tmp_path):
    env = _merge(tmp_path, "https://cti.example.test", "dummy-not-a-real-token-0000")
    assert env["OPENCTI_URL"] == "https://cti.example.test"
    assert env["OPENCTI_TOKEN"] == "dummy-not-a-real-token-0000"


@pytest.mark.parametrize("url, token", [("", ""), ("https://cti.example.test", "")])
def test_blank_answers_give_the_new_config_placeholders(tmp_path, url, token):
    env = _merge(tmp_path, url, token)
    assert env["OPENCTI_URL"] == (url or "${OPENCTI_URL}")
    assert env["OPENCTI_TOKEN"] == "${OPENCTI_TOKEN}"
