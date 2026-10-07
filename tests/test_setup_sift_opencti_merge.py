"""A setup-sift re-run that adds the threat-intel backend to an existing
gateway.yaml writes the URL and token the wizard collected.

The merge path added the entry with no OpenCTI settings at all. The answers
reach the merge on fd 3, never in argv or the environment. Blank answers give
the same ${VAR} placeholders as a new config. The backend is added as
threatintel-mcp; a config that has it under its earlier name, opencti-mcp, is
left as it is. Runs the installer's own blocks in tmp_path, with a dummy token.
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


_gen_start = SCRIPT.index('    "$VENV_PYTHON" << PYEOF\n', _end)
GENERATE = SCRIPT[
    _gen_start : SCRIPT.index("PYEOF\n", _gen_start + 30) + len("PYEOF\n")
]


def _run(tmp_path, body):
    p = subprocess.run(
        ["bash", "-c", body],
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert p.returncode == 0, p.stdout + p.stderr
    return p.stdout


def _merge(tmp_path, url, token, existing=EXISTING):
    config = tmp_path / "gateway.yaml"
    config.write_text(yaml.safe_dump(existing))
    body = "\n".join(
        [
            "set -euo pipefail",
            'info() { echo "INFO $*"; }',
            f'GATEWAY_CONFIG="{config}"; VENV_PYTHON="{sys.executable}"',
            f'INSTALL_OPENCTI=true; OPENCTI_URL="{url}"; OPENCTI_TOKEN="{token}"',
            MERGE,
        ]
    )
    _run(tmp_path, body)
    return yaml.safe_load(config.read_text())["backends"]["threatintel-mcp"]["env"]


def test_a_merged_opencti_entry_carries_the_wizards_url_and_token(tmp_path):
    env = _merge(tmp_path, "https://cti.example.test", "dummy-not-a-real-token-0000")
    assert env["OPENCTI_URL"] == "https://cti.example.test"
    assert env["OPENCTI_TOKEN"] == "dummy-not-a-real-token-0000"


@pytest.mark.parametrize("url, token", [("", ""), ("https://cti.example.test", "")])
def test_blank_answers_give_the_new_config_placeholders(tmp_path, url, token):
    env = _merge(tmp_path, url, token)
    assert env["OPENCTI_URL"] == (url or "${OPENCTI_URL}")
    assert env["OPENCTI_TOKEN"] == "${OPENCTI_TOKEN}"


def test_a_config_with_the_earlier_name_is_left_byte_for_byte(tmp_path):
    existing = {
        "backends": {
            **EXISTING["backends"],
            "opencti-mcp": {
                "type": "stdio",
                "command": "python",
                "args": ["-m", "opencti_mcp"],
                "env": {"OPENCTI_URL": "https://mine.example.test"},
            },
        }
    }
    full = {
        name: {"type": "stdio", "command": "python", "args": ["-m", module]}
        for name, module in (
            ("forensic-mcp", "forensic_mcp"),
            ("case-mcp", "case_mcp"),
            ("report-mcp", "report_mcp"),
        )
    }
    existing["backends"].update(full)
    config = tmp_path / "gateway.yaml"
    config.write_text(yaml.safe_dump(existing))
    before = config.read_bytes()
    out = _run(
        tmp_path,
        "\n".join(
            [
                "set -euo pipefail",
                'info() { echo "INFO $*"; }',
                f'GATEWAY_CONFIG="{config}"; VENV_PYTHON="{sys.executable}"',
                'INSTALL_OPENCTI=true; OPENCTI_URL="https://cti.example.test"',
                'OPENCTI_TOKEN="dummy-not-a-real-token-0000"',
                MERGE,
            ]
        ),
    )
    assert "All expected backends already present." in out
    assert config.read_bytes() == before


def test_a_new_config_names_the_backend_threatintel_mcp(tmp_path):
    config = tmp_path / "gateway.yaml"
    _run(
        tmp_path,
        "\n".join(
            [
                "set -euo pipefail",
                f'GATEWAY_CONFIG="{config}"; VENV_PYTHON="{sys.executable}"',
                'REMOTE_MODE=false; TOKEN="vhir_gw_000000000000000000000000"',
                'GATEWAY_PORT=4508; EXAMINER_NAME="tester"',
                "INSTALL_TRIAGE=false; INSTALL_RAG=false; INSTALL_OPENSEARCH=false",
                'INSTALL_OPENCTI=true; OPENCTI_URL="https://cti.example.test"',
                'OPENCTI_TOKEN="dummy-not-a-real-token-0000"',
                GENERATE,
            ]
        ),
    )
    backends = yaml.safe_load(config.read_text())["backends"]
    assert "opencti-mcp" not in backends
    entry = backends["threatintel-mcp"]
    assert entry["args"] == ["-m", "opencti_mcp"]
    assert entry["env"]["OPENCTI_URL"] == "https://cti.example.test"
