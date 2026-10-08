"""The shell commands that have an MCP route, and the hooks' sidecar.

`claude-code/shared/hooks/mcp-routes.tsv` is rendered from the sift-mcp
catalog (plus `vhir ingest`); a test renders it again and compares. The
sidecar `mcp-route.py` reads a command on stdin and prints its route as JSON,
or nothing; it never fails, so a hook never blocks on it.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from sift_mcp.routes import FILENAME, render

HOOKS = Path(__file__).resolve().parents[1] / "claude-code" / "shared" / "hooks"
SIDECAR = HOOKS / "mcp-route.py"


def _route(command, script=SIDECAR):
    p = subprocess.run(
        [sys.executable, "-I", str(script)],
        input=command,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert p.returncode == 0 and p.stderr == "", p.stderr
    return json.loads(p.stdout) if p.stdout.strip() else None


def _table():
    return [
        ln.split("\t")
        for ln in (HOOKS / FILENAME).read_text().splitlines()
        if ln and not ln.startswith("#")
    ]


def test_the_committed_table_is_the_catalog_rendered_again():
    assert (HOOKS / FILENAME).read_text() == render()


def test_forensic_tools_are_routed_and_everyday_utilities_are_not():
    routed = {row[0]: row[1] for row in _table()}
    assert routed["vol"] == "sift-mcp run_command"
    assert routed["MFTECmd"] == "sift-mcp run_command"
    assert routed["vhir ingest"] == "opensearch-mcp idx_ingest"
    for utility in ("ls", "grep", "sed", "awk", "find", "cat"):
        assert utility not in routed


@pytest.mark.parametrize(
    "command,key",
    [
        ("vol -f mem.raw windows.pslist", "vol"),
        ("/usr/local/bin/vol -f x", "vol"),
        ("sudo -u examiner vol -f x", "vol"),
        ("FOO=1 env -u PATH BAR=2 MFTECmd -f x", "MFTECmd"),
        ("nice -n 5 fls -r img.dd", "fls"),
        ("vhir ingest /evidence/host1", "vhir ingest"),
    ],
)
def test_a_routed_command_gets_its_route_and_the_advisory(command, key):
    found = _route(command)
    assert found["command"] == key
    assert found["mcp_route"] in ("sift-mcp run_command", "opensearch-mcp idx_ingest")
    assert "Prefer it" in found["advisory"] and "stays allowed" in found["advisory"]


@pytest.mark.parametrize(
    "command",
    ["ls -la", "grep x f | vol -f y", "vhir case list", "", "echo 'unterminated"],
)
def test_anything_else_gets_nothing(command):
    """Only the first command counts (a routed tool later in a pipe isn't
    marked: a stated limitation)."""
    assert _route(command) is None


def test_every_command_in_the_table_is_found_by_the_sidecar():
    for command, mcp_route, _tool in _table():
        assert _route(f"{command} --help")["mcp_route"] == mcp_route, command


def test_without_its_table_the_sidecar_prints_nothing(tmp_path):
    lone = tmp_path / "mcp-route.py"
    shutil.copy(SIDECAR, lone)
    assert _route("vol -f x", script=lone) is None
