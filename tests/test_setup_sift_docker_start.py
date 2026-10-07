"""The installer carries on when the Docker unit won't start.

`sudo systemctl start docker` ran unguarded under `set -e`, so a unit that
failed to start ended the installer before its own "Could not start Docker"
check, and before every later phase. Runs the installer's own block in
tmp_path with docker, groups and sudo stubbed.
"""

import subprocess
from pathlib import Path

import pytest

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()
_start = SCRIPT.index("            # Ensure Docker is accessible before calling")
BLOCK = SCRIPT[_start : SCRIPT.index("            # Normal call (docker", _start)]
PROLOGUE = (
    "set -euo pipefail\n"
    'info() { echo "INFO $*"; }; ok() { echo "OK $*"; }\n'
    'warn() { echo "WARN $*"; }\n'
    "SETUP_OS_SCRIPT=/opt/setup-opensearch.sh\n"
)


def _run(tmp_path, unit_starts: bool, docker_works: bool):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stubs = {
        "docker": f"exit {0 if docker_works else 1}",
        "groups": "echo examiner docker",
        "sudo": f'[[ "$1 $2" == "systemctl start" ]] && exit {0 if unit_starts else 1}'
        "\nexit 0",
    }
    for name, body in stubs.items():
        (bin_dir / name).write_text("#!/bin/bash\n" + body + "\n")
        (bin_dir / name).chmod(0o755)
    p = subprocess.run(
        ["bash", "-c", PROLOGUE + BLOCK + 'echo "CONTINUED [$SETUP_OS_SCRIPT]"\n'],
        env={"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    return p.returncode, p.stdout + p.stderr


def test_a_unit_that_fails_to_start_is_reported_and_setup_continues(tmp_path):
    rc, out = _run(tmp_path, unit_starts=False, docker_works=False)
    assert rc == 0, out
    assert "WARN Could not start Docker. OpenSearch setup skipped." in out
    assert "CONTINUED []" in out


@pytest.mark.parametrize(
    "docker_works, expected",
    [(False, "CONTINUED []"), (True, "CONTINUED [/opt/setup-opensearch.sh]")],
    ids=["started, still unusable", "docker already works"],
)
def test_anchor_a_unit_that_starts_is_as_before(tmp_path, docker_works, expected):
    rc, out = _run(tmp_path, unit_starts=True, docker_works=docker_works)
    assert rc == 0 and expected in out, out
    assert ("Could not start Docker" in out) is not docker_works
