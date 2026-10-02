"""A failed OpenSearch setup fails the install, and the summary says so.

The setup's failure was a [WARN] mid-output: the summary was silent and the
installer exited 0, leaving an opensearch backend registered with no
cluster. These run the installer's own OpenSearch block, summary and exit
with every external command stubbed and a setup script that exits as told,
never the installer.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "setup-sift.sh"


def _slice(text: str, start: str, end: str | None) -> str:
    i = text.index(start)
    return text[i : text.index(end, i)] if end else text[i:]


def _install(
    tmp_path: Path, setup_exit: int, docker_group: bool
) -> subprocess.CompletedProcess:
    """`docker_group`: docker works directly, so the setup runs as `bash`.
    Otherwise the user is added to the group and it runs through `sg`."""
    os_dir = tmp_path / "opensearch-mcp"
    (os_dir / "scripts").mkdir(parents=True)
    setup = os_dir / "scripts" / "setup-opensearch.sh"
    setup.write_text(f"#!/usr/bin/env bash\necho SETUP-RAN\nexit {setup_exit}\n")
    text = SCRIPT.read_text()
    docker = "docker(){ return 0; }" if docker_group else "docker(){ return 1; }"
    harness = "\n".join(
        [
            "set -euo pipefail",
            "RED= GREEN= YELLOW= BLUE= BOLD= NC=",
            'info(){ echo "[INFO] $*"; }; ok(){ echo "[OK] $*"; }',
            'warn(){ echo "[WARN] $*"; }; err(){ echo "[ERROR] $*"; }',
            'header(){ echo "=== $* ==="; }',
            "uv(){ return 0; }; git(){ return 0; }; " + docker,
            "groups(){ echo examiner; }; sudo(){ return 0; }",
            'sg(){ bash -c "$3"; }',
            f'HOME="{tmp_path}"; INSTALL_DIR="{tmp_path}/sift-mcp"; VENV_PYTHON=python3',
            "USER=examiner; INSTALL_OPENSEARCH_FLAG=true; INSTALL_ERRORS=0; LOCKED=()",
            "REMOTE_MODE=false; AUTOSTART=true; TIER_DISPLAY=x; EXAMINER_NAME=x",
            "CASE_DIR=x; GATEWAY_PORT=4508; GATEWAY_CONFIG=x",
            _slice(text, "# --- OpenSearch MCP", "# --- Dependency check"),
            _slice(text, "\n# Summary\n", "# Data Maintenance"),
            _slice(text, "# Exit with error", None),
        ]
    )
    (tmp_path / "sift-mcp").mkdir()
    return subprocess.run(
        ["bash", "-c", harness], capture_output=True, text=True, timeout=60
    )


@pytest.mark.parametrize("docker_group", [True, False], ids=["bash", "sg"])
def test_a_failed_setup_fails_the_install(tmp_path, docker_group):
    run = _install(tmp_path, setup_exit=1, docker_group=docker_group)
    assert "SETUP-RAN" in run.stdout, run.stdout + run.stderr
    assert run.returncode == 1, run.stdout
    summary = run.stdout[run.stdout.index("=== Installation Complete ===") :]
    rerun = f"Re-run: bash {tmp_path}/sift-mcp/../opensearch-mcp/scripts/setup-opensearch.sh"
    assert "[ERROR] OpenSearch setup failed" in summary and rerun in summary, summary


@pytest.mark.parametrize("docker_group", [True, False], ids=["bash", "sg"])
def test_a_setup_that_works_leaves_the_install_alone(tmp_path, docker_group):
    run = _install(tmp_path, setup_exit=0, docker_group=docker_group)
    assert "SETUP-RAN" in run.stdout, run.stdout + run.stderr
    assert run.returncode == 0, run.stdout
    assert "[ERROR]" not in run.stdout
