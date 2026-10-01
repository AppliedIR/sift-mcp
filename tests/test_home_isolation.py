"""The suite never touches the HOME it was started with.

Each row starts a child pytest on this file with HOME set to a scratch
directory standing in for the real one, runs one probe there, and checks the
scratch directory afterwards. The probes run only in that child.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

# Imported at collection, as test modules import them, so a redirect that runs
# later than collection (a fixture) is seen too late — as it would be.
from case_mcp import server as case_server
from forensic_mcp.case import manager
from report_mcp import server as report_server
from sift_gateway import join

_PROBE = os.environ.get("HOME_ISOLATION_PROBE")
_ROOT = Path(__file__).parent.parent


def _child(tmp_path: Path, probe: str, **env_extra: str) -> tuple[Path, dict]:
    original = tmp_path / "original-home"
    (original / ".vhir").mkdir(parents=True)
    (original / ".vhir" / "active_case").write_text("/the/original/case\n")
    out = tmp_path / "probe.json"
    env = {
        **os.environ,
        "HOME": str(original),
        "HOME_ISOLATION_PROBE": str(out),
        **env_extra,
    }
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-q",
            f"{__file__}::{probe}",
        ],
        cwd=_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert run.returncode == 0, run.stdout[-3000:]
    return original, json.loads(out.read_text())


def test_activating_a_case_leaves_the_original_pointer(tmp_path):
    original, _ = _child(tmp_path, "test_probe_activate_a_case")
    assert (original / ".vhir" / "active_case").read_text() == "/the/original/case\n"


def test_module_level_paths_are_not_under_the_original_home(tmp_path):
    original, paths = _child(tmp_path, "test_probe_module_paths")
    assert paths and not [p for p in paths.values() if p.startswith(str(original))], (
        paths
    )


@pytest.mark.skipif(not _PROBE, reason="runs only in the child started above")
def test_probe_activate_a_case(tmp_path):
    from vhir_cli.main import _case_activate_data

    cases = tmp_path / "cases"
    (cases / "CASE-P").mkdir(parents=True)
    (cases / "CASE-P" / "CASE.yaml").write_text("case_id: CASE-P\n")
    _case_activate_data("CASE-P", cases_dir=str(cases))
    Path(_PROBE).write_text("{}")


@pytest.mark.skipif(not _PROBE, reason="runs only in the child started above")
def test_probe_module_paths():
    paths = {
        "case-mcp _ACTIVE_CASE_FILE": str(case_server._ACTIVE_CASE_FILE),
        "forensic-mcp _ACTIVE_CASE_FILE": str(manager._ACTIVE_CASE_FILE),
        "report-mcp _ACTIVE_CASE_FILE": str(report_server._ACTIVE_CASE_FILE),
        "sift-gateway _STATE_DIR": str(join._STATE_DIR),
    }
    Path(_PROBE).write_text(json.dumps(paths))


def test_a_case_named_in_the_environment_is_not_written(tmp_path):
    """VHIR_CASE_DIR set when the suite starts doesn't receive its audit."""
    case = tmp_path / "named-case"
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: named\n")
    _child(tmp_path, "test_probe_audit", VHIR_CASE_DIR=str(case))
    assert list((case / "audit").iterdir()) == []


@pytest.mark.skipif(not _PROBE, reason="runs only in the child started above")
def test_probe_audit():
    from sift_common.audit import AuditWriter

    AuditWriter("home-isolation-probe").log(tool="probe", params={}, result_summary="x")
    Path(_PROBE).write_text("{}")
