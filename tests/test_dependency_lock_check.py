"""deps/check-lock.py: a venv against the dependency lock.

The venv is a directory of .dist-info records and uv a stand-in on PATH whose
`pip check` result each row chooses, so every row runs the real script.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

CHECK = Path(__file__).parent.parent / "deps" / "check-lock.py"
OLD = sys.version_info < (3, 11)

LOCK = """\
# header
starlette==1.7.0 \\
    --hash=sha256:aaaa
uvicorn==0.54.0 \\
    --hash=sha256:bbbb
setuptools==84.0.0 \\
    --hash=sha256:cccc
numpy==2.2.6 ; python_full_version < '3.11' \\
    --hash=sha256:dddd
numpy==2.4.0 ; python_full_version >= '3.11' \\
    --hash=sha256:eeee
scipy==1.16.0 ; python_full_version >= '3.11' \\
    --hash=sha256:ffff
scipy==1.15.3 ; python_full_version < '3.11' \\
    --hash=sha256:9999
"""
# Each listed once per Python range, in opposite orders: neither "first entry
# wins" nor "last entry wins" can stand in for evaluating the marker.
NUMPY = "2.2.6" if OLD else "2.4.0"
NUMPY_OTHER = "2.4.0" if OLD else "2.2.6"
SCIPY = "1.15.3" if OLD else "1.16.0"
SCIPY_OTHER = "1.16.0" if OLD else "1.15.3"
CLEAN = {"starlette": "1.7.0", "uvicorn": "0.54.0", "numpy": NUMPY, "scipy": SCIPY}


def _venv(tmp_path: Path, dists: dict, editable: dict | None = None) -> Path:
    site = tmp_path / "site"
    for name, version in {**dists, **(editable or {})}.items():
        info = site / f"{name}-{version}.dist-info"
        info.mkdir(parents=True)
        (info / "METADATA").write_text(f"Name: {name}\nVersion: {version}\n")
        if editable and name in editable:
            url = {"url": "file:///src", "dir_info": {"editable": True}}
            (info / "direct_url.json").write_text(json.dumps(url))
    return site


def _run(tmp_path, mode, dists, *, pip_check_ok=True, editable=None):
    lock = tmp_path / "vhir.lock"
    lock.write_text(LOCK)
    site = _venv(tmp_path, dists, editable)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    uv = bin_dir / "uv"
    uv.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "uv 0.12.20"; exit 0; fi\n'
        f'echo "uv $*" >> "{tmp_path}/uv.log"\n'
        + (
            "exit 0\n"
            if pip_check_ok
            else 'echo "x 1 requires y<2, but 2 is installed"; exit 1\n'
        )
    )
    uv.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    run = subprocess.run(
        [sys.executable, str(CHECK), mode, "--lock", str(lock), "--site", str(site)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    log = tmp_path / "uv.log"
    run.pip_checked = log.exists() and "pip check" in log.read_text()
    return run


def test_a_clean_venv_passes(tmp_path):
    run = _run(tmp_path, "--strict", CLEAN)
    assert run.returncode == 0, run.stderr
    assert "Dependencies match the lock: 4 packages" in run.stdout
    assert "uv 0.12.20" in run.stdout and run.pip_checked


def test_drift_is_a_loud_failure_naming_the_package_and_the_repair(tmp_path):
    run = _run(tmp_path, "--strict", {**CLEAN, "starlette": "0.50.0"})
    assert run.returncode == 1
    assert "starlette installed 0.50.0, lock 1.7.0" in run.stderr
    repair = [x for x in run.stderr.splitlines() if "uv pip install" in x]
    assert len(repair) == 1 and "starlette==1.7.0" in repair[0]
    assert "-c " in repair[0] and "-b " in repair[0]
    assert "uvicorn" not in run.stderr


def test_the_lock_entry_for_this_python_is_the_one_compared(tmp_path):
    assert _run(tmp_path, "--strict", CLEAN).returncode == 0
    for name, other in (("numpy", NUMPY_OTHER), ("scipy", SCIPY_OTHER)):
        d = tmp_path / name
        d.mkdir()
        run = _run(d, "--strict", {**CLEAN, name: other})
        assert run.returncode == 1 and f"{name} installed {other}" in run.stderr


def test_editables_are_skipped_and_unlocked_packages_listed(tmp_path):
    run = _run(
        tmp_path,
        "--strict",
        {**CLEAN, "leftover": "1.0"},
        editable={"sift-mcp": "0.6.1"},
    )
    assert run.returncode == 0, run.stderr
    assert "not in the lock" in run.stdout and "leftover" in run.stdout
    assert "sift-mcp" not in run.stdout


def test_unmet_requirements_fail(tmp_path):
    run = _run(tmp_path, "--strict", CLEAN, pip_check_ok=False)
    assert run.returncode == 1 and "requires y<2" in run.stderr


def test_strict_leaves_requirements_to_final_while_pycti_is_installed(tmp_path):
    run = _run(tmp_path, "--strict", {**CLEAN, "pycti": "6.9.29"}, pip_check_ok=False)
    assert run.returncode == 0, run.stderr
    assert not run.pip_checked


def test_final_lists_what_pycti_6_holds_and_why_it_matters(tmp_path):
    held = {"starlette": "0.50.0", "uvicorn": "0.35.0", "setuptools": "80.9.0"}
    run = _run(tmp_path, "--final", {**CLEAN, **held, "pycti": "6.9.29"})
    assert run.returncode == 0, run.stderr
    assert "pycti 6.9.29" in run.stdout
    for line in ("starlette 0.50.0 (lock 1.7.0)", "uvicorn 0.35.0 (lock 0.54.0)"):
        assert line in run.stdout
    note = [x for x in run.stdout.splitlines() if "pycti 6 holds" in x]
    assert len(note) == 1
    assert "starlette" in note[0] and "security advisories" in note[0]
    assert "7.x" in note[0]


def test_final_with_pycti_7_has_no_pycti_6_note(tmp_path):
    run = _run(
        tmp_path, "--final", {**CLEAN, "setuptools": "82.0.1", "pycti": "7.261002.0"}
    )
    assert run.returncode == 0, run.stderr
    assert "setuptools 82.0.1 (lock 84.0.0)" in run.stdout
    assert "pycti 6 holds" not in run.stdout


@pytest.mark.parametrize("mode", ["--final"])
def test_final_still_fails_on_conflicts_and_on_drift_without_pycti(tmp_path, mode):
    run = _run(tmp_path, mode, {**CLEAN, "pycti": "6.9.29"}, pip_check_ok=False)
    assert run.returncode == 1 and run.pip_checked
    other = tmp_path / "other"
    other.mkdir()
    run = _run(other, mode, {**CLEAN, "starlette": "0.50.0"})
    assert run.returncode == 1 and "starlette installed 0.50.0" in run.stderr
