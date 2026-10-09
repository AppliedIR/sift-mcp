"""An acquisition run (dc3dd, ewfacquire) is marked as one, so its outputs are
known to be acquired evidence; it writes in its own folder like any run."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path

import pytest
from sift_mcp.catalog import get_tool_def
from sift_mcp.server import create_server

DC3DD = """#!/bin/sh
for a; do case "$a" in if=*) src=${a#if=};; of=*) dst=${a#of=};; esac; done
cat "$src" > "$dst"
"""


@pytest.fixture
def case(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "examiner1")
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    d = tmp_path / "cases" / "case-a"
    (d / "evidence").mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: case-a\nstatus: open\n")
    (home / ".vhir" / "active_case").write_text(str(d))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("dc3dd", DC3DD), ("sudo", '#!/bin/sh\nexec "$@"\n')):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    return d


def _run(case: Path, command: list[str]) -> dict:
    asyncio.run(
        create_server().call_tool("run_command", {"command": command, "purpose": "t"})
    )
    lines = (case / "audit" / "sift-mcp.jsonl").read_text().splitlines()
    return json.loads(lines[-1])


def test_the_catalog_marks_the_acquisition_tools():
    assert get_tool_def("dc3dd").acquisition and get_tool_def("ewfacquire").acquisition
    assert not get_tool_def("7z").acquisition


@pytest.mark.parametrize("sudo", [[], ["sudo"]])
def test_an_acquisition_writes_in_its_folder_and_is_marked(case, sudo):
    src = case / "evidence" / "src.raw"
    src.write_bytes(b"SOURCE DISK")
    e = _run(case, [*sudo, "dc3dd", f"if={src}", "of=disk.dd"])
    image = case / "extractions" / e["audit_id"] / "disk.dd"
    assert image.read_bytes() == b"SOURCE DISK"
    (out,) = e["outputs"]
    assert out["path"] == str(image)
    assert out["sha256"] == hashlib.sha256(b"SOURCE DISK").hexdigest()
    assert e["acquisition"] is True and e["acquisition_tool"] == "dc3dd"


def test_any_other_run_is_not_an_acquisition(case):
    e = _run(case, ["ls", str(case)])
    assert "acquisition" not in e and "acquisition_tool" not in e
