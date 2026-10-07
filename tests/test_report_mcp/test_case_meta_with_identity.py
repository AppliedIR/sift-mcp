"""set_case_metadata never writes over a case's identity.

It read CASE.yaml, changed one field and wrote it back with no lock, so an
identity minted in between (sift-common's ensure_case_uuid) was lost. It now
writes under the same lock as the mint.
"""

from __future__ import annotations

import threading
import time

import pytest
import report_mcp.server as report_server
import yaml
from report_mcp.server import create_server
from sift_common.host_identity import ensure_case_uuid


@pytest.fixture
def cases(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setattr(report_server, "_ACTIVE_CASE_FILE", tmp_path / "none")
    # The unlocked write, slowed so a mint can land between read and write
    write = report_server._atomic_write

    def slow(path, content):
        time.sleep(0.02)
        write(path, content)

    monkeypatch.setattr(report_server, "_atomic_write", slow)

    def make(n):
        case = tmp_path / f"C-{n}"
        (case / "audit").mkdir(parents=True)
        (case / "CASE.yaml").write_text(f"case_id: C-{n}\nstatus: open\nname: x\n")
        return case

    return make


def _set(results):
    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    results.append(tools["set_case_metadata"].fn(field="incident_type", value="bec"))


def test_a_mint_during_set_case_metadata_is_kept(cases, monkeypatch):
    for n in range(100):
        case = cases(n)
        monkeypatch.setenv("VHIR_CASE_DIR", str(case))
        results: list = []
        setter = threading.Thread(target=_set, args=(results,))
        setter.start()
        time.sleep(0.005)
        ensure_case_uuid(case)
        setter.join()
        meta = yaml.safe_load((case / "CASE.yaml").read_text())
        assert results[0].get("status") == "set", results
        assert meta.get("case_uuid") and meta["incident_type"] == "bec", (n, meta)


def test_update_case_meta_keeps_every_other_key(tmp_path):
    from sift_common.host_identity import update_case_meta

    (tmp_path / "CASE.yaml").write_text("case_id: C\nstatus: open\nextra: [1, 2]\n")
    update_case_meta(tmp_path, {"severity": "high"})
    meta = yaml.safe_load((tmp_path / "CASE.yaml").read_text())
    assert meta == {
        "case_id": "C",
        "status": "open",
        "extra": [1, 2],
        "severity": "high",
    }
