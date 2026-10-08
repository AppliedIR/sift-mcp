"""forensic-mcp holds vhir's case lock while it writes a case.

A signed commit (CLI or portal) holds the case lock from its reload to its
save. forensic-mcp's record_finding and record_timeline_event take the same
lock (`/var/lib/vhir/ledger/{case_id}.lock`) around their whole load-to-save,
so neither can overwrite the other's write. forensic-mcp keeps a copy of the
lock helper (it doesn't depend on vhir-cli); these rows pin it to vhir's.
"""

import json
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import forensic_mcp.case.manager as fm
import pytest
import yaml

ledger = pytest.importorskip("vhir_cli.ledger")
from vhir_cli.case_io import case_id_of, ioc_values, normalize_ioc  # noqa: E402

from test_forensic_mcp.test_case_manager import active_case, manager  # noqa: E402, F401

FINDING = {
    "title": "Beacon",
    "audit_ids": ["wt-tester-20260219-001"],
    "observation": "o",
    "interpretation": "i",
    "confidence": "MEDIUM",
    "confidence_justification": "one source",
    "type": "finding",
}


@pytest.mark.parametrize("with_id", [True, False])
def test_the_lock_path_is_vhir_s(tmp_path, with_id):
    d = tmp_path / "C-folder"
    d.mkdir()
    meta = {"name": "x", **({"case_id": "C-meta"} if with_id else {})}
    (d / "CASE.yaml").write_text(yaml.dump(meta))
    ours = fm.case_lock_path(fm.CaseManager()._case_id(d))
    assert ours == ledger.lock_path(case_id_of(d))


@pytest.mark.parametrize("bad", ["..", "a/b", "a\nb", ""])
def test_an_unusable_case_id_is_refused_like_vhir(bad):
    with pytest.raises(fm.CaseLockError):
        fm.case_lock_path(bad)
    with pytest.raises(ValueError):
        ledger.lock_path(bad)


def test_a_finding_waits_for_a_commit_holding_the_lock(manager, active_case):  # noqa: F811
    held, release = threading.Event(), threading.Event()

    def commit():
        with ledger.case_lock(active_case["case_id"]):
            held.set()
            release.wait(5)

    t = threading.Thread(target=commit)
    t.start()
    held.wait(5)
    threading.Timer(0.3, release.set).start()
    start = time.monotonic()
    result = manager.record_finding(dict(FINDING))
    t.join()
    assert time.monotonic() - start >= 0.25  # it waited for the commit
    assert result["status"] == "STAGED"


def test_a_busy_lock_records_nothing(manager, active_case, monkeypatch):  # noqa: F811
    monkeypatch.setattr(fm, "CASE_LOCK_SECONDS", 0.2)
    case = Path(active_case["path"])
    before = {p.name: p.read_bytes() for p in case.iterdir() if p.is_file()}
    with ledger.case_lock(active_case["case_id"]):
        with pytest.raises(fm.CaseLockError, match="nothing was recorded"):
            manager.record_finding(dict(FINDING))
        with pytest.raises(fm.CaseLockError):
            manager.record_timeline_event(
                {"timestamp": "2026-10-08T10:00:00Z", "description": "d"}
            )
    assert {p.name: p.read_bytes() for p in case.iterdir() if p.is_file()} == before


def test_a_commit_waits_for_forensic_mcp(manager, active_case):  # noqa: F811
    with fm.case_lock(active_case["case_id"]):
        with pytest.raises(ledger.LedgerBusy):
            ledger.case_lock(active_case["case_id"], timeout=0.2).acquire()


def test_a_missing_lock_folder_names_the_fix(
    manager, active_case, monkeypatch, tmp_path
):  # noqa: F811
    monkeypatch.setattr(fm, "LEDGER_DIR", tmp_path / "not-made")
    with pytest.raises(fm.CaseLockError, match="run `vhir update` to create it"):
        manager.record_finding(dict(FINDING))
    findings = json.loads((Path(active_case["path"]) / "findings.json").read_text())
    assert findings == []


def test_locking_never_makes_a_chain_file(manager, active_case):  # noqa: F811
    manager.record_finding(dict(FINDING))
    assert not ledger.chain_path(active_case["case_id"]).exists()


@pytest.mark.parametrize(
    "iocs",
    [
        ["10.0.0.1:8443", "evil[.]com", "hxxp://evil.com/x", "C:\\Temp\\a.exe"],
        {"IPv4": ["10.0.0.2", "10.0.0.2"], "Domains": "bad.example"},
        [{"value": "rsydow-a", "type": "user-account"}, {"value": "10.0.0.3:80", "type": "ipv4-addr"}],
        ["1.2.3.4/24", "999.1.1.1:22", "  spaced.example  ", ""],
    ],
)  # fmt: skip
def test_vhir_extracts_the_same_ioc_values(manager, active_case, iocs):  # noqa: F811
    """vhir's cascade planner reads a finding's IOCs as forensic-mcp does."""
    manager.record_finding({**FINDING, "iocs": iocs})
    stored = json.loads((Path(active_case["path"]) / "iocs.json").read_text())
    assert {normalize_ioc(i["value"]) for i in stored} == ioc_values(iocs)


def test_forensic_mcp_holds_the_lock_for_less_than_the_portal_waits(
    manager,
    active_case,
    monkeypatch,  # noqa: F811
):
    """The portal's commit waits up to its acquisition limit for the case
    lock, then answers LEDGER_BUSY. forensic-mcp's longest hold, recording a
    finding (with its timeline event and IOCs) and an event on a case that
    already holds many records, stays well under it."""
    from case_dashboard.signing import LOCK_SECONDS

    case = Path(active_case["path"])
    many = [dict(FINDING, id=f"F-tester-{n:03d}", status="DRAFT", iocs=[f"10.0.{n // 250}.{n % 250}"])
            for n in range(1, 501)]  # fmt: skip
    (case / "findings.json").write_text(json.dumps(many))
    holds, real = [], fm.case_lock

    @contextmanager
    def timed(*a, **k):
        with real(*a, **k):
            start = time.monotonic()
            try:
                yield
            finally:
                holds.append(time.monotonic() - start)

    monkeypatch.setattr(fm, "case_lock", timed)
    finding = dict(
        FINDING, iocs=["10.9.9.9", "evil.example"], timestamp="2026-10-08T10:00:00Z"
    )
    assert manager.record_finding(finding)["status"] == "STAGED"
    manager.record_timeline_event(
        {"timestamp": "2026-10-08T10:00:00Z", "description": "d"}
    )
    assert holds, "forensic-mcp took no case lock"
    assert max(holds) < LOCK_SECONDS / 4, holds  # a quarter of it, on a loaded box
