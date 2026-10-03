"""The dashboard's commit: an explicit reject wins over finding coupling.

Approving a finding approves the timeline events auto-created from it. The
coupling re-approved any event that wasn't APPROVED, including one the
examiner had rejected (in the same review, or earlier), and signed it.
Coupling now approves only DRAFT events; rejecting a finding still cascades.

The real _apply_delta runs on a scratch case; the HMAC ledger writer (which
writes /var/lib/vhir) is replaced by a recorder.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import case_dashboard.routes as D
import pytest

NOW0 = "2026-10-03T07:00:00+00:00"


def _finding(fid):
    f = {
        "id": fid,
        "type": "finding",
        "title": f"title {fid}",
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "MEDIUM",
        "status": "DRAFT",
        "examiner": "steve",
        "created_by": "steve",
        "staged": NOW0,
        "modified_at": NOW0,
        "audit_ids": ["x-1"],
    }
    f["content_hash"] = D._compute_content_hash(f)
    return f


def _event(tid, src):
    t = {
        "id": tid,
        "timestamp": NOW0,
        "description": f"ev {tid}",
        "event_type": "other",
        "related_findings": [src],
        "auto_created_from": src,
        "status": "DRAFT",
        "staged": NOW0,
        "modified_at": NOW0,
        "created_by": "steve",
        "examiner": "steve",
        "audit_ids": ["x-1"],
    }
    t["content_hash"] = D._compute_content_hash(t)
    return t


@pytest.fixture
def case(tmp_path, monkeypatch):
    """F (with auto events T1, T2 and an IOC) and an unrelated finding X."""
    signed = []
    monkeypatch.setattr(
        D,
        "_write_hmac_entries",
        lambda case_dir, case_id, items, *a: (
            signed.extend(i["id"] for i in items) or []
        ),
    )
    d = tmp_path / "C-1"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: C-1\n")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))

    def make(**overrides):
        items = {
            "F": _finding("F-steve-001"),
            "X": _finding("F-steve-002"),
            "T1": _event("T-steve-001", "F-steve-001"),
            "T2": _event("T-steve-002", "F-steve-001"),
        }
        for k, v in overrides.items():
            items[k].update(v)
        (d / "findings.json").write_text(json.dumps([items["F"], items["X"]]))
        (d / "timeline.json").write_text(json.dumps([items["T1"], items["T2"]]))
        ioc = {
            "id": "IOC-steve-001",
            "value": "1.2.3.4",
            "type": "ipv4-addr",
            "status": "DRAFT",
            "source_findings": ["F-steve-001"],
            "manually_reviewed": False,
            "confidence": "MEDIUM",
            "content_hash": "h",
        }
        (d / "iocs.json").write_text(json.dumps([ioc]))

    def commit(*entries):
        items = [dict(type="finding", **e) for e in entries]
        (d / "pending-reviews.json").write_text(
            json.dumps({"case_id": "C-1", "items": items})
        )
        D._apply_delta(d, "steve", b"k" * 32)

    def state():
        tl = {t["id"]: t for t in json.loads((d / "timeline.json").read_text())}
        fi = {f["id"]: f for f in json.loads((d / "findings.json").read_text())}
        return (
            fi["F-steve-001"]["status"],
            tl["T-steve-001"]["status"],
            tl["T-steve-002"]["status"],
        )

    return SimpleNamespace(make=make, commit=commit, state=state, signed=signed)


REJECT_T2 = {"id": "T-steve-002", "action": "reject", "rejection_reason": "no"}
APPROVE_F = {"id": "F-steve-001", "action": "approve"}


def test_4_a_delta_rejecting_the_event_and_approving_the_finding(case):
    case.make()
    case.commit(REJECT_T2, APPROVE_F)
    assert case.state() == ("APPROVED", "APPROVED", "REJECTED")
    assert "T-steve-002" not in case.signed


def test_a_a_rejected_event_survives_an_unrelated_commit(case):
    case.make(
        F={"status": "APPROVED"},
        T1={"status": "APPROVED"},
        T2={"status": "REJECTED", "rejection_reason": "explicit"},
    )
    case.commit({"id": "F-steve-002", "action": "approve"})
    assert case.state() == ("APPROVED", "APPROVED", "REJECTED")
    assert "T-steve-002" not in case.signed


def test_b_an_event_rejected_after_its_finding_was_approved(case):
    case.make()
    case.commit(APPROVE_F)
    case.signed.clear()
    case.commit(REJECT_T2)
    assert case.state() == ("APPROVED", "APPROVED", "REJECTED")
    assert "T-steve-002" not in case.signed


def test_c_an_approved_event_is_not_approved_again(case):
    case.make(T1={"status": "APPROVED"})
    case.commit(APPROVE_F)
    assert case.state() == ("APPROVED", "APPROVED", "APPROVED")
    assert "T-steve-001" not in case.signed and "T-steve-002" in case.signed


def test_d_anchor_rejecting_the_finding_cascades(case):
    case.make(
        F={"status": "APPROVED"}, T1={"status": "APPROVED"}, T2={"status": "APPROVED"}
    )
    case.commit({"id": "F-steve-001", "action": "reject", "rejection_reason": "no"})
    assert case.state() == ("REJECTED", "REJECTED", "REJECTED")


def test_anchor_untouched_events_follow_the_finding(case):
    case.make()
    case.commit(APPROVE_F)
    assert case.state() == ("APPROVED", "APPROVED", "APPROVED")
    assert {"T-steve-001", "T-steve-002"} <= set(case.signed)
