"""The portal's commit: an explicit reject wins over finding coupling.

Approving a finding approves the timeline event it was auto-created with (the
finding's signed `timeline_event_id`). That coupling once re-approved any
event that wasn't APPROVED, including one the examiner had rejected, and
signed it. Coupling approves only a DRAFT event; rejecting a finding still
cascades. The signed commit runs end to end on a scratch case.
"""

from __future__ import annotations

import pytest

from .conftest import enrol, event, finding, reviewed


@pytest.fixture
def case(portal):
    """F (auto-created T1, plus T2 citing it) and an unrelated finding X."""
    enrol("steve")

    def make(**overrides):
        items = {
            "F": finding("F-steve-001", timeline_event_id="T-steve-001"),
            "X": finding("F-steve-002"),
            "T1": event("T-steve-001", "F-steve-001"),
            "T2": event("T-steve-002", "F-steve-001"),
        }
        for k, v in overrides.items():
            items[k].update(v)
        portal.write("findings.json", [items["F"], items["X"]])
        portal.write("timeline.json", [items["T1"], items["T2"]])

    def commit(*decisions):
        entries = [reviewed(portal, i, a, **kw) for i, a, kw in decisions]
        r = portal.sign_all(entries)
        assert r.status_code == 200, r.text

    def state():
        return tuple(
            portal.item(i)["status"]
            for i in ("F-steve-001", "T-steve-001", "T-steve-002")
        )

    def signed():
        return [(ln["item_id"], ln["decision"]) for ln in portal.chain()]

    portal.make, portal.decide, portal.state, portal.signed = (
        make,
        commit,
        state,
        signed,
    )
    return portal


REJECT_T2 = ("T-steve-002", "reject", {"rejection_reason": "no"})
APPROVE_F = ("F-steve-001", "approve", {})


def test_4_a_delta_rejecting_the_event_and_approving_the_finding(case):
    case.make()
    case.decide(REJECT_T2, APPROVE_F)
    assert case.state() == ("APPROVED", "APPROVED", "REJECTED")
    assert ("T-steve-002", "approve") not in case.signed()


def test_a_a_rejected_event_survives_an_unrelated_commit(case):
    case.make(
        F={"status": "APPROVED"},
        T1={"status": "APPROVED"},
        T2={"status": "REJECTED", "rejection_reason": "explicit"},
    )
    case.decide(("F-steve-002", "approve", {}))
    assert case.state() == ("APPROVED", "APPROVED", "REJECTED")
    assert case.signed() == [("F-steve-002", "approve")]


def test_b_an_event_rejected_after_its_finding_was_approved(case):
    case.make()
    case.decide(APPROVE_F)
    case.decide(REJECT_T2)
    assert case.state() == ("APPROVED", "APPROVED", "REJECTED")
    assert ("T-steve-002", "approve") not in case.signed()


def test_c_an_approved_event_is_not_approved_again(case):
    case.make(T1={"status": "APPROVED"})
    case.decide(APPROVE_F)
    assert case.state() == ("APPROVED", "APPROVED", "DRAFT")
    assert case.signed() == [("F-steve-001", "approve")]


def test_d_anchor_rejecting_the_finding_cascades_to_its_event(case):
    case.make(
        F={"status": "APPROVED"}, T1={"status": "APPROVED"}, T2={"status": "APPROVED"}
    )
    case.decide(("F-steve-001", "reject", {"rejection_reason": "no"}))
    assert case.state() == ("REJECTED", "REJECTED", "APPROVED")


def test_anchor_the_linked_event_follows_the_finding(case):
    """Only the event the finding names in its signed `timeline_event_id`
    cascades; another event citing it is decided on its own."""
    case.make()
    case.decide(APPROVE_F)
    assert case.state() == ("APPROVED", "APPROVED", "DRAFT")
    assert case.signed() == [("F-steve-001", "approve"), ("T-steve-001", "approve")]
