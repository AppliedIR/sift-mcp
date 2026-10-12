"""The IOC completeness warning reads a dict IOC by its value:
`{"type": "ip", "value": "10.1.2.3"}` lists 10.1.2.3, as the string form
does; a dict with no value lists nothing. Before, only string IOCs were read,
so every dict-form IOC was reported missing from the list."""

from __future__ import annotations

import pytest

from .test_case_manager import active_case, manager  # noqa: F401 (fixtures)

LISTED, UNLISTED = "10.1.2.3", "10.9.9.9"


def _missing(mgr, iocs):
    finding = {
        "title": "Beacon",
        "audit_ids": ["wt-tester-20260219-001"],
        "observation": f"connections to {LISTED} and {UNLISTED} seen in 4688",
        "interpretation": "C2 traffic",
        "confidence": "MEDIUM",
        "confidence_justification": "one source",
        "type": "finding",
    }
    if iocs is not None:
        finding["iocs"] = iocs
    result = mgr.record_finding(finding)
    assert result["status"] == "STAGED", result
    lead = "IOC completeness: "
    warning = result.get("warning", "")
    if lead not in warning:
        return None
    named = warning.split(lead, 1)[1].split("not in iocs list: ", 1)[1]
    return [v for v in (UNLISTED, LISTED) if v in named], warning


@pytest.mark.parametrize(
    "iocs",
    [
        [{"type": "ip", "value": LISTED}],
        [
            {"type": "ip", "value": LISTED},
            {"type": "ip"},
            {"type": "x", "value": 7},
        ],  # one with no value, one with an int value
        [LISTED],  # the string form, as before
        [{"type": "ip", "value": " 10.1.2.3 "}],  # normalised as the string form is
    ],
    ids=["dict", "no-value-and-int", "string", "dict-spaced"],
)
@pytest.mark.usefixtures("active_case")
def test_only_the_unlisted_ip_is_named(manager, iocs):  # noqa: F811
    named, warning = _missing(manager, iocs)
    assert named == [UNLISTED], warning
    assert "IOC completeness: 1 value(s) in text but not in iocs list" in warning


@pytest.mark.usefixtures("active_case")
def test_with_no_iocs_both_are_named(manager):  # noqa: F811
    """No iocs at all: both are named, as before."""
    named, warning = _missing(manager, None)
    assert sorted(named) == sorted([LISTED, UNLISTED]), warning
