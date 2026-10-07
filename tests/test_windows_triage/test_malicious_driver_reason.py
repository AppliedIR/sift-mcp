"""A LOLDrivers entry in the malicious category is named as a known malicious
driver, not as a vulnerable one.

check_hash said "Vulnerable driver: GMER" and "Vulnerability: malicious" for
every category spelling. The verdict and confidence are unchanged.
"""

import pytest
from windows_triage.analysis.verdicts import Verdict, calculate_hash_verdict


def _reasons(category):
    result = calculate_hash_verdict(
        is_vulnerable_driver=True,
        driver_info={"product": "GMER", "vulnerability_type": category},
    )
    assert (result.verdict, result.confidence) == (Verdict.SUSPICIOUS, "high")
    return result.reasons


@pytest.mark.parametrize("category", ["malicious", "malicious driver"])
def test_a_malicious_driver_is_named_as_one(category):
    reasons = _reasons(category)
    assert reasons[0] == "Known malicious driver (LOLDrivers): GMER"
    assert not [r for r in reasons if r.startswith("Vulnerab")]


@pytest.mark.parametrize("category", ["vulnerable", "vulnerable driver"])
def test_anchor_a_vulnerable_driver_reads_as_before(category):
    assert _reasons(category) == [
        "Vulnerable driver: GMER",
        f"Vulnerability: {category}",
    ]
