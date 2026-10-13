"""The portal shows no provenance tier: a finding no longer stores one, so a
new finding is never shown as "NONE", and an older finding that stored a
tier (as text or as a summary) still renders, by its provenance grade. The
tier filter and the provenance-warnings block are gone with it.

The page's own script runs under node with a stand-in `document`
(test_portal_provenance_display's driver); each row renders a finding's card."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from .conftest import finding
from .test_portal_provenance_display import DRIVER, PAGE, text

FINDINGS = [
    # as stored now: no tier
    finding("F-steve-100", provenance_schema=2, provenance_grade="FULL"),
    # older records: a tier as text, or as a summary with warnings
    finding("F-steve-101", provenance="MCP", provenance_grade="FULL"),
    finding(
        "F-steve-102",
        provenance={"summary": "SHELL"},
        provenance_warnings=["evidence trail incomplete"],
    ),
]


@pytest.fixture(scope="module")
def shown() -> dict:
    node = shutil.which("node")
    if not node:
        pytest.skip("node isn't installed")
    r = subprocess.run([node, "-e", DRIVER], capture_output=True, text=True, timeout=120,
                       input=json.dumps({"page": str(PAGE), "findings": FINDINGS,
                                         "audit": []}))  # fmt: skip
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout)


@pytest.mark.parametrize("fid", ["F-steve-100", "F-steve-101", "F-steve-102"])
def test_a_finding_renders_with_no_tier(shown, fid):
    card = text(shown[fid]["card"])
    assert f"title {fid}" in card  # it rendered
    assert not re.search(r"Provenance:\s*(NONE|MCP|SHELL|HOOK|MIXED)", card), card


def test_the_tier_filter_and_the_warnings_block_are_gone():
    page = PAGE.read_text()
    assert 'id="filterProv"' not in page and "filterProv" not in page
    assert "f.provenance_warnings" not in page


SIGNED_AT_064 = Path(__file__).parents[1] / "test_forensic_mcp" / "signed_at_064.json"


def test_the_api_serves_a_finding_signed_at_0_6_4_as_stored(portal):
    """The tier and its warnings stay on an older record, as signed: the
    page's checks compare what it's served with what was signed."""
    from vhir_cli.case_io import VIEW_EXCLUDES

    stored = json.loads(SIGNED_AT_064.read_text())["findings"]
    portal.write("findings.json", stored)
    served = {f["id"]: f for f in portal.get("/api/findings").json()}
    assert sorted(served) == sorted(f["id"] for f in stored)
    for f in stored:
        for got in (served[f["id"]], portal.get(f"/api/findings/{f['id']}").json()):
            assert {k: got[k] for k in f} == f
            assert set(got) - set(f) <= VIEW_EXCLUDES[1]
