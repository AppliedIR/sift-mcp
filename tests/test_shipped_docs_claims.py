"""The shipped docs describe signed approvals, not the old HMAC ledger.

The README, the architecture page, the portal guide and the Claude Code
welcome text described a password-keyed HMAC ledger and a challenge-response
commit. Approvals are now signed with each examiner's own key, in the
browser or at the terminal; these rows pin that the old claims are gone and
the portal guide says what the signing dialog does.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SHIPPED = (
    [ROOT / "README.md", ROOT / "ARCHITECTURE.md"]
    + sorted((ROOT / "docs").glob("*.md"))
    + sorted((ROOT / "claude-code").rglob("*.md"))
)
FALSE = [
    r"HMAC", r"challenge-response commit", r"re-signs?", r"cannot forge",
    r"password hash(?:es)? (?:files|restore)", r"PBKDF2-derived cryptographic signing",
]  # fmt: skip


@pytest.mark.parametrize("path", SHIPPED, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_shipped_doc_makes_an_old_claim(path):
    hits = [p for p in FALSE if re.search(p, path.read_text())]
    assert hits == [], hits


def test_the_portal_guide_says_what_the_signing_dialog_does():
    text = " ".join((ROOT / "docs" / "examiner-portal.md").read_text().split())
    for phrase in [
        "Lists every decision before the passphrase field opens",
        'each is signed (as you) only if you tick "Include and sign as me"',
        "The passphrase never leaves the browser. The gateway checks every signature",
        "TODO entries stay staged; `vhir approve --review` creates them.",
        "`vhir enrol --name NAME`",
    ]:
        assert phrase in text, phrase
