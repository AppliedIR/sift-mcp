"""Both shipped Claude Code templates deny `vhir approve` and `vhir reject`.

The full template carried the four rules; the lite one (deployed by
quickstart-lite.sh) had no deny list, so a lite session's shell tool could
run an approval. The parity with vhir's own client settings is pinned where
both sources are installed.
"""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent
RULES = {
    "Bash(vhir approve*)",
    "Bash(*vhir approve*)",
    "Bash(vhir reject*)",
    "Bash(*vhir reject*)",
}


@pytest.mark.parametrize("template", ["full", "lite"])
def test_the_template_denies_approve_and_reject(template):
    settings = json.loads(
        (ROOT / "claude-code" / template / "settings.json").read_text()
    )
    assert set(settings["permissions"]["deny"]) >= RULES


def test_the_rules_are_vhir_s():
    client_setup = pytest.importorskip("vhir_cli.commands.client_setup")
    ours = {
        r for r in client_setup._FORENSIC_DENY_RULES if "approve" in r or "reject" in r
    }
    assert ours == RULES
