"""The model-facing hints name the threat-intel tool, not a backend.

An install upgraded from an earlier version serves the threat-intel backend
as opencti-mcp, a new one as threatintel-mcp; the tool is lookup_ioc in
both, so that is what the hints name.
"""

import sift_common.instructions as instructions
from sift_mcp import response


def test_instructions_and_hints_name_no_threat_intel_backend():
    texts = [v for v in vars(instructions).values() if isinstance(v, str)]
    texts += [h for hints in response._RELATED_TOOLS.values() for h in hints]
    joined = " ".join(texts)
    assert "threatintel-mcp" not in joined and "opencti-mcp" not in joined
    assert "lookup_ioc (threat intel)" in joined
