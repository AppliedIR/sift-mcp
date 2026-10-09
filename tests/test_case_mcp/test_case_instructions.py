"""case-mcp's instructions agree with evidence_register: the AI may register
original evidence, marked as its own; nothing says every change needs the
examiner's confirmation."""

from sift_common.instructions import CASE_MCP


def test_the_instructions_say_the_ai_may_register_originals_as_its_own():
    assert "require examiner confirmation" not in CASE_MCP
    assert "You may register originals: each is marked as the AI's." in CASE_MCP
