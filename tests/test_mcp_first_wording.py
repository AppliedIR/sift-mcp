"""The always-on text says MCP first, by advice, never a block.

The AGENTS.md core and forensic-mcp's instructions say it. The instructions
the backends send stay within their size on the integrated release head plus
that one sentence (every byte is in every session's context).
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTRUCTIONS = ROOT / "packages/sift-common/src/sift_common/instructions.py"
# the ten strings' total on the integrated release head, before this sentence
BASE_TOTAL = 20467
SENTENCE = (
    ": weaker evidence than an audit_id, graded as shell evidence, and a command"
    " with an MCP route is marked so in the audit"
)
# the OpenSearch guidance on long evtx values, as approved; added after a space
EVTX_SENTENCE = (
    "An evtx winlog.event_data keyword value longer than its field's limit is kept"
    " in the record but not indexed: 8,191 characters (ScriptBlockText: 32,766), or"
    " 1,024 for fields other than ScriptBlockText in records stored before the"
    " case's index was updated. A search on that field doesn't find it, so 0 hits"
    " there doesn't prove absence."
)
# the OpenSearch guidance on EZ-tool CSV times, as approved; added after a space
EZ_SENTENCE = (
    "EZ-tool CSV indices made by idx_ingest (mft, usn, amcache, shimcache, registry, ...)"
    " carry file and key times, not event times: they aren't in time windows, the default"
    " timeline or the case time range, so query them by their own date field (e.g."
    " Created0x10) with index=."
)
# forensic-mcp's confidence and evidence-standards lines, as approved: judged,
# not counted. They replace 619 characters with 758, so the budget grows by
# the 108 it lacked, and 10 to spare
JUDGMENT_LINES = (
    "CONFIDENCE LEVELS (your judgment; justify it): HIGH — the cited evidence shows"
    " it directly, what you checked agrees, nothing contradicts it (not certainty)."
    ' MEDIUM (intelligence "moderate") — credible support, but not corroborated or'
    " direct enough for HIGH, or another reading is open. LOW — significant"
    " assumptions, fragmented evidence or an unreliable source. SPECULATIVE — no"
    " direct evidence yet; label it.",
    "EVIDENCE STANDARDS: CONFIRMED — an artifact records the claim itself. INDICATED"
    " — an artifact records the claim's subject but stops short of the claim; name"
    " the gap. INFERRED — no artifact records it; reasoned from other facts (state"
    " the chain). UNKNOWN — no evidence either way; do not guess. CONTRADICTED —"
    " evidence disputes it; stop and reassess.",
)
JUDGMENT_GROWTH = 118

# the required skeptic (grading Spec A4), as approved; added after a space
SKEPTIC_SENTENCE = (
    "A finding-skeptic challenge (isolated agent) is required; with none, send"
    ' challenged {"outcome": "not_challenged", "reason": why}.'
)


def _strings():
    out = {}
    for node in ast.parse(INSTRUCTIONS.read_text()).body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                out[node.targets[0].id] = node.value.value
    return out


def test_forensic_mcp_says_shell_evidence_is_graded_and_marked():
    assert SENTENCE in _strings()["FORENSIC_MCP"]


def test_opensearch_says_long_evtx_values_are_not_indexed():
    assert EVTX_SENTENCE in _strings()["OPENSEARCH"]


def test_opensearch_says_ez_csv_indices_carry_no_event_time_once():
    assert _strings()["OPENSEARCH"].count(EZ_SENTENCE) == 1


def test_forensic_mcp_says_a_challenge_is_required():
    assert SKEPTIC_SENTENCE in _strings()["FORENSIC_MCP"]


def test_the_backend_instructions_stay_within_their_budget():
    strings = _strings()
    assert len(strings) == 10
    budget = (
        BASE_TOTAL + len(SENTENCE) + len(EVTX_SENTENCE) + len(EZ_SENTENCE)
        + len(SKEPTIC_SENTENCE) + 3
    )  # fmt: skip
    budget += JUDGMENT_GROWTH
    assert sum(len(v) for v in strings.values()) <= budget


def test_the_agents_core_says_mcp_first_by_advice_never_a_block():
    agents = (ROOT / "AGENTS.md").read_text()
    assert "MCP first, by advice" in agents and "never blocked" in agents


def test_forensic_mcp_states_confidence_and_the_ladder_as_approved():
    lines = _strings()["FORENSIC_MCP"].split("\n\n")
    for line in JUDGMENT_LINES:
        assert line in lines
    assert sum(len(line) for line in JUDGMENT_LINES) == 758
