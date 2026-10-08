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
BASE_TOTAL = 20045
SENTENCE = (
    ": weaker evidence than an audit_id, graded as shell evidence, and a command"
    " with an MCP route is marked so in the audit"
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


def test_the_backend_instructions_stay_within_their_budget():
    strings = _strings()
    assert len(strings) == 10
    assert sum(len(v) for v in strings.values()) <= BASE_TOTAL + len(SENTENCE)


def test_the_agents_core_says_mcp_first_by_advice_never_a_block():
    agents = (ROOT / "AGENTS.md").read_text()
    assert "MCP first, by advice" in agents and "never blocked" in agents
