"""run_command takes a preview_lines below 0 as none asked for.

The MCP tool clamps it to 0..200 at the door. Before, a negative value reached
the parser as a cap: a JSON reply came back with no entries. Now it gets the
budget fill that 0 gets. The real run_command runs in-process on a scratch case.
"""

from __future__ import annotations

import asyncio
import json
import sys

import pytest
import sift_mcp.tools.generic as generic
from sift_mcp.catalog import ToolDefinition
from sift_mcp.server import create_server

from .test_run_command_record import case  # noqa: F401 (fixture)

ROWS = [{"PID": 1000 + i, "ImageFileName": f"svchost{i}.exe"} for i in range(400)]
PRINT = f"import json\nprint(json.dumps({ROWS!r}, indent=2))\n"


def _reply(case, preview_lines):
    script = case / "extractions" / "rows.py"
    script.write_text(PRINT)
    r = asyncio.run(
        create_server().call_tool(
            "run_command",
            {
                "command": [sys.executable, str(script)],
                "purpose": "t",
                "preview_lines": preview_lines,
            },
        )
    )
    r = r[0] if isinstance(r, tuple) else r
    return json.loads(r[0].text)


@pytest.fixture
def json_tool(monkeypatch):
    """The command's output parsed as JSON, as a catalog JSON tool's is."""
    td = ToolDefinition(name="py", binary="python3", category="t", output_format="json")
    monkeypatch.setattr(generic, "get_tool_def", lambda name: td)
    monkeypatch.delenv("SIFT_RESPONSE_BUDGET", raising=False)


@pytest.fixture
def seen(monkeypatch):
    """The preview_lines run_command hands the runner."""
    got = []
    real = generic.run_command

    def spy(*a, **kw):
        got.append(kw.get("preview_lines"))
        return real(*a, **kw)

    monkeypatch.setattr(generic, "run_command", spy)
    return got


NEGATIVE = [-1, -5, -200, -10_000, -(2**31)]


@pytest.mark.parametrize("n", NEGATIVE)
@pytest.mark.usefixtures("json_tool")
def test_a_negative_preview_lines_gets_the_budget_fill_of_0(case, n):  # noqa: F811
    zero, neg = _reply(case, 0), _reply(case, n)
    assert zero["output_format"] == neg["output_format"] == "parsed_json"
    assert len(zero["data"]["data"]) > 20
    assert neg["data"] == zero["data"]


@pytest.mark.parametrize(
    "n,want", [(n, 0) for n in NEGATIVE] + [(0, 0), (1, 1), (5, 5), (200, 200),
                                            (201, 200), (10_000, 200)]
)  # fmt: skip
def test_the_door_clamps_to_0_through_200(case, n, want, seen):  # noqa: F811
    assert "error" not in _reply(case, n)
    assert seen == [want]


@pytest.mark.parametrize("n", [1, 5, 20])
@pytest.mark.usefixtures("json_tool")
def test_twin_a_positive_preview_lines_still_caps_json(case, n):  # noqa: F811
    out = _reply(case, n)
    assert out["data"]["data"] == ROWS[:n]
