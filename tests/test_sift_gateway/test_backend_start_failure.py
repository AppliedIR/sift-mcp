"""One backend failing at startup leaves the gateway serving the others.

The per-backend catch named BaseExceptionGroup, which Python 3.10 doesn't
have: evaluating the clause raised NameError, the lifespan failed, and the
whole gateway exited. These rows fail on 3.10 without the fix; 3.11+ has the
builtin, so they pass there either way.
"""

from __future__ import annotations

import sys
import textwrap
from unittest.mock import AsyncMock

from mcp.shared.exceptions import McpError
from mcp.types import ErrorData, Tool
from sift_gateway.server import Gateway
from starlette.testclient import TestClient

from .conftest import MockBackend


class _FailingBackend(MockBackend):
    async def start(self) -> None:
        raise McpError(ErrorData(code=-32000, message="Connection closed"))


async def test_start_survives_a_backend_raising_mcp_error():
    gw = Gateway({"backends": {}})
    good = MockBackend("good", tools=[Tool(name="ping", inputSchema={})])
    gw.backends = {"bad": _FailingBackend("bad"), "good": good}
    gw._notify_backend_case = AsyncMock()

    await gw.start()

    assert good.started and not gw.backends["bad"].started
    assert gw._tool_map == {"ping": "good"}


def test_gateway_with_a_backend_that_dies_at_startup_serves_health(tmp_path):
    """Real stdio backends: one serves a tool, the other exits the way
    windows-triage does without its databases."""
    good = tmp_path / "good_server.py"
    good.write_text(
        textwrap.dedent(
            """\
            from mcp.server.fastmcp import FastMCP
            m = FastMCP("good")
            @m.tool()
            def ping() -> str:
                return "pong"
            m.run()
            """
        )
    )
    bad = tmp_path / "bad_server.py"
    bad.write_text(
        "import sys\n"
        'print("unable to open database file", file=sys.stderr)\n'
        "raise SystemExit(1)\n"
    )
    config = {
        "gateway": {"host": "127.0.0.1", "port": 0},
        "api_keys": {},
        "backends": {
            "good": {"type": "stdio", "command": sys.executable, "args": [str(good)]},
            "bad": {"type": "stdio", "command": sys.executable, "args": [str(bad)]},
        },
    }
    app = Gateway(config).create_app()
    with TestClient(app) as client:  # runs the lifespan, which starts both
        health = client.get("/health").json()
    assert health["status"] == "degraded"
    assert health["backends"]["good"]["status"] == "ok"
    assert health["backends"]["bad"]["status"] != "ok"
