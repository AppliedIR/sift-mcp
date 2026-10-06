"""Every opencti-mcp call in TOOL_REFERENCE.md uses keywords the tool declares."""

import asyncio
import re
from pathlib import Path

from mcp.types import ListToolsRequest
from opencti_mcp.config import Config
from opencti_mcp.server import OpenCTIMCPServer
from pydantic import SecretStr

ROOT = Path(__file__).parent.parent.parent
CALL = re.compile(r"opencti-mcp\s+(\w+)\(([^)]*)\)")


def test_tool_reference_calls_use_declared_keywords():
    config = Config(
        opencti_url="http://127.0.0.1:9",
        opencti_token=SecretStr("dummy-not-a-real-token-0000"),
    )
    handler = OpenCTIMCPServer(config).server.request_handlers[ListToolsRequest]
    tools = asyncio.run(handler(ListToolsRequest(method="tools/list"))).root.tools
    declared = {t.name: set(t.inputSchema.get("properties", {})) for t in tools}
    seen, bad = 0, []
    for doc in sorted(ROOT.glob("claude-code/*/TOOL_REFERENCE.md")):
        for n, line in enumerate(doc.read_text().splitlines(), 1):
            for tool, args in CALL.findall(line):
                seen += 1
                for kw in re.findall(r"(\w+)\s*=", args):
                    if kw not in declared.get(tool, set()):
                        bad.append(f"{doc.relative_to(ROOT)}:{n} {tool}({kw}=)")
    assert seen and not bad, bad
