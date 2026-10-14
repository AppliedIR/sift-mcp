"""forensic-rag's tool is search_knowledge, and its guidance is found by that
name: through get_tool_guidance, and as the knowledge base's tool entry."""

from __future__ import annotations

import asyncio
import json

from forensic_knowledge import loader
from forensic_mcp.server import create_server


def _guidance(tool: str) -> dict:
    server = create_server(reference_mode="tools")
    result = asyncio.run(server.call_tool("get_tool_guidance", {"tool_name": tool}))
    return json.loads(result[0].text)


def test_get_tool_guidance_answers_for_search_knowledge():
    g = _guidance("search_knowledge")
    assert g["tool"] == "forensic-rag-mcp: search_knowledge"
    assert "0.85+" in g["score_interpretation"]


def test_the_guidance_offered_names_the_real_tool():
    assert "search_knowledge" in _guidance("no_such_tool")["available"]
    assert "search" not in _guidance("no_such_tool")["available"]


def test_the_tool_entry_is_found_by_the_real_name():
    loader.clear_cache()
    assert loader.get_tool("search_knowledge")["mcp_server"] == "forensic-rag-mcp"
    assert loader.get_tool("search") is None
