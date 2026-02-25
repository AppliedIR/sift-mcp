"""Shared test fixtures."""

from unittest.mock import MagicMock

import pytest
from mcp.types import Tool
from sift_gateway.backends.base import MCPBackend


class MockBackend(MCPBackend):
    """In-memory mock backend for testing."""

    def __init__(self, name: str, config: dict = None, tools: list[Tool] = None):
        super().__init__(name, config or {"type": "stdio", "enabled": True})
        self._mock_tools = tools or []
        self._call_log: list[dict] = []

    async def start(self) -> None:
        self._started = True

    async def stop(self) -> None:
        self._started = False

    async def list_tools(self) -> list[Tool]:
        return self._mock_tools

    async def call_tool(self, name: str, arguments: dict) -> list:
        self._call_log.append({"name": name, "arguments": arguments})
        return [
            MagicMock(
                model_dump=lambda: {"type": "text", "text": f"result from {name}"}
            )
        ]

    async def health_check(self) -> dict:
        if self._started:
            return {"status": "ok", "type": "mock", "tools": len(self._mock_tools)}
        return {"status": "stopped", "type": "mock"}


def make_tool(name: str, description: str = "") -> Tool:
    """Create a Tool instance for testing."""
    return Tool(
        name=name,
        description=description,
        inputSchema={"type": "object", "properties": {}},
    )


@pytest.fixture
def sample_config():
    """Return a minimal gateway config for testing."""
    return {
        "gateway": {
            "host": "127.0.0.1",
            "port": 4508,
            "log_level": "INFO",
        },
        "api_keys": {
            "test_key_1": {"analyst": "alice", "role": "lead"},
            "test_key_2": {"analyst": "bob", "role": "examiner"},
        },
        "backends": {
            "backend-a": {
                "type": "stdio",
                "command": "python",
                "args": ["-m", "fake_a"],
                "enabled": True,
            },
            "backend-b": {
                "type": "stdio",
                "command": "python",
                "args": ["-m", "fake_b"],
                "enabled": True,
            },
        },
    }


@pytest.fixture
def mock_backends():
    """Return two mock backends with distinct tools."""
    backend_a = MockBackend(
        "backend-a",
        tools=[
            make_tool("analyze_file", "Analyze a file"),
            make_tool("list_evidence", "List evidence items"),
        ],
    )
    backend_b = MockBackend(
        "backend-b",
        tools=[
            make_tool("search_intel", "Search threat intel"),
            make_tool("check_hash", "Check a hash"),
        ],
    )
    return {"backend-a": backend_a, "backend-b": backend_b}
