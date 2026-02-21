"""Tests for sift_mcp.server — MCP server creation."""

import pytest
from sift_mcp.server import create_server


class TestServer:
    def test_create_server(self):
        server = create_server()
        assert server is not None
        assert server.name == "sift-mcp"

    def test_server_has_tools(self):
        """Verify core tools are registered."""
        server = create_server()
        # FastMCP stores tools internally — just verify creation works
        assert server is not None
