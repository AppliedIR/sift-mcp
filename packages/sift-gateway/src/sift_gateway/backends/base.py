"""Abstract base class for MCP backends."""

from abc import ABC, abstractmethod

from mcp.types import Tool


class MCPBackend(ABC):
    """Base class for all MCP backend connections.

    A backend represents a single MCP server that the gateway proxies to.
    It may be a local subprocess (stdio) or a remote HTTP server.
    """

    def __init__(self, name: str, config: dict):
        self.name = name
        self.config = config
        self._started = False
        self.last_tool_call: float = 0.0  # time.monotonic() of last activity

    @property
    def enabled(self) -> bool:
        return self.config.get("enabled", True)

    @property
    def started(self) -> bool:
        return self._started

    @abstractmethod
    async def start(self) -> None:
        """Start the backend connection / subprocess."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Stop the backend connection / subprocess."""
        ...

    @abstractmethod
    async def list_tools(self) -> list[Tool]:
        """List tools exposed by this backend."""
        ...

    @abstractmethod
    async def call_tool(self, name: str, arguments: dict) -> list:
        """Call a tool on this backend and return the result content list."""
        ...

    @abstractmethod
    async def health_check(self) -> dict:
        """Return health status for this backend.

        Returns:
            Dict with at least {"status": "ok"|"error", ...}
        """
        ...
