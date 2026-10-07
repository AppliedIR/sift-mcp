"""Abstract base class for MCP backends."""

import asyncio
from abc import ABC, abstractmethod

from mcp.types import Tool


class ToolResult(list):
    """A tool call's content list, carrying the backend's MCP ``isError`` flag."""

    def __init__(self, content=(), is_error: bool = False):
        super().__init__(content)
        self.is_error = is_error


async def in_own_task(coro):
    """Await ``coro`` in a throwaway task of its own.

    A backend's start opens transport scopes in the task that runs it. From
    Python 3.12, ``wait_for`` runs its coroutine in the caller's task, so a
    start from a request (or from a long-lived task) would leave them open
    there, where a later stop from elsewhere breaks that task.
    """
    return await asyncio.ensure_future(coro)


class MCPBackend(ABC):
    """Base class for all MCP backend connections.

    A backend represents a single MCP server that the gateway proxies to.
    It may be a local subprocess (stdio) or a remote HTTP server.
    """

    def __init__(self, name: str, config: dict):
        self.name = name
        self.config = config
        self._started = False
        self._instructions: str | None = None
        self.last_tool_call: float = 0.0  # time.monotonic() of last activity

    @property
    def enabled(self) -> bool:
        return self.config.get("enabled", True)

    @property
    def started(self) -> bool:
        return self._started

    @property
    def instructions(self) -> str | None:
        """Instructions captured from the backend during initialize()."""
        return self._instructions

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
