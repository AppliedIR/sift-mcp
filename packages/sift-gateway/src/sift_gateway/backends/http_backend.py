"""HTTP-based MCP backend — connects to a remote MCP server via Streamable HTTP transport."""

import asyncio
import logging
from contextlib import AsyncExitStack
from urllib.parse import urlparse

from mcp.client.streamable_http import streamablehttp_client
from mcp.client.session import ClientSession
from mcp.types import Tool

from sift_gateway.backends.base import MCPBackend

logger = logging.getLogger(__name__)

# Timeout (seconds) for backend operations
_TOOL_LIST_TIMEOUT = 30
_TOOL_CALL_TIMEOUT = 300
_STOP_TIMEOUT = 15


class HttpMCPBackend(MCPBackend):
    """Backend that connects to a remote MCP server via Streamable HTTP."""

    def __init__(self, name: str, config: dict):
        super().__init__(name, config)
        self._session: ClientSession | None = None
        self._exit_stack: AsyncExitStack | None = None
        self._tools_cache: list[Tool] | None = None

        # Validate URL format at construction time
        url = config.get("url")
        if url:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                raise ValueError(
                    f"Backend {name}: URL must use http or https scheme, got {parsed.scheme!r}"
                )

    async def start(self) -> None:
        if self._started:
            return

        url = self.config.get("url")
        if not url:
            raise ValueError(f"Backend {self.name}: 'url' is required for http type")

        headers = {}
        bearer_token = self.config.get("bearer_token")
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        extra_headers = self.config.get("headers") or {}
        headers.update(extra_headers)

        self._exit_stack = AsyncExitStack()
        try:
            transport = await self._exit_stack.enter_async_context(
                streamablehttp_client(url, headers=headers if headers else None)
            )
            read_stream, write_stream, _ = transport
            self._session = await self._exit_stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            await self._session.initialize()
            self._started = True
            logger.info("Backend %s started (http -> %s)", self.name, url)
        except Exception as exc:
            logger.error("Backend %s failed to start (http -> %s): %s: %s", self.name, url, type(exc).__name__, exc)
            try:
                await self._exit_stack.aclose()
            except Exception as cleanup_exc:
                logger.warning("Backend %s cleanup after failed start also failed: %s", self.name, cleanup_exc)
            self._exit_stack = None
            self._session = None
            raise

    async def stop(self) -> None:
        if not self._started:
            return
        if self._exit_stack:
            try:
                await asyncio.wait_for(self._exit_stack.aclose(), timeout=_STOP_TIMEOUT)
            except asyncio.TimeoutError:
                logger.warning("Backend %s stop timed out after %ds", self.name, _STOP_TIMEOUT)
            except Exception as exc:
                logger.error("Backend %s error during stop: %s: %s", self.name, type(exc).__name__, exc)
        self._exit_stack = None
        self._session = None
        self._tools_cache = None
        self._started = False
        logger.info("Backend %s stopped", self.name)

    async def list_tools(self) -> list[Tool]:
        if not self._started or not self._session:
            raise RuntimeError(f"Backend {self.name} is not started")

        if self._tools_cache is None:
            result = await asyncio.wait_for(
                self._session.list_tools(), timeout=_TOOL_LIST_TIMEOUT
            )
            self._tools_cache = result.tools
        return self._tools_cache

    async def call_tool(self, name: str, arguments: dict) -> list:
        if not self._started or not self._session:
            raise RuntimeError(f"Backend {self.name} is not started")

        result = await asyncio.wait_for(
            self._session.call_tool(name, arguments), timeout=_TOOL_CALL_TIMEOUT
        )
        return result.content

    async def health_check(self) -> dict:
        if not self._started or not self._session:
            return {"status": "stopped", "type": "http", "url": self.config.get("url")}
        try:
            await self.list_tools()
            return {
                "status": "ok",
                "type": "http",
                "url": self.config.get("url"),
                "tools": len(self._tools_cache or []),
            }
        except Exception as exc:
            logger.warning("Backend %s health check failed: %s: %s", self.name, type(exc).__name__, exc)
            return {
                "status": "error",
                "type": "http",
                "url": self.config.get("url"),
                "error": str(exc),
            }
