"""HTTP-based MCP backend — connects to a remote MCP server via Streamable HTTP transport."""

import asyncio
import logging
import os
from contextlib import AsyncExitStack
from urllib.parse import urlparse

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.types import Tool

from sift_gateway.backends.base import MCPBackend

logger = logging.getLogger(__name__)

# Timeout (seconds) for backend operations
_TOOL_LIST_TIMEOUT = 30
_TOOL_CALL_TIMEOUT = 300
_STOP_TIMEOUT = 15


def _make_pinned_tls_factory(cert_path: str):
    """Return an httpx_client_factory that pins TLS verification to a specific cert."""
    import httpx
    from mcp.shared._httpx_utils import (
        MCP_DEFAULT_SSE_READ_TIMEOUT,
        MCP_DEFAULT_TIMEOUT,
    )

    def factory(headers=None, timeout=None, auth=None):
        kwargs = {"follow_redirects": True, "verify": cert_path}
        if headers is not None:
            kwargs["headers"] = headers
        if timeout is None:
            kwargs["timeout"] = httpx.Timeout(
                MCP_DEFAULT_TIMEOUT, read=MCP_DEFAULT_SSE_READ_TIMEOUT
            )
        else:
            kwargs["timeout"] = timeout
        if auth is not None:
            kwargs["auth"] = auth
        return httpx.AsyncClient(**kwargs)

    return factory


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
            client_factory_kwargs = {}
            tls_cert = self.config.get("tls_cert")
            if tls_cert:
                tls_cert = os.path.expanduser(tls_cert)
                client_factory_kwargs["httpx_client_factory"] = (
                    _make_pinned_tls_factory(tls_cert)
                )

            transport = await self._exit_stack.enter_async_context(
                streamablehttp_client(
                    url,
                    headers=headers if headers else None,
                    **client_factory_kwargs,
                )
            )
            read_stream, write_stream, _ = transport
            self._session = await self._exit_stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            result = await self._session.initialize()
            self._instructions = result.instructions
            self._started = True
            logger.info("Backend %s started (http -> %s)", self.name, url)
        except BaseException as exc:
            logger.error(
                "Backend %s failed to start (http -> %s): %s: %s",
                self.name,
                url,
                type(exc).__name__,
                exc,
            )
            try:
                await self._exit_stack.aclose()
            except BaseException as cleanup_exc:
                logger.warning(
                    "Backend %s cleanup after failed start also failed: %s",
                    self.name,
                    cleanup_exc,
                )
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
                logger.warning(
                    "Backend %s stop timed out after %ds", self.name, _STOP_TIMEOUT
                )
            except BaseException as exc:
                level = logging.DEBUG if "cancel scope" in str(exc) else logging.ERROR
                logger.log(
                    level,
                    "Backend %s error during stop: %s: %s",
                    self.name,
                    type(exc).__name__,
                    exc,
                )
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

    async def _teardown(self) -> None:
        """Clean up session state so the backend can be restarted."""
        self._tools_cache = None
        self._session = None
        self._started = False
        if self._exit_stack:
            try:
                await self._exit_stack.aclose()
            except BaseException:
                pass
            self._exit_stack = None

    async def call_tool(self, name: str, arguments: dict) -> list:
        if not self._started or not self._session:
            raise RuntimeError(f"Backend {self.name} is not started")

        try:
            result = await asyncio.wait_for(
                self._session.call_tool(name, arguments), timeout=_TOOL_CALL_TIMEOUT
            )
            return result.content
        except (ConnectionError, OSError) as exc:
            logger.error(
                "Backend %s connection lost during call_tool: %s", self.name, exc
            )
            await self._teardown()
            raise
        except Exception as exc:
            exc_str = str(exc).lower()
            if "session terminated" in exc_str or "session not found" in exc_str:
                # Session went stale — reconnect and retry once instead of
                # tearing down and cascading through the lazy-restart cycle.
                logger.warning(
                    "Backend %s session terminated, reconnecting: %s",
                    self.name,
                    exc,
                )
                await self._teardown()
                try:
                    await self.start()
                    result = await asyncio.wait_for(
                        self._session.call_tool(name, arguments),
                        timeout=_TOOL_CALL_TIMEOUT,
                    )
                    return result.content
                except Exception as retry_exc:
                    logger.error(
                        "Backend %s retry after reconnect failed: %s",
                        self.name,
                        retry_exc,
                    )
                    await self._teardown()
                    raise retry_exc from exc
            raise

    async def health_check(self) -> dict:
        if not self._started or not self._session:
            return {"status": "stopped", "type": "http"}
        try:
            await self.list_tools()
            return {
                "status": "ok",
                "type": "http",
                "tools": len(self._tools_cache or []),
            }
        except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
            logger.warning(
                "Backend %s health check failed: %s: %s",
                self.name,
                type(exc).__name__,
                exc,
            )
            return {
                "status": "error",
                "type": "http",
                "error": type(exc).__name__,
            }
