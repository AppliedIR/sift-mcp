"""Streamable HTTP MCP endpoint for the AIIR gateway.

Exposes the gateway's aggregated tools via the MCP protocol using a
low-level ``Server`` that proxies through the gateway's existing backend
infrastructure.  The ``StreamableHTTPSessionManager`` provides ASGI
request handling; we wrap it with an auth layer and mount it as a route
in the Starlette app.
"""

from __future__ import annotations

import hmac
import json
import logging
import time
from collections.abc import Sequence
from typing import Any

from mcp.server.lowlevel.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import TextContent, Tool
from sift_common.instructions import GATEWAY as _GATEWAY_INSTRUCTIONS
from starlette.requests import Request
from starlette.responses import JSONResponse

from sift_gateway.rate_limit import check_rate_limit

logger = logging.getLogger(__name__)

# Tools that accept analyst_override for identity injection.
ANALYST_TOOLS: frozenset[str] = frozenset(
    {
        "record_action",
        "record_finding",
        "record_timeline_event",
        "add_todo",
        "update_todo",
        "complete_todo",
        "log_reasoning",
        "log_external_action",
    }
)

# Maximum length for bearer tokens (DoS protection)
_MAX_TOKEN_LENGTH = 1024

# Maximum MCP request body size (10 MB)
_MAX_REQUEST_BYTES = 10 * 1024 * 1024


# ---------------------------------------------------------------------------
# ASGI-level auth wrapper
# ---------------------------------------------------------------------------


class MCPAuthASGIApp:
    """ASGI app that authenticates requests then delegates to the session manager.

    We cannot use Starlette's ``BaseHTTPMiddleware`` for the ``/mcp`` route
    because it buffers responses and breaks SSE streaming.  Instead this thin
    ASGI wrapper reads the ``Authorization`` header from the raw scope,
    performs timing-safe key lookup, sets identity on ``scope["state"]``,
    and delegates to ``session_manager.handle_request``.
    """

    def __init__(
        self,
        session_manager: StreamableHTTPSessionManager,
        api_keys: dict[str, dict] | None = None,
    ):
        self.session_manager = session_manager
        self.api_keys = api_keys or {}

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        # Ensure scope["state"] exists
        scope.setdefault("state", {})

        # Rate limit check (before auth or any processing).
        # Extract client IP from the ASGI scope.
        client = scope.get("client")
        client_ip = client[0] if client else "unknown"
        if not check_rate_limit(client_ip):
            resp = JSONResponse(
                {"error": "Rate limit exceeded"},
                status_code=429,
            )
            await resp(scope, receive, send)
            return

        # Request size validation via Content-Length header
        content_length = _get_content_length(scope)
        if content_length is None and scope.get("method", "") == "POST":
            resp = JSONResponse(
                {"error": "Content-Length header required"},
                status_code=411,
            )
            await resp(scope, receive, send)
            return
        if content_length is not None and content_length > _MAX_REQUEST_BYTES:
            resp = JSONResponse(
                {"error": f"Request body too large (max {_MAX_REQUEST_BYTES} bytes)"},
                status_code=413,
            )
            await resp(scope, receive, send)
            return

        if not self.api_keys:
            # No keys configured — single-user / anonymous mode
            scope["state"]["examiner"] = "anonymous"
            scope["state"]["role"] = "examiner"
            await self.session_manager.handle_request(scope, receive, send)
            return

        # Extract Authorization header from raw ASGI headers
        token = _extract_bearer_token(scope)

        if token is None:
            resp = JSONResponse(
                {"error": "Missing or invalid Authorization header"},
                status_code=401,
            )
            await resp(scope, receive, send)
            return

        # Length check: reject excessively long tokens before timing-safe comparison
        if len(token) > _MAX_TOKEN_LENGTH:
            logger.warning(
                "MCP endpoint: rejected oversized bearer token (%d bytes)", len(token)
            )
            resp = JSONResponse(
                {"error": "Invalid API key"},
                status_code=403,
            )
            await resp(scope, receive, send)
            return

        # Timing-safe key lookup: iterate ALL keys to prevent timing leaks
        matched_key = None
        for candidate in self.api_keys:
            if hmac.compare_digest(token, candidate) and matched_key is None:
                matched_key = candidate

        if matched_key is None:
            resp = JSONResponse(
                {"error": "Invalid API key"},
                status_code=403,
            )
            await resp(scope, receive, send)
            return

        key_info = self.api_keys.get(matched_key, {})
        if not isinstance(key_info, dict):
            logger.error("MCP endpoint: API key config for matched key is not a dict")
            resp = JSONResponse(
                {"error": "Server configuration error"},
                status_code=500,
            )
            await resp(scope, receive, send)
            return

        scope["state"]["examiner"] = key_info.get(
            "examiner", key_info.get("analyst", "unknown")
        )
        scope["state"]["role"] = key_info.get("role", "examiner")
        await self.session_manager.handle_request(scope, receive, send)


def _get_content_length(scope: dict) -> int | None:
    """Extract Content-Length from raw ASGI scope headers. Returns None if absent or invalid."""
    headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
    for name, value in headers:
        if name.lower() == b"content-length":
            try:
                return int(value.decode("latin-1"))
            except (ValueError, OverflowError, UnicodeDecodeError):
                return None
    return None


def _extract_bearer_token(scope: dict) -> str | None:
    """Pull the bearer token from raw ASGI scope headers."""
    headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
    for name, value in headers:
        if name.lower() == b"authorization":
            try:
                decoded = value.decode("latin-1")
            except (UnicodeDecodeError, AttributeError):
                logger.warning("MCP endpoint: failed to decode authorization header")
                return None
            if decoded.lower().startswith("bearer "):
                return decoded[7:].strip()
    return None


# ---------------------------------------------------------------------------
# MCP server factory
# ---------------------------------------------------------------------------


def create_mcp_server(gateway: Any) -> Server:
    """Build a low-level MCP ``Server`` that proxies through *gateway*.

    ``@server.list_tools()`` aggregates tools from all backends (with
    collision-prefixed names).  ``@server.call_tool()`` routes to the
    correct backend, injecting analyst identity from the HTTP request.
    """
    server = Server("sift-gateway", instructions=_GATEWAY_INSTRUCTIONS)

    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        return await gateway.get_tools_list()

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict) -> Sequence[TextContent]:
        # Extract examiner from the Starlette Request stashed by the transport
        examiner = None
        try:
            ctx = server.request_context
            request: Request | None = ctx.request
            if request is not None:
                examiner = getattr(request.state, "examiner", None)
                if examiner is None:
                    examiner = getattr(request.state, "analyst", None)
        except LookupError:
            pass

        try:
            result = await gateway.call_tool(name, arguments, examiner=examiner)
        except KeyError as e:
            logger.warning("MCP call_tool unknown tool: %s", e)
            return [TextContent(type="text", text=f"Error: unknown tool {name}")]
        except (RuntimeError, ConnectionError, OSError) as e:
            logger.error("MCP call_tool backend error for %s: %s", name, e)
            return [TextContent(type="text", text=f"Error: backend failure for {name}")]
        except Exception as e:
            logger.error(
                "MCP call_tool unexpected error for %s: %s: %s",
                name,
                type(e).__name__,
                e,
            )
            return [
                TextContent(type="text", text=f"Error: unexpected failure for {name}")
            ]

        # Normalise to list of TextContent for the MCP protocol
        contents: list[TextContent] = []
        for item in result:
            if isinstance(item, TextContent):
                contents.append(item)
            elif hasattr(item, "model_dump"):
                contents.append(
                    TextContent(type="text", text=json.dumps(item.model_dump()))
                )
            else:
                contents.append(TextContent(type="text", text=str(item)))
        return contents

    return server


def create_backend_mcp_server(gateway: Any, backend_name: str) -> Server:
    """Build a low-level MCP ``Server`` exposing only *backend_name*'s tools.

    Unlike :func:`create_mcp_server` (which aggregates all backends), this
    creates a dedicated server for a single backend.  Each gets its own
    ``Server`` + ``StreamableHTTPSessionManager`` + ``MCPAuthASGIApp`` triple
    so that MCP sessions are isolated per backend.
    """
    backend = gateway.backends[backend_name]
    server = Server(f"sift-gateway/{backend_name}")

    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        if not backend.started:
            await gateway.ensure_backend_started(backend_name)
        backend.last_tool_call = time.monotonic()
        return await backend.list_tools()

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict) -> Sequence[TextContent]:
        if not backend.started:
            await gateway.ensure_backend_started(backend_name)
        backend.last_tool_call = time.monotonic()

        examiner = None
        try:
            ctx = server.request_context
            request: Request | None = ctx.request
            if request is not None:
                examiner = getattr(request.state, "examiner", None)
                if examiner is None:
                    examiner = getattr(request.state, "analyst", None)
        except LookupError:
            pass

        # Inject examiner identity for analyst tools
        if examiner and name in ANALYST_TOOLS:
            arguments = {**arguments, "analyst_override": examiner}

        try:
            result = await backend.call_tool(name, arguments)
        except (RuntimeError, ConnectionError, OSError) as e:
            logger.error(
                "Per-backend call_tool error for %s/%s: %s", backend_name, name, e
            )
            return [TextContent(type="text", text=f"Error: backend failure for {name}")]
        except Exception as e:
            logger.error(
                "Per-backend call_tool unexpected error for %s/%s: %s: %s",
                backend_name,
                name,
                type(e).__name__,
                e,
            )
            return [
                TextContent(type="text", text=f"Error: unexpected failure for {name}")
            ]

        # Normalise to list of TextContent
        contents: list[TextContent] = []
        for item in result:
            if isinstance(item, TextContent):
                contents.append(item)
            elif hasattr(item, "model_dump"):
                contents.append(
                    TextContent(type="text", text=json.dumps(item.model_dump()))
                )
            else:
                contents.append(TextContent(type="text", text=str(item)))
        return contents

    return server


# ---------------------------------------------------------------------------
# Session manager factory
# ---------------------------------------------------------------------------


def create_session_manager(mcp_server: Server) -> StreamableHTTPSessionManager:
    """Create a ``StreamableHTTPSessionManager`` wrapping *mcp_server*."""
    return StreamableHTTPSessionManager(
        app=mcp_server,
        stateless=False,
    )
