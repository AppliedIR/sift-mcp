"""Streamable HTTP MCP endpoint for the AIIR gateway.

Exposes the gateway's aggregated tools via the MCP protocol using a
low-level ``Server`` that proxies through the gateway's existing backend
infrastructure.  The ``StreamableHTTPSessionManager`` provides ASGI
request handling; we wrap it with an auth layer and mount it as a route
in the Starlette app.
"""

from __future__ import annotations

import hmac
import logging
from typing import Any, Sequence

from mcp.server.lowlevel.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import Tool, TextContent
from starlette.requests import Request
from starlette.responses import JSONResponse

from sift_gateway.rate_limit import check_rate_limit

logger = logging.getLogger(__name__)


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

        if not self.api_keys:
            # No keys configured — single-user / anonymous mode
            scope["state"]["analyst"] = "anonymous"
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

        key_info = self.api_keys[matched_key]
        scope["state"]["analyst"] = key_info.get(
            "examiner", key_info.get("analyst", "unknown")
        )
        scope["state"]["role"] = key_info.get("role", "examiner")
        await self.session_manager.handle_request(scope, receive, send)


def _extract_bearer_token(scope: dict) -> str | None:
    """Pull the bearer token from raw ASGI scope headers."""
    headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
    for name, value in headers:
        if name.lower() == b"authorization":
            decoded = value.decode("latin-1")
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
    server = Server("sift-gateway")

    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        return await gateway.get_tools_list()

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict) -> Sequence[TextContent]:
        # Extract analyst from the Starlette Request stashed by the transport
        analyst = None
        try:
            ctx = server.request_context
            request: Request | None = ctx.request
            if request is not None:
                analyst = getattr(request.state, "analyst", None)
        except LookupError:
            pass

        try:
            result = await gateway.call_tool(name, arguments, analyst=analyst)
        except KeyError as e:
            logger.warning("MCP call_tool unknown tool: %s", e)
            return [TextContent(type="text", text=f"Error: unknown tool {name}")]
        except (RuntimeError, ConnectionError, OSError) as e:
            logger.error("MCP call_tool backend error for %s: %s", name, e)
            return [TextContent(type="text", text=f"Error: backend failure for {name}: {e}")]
        except Exception as e:
            logger.error("MCP call_tool unexpected error for %s: %s: %s", name, type(e).__name__, e)
            return [TextContent(type="text", text=f"Error: {type(e).__name__}: {e}")]

        # Normalise to list of TextContent for the MCP protocol
        contents: list[TextContent] = []
        for item in result:
            if isinstance(item, TextContent):
                contents.append(item)
            elif hasattr(item, "model_dump"):
                import json
                contents.append(TextContent(type="text", text=json.dumps(item.model_dump())))
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
