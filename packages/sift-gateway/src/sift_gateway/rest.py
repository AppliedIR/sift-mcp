"""REST API routes for /api/v1/."""

import json
import logging
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from sift_gateway.auth import resolve_analyst
from sift_gateway.rate_limit import check_rate_limit

logger = logging.getLogger(__name__)

# Maximum request body size (10 MB)
_MAX_REQUEST_BYTES = 10 * 1024 * 1024


async def list_tools(request: Request) -> JSONResponse:
    """GET /api/v1/tools — list all aggregated tools.

    Query params:
        backend: filter tools by backend name
    """
    gateway = request.app.state.gateway
    backend_filter = request.query_params.get("backend")

    # Reuse gateway.get_tools_list() for descriptions and schemas
    all_tools = await gateway.get_tools_list()

    tools = []
    for t in sorted(all_tools, key=lambda x: x.name):
        backend_name = gateway._tool_map.get(t.name, "")
        if backend_filter and backend_name != backend_filter:
            continue
        tools.append({
            "name": t.name,
            "backend": backend_name,
            "description": t.description or "",
            "input_schema": t.inputSchema,
        })

    return JSONResponse({"tools": tools, "count": len(tools)})


async def call_tool(request: Request) -> JSONResponse:
    """POST /api/v1/tools/{tool_name} — call a tool.

    Body:
        {"arguments": {...}}
    """
    # Rate limit check (before any body processing)
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        return JSONResponse(
            {"error": "Rate limit exceeded"},
            status_code=429,
        )

    gateway = request.app.state.gateway
    tool_name = request.path_params["tool_name"]
    identity = resolve_analyst(request)

    # Read the raw body and enforce actual size limit.
    # Checking Content-Length alone is insufficient because the header
    # can be absent or spoofed; reading the body is authoritative.
    raw_body = await request.body()
    if len(raw_body) > _MAX_REQUEST_BYTES:
        return JSONResponse(
            {"error": f"Request body too large (max {_MAX_REQUEST_BYTES} bytes)"},
            status_code=413,
        )

    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    arguments = body.get("arguments", {})
    if not isinstance(arguments, dict):
        return JSONResponse({"error": "arguments must be an object"}, status_code=400)

    if tool_name not in gateway._tool_map:
        return JSONResponse(
            {"error": f"Tool not found: {tool_name}"},
            status_code=404,
        )

    try:
        result = await gateway.call_tool(tool_name, arguments, analyst=identity.get("analyst"))
        # Serialize content items
        serialized = []
        for item in result:
            if hasattr(item, "model_dump"):
                serialized.append(item.model_dump())
            elif hasattr(item, "__dict__"):
                serialized.append(item.__dict__)
            else:
                serialized.append(str(item))

        return JSONResponse({
            "tool": tool_name,
            "backend": gateway._tool_map[tool_name],
            "result": serialized,
        })
    except KeyError as exc:
        logger.error("Tool call failed — tool not in map: %s — %s", tool_name, exc)
        return JSONResponse(
            {"error": f"Tool not found: {tool_name}"},
            status_code=404,
        )
    except Exception as exc:
        logger.error("Tool call failed: %s — %s: %s", tool_name, type(exc).__name__, exc, exc_info=True)
        return JSONResponse(
            {"error": "Tool call failed", "tool": tool_name, "error_type": type(exc).__name__},
            status_code=500,
        )


async def list_backends(request: Request) -> JSONResponse:
    """GET /api/v1/backends — list all backends with status."""
    gateway = request.app.state.gateway

    backends = []
    for name, backend in gateway.backends.items():
        try:
            health = await backend.health_check()
        except (RuntimeError, ConnectionError, OSError) as e:
            logger.warning("Health check failed for backend %s: %s", name, e)
            health = {"status": "error", "detail": str(e)}
        except Exception as e:
            logger.warning("Health check unexpected error for backend %s: %s", name, e)
            health = {"status": "error"}

        backends.append({
            "name": name,
            "type": backend.config.get("type", "stdio"),
            "enabled": backend.enabled,
            "health": health,
        })

    return JSONResponse({"backends": backends, "count": len(backends)})


def rest_routes() -> list[Route]:
    """Return REST API v1 routes."""
    return [
        Route("/api/v1/tools", list_tools, methods=["GET"]),
        Route("/api/v1/tools/{tool_name}", call_tool, methods=["POST"]),
        Route("/api/v1/backends", list_backends, methods=["GET"]),
    ]
