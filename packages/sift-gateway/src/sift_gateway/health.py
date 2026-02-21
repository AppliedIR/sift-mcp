"""Health check endpoint."""

import logging
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

logger = logging.getLogger(__name__)


async def health_endpoint(request: Request) -> JSONResponse:
    """GET /health — returns gateway status and backend health.

    Response:
        {
            "status": "ok",
            "backends": {
                "forensic-mcp": {"status": "ok", "type": "stdio", "tools": 5},
                ...
            },
            "tools_count": 42
        }
    """
    gateway = request.app.state.gateway

    backend_health = {}
    for name, backend in gateway.backends.items():
        try:
            backend_health[name] = await backend.health_check()
        except (RuntimeError, ConnectionError, OSError) as e:
            logger.warning("Health check failed for backend %s: %s", name, e)
            backend_health[name] = {"status": "error", "detail": str(e)}
        except Exception as e:
            logger.warning("Health check unexpected error for backend %s: %s", name, e)
            backend_health[name] = {"status": "error"}

    tools_count = len(gateway._tool_map)
    all_ok = all(h.get("status") == "ok" for h in backend_health.values())

    return JSONResponse({
        "status": "ok" if all_ok else "degraded",
        "backends": backend_health,
        "tools_count": tools_count,
    })


def health_routes() -> list[Route]:
    """Return the health check route."""
    return [Route("/health", health_endpoint, methods=["GET"])]
