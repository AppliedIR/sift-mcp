"""Health check endpoint."""

import asyncio
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

logger = logging.getLogger(__name__)

# Timeout (seconds) for individual backend health checks
_HEALTH_CHECK_TIMEOUT = 10


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

    async def _check_one(name: str, backend) -> tuple[str, dict]:
        try:
            result = await asyncio.wait_for(
                backend.health_check(), timeout=_HEALTH_CHECK_TIMEOUT
            )
            return name, result
        except asyncio.TimeoutError:
            logger.warning(
                "Health check timed out for backend %s after %ds",
                name,
                _HEALTH_CHECK_TIMEOUT,
            )
            return name, {"status": "error", "error": "health check timed out"}
        except Exception as exc:
            logger.warning(
                "Health check failed for backend %s: %s: %s",
                name,
                type(exc).__name__,
                exc,
            )
            return name, {"status": "error", "error": f"{type(exc).__name__}: {exc}"}

    results = await asyncio.gather(
        *(_check_one(n, b) for n, b in gateway.backends.items())
    )
    backend_health = dict(results)

    tools_count = len(gateway._tool_map)
    all_ok = all(h.get("status") == "ok" for h in backend_health.values())

    return JSONResponse(
        {
            "status": "ok" if all_ok else "degraded",
            "backends": backend_health,
            "tools_count": tools_count,
        }
    )


def health_routes() -> list[Route]:
    """Return the health check route."""
    return [Route("/health", health_endpoint, methods=["GET"])]
