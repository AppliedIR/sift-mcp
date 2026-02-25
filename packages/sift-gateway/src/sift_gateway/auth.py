"""API key authentication middleware and examiner identity resolution."""

import hmac
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# Paths exempt from authentication.
# /mcp is handled by its own ASGI-level auth (MCPAuthASGIApp) because
# BaseHTTPMiddleware buffers responses and breaks SSE streaming.
_PUBLIC_PATHS = {"/health", "/health/", "/mcp", "/api/v1/setup/join"}

# Maximum length for bearer tokens (DoS protection against megabyte-sized headers)
_MAX_TOKEN_LENGTH = 1024


class AuthMiddleware(BaseHTTPMiddleware):
    """Starlette middleware for API key authentication.

    Checks the Authorization header for a Bearer token and resolves
    it to an examiner identity from the config's api_keys mapping.

    If no api_keys are configured, auth is disabled (single-user mode)
    and examiner defaults to "anonymous".
    """

    def __init__(self, app, api_keys: dict | None = None):
        super().__init__(app)
        self.api_keys = api_keys or {}

    async def dispatch(self, request: Request, call_next):
        # Public paths skip auth
        # /mcp and /mcp/* are handled by MCPAuthASGIApp (ASGI-level auth)
        if request.url.path in _PUBLIC_PATHS or request.url.path.startswith("/mcp/"):
            request.state.examiner = None
            request.state.role = None
            return await call_next(request)

        # If no api_keys configured, auth is disabled (single-user mode)
        if not self.api_keys:
            request.state.examiner = "anonymous"
            request.state.role = "examiner"
            return await call_next(request)

        # Extract bearer token
        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            return JSONResponse(
                {"error": "Missing or invalid Authorization header"},
                status_code=401,
            )

        token = auth_header[7:].strip()

        # Length check: reject excessively long tokens before timing-safe comparison
        if len(token) > _MAX_TOKEN_LENGTH:
            logger.warning("Rejected oversized bearer token (%d bytes)", len(token))
            return JSONResponse(
                {"error": "Invalid API key"},
                status_code=403,
            )

        # Timing-safe key lookup: iterate ALL keys to prevent timing leaks
        matched_key = None
        for candidate in self.api_keys:
            if hmac.compare_digest(token, candidate) and matched_key is None:
                matched_key = candidate

        if matched_key is None:
            return JSONResponse(
                {"error": "Invalid API key"},
                status_code=403,
            )

        key_info = self.api_keys.get(matched_key, {})
        if not isinstance(key_info, dict):
            logger.error(
                "API key config for matched key is not a dict, got %s",
                type(key_info).__name__,
            )
            return JSONResponse(
                {"error": "Server configuration error"},
                status_code=500,
            )
        request.state.examiner = key_info.get(
            "examiner", key_info.get("analyst", "unknown")
        )
        request.state.role = key_info.get("role", "examiner")
        return await call_next(request)


def resolve_examiner(request: Request) -> dict:
    """Extract examiner identity from a request that has passed through AuthMiddleware.

    Returns:
        Dict with examiner and role keys.
    """
    # Support both new (examiner) and legacy (analyst) attribute names
    examiner = getattr(request.state, "examiner", None)
    if examiner is None:
        examiner = getattr(request.state, "analyst", "anonymous")
    return {
        "examiner": examiner,
        "role": getattr(request.state, "role", "examiner"),
    }
