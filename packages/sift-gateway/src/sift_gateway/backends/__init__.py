"""MCP backend implementations."""

import logging
import shutil
from urllib.parse import urlparse

from sift_gateway.backends.base import MCPBackend
from sift_gateway.backends.http_backend import HttpMCPBackend
from sift_gateway.backends.stdio_backend import StdioMCPBackend

logger = logging.getLogger(__name__)


def create_backend(name: str, config: dict) -> MCPBackend:
    """Factory: create a backend from config.

    Args:
        name: Backend name (e.g. "forensic-mcp").
        config: Backend config dict with at minimum a "type" key.

    Returns:
        An MCPBackend instance.

    Raises:
        ValueError: If the backend type is unknown or config is invalid.
    """
    backend_type = config.get("type", "stdio")

    if backend_type == "stdio":
        # Validate required keys for stdio
        command = config.get("command")
        if not command:
            raise ValueError(f"Backend {name!r}: stdio type requires 'command' key")
        if not isinstance(command, str):
            raise ValueError(
                f"Backend {name!r}: 'command' must be a string, got {type(command).__name__}"
            )
        # Warn (don't fail) if command not found on PATH — it may exist at runtime
        if shutil.which(command) is None:
            logger.warning("Backend %s: command %r not found on PATH", name, command)
        return StdioMCPBackend(name, config)

    elif backend_type == "http":
        # Validate required keys for http
        url = config.get("url")
        if not url:
            raise ValueError(f"Backend {name!r}: http type requires 'url' key")
        if not isinstance(url, str):
            raise ValueError(
                f"Backend {name!r}: 'url' must be a string, got {type(url).__name__}"
            )
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"Backend {name!r}: URL must use http or https scheme, got {parsed.scheme!r}"
            )
        if not parsed.hostname:
            raise ValueError(f"Backend {name!r}: URL must include a hostname")
        return HttpMCPBackend(name, config)

    else:
        raise ValueError(f"Unknown backend type: {backend_type!r} for backend {name!r}")


__all__ = ["MCPBackend", "StdioMCPBackend", "HttpMCPBackend", "create_backend"]
