"""MCP backend implementations."""

from sift_gateway.backends.base import MCPBackend
from sift_gateway.backends.stdio_backend import StdioMCPBackend
from sift_gateway.backends.http_backend import HttpMCPBackend


def create_backend(name: str, config: dict) -> MCPBackend:
    """Factory: create a backend from config.

    Args:
        name: Backend name (e.g. "forensic-mcp").
        config: Backend config dict with at minimum a "type" key.

    Returns:
        An MCPBackend instance.

    Raises:
        ValueError: If the backend type is unknown.
    """
    backend_type = config.get("type", "stdio")
    if backend_type == "stdio":
        return StdioMCPBackend(name, config)
    elif backend_type == "http":
        return HttpMCPBackend(name, config)
    else:
        raise ValueError(f"Unknown backend type: {backend_type!r} for backend {name!r}")


__all__ = ["MCPBackend", "StdioMCPBackend", "HttpMCPBackend", "create_backend"]
