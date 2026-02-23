"""Sift-mcp exceptions."""


class SiftError(Exception):
    """Base exception for sift-mcp."""


class ToolNotFoundError(SiftError):
    """Tool binary not found on system."""


class ToolNotInCatalogError(SiftError):
    """Tool not in the approved catalog."""


class DeniedBinaryError(SiftError):
    """Raised when a binary is on the hard denylist."""


class ExecutionError(SiftError):
    """Tool execution failed."""


class ExecutionTimeoutError(SiftError):
    """Tool execution timed out."""


# Backward compatibility alias
TimeoutError = ExecutionTimeoutError
