"""Custom exception hierarchy for OpenCTI MCP.

Security: Exception messages are designed to be safe for client exposure
where appropriate. Internal details should only be logged, never returned.
"""

from __future__ import annotations


class OpenCTIMCPError(Exception):
    """Base exception for OpenCTI MCP server.

    All custom exceptions inherit from this class, allowing callers to
    catch all MCP-specific errors with a single except clause.
    """

    def __init__(self, message: str, *, safe_message: str | None = None) -> None:
        """Initialize exception.

        Args:
            message: Full error message (for logging)
            safe_message: Client-safe message (no internal details)
        """
        super().__init__(message)
        self._safe_message = safe_message or message

    @property
    def safe_message(self) -> str:
        """Return client-safe error message."""
        return self._safe_message


class ConfigurationError(OpenCTIMCPError):
    """Configuration or credential error.

    Raised when:
    - OpenCTI token is missing or invalid
    - Token file has insecure permissions
    - OpenCTI URL is invalid
    """

    pass


class ConnectionError(OpenCTIMCPError):
    """OpenCTI connection failure.

    Raised when:
    - Cannot connect to OpenCTI
    - Connection timeout
    - Network errors
    """

    def __init__(self, message: str) -> None:
        # Never expose connection details to clients
        super().__init__(
            message, safe_message="Unable to connect to OpenCTI. Check server status."
        )


class DegradedError(OpenCTIMCPError):
    """OpenCTI backend in degraded mode (startup probe failed).

    Distinct from ConnectionError so the retry-with-backoff loop in
    OpenCTIClient does NOT retry — degraded mode is set explicitly by
    validate_startup, won't clear without operator action, so retrying
    just delays the failure. The chokepoint guard in connect() raises
    this; the retry-loop's `_is_transient_error` checks by class name
    ("ConnectionError") so DegradedError correctly falls through to
    the non-transient branch and raises immediately.

    Operators recover via `vhir service restart opencti-mcp` after the
    OpenCTI server returns.
    """

    def __init__(self, message: str) -> None:
        super().__init__(
            message,
            safe_message=(
                "OpenCTI backend in DEGRADED mode — server unreachable. "
                "Run `vhir service restart opencti-mcp` after server returns."
            ),
        )


class ValidationError(OpenCTIMCPError):
    """Input validation failure.

    Raised when:
    - Input exceeds length limits
    - Invalid IOC format
    - Invalid parameter values

    These errors are generally safe to return to clients as they
    describe input problems, not internal state.
    """

    pass


class QueryError(OpenCTIMCPError):
    """Query execution failure.

    Raised when:
    - GraphQL query fails
    - Unexpected response format
    - API errors
    """

    def __init__(self, message: str) -> None:
        # Never expose query details to clients
        super().__init__(
            message, safe_message="Query failed. Check server logs for details."
        )


class RateLimitError(OpenCTIMCPError):
    """Rate limit exceeded.

    Raised when:
    - Too many queries in time window
    - Enrichment quota exceeded
    """

    def __init__(self, wait_seconds: float, limit_type: str = "query") -> None:
        message = f"Rate limit exceeded for {limit_type}. Wait {wait_seconds:.1f}s."
        super().__init__(message, safe_message=message)
        self.wait_seconds = wait_seconds
        self.limit_type = limit_type
