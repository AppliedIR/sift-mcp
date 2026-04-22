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


class VersionMismatchError(OpenCTIMCPError):
    """pycti major version does not match the connected OpenCTI server.

    Raised at connect time (UAT 2026-04-22) when pycti's major doesn't
    match the server's `about.version` major. Without this enforcement,
    per-IOC queries emit misleading `GRAPHQL_VALIDATION_FAILED: Unknown
    type "..."` errors (e.g., pycti 7.x's AIPrompt fragment against a
    6.x server). Fail-fast at init so the operator sees one clear error
    pointing at the fix.
    """

    def __init__(self, pycti_version: str, server_version: str) -> None:
        pycti_major = pycti_version.split(".", 1)[0] if pycti_version else "?"
        server_major = server_version.split(".", 1)[0] if server_version else "?"
        # Build the install-hint defensively. Upstream
        # _enforce_version_compat returns early on unparseable versions,
        # so server_major == "?" is currently unreachable — but guarding
        # the int() call here prevents a future refactor from surfacing
        # ValueError from inside error construction (CR 2026-04-22).
        try:
            next_major = int(server_major) + 1
            install_hint = f"'pycti>={server_major}.0,<{next_major}.0'"
        except (ValueError, TypeError):
            install_hint = "the version matching your server"
        message = (
            f"opencti-mcp: pycti {pycti_major}.x installed but OpenCTI "
            f"server is version {server_version}. Pin pycti to "
            f"{server_major}.x (e.g., `uv pip install {install_hint}`). "
            f"See packages/opencti/README.md "
            f'"OpenCTI version compatibility".'
        )
        super().__init__(message, safe_message=message)
        self.pycti_version = pycti_version
        self.server_version = server_version
