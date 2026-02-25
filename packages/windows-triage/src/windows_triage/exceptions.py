"""
Custom Exception Hierarchy for Windows Triage MCP Server

Exception Types:
    - WindowsTriageError: Base exception for all windows-triage errors
    - ValidationError: Input validation failed - safe to return to users
    - DatabaseError: Database operation failed - may contain internal details
    - ConfigurationError: Configuration problem - typically fatal at startup

Usage:
    from windows_triage.exceptions import ValidationError, DatabaseError

    def check_file(path: str):
        if len(path) > MAX_PATH_LENGTH:
            raise ValidationError(f"Path exceeds maximum length of {MAX_PATH_LENGTH}")
"""

from __future__ import annotations


class WindowsTriageError(Exception):
    """Base exception for windows-triage-mcp.

    All custom exceptions inherit from this class, allowing callers to catch
    all windows-triage errors with a single except clause if desired.
    """

    pass


class ValidationError(WindowsTriageError):
    """Input validation failed.

    This exception indicates that user-provided input failed validation checks.
    The error message is safe to return directly to users as it does not
    contain internal implementation details.

    Examples:
        - Path exceeds maximum length
        - Invalid hash format
        - Missing required parameter
        - Null bytes in input
    """

    pass


class DatabaseError(WindowsTriageError):
    """Database operation failed.

    This exception indicates a database-level error occurred. The error message
    may contain internal details (table names, SQL errors) and should be logged
    but not returned directly to users.

    Examples:
        - Database file not found
        - SQL query failed
        - Database corruption detected
        - Connection failed
    """

    pass


class ConfigurationError(WindowsTriageError):
    """Configuration problem detected.

    This exception indicates a configuration problem that typically prevents
    the server from operating correctly. Usually raised at startup.

    Examples:
        - Invalid environment variable value
        - Required database file missing
        - Invalid log level specified
    """

    pass
