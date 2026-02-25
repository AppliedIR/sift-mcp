"""Structured logging configuration for OpenCTI MCP.

Provides JSON-formatted logging suitable for production environments
and log aggregation systems.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import uuid
from datetime import datetime, timezone
from typing import Any


class StructuredFormatter(logging.Formatter):
    """JSON log formatter for structured logging.

    Outputs logs in JSON format with consistent fields for
    easy parsing by log aggregation systems.
    """

    def __init__(self, service_name: str = "opencti-mcp") -> None:
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service_name,
        }

        # Add location info for errors
        if record.levelno >= logging.WARNING:
            log_data["location"] = {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
            }

        # Add extra fields (filtering out standard LogRecord attributes)
        standard_attrs = {
            "name",
            "msg",
            "args",
            "created",
            "filename",
            "funcName",
            "levelname",
            "levelno",
            "lineno",
            "module",
            "msecs",
            "pathname",
            "process",
            "processName",
            "relativeCreated",
            "stack_info",
            "exc_info",
            "exc_text",
            "thread",
            "threadName",
            "taskName",
            "message",
        }

        for key, value in record.__dict__.items():
            if key not in standard_attrs and not key.startswith("_"):
                # Ensure value is JSON serializable
                try:
                    json.dumps(value)
                    log_data[key] = value
                except (TypeError, ValueError):
                    log_data[key] = str(value)

        return json.dumps(log_data, default=str)


class RequestContextFilter(logging.Filter):
    """Filter that adds request context to log records.

    Adds a correlation ID for tracking related log entries.

    Thread-safety: Uses a lock to protect _context dict from
    concurrent access when used with asyncio.to_thread().
    """

    def __init__(self) -> None:
        super().__init__()
        self._context: dict[str, str] = {}
        self._lock = threading.Lock()

    def set_request_id(self, request_id: str | None = None) -> str:
        """Set the current request ID (thread-safe)."""
        if request_id is None:
            request_id = str(uuid.uuid4())[:8]
        with self._lock:
            self._context["request_id"] = request_id
        return request_id

    def clear_request_id(self) -> None:
        """Clear the current request ID (thread-safe)."""
        with self._lock:
            self._context.pop("request_id", None)

    def filter(self, record: logging.LogRecord) -> bool:
        """Add context to log record (thread-safe)."""
        with self._lock:
            for key, value in self._context.items():
                setattr(record, key, value)
        return True


# Global context filter for request tracking
_context_filter = RequestContextFilter()


def setup_logging(
    level: int = logging.INFO,
    json_format: bool = True,
    service_name: str = "opencti-mcp",
) -> None:
    """Configure logging for the MCP server.

    Args:
        level: Logging level (default: INFO)
        json_format: Use JSON formatting (default: True for production)
        service_name: Service name for log entries
    """
    # Get root logger for our package
    logger = logging.getLogger("opencti_mcp")
    logger.setLevel(level)

    # Remove existing handlers
    logger.handlers.clear()

    # Create handler (stderr to keep stdout clean for MCP protocol)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)

    # Set formatter
    formatter: logging.Formatter
    if json_format:
        formatter = StructuredFormatter(service_name)
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

    handler.setFormatter(formatter)

    # Add context filter
    handler.addFilter(_context_filter)

    logger.addHandler(handler)

    # Prevent propagation to root logger
    logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the opencti_mcp prefix."""
    return logging.getLogger(f"opencti_mcp.{name}")


def set_request_id(request_id: str | None = None) -> str:
    """Set request ID for correlation."""
    return _context_filter.set_request_id(request_id)


def clear_request_id() -> None:
    """Clear request ID after request completes."""
    _context_filter.clear_request_id()
