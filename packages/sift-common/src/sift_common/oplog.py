"""Operational logging for AIIR MCP servers.

Structured JSON logging to stderr and optionally to ~/.aiir/logs/.
Canonical implementation shared by all SIFT-platform MCPs via sift-common.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class _StructuredFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def __init__(self, service_name: str = "forensic-mcp") -> None:
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service_name,
        }
        if record.levelno >= logging.WARNING:
            log_data["location"] = {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            }
        if record.exc_info and record.exc_info[0]:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
            }
        return json.dumps(log_data, default=str)


def setup_logging(
    service_name: str = "forensic-mcp",
    *,
    level: int = logging.INFO,
    json_format: bool | None = None,
    log_to_file: bool | None = None,
) -> None:
    """Configure operational logging.

    Args:
        service_name: Service name for log entries.
        level: Logging level.
        json_format: Use JSON formatting. If None, checks AIIR_LOG_FORMAT env
            var (default: "json"). Set to "text" for plain text.
        log_to_file: Write to ~/.aiir/logs/{service_name}.jsonl. If None,
            checks AIIR_LOG_FILE env var (default: "true").
    """
    if json_format is None:
        json_format = os.environ.get("AIIR_LOG_FORMAT", "json").lower() != "text"
    if log_to_file is None:
        log_to_file = os.environ.get("AIIR_LOG_FILE", "true").lower() in (
            "true",
            "1",
            "yes",
        )

    pkg_logger = logging.getLogger(service_name.replace("-", "_"))
    pkg_logger.setLevel(level)
    pkg_logger.handlers.clear()

    formatter: logging.Formatter
    if json_format:
        formatter = _StructuredFormatter(service_name)
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

    # Always log to stderr
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(level)
    stderr_handler.setFormatter(formatter)
    pkg_logger.addHandler(stderr_handler)

    # Optionally log to ~/.aiir/logs/
    if log_to_file:
        try:
            log_dir = Path.home() / ".aiir" / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(
                log_dir / f"{service_name}.jsonl",
                encoding="utf-8",
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(_StructuredFormatter(service_name))
            pkg_logger.addHandler(file_handler)
        except OSError as exc:
            pkg_logger.warning(
                "Failed to set up file logging to ~/.aiir/logs/: %s: %s",
                type(exc).__name__,
                exc,
            )
        except Exception as exc:
            pkg_logger.warning(
                "Unexpected error setting up file logging: %s: %s",
                type(exc).__name__,
                exc,
            )

    pkg_logger.propagate = False
