"""OpenCTI MCP Server - Threat Intelligence for Claude Code.

This package provides an MCP (Model Context Protocol) server that exposes
OpenCTI threat intelligence capabilities to Claude Code and other MCP clients.

Features:
    - Search indicators, threat actors, malware, CVEs
    - IOC context lookup with relationships
    - Recent indicator retrieval
    - Optional enrichment via VirusTotal/Shodan
    - Adaptive metrics for production resilience

Usage:
    python -m opencti_mcp
"""

__version__ = "0.5.0"
__author__ = "AppliedIncidentResponse.com"

from .adaptive import (
    AdaptiveConfig,
    AdaptiveMetrics,
    LatencyStats,
    get_global_metrics,
    reset_global_metrics,
)
from .client import CircuitState, OpenCTIClient
from .config import Config
from .errors import (
    ConfigurationError,
    ConnectionError,
    OpenCTIMCPError,
    QueryError,
    RateLimitError,
    ValidationError,
)
from .logging import get_logger, setup_logging
from .server import OpenCTIMCPServer

__all__ = [
    "__version__",
    "OpenCTIMCPError",
    "ConfigurationError",
    "ConnectionError",
    "ValidationError",
    "QueryError",
    "RateLimitError",
    "Config",
    "OpenCTIClient",
    "CircuitState",
    "OpenCTIMCPServer",
    "setup_logging",
    "get_logger",
    "AdaptiveMetrics",
    "AdaptiveConfig",
    "LatencyStats",
    "get_global_metrics",
    "reset_global_metrics",
]
