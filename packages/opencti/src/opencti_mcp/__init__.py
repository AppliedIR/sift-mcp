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

from .errors import (
    OpenCTIMCPError,
    ConfigurationError,
    ConnectionError,
    ValidationError,
    QueryError,
    RateLimitError,
)
from .config import Config
from .client import OpenCTIClient, CircuitState
from .server import OpenCTIMCPServer
from .logging import setup_logging, get_logger
from .adaptive import (
    AdaptiveMetrics,
    AdaptiveConfig,
    LatencyStats,
    get_global_metrics,
    reset_global_metrics,
)

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
