"""Entry point for running OpenCTI MCP server.

Usage:
    python -m opencti_mcp

Environment Variables:
    OPENCTI_URL: OpenCTI server URL (default: http://localhost:8080)
    OPENCTI_TOKEN: API token for authentication
    OPENCTI_TIMEOUT: Request timeout in seconds (default: 60)
    OPENCTI_MAX_RESULTS: Maximum results per query (default: 100)
    AIIR_LOG_FORMAT: Log format - "json" (default) or "text"
    AIIR_LOG_FILE: Write to ~/.aiir/logs/ - "true" (default) or "false"

Feature Flags (FF_ prefix):
    FF_STARTUP_VALIDATION: Enable startup connectivity test (default: true)
    FF_RESPONSE_CACHING: Cache search responses (default: false)
    FF_GRACEFUL_DEGRADATION: Return cached results on failure (default: true)
    FF_NEGATIVE_CACHING: Cache "not found" results (default: true)

Token can also be provided via:
    ~/.config/opencti-mcp/token (with 600 permissions)
    .env file (OPENCTI_TOKEN=...)
"""

from __future__ import annotations

import asyncio
import logging
import sys

from .config import Config
from .client import OpenCTIClient
from .errors import ConfigurationError
from .feature_flags import get_feature_flags
from .server import OpenCTIMCPServer
from .oplog import setup_logging


def main() -> None:
    """Main entry point."""
    # Configure logging (JSON by default, text for development)
    setup_logging("opencti-mcp")
    logger = logging.getLogger("opencti_mcp")

    try:
        # Load configuration
        config = Config.load()
        logger.info(f"Starting OpenCTI MCP server: {config}")

        # Load feature flags
        flags = get_feature_flags()
        logger.debug(f"Feature flags: {flags.to_dict()}")

        # Startup validation (if enabled)
        if flags.startup_validation:
            logger.info("Running startup validation...")
            client = OpenCTIClient(config)
            validation = client.validate_startup()

            # Log warnings
            for warning in validation.get("warnings", []):
                logger.warning(f"Startup warning: {warning}")

            # Log version info
            if validation.get("opencti_version"):
                logger.info(
                    f"Connected to OpenCTI {validation['opencti_version']}",
                    extra={"opencti_version": validation["opencti_version"]}
                )

            # Check for critical errors
            if not validation.get("valid", True):
                for error in validation.get("errors", []):
                    logger.error(f"Startup error: {error}")
                # Don't fail hard - allow server to start, it will report errors on queries
                logger.warning(
                    "Startup validation had errors - server will start but may have issues"
                )

        # Create and run server
        server = OpenCTIMCPServer(config)
        asyncio.run(server.run())

    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        print(f"Error: {e}", file=sys.stderr)
        print("\nTo configure, set OPENCTI_TOKEN environment variable", file=sys.stderr)
        print("or create ~/.config/opencti-mcp/token file", file=sys.stderr)
        sys.exit(1)

    except KeyboardInterrupt:
        logger.info("Shutting down")

    except Exception as e:
        logger.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()
