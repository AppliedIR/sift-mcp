"""Entry point for forensic-mcp server."""

import argparse
import logging

from forensic_mcp.oplog import setup_logging
from forensic_mcp.server import create_server

logger = logging.getLogger(__name__)


def main() -> None:
    """Run the forensic MCP server."""
    parser = argparse.ArgumentParser(description="forensic-mcp server")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--resources",
        action="store_true",
        default=True,
        help="Register discipline reference data as MCP resources (default)",
    )
    mode_group.add_argument(
        "--deferred-tools",
        action="store_true",
        help="Register discipline reference data as tools instead of resources (for clients without resource support)",
    )
    args = parser.parse_args()

    setup_logging("forensic-mcp")
    reference_mode = "tools" if args.deferred_tools else "resources"
    logger.info("Starting forensic-mcp server (reference_mode=%s)", reference_mode)
    server = create_server(reference_mode=reference_mode)
    server.run()


if __name__ == "__main__":
    main()
