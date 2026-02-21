"""Entry point for forensic-mcp server."""

import logging

from forensic_mcp.oplog import setup_logging
from forensic_mcp.server import create_server

logger = logging.getLogger(__name__)


def main() -> None:
    """Run the forensic MCP server."""
    setup_logging("forensic-mcp")
    logger.info("Starting forensic-mcp server")
    server = create_server()
    server.run()


if __name__ == "__main__":
    main()
