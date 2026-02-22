"""Entry point for sift-gateway."""

import argparse
import logging
import sys

import uvicorn
import yaml

from sift_gateway.config import load_config
from sift_gateway.oplog import setup_logging
from sift_gateway.server import Gateway

logger = logging.getLogger(__name__)


def main():
    setup_logging("sift-gateway")
    parser = argparse.ArgumentParser(
        description="AIIR Gateway — MCP aggregation service"
    )
    parser.add_argument(
        "--config",
        default="gateway.yaml",
        help="Path to gateway YAML config file (default: gateway.yaml)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Bind host (overrides config)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port (overrides config)",
    )
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except FileNotFoundError as exc:
        logger.error("Config file not found: %s", args.config)
        print(f"ERROR: Config file not found: {args.config}", file=sys.stderr)
        print("Create gateway.yaml using 'aiir setup' or see sift-gateway documentation.", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as exc:
        logger.error("Invalid YAML in config file %s: %s", args.config, exc)
        print(f"ERROR: Invalid YAML in config file {args.config}: {exc}", file=sys.stderr)
        sys.exit(1)

    # Validate config structure
    gw_config = config.get("gateway", {})
    if not isinstance(gw_config, dict):
        logger.error("Config 'gateway' key must be a mapping, got %s", type(gw_config).__name__)
        print(f"ERROR: Config 'gateway' key must be a mapping, got {type(gw_config).__name__}", file=sys.stderr)
        sys.exit(1)

    host = args.host or gw_config.get("host", "127.0.0.1")
    port = args.port or gw_config.get("port", 4508)
    if not isinstance(port, int):
        logger.error("Config 'gateway.port' must be an integer, got %r", port)
        print(f"ERROR: Config 'gateway.port' must be an integer, got {port!r}", file=sys.stderr)
        sys.exit(1)

    gateway = Gateway(config)
    app = gateway.create_app()
    uvicorn.run(app, host=host, port=port, log_level=gw_config.get("log_level", "info").lower())


if __name__ == "__main__":
    main()
