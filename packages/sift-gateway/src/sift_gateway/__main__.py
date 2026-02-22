"""Entry point for sift-gateway."""

import argparse
import logging
import sys
from pathlib import Path

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

    # TLS configuration
    tls_config = gw_config.get("tls", {})
    ssl_kwargs = {}
    if tls_config:
        certfile = tls_config.get("certfile")
        keyfile = tls_config.get("keyfile")
        if not certfile or not keyfile:
            logger.error("TLS config requires both 'certfile' and 'keyfile'")
            print("ERROR: TLS config requires both 'certfile' and 'keyfile'", file=sys.stderr)
            sys.exit(1)
        if not Path(certfile).is_file():
            logger.error("TLS certificate file not found: %s", certfile)
            print(f"ERROR: TLS certificate file not found: {certfile}", file=sys.stderr)
            sys.exit(1)
        if not Path(keyfile).is_file():
            logger.error("TLS key file not found: %s", keyfile)
            print(f"ERROR: TLS key file not found: {keyfile}", file=sys.stderr)
            sys.exit(1)
        ssl_kwargs["ssl_certfile"] = certfile
        ssl_kwargs["ssl_keyfile"] = keyfile

    host = args.host or gw_config.get("host", "0.0.0.0" if ssl_kwargs else "127.0.0.1")
    port = args.port or gw_config.get("port", 4508)
    if not isinstance(port, int):
        logger.error("Config 'gateway.port' must be an integer, got %r", port)
        print(f"ERROR: Config 'gateway.port' must be an integer, got {port!r}", file=sys.stderr)
        sys.exit(1)

    gateway = Gateway(config)
    app = gateway.create_app()
    uvicorn.run(
        app, host=host, port=port,
        log_level=gw_config.get("log_level", "info").lower(),
        **ssl_kwargs,
    )


if __name__ == "__main__":
    main()
