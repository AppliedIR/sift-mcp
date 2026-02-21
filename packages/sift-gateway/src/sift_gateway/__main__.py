"""Entry point for aiir-gateway."""

import argparse
import uvicorn

from sift_gateway.config import load_config
from sift_gateway.oplog import setup_logging
from sift_gateway.server import Gateway


def main():
    setup_logging("aiir-gateway")
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

    config = load_config(args.config)
    gw_config = config.get("gateway", {})
    host = args.host or gw_config.get("host", "127.0.0.1")
    port = args.port or gw_config.get("port", 4508)

    gateway = Gateway(config)
    app = gateway.create_app()
    uvicorn.run(app, host=host, port=port, log_level=gw_config.get("log_level", "info").lower())


if __name__ == "__main__":
    main()
