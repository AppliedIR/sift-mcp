"""Entry point: python -m sift_mcp"""

from sift_common import isolate_stdio_transport

if __name__ == "__main__":
    isolate_stdio_transport()  # before any of this server's own imports

from sift_mcp.oplog import setup_logging
from sift_mcp.server import create_server


def main():
    setup_logging("sift-mcp")
    server = create_server()
    server.run()


if __name__ == "__main__":
    main()
