"""Run case-mcp as a module: python -m case_mcp"""

from sift_common import isolate_stdio_transport

if __name__ == "__main__":
    isolate_stdio_transport()  # before any of this server's own imports

from case_mcp.server import main

if __name__ == "__main__":
    main()
