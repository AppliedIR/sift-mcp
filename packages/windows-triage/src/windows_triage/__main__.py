"""Allow running as python -m windows_triage."""

from sift_common import isolate_stdio_transport

if __name__ == "__main__":
    isolate_stdio_transport()  # before any of this server's own imports

from windows_triage.server import main

if __name__ == "__main__":
    main()
