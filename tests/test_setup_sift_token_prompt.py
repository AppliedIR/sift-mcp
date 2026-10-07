"""The installer reads the OpenCTI API token without echoing it.

It read the token with `read -rp`, so the token appeared on the terminal as
it was typed. Runs the installer's own line in a pseudo-terminal; piped
input (a scripted install) still reads the token.
"""

import os
import pty
import select
import subprocess
import time
from pathlib import Path

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()
LINE = next(
    line.strip() for line in SCRIPT.splitlines() if '"OpenCTI API Token: "' in line
)
TOKEN = "SENTINELTOKEN123"
BODY = f'{LINE}\necho ""\nprintf "LEN=%s\\n" "${{#OPENCTI_TOKEN}}"\n'


def _read_until(fd, marker: bytes, timeout: float = 10) -> bytes:
    out, end = b"", time.monotonic() + timeout
    while marker not in out and time.monotonic() < end:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                chunk = os.read(fd, 1024)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
    return out


def test_a_typed_token_is_not_shown_on_the_terminal():
    pid, fd = pty.fork()
    if pid == 0:  # the child: its terminal is the pty
        os.execve(
            "/bin/bash",
            ["bash", "-c", "READ_FROM=/dev/tty\n" + BODY],
            {"PATH": "/usr/bin:/bin"},
        )
    try:
        shown = _read_until(fd, b"OpenCTI API Token: ")
        os.write(fd, TOKEN.encode() + b"\n")
        shown += _read_until(fd, b"LEN=16")
    finally:
        os.waitpid(pid, 0)
    assert b"LEN=16" in shown, shown
    assert TOKEN.encode() not in shown, shown


def test_anchor_a_piped_token_is_still_read():
    p = subprocess.run(
        ["bash", "-c", "READ_FROM=/dev/stdin\n" + BODY],
        input=TOKEN + "\n",
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin"},
        timeout=30,
    )
    assert "LEN=16" in p.stdout, p
