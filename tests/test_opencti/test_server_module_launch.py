"""`python -m opencti_mcp.server` serves, as the lite install's MCP entry runs it.

quickstart-lite writes `-m opencti_mcp.server` for opencti-mcp. Without a main
guard in that module, Python imported it and exited 0, and the MCP client saw
EOF. Offline: a dummy token, a URL nothing listens on, no startup probe.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import opencti_mcp


def test_the_server_module_answers_initialize(tmp_path):
    src = str(Path(opencti_mcp.__file__).parent.parent)
    env = {
        "HOME": str(tmp_path),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": os.pathsep.join([src, os.environ.get("PYTHONPATH", "")]),
        "OPENCTI_URL": "http://127.0.0.1:9",
        "OPENCTI_TOKEN": "dummy-not-a-real-token-0000",
        "FF_STARTUP_VALIDATION": "false",
        "VHIR_LOG_FILE": "false",
    }
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"},
        },
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "opencti_mcp.server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
        cwd=tmp_path,
        text=True,
    )
    try:
        out, _ = proc.communicate(json.dumps(request) + "\n", timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    replies = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    assert any(r.get("id") == 1 and "result" in r for r in replies), (
        proc.returncode,
        out,
    )
