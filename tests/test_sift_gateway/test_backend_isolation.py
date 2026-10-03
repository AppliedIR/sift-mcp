"""Python backends, the gateway itself and lite's entries start isolated (-I).

Without -I, `python -m X` puts the current directory first on sys.path, so a
`json.py` or `re.py` in the directory the gateway (or Claude Code, for lite)
runs from would be imported. The gateway adds -I to every `python -m`
backend it starts, which reaches existing installs whose gateway.yaml is
never rewritten; a backend whose env sets PYTHONPATH is left as it is.
"""

import asyncio
import contextlib
import json
import re
from pathlib import Path

import pytest
import sift_gateway.backends.stdio_backend as sb
from sift_gateway.backends import create_backend

ROOT = Path(__file__).parent.parent.parent


class _Stop(Exception):
    pass


def _started_args(monkeypatch, cfg):
    seen = []

    @contextlib.asynccontextmanager
    async def fake_stdio_client(params):
        seen.append(params.args)
        raise _Stop
        yield

    monkeypatch.setattr(sb, "stdio_client", fake_stdio_client)
    with contextlib.suppress(BaseException):
        asyncio.run(create_backend("b", cfg).start())
    return seen[0]


@pytest.mark.parametrize(
    "cfg,expected",
    [
        (
            {"type": "stdio", "command": "/v/bin/python", "args": ["-m", "case_mcp"]},
            ["-I", "-m", "case_mcp"],
        ),
        (  # anchors: unchanged
            {"type": "stdio", "command": "/v/bin/python3", "args": ["-I", "-m", "x"]},
            ["-I", "-m", "x"],
        ),
        (
            {"type": "stdio", "command": "/v/bin/python", "args": ["/srv/x.py"]},
            ["/srv/x.py"],
        ),
        (
            {"type": "stdio", "command": "/usr/bin/node", "args": ["-m", "x"]},
            ["-m", "x"],
        ),
        (
            {
                "type": "stdio",
                "command": "/v/bin/python",
                "args": ["-m", "mine"],
                "env": {"PYTHONPATH": "/opt/mine"},
            },
            ["-m", "mine"],
        ),
    ],
    ids=["python -m", "already -I", "script", "not python", "own PYTHONPATH"],
)
def test_python_module_backends_start_isolated(monkeypatch, cfg, expected):
    assert _started_args(monkeypatch, cfg) == expected


def test_every_gateway_launch_in_the_installer_is_isolated():
    script = (ROOT / "setup-sift.sh").read_text()
    assert len(re.findall(r"python\"? -I -m sift_gateway", script)) == 3
    assert not re.search(r"python\"? -m sift_gateway", script)


def test_lite_entries_start_isolated():
    example = json.loads((ROOT / "claude-code/lite/mcp.json.example").read_text())
    for name, entry in example["mcpServers"].items():
        assert entry["args"][:2] == ["-I", "-m"], name
    lite = (ROOT / "quickstart-lite.sh").read_text()
    assert '\\"args\\": [\\"-I\\", \\"-m\\", \\"opencti_mcp.server\\"]' in lite
    assert not re.search(r'\\"args\\": \[\\"-m\\"', lite)
