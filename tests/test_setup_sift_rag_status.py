"""The installer's data check says when the RAG index is empty, not that it's current.

An index that was never downloaded (or only partly built) holds no documents,
and the status reports no source with an update, so the check printed
"[OK] … all 23 sources are current" over an empty knowledge base. These run
the installer's own check with the status command stubbed, never the
installer.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()
_start = SCRIPT.index('RAG_STALE_COUNT=""\nif $INSTALL_RAG; then')
CHECK = SCRIPT[_start : SCRIPT.index("if $INSTALL_TRIAGE; then", _start)]

EMPTY = (
    "[WARN] RAG knowledge base: the index is empty, so knowledge search returns nothing. "
    "Download it with GITHUB_TOKEN set (GitHub can refuse unauthenticated downloads): "
    "{py} -m rag_mcp.scripts.download_index, then restart the gateway "
    "(systemctl --user restart vhir-gateway, or however you start it)"
)


def _sources(updates: int) -> list[dict]:
    return [{"name": f"src{i}", "has_update": i < updates} for i in range(23)]


def _check(tmp_path: Path, status: str | None, rc: int = 0, timed_out: bool = False):
    """`status`: what `rag_mcp.status --json` prints (None: nothing); `rc` its exit."""
    py = tmp_path / "venv-python"
    (tmp_path / "status.json").write_text(status or "")
    py.write_text(
        "#!/bin/bash\n"
        'if [[ "$*" == "-m rag_mcp.status --json" ]]; then\n'
        f'  cat "{tmp_path}/status.json"; exit {rc}\n'
        "fi\n"
        'exec python3 "$@"\n'
    )
    py.chmod(0o755)
    harness = "\n".join(
        [
            "set -euo pipefail",
            "BOLD= NC=",
            'ok(){ echo "[OK] $*"; }; warn(){ echo "[WARN] $*"; }',
            'prompt_yn(){ echo "[PROMPT] $*"; return 1; }',
            "timeout(){ return 124; }" if timed_out else "",
            f'VENV_PYTHON="{py}"; INSTALL_RAG=true; AUTO_YES=true',
            CHECK,
        ]
    )
    out = subprocess.run(
        ["bash", "-c", harness],
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=60,
    )
    return out.returncode, [ln.strip() for ln in out.stdout.splitlines()], str(py)


def _status(exists: bool, docs: int, sources: list[dict], warnings=()) -> str:
    return json.dumps(
        {
            "index_exists": exists,
            "document_count": docs,
            "online_sources": sources,
            "warnings": list(warnings),
        }
    )


def test_an_absent_index_is_reported_empty(tmp_path):
    rc, lines, py = _check(tmp_path, _status(False, 0, []))
    assert rc == 0 and lines == [EMPTY.format(py=py)]


def test_a_partly_built_index_is_reported_empty(tmp_path):
    rc, lines, py = _check(tmp_path, _status(True, 0, _sources(0)))
    assert rc == 0 and lines == [EMPTY.format(py=py)]


@pytest.mark.parametrize(
    "sources", [_sources(0), []], ids=["with metadata", "no metadata"]
)
def test_anchor_a_populated_index_with_nothing_to_update_is_current(tmp_path, sources):
    rc, lines, _ = _check(tmp_path, _status(True, 2, sources))
    assert rc == 0 and lines == ["[OK] RAG knowledge base: all 23 sources are current."]


def test_anchor_updates_available_are_offered_as_before(tmp_path):
    rc, lines, py = _check(tmp_path, _status(True, 2, _sources(3)))
    assert rc == 0 and lines == [
        "RAG knowledge base: 3 of 23 sources have updates available.",
        f"Refresh now or later with: {py} -m rag_mcp.refresh",
        "Time: a few minutes to a couple of hours depending on changes and CPU.",
    ]


@pytest.mark.parametrize(
    "status,rc,timed_out",
    [
        (None, 1, False),
        (_status(True, 2, _sources(0)), 0, True),
        ("not json", 0, False),
    ],
    ids=["status fails", "status times out", "status prints garbage"],
)
def test_anchor_an_unreadable_status_is_still_unchecked(
    tmp_path, status, rc, timed_out
):
    rc_out, lines, py = _check(tmp_path, status, rc, timed_out)
    assert rc_out == 0 and lines == [
        f"[WARN] Could not check RAG status. Check later with: {py} -m rag_mcp.status"
    ]


@pytest.mark.parametrize(
    "warning",
    [
        "Error reading ChromaDB: attempt to write a readonly database",
        "Could not read metadata.json: [Errno 13] Permission denied",
    ],
    ids=["unreadable database", "unreadable metadata"],
)
def test_an_index_it_cannot_read_is_unchecked_not_empty(tmp_path, warning):
    rc, lines, py = _check(tmp_path, _status(True, 0, _sources(0), [warning]))
    assert rc == 0 and lines == [
        f"[WARN] Could not check RAG status. Check later with: {py} -m rag_mcp.status"
    ]


def test_anchor_an_absent_index_with_its_not_found_warning_is_still_empty(tmp_path):
    status = _status(
        False, 0, [], ["Index not found. Run 'python -m rag_mcp.build' first."]
    )
    rc, lines, py = _check(tmp_path, status)
    assert rc == 0 and lines == [EMPTY.format(py=py)]
