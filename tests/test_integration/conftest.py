"""Shared fixtures for integration tests.

Tests in this directory run real forensic tools against real evidence
at /cases/integration-test/evidence/. All tests are marked with
@pytest.mark.integration and skip cleanly when evidence is absent.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

EVIDENCE_BASE = Path("/cases/integration-test")

pytestmark = pytest.mark.integration


def _evidence_available() -> bool:
    """Check whether the integration test evidence directory has files."""
    edir = EVIDENCE_BASE / "evidence"
    return edir.is_dir() and any(edir.iterdir())


# ---------------------------------------------------------------------------
# Session-scoped fixtures (shared across all tests in the run)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def evidence_dir() -> Path:
    """Root evidence directory. Skips all dependent tests when absent."""
    if not _evidence_available():
        pytest.skip("Integration evidence not found at /cases/integration-test/evidence/")
    return EVIDENCE_BASE / "evidence"


@pytest.fixture(scope="session")
def e01_image(evidence_dir) -> Path:
    """Path to the EWF disk image. Skips if missing."""
    path = evidence_dir / "base-dc-cdrive.E01"
    if not path.exists():
        pytest.skip("base-dc-cdrive.E01 not found")
    return path


@pytest.fixture(scope="session")
def extraction_dir(evidence_dir) -> Path:
    """Extract shimcache.zip once per session.

    Files persist in /cases/integration-test/extractions/shimcache/
    across runs. Re-extracted only if the directory is empty or missing.
    """
    dest = EVIDENCE_BASE / "extractions" / "shimcache"
    archive = evidence_dir / "kansa-post-intrusion_shimcache.zip"
    if not archive.exists():
        pytest.skip("kansa-post-intrusion_shimcache.zip not found")

    if not dest.is_dir() or not any(dest.rglob("*.csv")):
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["7z", "x", "-y", str(archive), f"-o{dest}"],
            check=True,
            capture_output=True,
        )

    return dest


@pytest.fixture(scope="session")
def extracted_csvs(extraction_dir) -> list[Path]:
    """List of CSV paths from the shimcache extraction."""
    csvs = sorted(extraction_dir.rglob("*.csv"))
    assert csvs, f"No CSVs found in {extraction_dir}"
    return csvs


# ---------------------------------------------------------------------------
# Function-scoped fixtures (fresh per test)
# ---------------------------------------------------------------------------


@pytest.fixture
def run_command_executor():
    """Return the generic.run_command function (executor layer).

    This is the catalog-gated executor that returns a raw dict with
    exit_code, stdout, stderr, elapsed_seconds, and command.
    """
    from sift_mcp.tools.generic import run_command
    return run_command


@pytest.fixture
def sift_server(tmp_path, monkeypatch):
    """Create a real sift-mcp server with audit writing to tmp_path.

    Returns the FastMCP server instance whose inner tools (run_command,
    list_available_tools, etc.) are callable directly.
    """
    monkeypatch.setenv("AIIR_EXAMINER", "integration")
    monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
    (tmp_path / "audit").mkdir(exist_ok=True)

    from sift_mcp.catalog import clear_catalog_cache
    from sift_mcp.response import reset_call_counter
    from sift_mcp.server import create_server

    clear_catalog_cache()
    reset_call_counter()
    server = create_server()
    yield server
    clear_catalog_cache()


@pytest.fixture
def case_manager(tmp_path, monkeypatch):
    """Create a CaseManager rooted in tmp_path for case workflow tests."""
    monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("AIIR_EXAMINER", "integration")

    from forensic_mcp.case.manager import CaseManager
    return CaseManager()
