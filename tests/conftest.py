"""Shared test fixtures for the Valhuntir SIFT monorepo."""

import atexit
import os
import shutil
import tempfile

import pytest

# Tests run under a temporary HOME: some activate cases and write audit entries
# for real. Only the model cache below is reached through the real one. Product
# modules read Path.home() when imported (case-mcp's _ACTIVE_CASE_FILE, the
# gateway's state directory), so this runs when the root conftest is imported,
# before any child conftest or test module.
_ORIGINAL_HOME = os.environ.get("HOME", "")
_TEST_HOME = tempfile.mkdtemp(prefix="sift-mcp-tests-home-")
atexit.register(shutil.rmtree, _TEST_HOME, ignore_errors=True)
os.environ["HOME"] = _TEST_HOME
if _ORIGINAL_HOME:
    # forensic-rag's embedding model cache.
    os.environ.setdefault("XDG_CACHE_HOME", os.path.join(_ORIGINAL_HOME, ".cache"))
for _var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR"):
    os.environ.pop(_var, None)


@pytest.fixture
def tmp_case_dir(tmp_path):
    """Create a temporary case directory with flat structure."""
    case_dir = tmp_path / "test-case"
    case_dir.mkdir()
    (case_dir / "audit").mkdir()
    return case_dir
