"""Shared test fixtures for the AIIR SIFT monorepo."""

import pytest


@pytest.fixture
def tmp_case_dir(tmp_path):
    """Create a temporary case directory with flat structure."""
    case_dir = tmp_path / "test-case"
    case_dir.mkdir()
    (case_dir / "audit").mkdir()
    return case_dir
