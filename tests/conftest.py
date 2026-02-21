"""Shared test fixtures for the AIIR SIFT monorepo."""

import os
import tempfile

import pytest


@pytest.fixture
def tmp_case_dir(tmp_path):
    """Create a temporary case directory with examiner structure."""
    case_dir = tmp_path / "test-case"
    case_dir.mkdir()
    examiner = os.environ.get("AIIR_EXAMINER", "testuser")
    examiner_dir = case_dir / "examiners" / examiner
    examiner_dir.mkdir(parents=True)
    (examiner_dir / "audit").mkdir()
    (examiner_dir / "findings").mkdir()
    (examiner_dir / "timeline").mkdir()
    return case_dir
