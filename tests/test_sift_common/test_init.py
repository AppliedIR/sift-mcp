"""Unit tests for sift_common — resolve_share_path and package init."""

from pathlib import Path

import pytest

from sift_common import resolve_share_path


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("AIIR_SHARE_ROOT", raising=False)


class TestResolveSharePath:
    def test_with_share_root(self, monkeypatch):
        monkeypatch.setenv("AIIR_SHARE_ROOT", "/mnt/wintools")
        result = resolve_share_path("extractions/output.csv")
        assert result == Path("/mnt/wintools/extractions/output.csv")

    def test_without_share_root(self):
        result = resolve_share_path("extractions/output.csv")
        assert result is None

    def test_empty_share_root(self, monkeypatch):
        monkeypatch.setenv("AIIR_SHARE_ROOT", "")
        result = resolve_share_path("file.txt")
        assert result is None

    def test_nested_path(self, monkeypatch):
        monkeypatch.setenv("AIIR_SHARE_ROOT", "/mnt/share")
        result = resolve_share_path("case1/extractions/deep/file.csv")
        assert result == Path("/mnt/share/case1/extractions/deep/file.csv")
