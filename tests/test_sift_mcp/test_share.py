"""Tests for share-relative path resolution (sift_common.resolve_share_path)."""

import pytest
from pathlib import Path

from sift_common import resolve_share_path


class TestResolveSharePath:

    def test_resolves_with_share_root(self, monkeypatch):
        monkeypatch.setenv("AIIR_SHARE_ROOT", "/mnt/wintools")
        result = resolve_share_path("extractions/evtxecmd-Security-003.csv")
        assert result == Path("/mnt/wintools/extractions/evtxecmd-Security-003.csv")

    def test_returns_none_without_share_root(self, monkeypatch):
        monkeypatch.delenv("AIIR_SHARE_ROOT", raising=False)
        result = resolve_share_path("extractions/output.csv")
        assert result is None

    def test_returns_none_with_empty_share_root(self, monkeypatch):
        monkeypatch.setenv("AIIR_SHARE_ROOT", "")
        result = resolve_share_path("extractions/output.csv")
        assert result is None

    def test_nested_relative_path(self, monkeypatch):
        monkeypatch.setenv("AIIR_SHARE_ROOT", "/mnt/cases/SRL2")
        result = resolve_share_path("extractions/evtx/Security.csv")
        assert result == Path("/mnt/cases/SRL2/extractions/evtx/Security.csv")

    def test_simple_filename(self, monkeypatch):
        monkeypatch.setenv("AIIR_SHARE_ROOT", "/mnt/wintools")
        result = resolve_share_path("output.csv")
        assert result == Path("/mnt/wintools/output.csv")

    def test_trailing_slash_on_share_root(self, monkeypatch):
        monkeypatch.setenv("AIIR_SHARE_ROOT", "/mnt/wintools/")
        result = resolve_share_path("extractions/output.csv")
        # Path() normalizes trailing slashes
        assert result == Path("/mnt/wintools/extractions/output.csv")
