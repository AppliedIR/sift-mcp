"""Tests for sift_mcp.config."""

import os
import pytest
from sift_mcp.config import SiftConfig, get_config


class TestSiftConfig:
    def test_defaults(self):
        cfg = SiftConfig()
        assert cfg.default_timeout == 600
        assert "/usr/local/bin" in cfg.tool_paths
        assert cfg.case_dir == ""

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("AIIR_CASE_DIR", "/tmp/test-case")
        monkeypatch.setenv("SIFT_TIMEOUT", "120")
        cfg = SiftConfig.from_env()
        assert cfg.case_dir == "/tmp/test-case"
        assert cfg.default_timeout == 120

    def test_extra_tool_paths(self, monkeypatch):
        monkeypatch.setenv("SIFT_TOOL_PATHS", "/opt/custom:/opt/other")
        cfg = SiftConfig.from_env()
        assert cfg.tool_paths[0] == "/opt/custom"
        assert cfg.tool_paths[1] == "/opt/other"

    def test_share_root_default(self):
        cfg = SiftConfig()
        assert cfg.share_root == ""

    def test_share_root_from_env(self, monkeypatch):
        monkeypatch.setenv("AIIR_SHARE_ROOT", "/mnt/wintools")
        cfg = SiftConfig.from_env()
        assert cfg.share_root == "/mnt/wintools"

    def test_get_config(self):
        cfg = get_config()
        assert isinstance(cfg, SiftConfig)
