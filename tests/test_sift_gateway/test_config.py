"""Tests for config loading and env var interpolation."""

import os
import pytest
import tempfile
from pathlib import Path

from sift_gateway.config import load_config, _interpolate_env, _walk_and_interpolate


# --- _interpolate_env ---

class TestInterpolateEnv:
    def test_simple_var(self, monkeypatch):
        monkeypatch.setenv("MY_VAR", "hello")
        assert _interpolate_env("${MY_VAR}") == "hello"

    def test_var_in_string(self, monkeypatch):
        monkeypatch.setenv("HOST", "localhost")
        assert _interpolate_env("http://${HOST}:8080") == "http://localhost:8080"

    def test_missing_var_unchanged(self):
        result = _interpolate_env("${SURELY_NOT_SET_12345}")
        assert result == "${SURELY_NOT_SET_12345}"

    def test_multiple_vars(self, monkeypatch):
        monkeypatch.setenv("A", "1")
        monkeypatch.setenv("B", "2")
        assert _interpolate_env("${A}-${B}") == "1-2"

    def test_no_vars(self):
        assert _interpolate_env("plain string") == "plain string"


# --- _walk_and_interpolate ---

class TestWalkAndInterpolate:
    def test_nested_dict(self, monkeypatch):
        monkeypatch.setenv("PORT", "9090")
        data = {"server": {"port": "${PORT}", "host": "localhost"}}
        result = _walk_and_interpolate(data)
        assert result == {"server": {"port": "9090", "host": "localhost"}}

    def test_list(self, monkeypatch):
        monkeypatch.setenv("ARG", "foo")
        data = ["${ARG}", "bar"]
        result = _walk_and_interpolate(data)
        assert result == ["foo", "bar"]

    def test_non_string_passthrough(self):
        assert _walk_and_interpolate(42) == 42
        assert _walk_and_interpolate(True) is True
        assert _walk_and_interpolate(None) is None


# --- load_config ---

class TestLoadConfig:
    def test_load_valid_yaml(self, tmp_path):
        config_file = tmp_path / "test.yaml"
        config_file.write_text("gateway:\n  port: 4508\n")
        result = load_config(str(config_file))
        assert result["gateway"]["port"] == 4508

    def test_load_with_env_interpolation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GW_PORT", "9999")
        config_file = tmp_path / "test.yaml"
        config_file.write_text("gateway:\n  port_str: '${GW_PORT}'\n")
        result = load_config(str(config_file))
        assert result["gateway"]["port_str"] == "9999"

    def test_missing_config_raises(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path/config.yaml")

    def test_empty_yaml_returns_empty_dict(self, tmp_path):
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")
        result = load_config(str(config_file))
        assert result == {}

    def test_full_config_structure(self, tmp_path):
        config_file = tmp_path / "full.yaml"
        config_file.write_text("""
gateway:
  host: "0.0.0.0"
  port: 4508
api_keys:
  key1:
    analyst: "steve"
    role: "lead"
backends:
  test-mcp:
    type: stdio
    command: python
    args: ["-m", "test_mcp"]
    enabled: true
""")
        result = load_config(str(config_file))
        assert result["gateway"]["host"] == "0.0.0.0"
        assert result["api_keys"]["key1"]["analyst"] == "steve"
        assert result["backends"]["test-mcp"]["type"] == "stdio"
