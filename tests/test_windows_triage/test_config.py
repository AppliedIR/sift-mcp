"""Tests for configuration module."""

import pytest
from windows_triage.config import (
    Config,
    _parse_int_env,
    get_config,
    reset_config,
)
from windows_triage.exceptions import ConfigurationError


class TestConfig:
    """Tests for Config class."""

    def test_default_config(self, tmp_path):
        """Test config with defaults."""
        config = Config(data_dir=tmp_path, skip_db_validation=True)
        assert config.cache_size == 10000
        assert config.log_level == "INFO"
        assert config.max_path_length == 4096

    def test_cache_size_bounds_valid(self, tmp_path):
        """Test valid cache_size values."""
        # Zero is valid (disables caching)
        config = Config(data_dir=tmp_path, cache_size=0, skip_db_validation=True)
        assert config.cache_size == 0

        # Max valid value
        config = Config(
            data_dir=tmp_path, cache_size=1_000_000, skip_db_validation=True
        )
        assert config.cache_size == 1_000_000

    def test_cache_size_too_large(self, tmp_path):
        """Test cache_size exceeding maximum."""
        with pytest.raises(ConfigurationError) as exc_info:
            Config(data_dir=tmp_path, cache_size=1_000_001, skip_db_validation=True)
        assert "cache_size" in str(exc_info.value)

    def test_cache_size_negative(self, tmp_path):
        """Test negative cache_size."""
        with pytest.raises(ConfigurationError) as exc_info:
            Config(data_dir=tmp_path, cache_size=-1, skip_db_validation=True)
        assert "cache_size" in str(exc_info.value)

    def test_max_path_length_bounds(self, tmp_path):
        """Test max_path_length bounds."""
        # Valid range
        config = Config(data_dir=tmp_path, max_path_length=1, skip_db_validation=True)
        assert config.max_path_length == 1

        config = Config(
            data_dir=tmp_path, max_path_length=32768, skip_db_validation=True
        )
        assert config.max_path_length == 32768

        # Out of bounds
        with pytest.raises(ConfigurationError):
            Config(data_dir=tmp_path, max_path_length=0, skip_db_validation=True)

        with pytest.raises(ConfigurationError):
            Config(data_dir=tmp_path, max_path_length=32769, skip_db_validation=True)

    def test_max_hash_length_bounds(self, tmp_path):
        """Test max_hash_length bounds."""
        # Valid range (32 = MD5 length, 256 reasonable max)
        config = Config(data_dir=tmp_path, max_hash_length=32, skip_db_validation=True)
        assert config.max_hash_length == 32

        config = Config(data_dir=tmp_path, max_hash_length=256, skip_db_validation=True)
        assert config.max_hash_length == 256

        # Out of bounds
        with pytest.raises(ConfigurationError):
            Config(data_dir=tmp_path, max_hash_length=31, skip_db_validation=True)

        with pytest.raises(ConfigurationError):
            Config(data_dir=tmp_path, max_hash_length=257, skip_db_validation=True)

    def test_invalid_log_level(self, tmp_path):
        """Test invalid log level."""
        with pytest.raises(ConfigurationError) as exc_info:
            Config(data_dir=tmp_path, log_level="INVALID", skip_db_validation=True)
        assert "log_level" in str(exc_info.value)

    def test_valid_log_levels(self, tmp_path):
        """Test all valid log levels."""
        for level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            config = Config(data_dir=tmp_path, log_level=level, skip_db_validation=True)
            assert config.log_level == level

        # Case insensitive
        config = Config(data_dir=tmp_path, log_level="debug", skip_db_validation=True)
        assert config.log_level == "debug"


class TestParseIntEnv:
    """Tests for _parse_int_env helper."""

    def test_default_value(self, monkeypatch):
        """Test default value when env var not set."""
        monkeypatch.delenv("WT_TEST_INT", raising=False)
        result = _parse_int_env("WT_TEST_INT", 42)
        assert result == 42

    def test_valid_int(self, monkeypatch):
        """Test parsing valid integer."""
        monkeypatch.setenv("WT_TEST_INT", "100")
        result = _parse_int_env("WT_TEST_INT", 42)
        assert result == 100

    def test_invalid_int(self, monkeypatch):
        """Test parsing invalid integer raises ConfigurationError."""
        monkeypatch.setenv("WT_TEST_INT", "not-a-number")
        with pytest.raises(ConfigurationError) as exc_info:
            _parse_int_env("WT_TEST_INT", 42)
        assert "WT_TEST_INT" in str(exc_info.value)

    def test_empty_string(self, monkeypatch):
        """Test empty string raises ConfigurationError."""
        monkeypatch.setenv("WT_TEST_INT", "")
        with pytest.raises(ConfigurationError):
            _parse_int_env("WT_TEST_INT", 42)

    def test_whitespace_only(self, monkeypatch):
        """Test whitespace-only string raises ConfigurationError."""
        monkeypatch.setenv("WT_TEST_INT", "   ")
        with pytest.raises(ConfigurationError):
            _parse_int_env("WT_TEST_INT", 42)


class TestGetConfig:
    """Tests for get_config function."""

    def test_singleton_behavior(self, tmp_path):
        """Test config is a singleton."""
        reset_config()
        config1 = get_config()
        config2 = get_config()
        assert config1 is config2

    def test_reload(self, tmp_path):
        """Test reload creates new config."""
        reset_config()
        config1 = get_config()
        config2 = get_config(reload=True)
        # New instance but same settings
        assert config1 is not config2

    def test_reset_config(self):
        """Test reset_config clears singleton."""
        reset_config()
        config1 = get_config()
        reset_config()
        config2 = get_config()
        assert config1 is not config2
