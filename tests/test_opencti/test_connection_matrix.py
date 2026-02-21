"""Connection establishment, URL edge cases, and SSL/TLS handling tests.

Test matrix covering:
- C1-C21: Connection establishment (URL formats, tokens, caching, thread safety)
- S1-S10: SSL/TLS handling (verify flags, env parsing, security warnings)
- U1-U10: URL edge cases (normalization, scheme validation, special formats)
"""

from __future__ import annotations

import logging
import os
import stat
import threading
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch, mock_open

import pytest

from opencti_mcp.config import (
    Config,
    SecretStr,
    _validate_url,
    _load_token,
    _load_token_file,
    _load_token_from_env_file,
)
from opencti_mcp.client import OpenCTIClient, TRANSIENT_ERRORS
from opencti_mcp.errors import ConfigurationError, ConnectionError


# =============================================================================
# Helpers
# =============================================================================

def make_config(**overrides: Any) -> Config:
    """Create a Config with sensible defaults, overridable by kwargs."""
    defaults = dict(
        opencti_url="http://localhost:8080",
        opencti_token=SecretStr("test-token-12345"),
        timeout_seconds=30,
        max_results=100,
    )
    defaults.update(overrides)
    return Config(**defaults)


# =============================================================================
# C1-C8: Connection URL Variants
# =============================================================================

class TestConnectionURLVariants:
    """C1-C8: Verify various URL formats are accepted and normalized."""

    @patch("pycti.OpenCTIApiClient")
    def test_c1_connect_http_localhost_default(self, mock_pycti_cls: Mock) -> None:
        """C1: Connect with http://localhost:8080 (default URL)."""
        mock_pycti_cls.return_value = MagicMock()
        config = make_config(opencti_url="http://localhost:8080")
        client = OpenCTIClient(config)

        result = client.connect()

        mock_pycti_cls.assert_called_once_with(
            "http://localhost:8080",
            "test-token-12345",
            log_level="error",
            requests_timeout=30,
            ssl_verify=True,
        )
        assert result is mock_pycti_cls.return_value

    @patch("pycti.OpenCTIApiClient")
    def test_c2_connect_https_url(self, mock_pycti_cls: Mock) -> None:
        """C2: Connect with https:// URL."""
        mock_pycti_cls.return_value = MagicMock()
        config = make_config(opencti_url="https://opencti.example.com")
        client = OpenCTIClient(config)

        result = client.connect()

        mock_pycti_cls.assert_called_once()
        call_args = mock_pycti_cls.call_args
        assert call_args[0][0] == "https://opencti.example.com"

    @patch("pycti.OpenCTIApiClient")
    def test_c3_connect_custom_port(self, mock_pycti_cls: Mock) -> None:
        """C3: Connect with custom port (e.g., :4000)."""
        mock_pycti_cls.return_value = MagicMock()
        config = make_config(opencti_url="http://localhost:4000")
        client = OpenCTIClient(config)

        client.connect()

        call_args = mock_pycti_cls.call_args
        assert call_args[0][0] == "http://localhost:4000"

    @patch("pycti.OpenCTIApiClient")
    def test_c4_connect_ip_address_no_hostname(self, mock_pycti_cls: Mock) -> None:
        """C4: Connect with IP address, no hostname (e.g., http://10.0.0.50:8080)."""
        mock_pycti_cls.return_value = MagicMock()
        config = make_config(opencti_url="http://10.0.0.50:8080")
        client = OpenCTIClient(config)

        client.connect()

        call_args = mock_pycti_cls.call_args
        assert call_args[0][0] == "http://10.0.0.50:8080"

    @patch("pycti.OpenCTIApiClient")
    def test_c5_connect_ipv6_address(self, mock_pycti_cls: Mock) -> None:
        """C5: Connect with IPv6 address (http://[::1]:8080)."""
        mock_pycti_cls.return_value = MagicMock()
        config = make_config(opencti_url="http://[::1]:8080")
        client = OpenCTIClient(config)

        client.connect()

        call_args = mock_pycti_cls.call_args
        assert call_args[0][0] == "http://[::1]:8080"

    @patch("pycti.OpenCTIApiClient")
    def test_c6_connect_url_with_path_prefix(self, mock_pycti_cls: Mock) -> None:
        """C6: Connect with URL path prefix — verify pycti receives the full URL."""
        mock_pycti_cls.return_value = MagicMock()
        config = make_config(opencti_url="https://host/opencti")
        client = OpenCTIClient(config)

        client.connect()

        call_args = mock_pycti_cls.call_args
        assert call_args[0][0] == "https://host/opencti"

    @patch("pycti.OpenCTIApiClient")
    def test_c7_connect_trailing_slash_stripped(self, mock_pycti_cls: Mock) -> None:
        """C7: Connect with trailing slash in URL — verify slash is stripped."""
        mock_pycti_cls.return_value = MagicMock()
        config = make_config(opencti_url="http://localhost:8080/")
        client = OpenCTIClient(config)

        # The Config __post_init__ should have stripped the slash
        assert config.opencti_url == "http://localhost:8080"

        client.connect()
        call_args = mock_pycti_cls.call_args
        assert call_args[0][0] == "http://localhost:8080"

    @patch("pycti.OpenCTIApiClient")
    def test_c8_connect_multiple_trailing_slashes_normalized(self, mock_pycti_cls: Mock) -> None:
        """C8: Connect with multiple trailing slashes — verify normalized."""
        mock_pycti_cls.return_value = MagicMock()
        config = make_config(opencti_url="http://localhost:8080///")
        client = OpenCTIClient(config)

        # _validate_url uses rstrip('/') which removes all trailing slashes
        assert config.opencti_url == "http://localhost:8080"

        client.connect()
        call_args = mock_pycti_cls.call_args
        assert call_args[0][0] == "http://localhost:8080"


# =============================================================================
# C9-C19: Token Handling
# =============================================================================

class TestTokenHandling:
    """C9-C19: Token loading, validation, and security."""

    def test_c9_token_from_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """C9: Token from env var (OPENCTI_TOKEN) via Config.load()."""
        monkeypatch.setenv("OPENCTI_TOKEN", "env-test-token-abc")
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")

        config = Config.load()

        assert config.opencti_token.get_secret_value() == "env-test-token-abc"

    def test_c10_token_from_config_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """C10: Token from file (~/.config/opencti-mcp/token) via _load_token()."""
        # Unset env var so it falls through to file
        monkeypatch.delenv("OPENCTI_TOKEN", raising=False)

        # Create a token file with correct permissions
        config_dir = tmp_path / ".config" / "opencti-mcp"
        config_dir.mkdir(parents=True)
        token_file = config_dir / "token"
        token_file.write_text("file-test-token-xyz")
        token_file.chmod(0o600)

        # Patch Path.home() to return tmp_path
        with patch.object(Path, "home", return_value=tmp_path):
            # Also patch the .env file path to avoid picking up real .env
            with patch.object(Path, "cwd", return_value=tmp_path / "nonexistent"):
                token = _load_token()

        assert token == "file-test-token-xyz"

    def test_c11_token_from_env_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """C11: Token from .env file."""
        monkeypatch.delenv("OPENCTI_TOKEN", raising=False)

        # Create .env file
        env_file = tmp_path / ".env"
        env_file.write_text('OPENCTI_TOKEN=dotenv-token-123\n')
        env_file.chmod(0o600)

        token = _load_token_from_env_file(env_file)
        assert token == "dotenv-token-123"

    def test_c11_token_from_env_file_quoted(self, tmp_path: Path) -> None:
        """C11b: Token from .env file with quotes."""
        env_file = tmp_path / ".env"
        env_file.write_text('OPENCTI_TOKEN="quoted-token-456"\n')
        env_file.chmod(0o600)

        token = _load_token_from_env_file(env_file)
        assert token == "quoted-token-456"

    def test_c12_token_with_leading_trailing_whitespace(self, tmp_path: Path) -> None:
        """C12: Token with leading/trailing whitespace — verify stripped (file loading)."""
        token_file = tmp_path / "token"
        token_file.write_text("  my-token-with-spaces  ")
        token_file.chmod(0o600)

        # _load_token_file calls .strip()
        token = _load_token_file(token_file)
        assert token == "my-token-with-spaces"

    def test_c13_token_with_trailing_newline(self, tmp_path: Path) -> None:
        """C13: Token with trailing newline (common from 'echo token > file') — verify stripped."""
        token_file = tmp_path / "token"
        token_file.write_text("my-token\n")
        token_file.chmod(0o600)

        token = _load_token_file(token_file)
        assert token == "my-token"

    def test_c14_uuid_format_token(self) -> None:
        """C14: UUID-format token (standard OpenCTI format)."""
        uuid_token = str(uuid.uuid4())
        config = make_config(opencti_token=SecretStr(uuid_token))
        assert config.opencti_token.get_secret_value() == uuid_token

    def test_c15_long_api_key_token(self) -> None:
        """C15: Long API key token (64+ chars, SaaS format)."""
        long_token = "a" * 128
        config = make_config(opencti_token=SecretStr(long_token))
        assert config.opencti_token.get_secret_value() == long_token
        assert len(config.opencti_token) == 128

    def test_c16_token_file_wrong_permissions_rejected(self, tmp_path: Path) -> None:
        """C16: Token file with wrong permissions (644) — verify rejected."""
        token_file = tmp_path / "token"
        token_file.write_text("secret-token")
        token_file.chmod(0o644)  # World-readable

        with pytest.raises(ConfigurationError, match="insecure permissions"):
            _load_token_file(token_file)

    def test_c17_token_file_correct_permissions_accepted(self, tmp_path: Path) -> None:
        """C17: Token file with correct permissions (600) — verify accepted."""
        token_file = tmp_path / "token"
        token_file.write_text("secret-token")
        token_file.chmod(0o600)

        token = _load_token_file(token_file)
        assert token == "secret-token"

    def test_c18_reject_empty_token(self) -> None:
        """C18: Reject empty token."""
        with pytest.raises(ConfigurationError, match="token is required"):
            make_config(opencti_token=SecretStr(""))

    def test_c19_whitespace_only_token_rejected_by_load(self) -> None:
        """C19: Whitespace-only token from env var is rejected by _load_token().

        _load_token() now strips and checks token values, so '   ' is
        treated as empty and Config.load() raises ConfigurationError.
        """
        with patch.dict("os.environ", {"OPENCTI_TOKEN": "   "}, clear=False):
            with pytest.raises(ConfigurationError, match="token not found"):
                Config.load()


# =============================================================================
# C20-C21: Connection Caching and Thread Safety
# =============================================================================

class TestConnectionCachingAndThreadSafety:
    """C20-C21: Client caching and concurrent access."""

    @patch("pycti.OpenCTIApiClient")
    def test_c20_connect_reuses_cached_client(self, mock_pycti_cls: Mock) -> None:
        """C20: Connect reuses cached client (second call returns same object)."""
        mock_instance = MagicMock()
        mock_pycti_cls.return_value = mock_instance

        config = make_config()
        client = OpenCTIClient(config)

        result1 = client.connect()
        result2 = client.connect()

        # pycti constructor should be called only once
        mock_pycti_cls.assert_called_once()
        assert result1 is result2
        assert result1 is mock_instance

    @patch("pycti.OpenCTIApiClient")
    def test_c21_thread_safe_concurrent_connect(self, mock_pycti_cls: Mock) -> None:
        """C21: Thread-safe concurrent connect calls — only one pycti client created."""
        call_count = 0
        barrier = threading.Barrier(5)

        def slow_init(*args: Any, **kwargs: Any) -> MagicMock:
            nonlocal call_count
            call_count += 1
            # Small sleep to increase contention window
            import time
            time.sleep(0.01)
            return MagicMock()

        mock_pycti_cls.side_effect = slow_init

        config = make_config()
        client = OpenCTIClient(config)

        results: list[Any] = [None] * 5
        errors: list[Exception | None] = [None] * 5

        def connect_thread(idx: int) -> None:
            try:
                barrier.wait(timeout=5)
                results[idx] = client.connect()
            except Exception as e:
                errors[idx] = e

        threads = [threading.Thread(target=connect_thread, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        # No errors should have occurred
        for i, err in enumerate(errors):
            assert err is None, f"Thread {i} raised: {err}"

        # Only one pycti client should have been created
        assert call_count == 1, f"Expected 1 client creation, got {call_count}"

        # All threads should return the same object
        for i in range(1, 5):
            assert results[i] is results[0], f"Thread {i} got different client"


# =============================================================================
# S1-S10: SSL/TLS Handling
# =============================================================================

class TestSSLTLSHandling:
    """S1-S10: SSL verification, env parsing, error handling, and HTTP warnings."""

    @patch("pycti.OpenCTIApiClient")
    def test_s1_ssl_verify_true_passed_to_pycti(self, mock_pycti_cls: Mock) -> None:
        """S1: ssl_verify=true passed to pycti client."""
        mock_pycti_cls.return_value = MagicMock()
        config = make_config(ssl_verify=True)
        client = OpenCTIClient(config)

        client.connect()

        call_kwargs = mock_pycti_cls.call_args
        assert call_kwargs[1]["ssl_verify"] is True

    @patch("pycti.OpenCTIApiClient")
    def test_s2_ssl_verify_false_passed_to_pycti(self, mock_pycti_cls: Mock) -> None:
        """S2: ssl_verify=false passed to pycti client."""
        mock_pycti_cls.return_value = MagicMock()
        config = make_config(ssl_verify=False)
        client = OpenCTIClient(config)

        client.connect()

        call_kwargs = mock_pycti_cls.call_args
        assert call_kwargs[1]["ssl_verify"] is False

    @pytest.mark.parametrize(
        "env_value,expected",
        [
            ("true", True),
            ("false", False),
            ("1", True),
            ("0", False),
            ("yes", True),
            ("no", False),
            ("True", True),
            ("FALSE", False),
            ("YES", True),
            ("No", False),
        ],
        ids=[
            "true", "false", "1", "0", "yes", "no",
            "True_caps", "FALSE_caps", "YES_caps", "No_caps",
        ],
    )
    def test_s3_ssl_verify_env_var_parsing(
        self,
        env_value: str,
        expected: bool,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """S3: OPENCTI_SSL_VERIFY env var parsing: various string forms."""
        monkeypatch.setenv("OPENCTI_SSL_VERIFY", env_value)
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")

        config = Config.load()

        assert config.ssl_verify is expected

    def test_s4_ssl_error_classified_as_transient(self) -> None:
        """S4: SSL error classified as transient (in TRANSIENT_ERRORS)."""
        assert "SSLError" in TRANSIENT_ERRORS

    def test_s5_ssl_error_message_no_certificate_leak(self) -> None:
        """S5: SSL error message doesn't leak certificate details.

        The ConnectionError safe_message should be generic.
        """
        error = ConnectionError("SSL: CERTIFICATE_VERIFY_FAILED [path: /etc/ssl/cert.pem]")
        assert "certificate" not in error.safe_message.lower()
        assert "ssl" not in error.safe_message.lower()
        assert error.safe_message == "Unable to connect to OpenCTI. Check server status."

    def test_s6_http_url_remote_host_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """S6: HTTP URL for remote host (e.g., http://example.com:8080) logs security warning."""
        with caplog.at_level(logging.WARNING, logger="opencti_mcp.config"):
            _validate_url("http://example.com:8080")

        assert any("HTTP" in rec.message and "plaintext" in rec.message for rec in caplog.records)

    def test_s7_http_url_localhost_no_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """S7: HTTP URL for localhost does NOT log warning."""
        with caplog.at_level(logging.WARNING, logger="opencti_mcp.config"):
            _validate_url("http://localhost:8080")

        warning_records = [
            r for r in caplog.records
            if "plaintext" in r.message.lower()
        ]
        assert len(warning_records) == 0

    @pytest.mark.parametrize(
        "url",
        [
            "http://10.0.0.50:8080",
            "http://172.16.0.1:8080",
            "http://172.31.255.255:8080",
            "http://192.168.1.100:8080",
        ],
        ids=["10.x", "172.16.x", "172.31.x", "192.168.x"],
    )
    def test_s8_http_url_private_ips_no_warning(
        self,
        url: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """S8: HTTP URL for private IPs (10.x, 172.16.x, 192.168.x) does NOT log warning."""
        with caplog.at_level(logging.WARNING, logger="opencti_mcp.config"):
            _validate_url(url)

        warning_records = [
            r for r in caplog.records
            if "plaintext" in r.message.lower()
        ]
        assert len(warning_records) == 0

    def test_s9_http_k8s_service_url_not_recognized_as_internal(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """S9: HTTP URL for K8s service — .cluster.local is NOT currently recognized as internal.

        BUG NOTED: The source code does not detect .cluster.local as an internal
        address, so it logs a plaintext warning. This documents the current behavior.
        """
        with caplog.at_level(logging.WARNING, logger="opencti_mcp.config"):
            result = _validate_url("http://svc.ns.svc.cluster.local:8080")

        # The URL is accepted
        assert result == "http://svc.ns.svc.cluster.local:8080"

        # Current behavior: it DOES warn (because .cluster.local is not in is_local check)
        warning_records = [
            r for r in caplog.records
            if "plaintext" in r.message.lower()
        ]
        assert len(warning_records) == 1, (
            "Expected 1 warning for K8s .cluster.local URL (not recognized as internal)"
        )

    def test_s10_https_url_never_logs_http_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """S10: HTTPS URL never logs HTTP warning regardless of host."""
        with caplog.at_level(logging.WARNING, logger="opencti_mcp.config"):
            _validate_url("https://example.com:8080")
            _validate_url("https://remote-server.io")
            _validate_url("https://10.0.0.50:443")

        warning_records = [
            r for r in caplog.records
            if "plaintext" in r.message.lower()
        ]
        assert len(warning_records) == 0


# =============================================================================
# U1-U10: URL Edge Cases
# =============================================================================

class TestURLEdgeCases:
    """U1-U10: URL normalization, validation, and special formats."""

    def test_u1_url_normalization_strips_trailing_slashes(self) -> None:
        """U1: URL normalization strips trailing slashes."""
        assert _validate_url("http://localhost:8080/") == "http://localhost:8080"
        assert _validate_url("http://localhost:8080///") == "http://localhost:8080"
        assert _validate_url("https://host:443/") == "https://host:443"

    def test_u2_reject_file_scheme(self) -> None:
        """U2: URL scheme must be http or https — reject file://"""
        with pytest.raises(ConfigurationError, match="Invalid URL scheme"):
            _validate_url("file:///etc/passwd")

    def test_u3_reject_ftp_scheme(self) -> None:
        """U3: URL scheme must be http or https — reject ftp://"""
        with pytest.raises(ConfigurationError, match="Invalid URL scheme"):
            _validate_url("ftp://host:8080")

    def test_u4_url_without_scheme_rejected(self) -> None:
        """U4: URL without scheme rejected or error."""
        with pytest.raises(ConfigurationError):
            _validate_url("localhost:8080")

    def test_u5_url_without_host_rejected(self) -> None:
        """U5: URL without host rejected."""
        with pytest.raises(ConfigurationError, match="missing host"):
            _validate_url("http://")

    def test_u6_kubernetes_service_url_accepted(self) -> None:
        """U6: Kubernetes service URL format accepted."""
        result = _validate_url(
            "http://opencti-platform.namespace.svc.cluster.local:8080"
        )
        assert result == "http://opencti-platform.namespace.svc.cluster.local:8080"

    def test_u7_https_with_standard_port_accepted(self) -> None:
        """U7: URL with port in HTTPS (https://host:443) accepted."""
        result = _validate_url("https://host:443")
        assert result == "https://host:443"

    def test_u8_https_with_non_standard_port_accepted(self) -> None:
        """U8: URL with non-standard HTTPS port (https://host:8443) accepted."""
        result = _validate_url("https://host:8443")
        assert result == "https://host:8443"

    def test_u9_very_long_url_handled_gracefully(self) -> None:
        """U9: Very long URL (1000+ chars) handled gracefully — no crash."""
        long_host = "a" * 1000
        long_url = f"http://{long_host}.com:8080"

        # Should not crash — either succeeds or raises a clear error
        try:
            result = _validate_url(long_url)
            # If it succeeds, the URL should be returned
            assert len(result) > 1000
        except ConfigurationError:
            # A clear error is also acceptable
            pass

    def test_u10_unicode_hostname_handled_gracefully(self) -> None:
        """U10: URL with unicode hostname — handled gracefully (no crash)."""
        try:
            result = _validate_url("http://\u00e9xample.com:8080")
            # If accepted, it should be a valid string
            assert isinstance(result, str)
        except ConfigurationError:
            # A clear rejection is also acceptable
            pass


# =============================================================================
# Reconnect Tests (supplementary)
# =============================================================================

class TestReconnect:
    """Verify reconnect clears cached client and creates a new one."""

    @patch("pycti.OpenCTIApiClient")
    def test_reconnect_creates_new_client(self, mock_pycti_cls: Mock) -> None:
        """reconnect() should clear the cached client and create a new one."""
        instance1 = MagicMock(name="client1")
        instance2 = MagicMock(name="client2")
        mock_pycti_cls.side_effect = [instance1, instance2]

        config = make_config()
        client = OpenCTIClient(config)

        first = client.connect()
        assert first is instance1

        second = client.reconnect()
        assert second is instance2
        assert mock_pycti_cls.call_count == 2

    @patch("pycti.OpenCTIApiClient")
    def test_connect_after_reconnect_returns_new_cached(self, mock_pycti_cls: Mock) -> None:
        """After reconnect, subsequent connect() should return the new cached client."""
        instance1 = MagicMock(name="client1")
        instance2 = MagicMock(name="client2")
        mock_pycti_cls.side_effect = [instance1, instance2]

        config = make_config()
        client = OpenCTIClient(config)

        client.connect()
        new_client = client.reconnect()
        same_client = client.connect()

        assert same_client is new_client
        assert mock_pycti_cls.call_count == 2


# =============================================================================
# Additional edge case coverage
# =============================================================================

class TestConfigEdgeCases:
    """Additional edge cases for Config construction and validation."""

    def test_config_url_with_whitespace_stripped(self) -> None:
        """URL with leading/trailing whitespace is stripped by _validate_url."""
        config = make_config(opencti_url="  http://localhost:8080  ")
        assert config.opencti_url == "http://localhost:8080"

    def test_config_empty_url_rejected(self) -> None:
        """Empty URL is rejected."""
        with pytest.raises(ConfigurationError, match="cannot be empty"):
            make_config(opencti_url="")

    def test_config_whitespace_only_url_rejected(self) -> None:
        """Whitespace-only URL is rejected."""
        with pytest.raises(ConfigurationError, match="cannot be empty"):
            make_config(opencti_url="   ")

    @patch("pycti.OpenCTIApiClient")
    def test_connect_import_error_raises_connection_error(self, mock_pycti_cls: Mock) -> None:
        """If pycti import fails, a ConnectionError is raised."""
        mock_pycti_cls.side_effect = ImportError("No module named 'pycti'")

        config = make_config()
        client = OpenCTIClient(config)

        with pytest.raises(ConnectionError, match="pycti not installed"):
            client.connect()

    @patch("pycti.OpenCTIApiClient")
    def test_connect_generic_exception_raises_connection_error(self, mock_pycti_cls: Mock) -> None:
        """Generic exceptions during connect are wrapped in ConnectionError."""
        mock_pycti_cls.side_effect = RuntimeError("unexpected failure")

        config = make_config()
        client = OpenCTIClient(config)

        with pytest.raises(ConnectionError, match="Connection failed"):
            client.connect()

    def test_secret_str_hides_value_in_repr(self) -> None:
        """SecretStr never reveals token in repr or str."""
        s = SecretStr("super-secret")
        assert "super-secret" not in repr(s)
        assert "super-secret" not in str(s)
        assert "***" in repr(s)
        assert str(s) == "***"

    def test_config_repr_hides_token(self) -> None:
        """Config repr never reveals the token."""
        config = make_config(opencti_token=SecretStr("my-secret-token"))
        r = repr(config)
        assert "my-secret-token" not in r
        assert "***" in r

    def test_url_path_prefix_preserved_in_config(self) -> None:
        """URL path prefix like /opencti is preserved after validation."""
        config = make_config(opencti_url="https://host.example.com/opencti/v2")
        assert config.opencti_url == "https://host.example.com/opencti/v2"

    def test_url_trailing_slash_on_path_stripped(self) -> None:
        """Trailing slash on URL with path is also stripped."""
        config = make_config(opencti_url="https://host.example.com/opencti/")
        assert config.opencti_url == "https://host.example.com/opencti"


class TestTokenFilePermissions:
    """Detailed token file permission tests."""

    def test_token_file_400_accepted(self, tmp_path: Path) -> None:
        """Token file with 400 (read-only owner) is also accepted."""
        token_file = tmp_path / "token"
        token_file.write_text("my-token")
        token_file.chmod(0o400)

        token = _load_token_file(token_file)
        assert token == "my-token"

    def test_token_file_640_rejected(self, tmp_path: Path) -> None:
        """Token file with 640 (group-readable) is rejected."""
        token_file = tmp_path / "token"
        token_file.write_text("my-token")
        token_file.chmod(0o640)

        with pytest.raises(ConfigurationError, match="insecure permissions"):
            _load_token_file(token_file)

    def test_token_file_nonexistent_returns_none(self, tmp_path: Path) -> None:
        """Non-existent token file returns None."""
        result = _load_token_file(tmp_path / "nonexistent")
        assert result is None

    def test_token_file_empty_returns_none(self, tmp_path: Path) -> None:
        """Empty token file returns None (after stripping)."""
        token_file = tmp_path / "token"
        token_file.write_text("")
        token_file.chmod(0o600)

        result = _load_token_file(token_file)
        assert result is None

    def test_token_file_whitespace_only_returns_none(self, tmp_path: Path) -> None:
        """Whitespace-only token file returns None (after stripping)."""
        token_file = tmp_path / "token"
        token_file.write_text("   \n  \n  ")
        token_file.chmod(0o600)

        result = _load_token_file(token_file)
        assert result is None


class TestEnvFileTokenLoading:
    """Tests for .env file token loading."""

    def test_env_file_with_single_quotes(self, tmp_path: Path) -> None:
        """Token in .env file with single quotes is unquoted."""
        env_file = tmp_path / ".env"
        env_file.write_text("OPENCTI_TOKEN='single-quoted-token'\n")
        env_file.chmod(0o600)

        token = _load_token_from_env_file(env_file)
        assert token == "single-quoted-token"

    def test_env_file_admin_token_variant(self, tmp_path: Path) -> None:
        """OPENCTI_ADMIN_TOKEN in .env file is also recognized."""
        env_file = tmp_path / ".env"
        env_file.write_text("OPENCTI_ADMIN_TOKEN=admin-token-123\n")
        env_file.chmod(0o600)

        token = _load_token_from_env_file(env_file)
        assert token == "admin-token-123"

    def test_env_file_comments_skipped(self, tmp_path: Path) -> None:
        """Comments and empty lines in .env file are skipped."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "# This is a comment\n"
            "\n"
            "SOME_OTHER_VAR=value\n"
            "OPENCTI_TOKEN=real-token\n"
        )
        env_file.chmod(0o600)

        token = _load_token_from_env_file(env_file)
        assert token == "real-token"

    def test_env_file_nonexistent_returns_none(self, tmp_path: Path) -> None:
        """Non-existent .env file returns None."""
        result = _load_token_from_env_file(tmp_path / ".env")
        assert result is None
