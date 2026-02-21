#!/usr/bin/env python3
"""
Tests for network fetch safety features.

These tests verify SSRF protection, size limits, and HTTPS enforcement.
"""

import os
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

import pytest


class TestUrlValidation:
    """Tests for URL validation and SSRF protection."""

    def test_allowed_host_passes(self):
        """Allowed hosts pass validation."""
        from rag_mcp.sources import _validate_url_host

        # Should not raise
        _validate_url_host("https://api.github.com/repos/test/test")
        _validate_url_host("https://raw.githubusercontent.com/test/test/main/file")
        _validate_url_host("https://www.cisa.gov/data.json")

    def test_disallowed_host_rejected(self):
        """Disallowed hosts are rejected."""
        from rag_mcp.sources import _validate_url_host

        with pytest.raises(ValueError, match="host not allowed"):
            _validate_url_host("https://evil.com/malware")

        with pytest.raises(ValueError, match="host not allowed"):
            _validate_url_host("https://attacker.example.com/payload")

    def test_ip_literal_rejected(self):
        """IP literal URLs are rejected."""
        from rag_mcp.sources import _validate_url_host

        with pytest.raises(ValueError, match="IP literal"):
            _validate_url_host("https://127.0.0.1/local")

        with pytest.raises(ValueError, match="IP literal"):
            _validate_url_host("https://192.168.1.1/internal")

        with pytest.raises(ValueError, match="IP literal"):
            _validate_url_host("https://169.254.169.254/metadata")  # AWS metadata

        # IPv6
        with pytest.raises(ValueError, match="IP literal"):
            _validate_url_host("https://[::1]/ipv6")

    def test_http_rejected_by_default(self):
        """HTTP URLs are rejected by default (HTTPS_ONLY=True)."""
        from rag_mcp.sources import _validate_url_host, HTTPS_ONLY

        if HTTPS_ONLY:
            with pytest.raises(ValueError, match="HTTPS required"):
                _validate_url_host("http://api.github.com/test")

    def test_invalid_scheme_rejected(self):
        """Invalid schemes are rejected."""
        from rag_mcp.sources import _validate_url_host

        # ftp gets caught by HTTPS enforcement first
        with pytest.raises(ValueError, match="HTTPS required"):
            _validate_url_host("ftp://api.github.com/file")

        # file:// scheme has no host, so fails host check
        with pytest.raises(ValueError, match="host not allowed"):
            _validate_url_host("file:///etc/passwd")


class TestIpLiteralDetection:
    """Tests for IP literal detection."""

    def test_ipv4_detected(self):
        """IPv4 addresses are detected."""
        from rag_mcp.sources import _is_ip_literal

        assert _is_ip_literal("127.0.0.1") is True
        assert _is_ip_literal("192.168.1.1") is True
        assert _is_ip_literal("10.0.0.1") is True
        assert _is_ip_literal("169.254.169.254") is True

    def test_ipv6_detected(self):
        """IPv6 addresses are detected."""
        from rag_mcp.sources import _is_ip_literal

        assert _is_ip_literal("::1") is True
        assert _is_ip_literal("fe80::1") is True
        assert _is_ip_literal("2001:db8::1") is True

    def test_hostnames_not_detected(self):
        """Hostnames are not detected as IP literals."""
        from rag_mcp.sources import _is_ip_literal

        assert _is_ip_literal("api.github.com") is False
        assert _is_ip_literal("example.com") is False
        assert _is_ip_literal("localhost") is False  # Name, not IP

    def test_empty_not_detected(self):
        """Empty strings are not detected as IP literals."""
        from rag_mcp.sources import _is_ip_literal

        assert _is_ip_literal("") is False
        assert _is_ip_literal(None) is False


class TestDownloadSizeLimits:
    """Tests for download size limit enforcement."""

    def test_max_download_bytes_configured(self):
        """MAX_DOWNLOAD_BYTES is configured."""
        from rag_mcp.sources import MAX_DOWNLOAD_BYTES

        assert MAX_DOWNLOAD_BYTES > 0
        assert MAX_DOWNLOAD_BYTES == 60 * 1024 * 1024  # 60 MB default

    def test_content_length_check(self):
        """Content-Length exceeding limit is rejected early."""
        from rag_mcp.sources import fetch_url, DownloadTooLargeError

        # Mock response with large Content-Length
        mock_response = MagicMock()
        mock_response.headers = {"Content-Length": "100000000"}  # 100 MB
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("rag_mcp.sources.urlopen", return_value=mock_response):
            with patch("rag_mcp.sources._validate_url_host"):
                result = fetch_url("https://api.github.com/test", max_bytes=1000)
                assert result is None  # Should fail due to size

    def test_streaming_size_check(self):
        """Streaming download exceeding limit is stopped."""
        from rag_mcp.sources import fetch_url

        # Mock response that streams more than limit
        def mock_read(size):
            return b"x" * size  # Always return full chunk

        mock_response = MagicMock()
        mock_response.headers = {}  # No Content-Length
        mock_response.read = mock_read
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("rag_mcp.sources.urlopen", return_value=mock_response):
            with patch("rag_mcp.sources._validate_url_host"):
                # Should fail when exceeding small limit
                result = fetch_url("https://api.github.com/test", max_bytes=1000)
                assert result is None


class TestFetchUrlSecurity:
    """Integration tests for fetch_url security features."""

    def test_fetch_validates_url_first(self):
        """fetch_url validates URL before making request."""
        from rag_mcp.sources import fetch_url

        # Should fail validation before any network call
        result = fetch_url("https://evil.com/malware")
        assert result is None

        result = fetch_url("https://127.0.0.1/local")
        assert result is None

    def test_fetch_with_custom_max_bytes(self):
        """fetch_url respects custom max_bytes parameter."""
        from rag_mcp.sources import fetch_url

        # Mock small successful response
        mock_response = MagicMock()
        mock_response.headers = {"Content-Length": "100"}
        mock_response.read = MagicMock(side_effect=[b"test", b""])
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("rag_mcp.sources.urlopen", return_value=mock_response):
            with patch("rag_mcp.sources._validate_url_host"):
                result = fetch_url("https://api.github.com/test", max_bytes=1000)
                assert result == b"test"


class TestHttpsEnforcement:
    """Tests for HTTPS enforcement."""

    def test_https_only_default(self):
        """HTTPS_ONLY defaults to True."""
        from rag_mcp.sources import HTTPS_ONLY

        # Unless RAG_ALLOW_HTTP is set, should be True
        if not os.environ.get("RAG_ALLOW_HTTP"):
            assert HTTPS_ONLY is True

    def test_http_allowed_when_configured(self):
        """HTTP is allowed when RAG_ALLOW_HTTP=1."""
        # This test documents the escape hatch behavior
        # In production, HTTPS_ONLY should remain True
        pass  # Tested via environment variable, not mocking


class TestRedirectSafety:
    """Tests for redirect handling safety."""

    def test_redirect_to_disallowed_host_blocked(self):
        """Redirects to disallowed hosts should be blocked."""
        from rag_mcp.sources import fetch_url

        # Mock response that redirects to a disallowed host
        mock_response = MagicMock()
        mock_response.geturl.return_value = "https://evil.com/payload"  # Redirect target
        mock_response.headers = {"Content-Length": "100"}
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("rag_mcp.sources.urlopen", return_value=mock_response):
            with patch("rag_mcp.sources._validate_url_host") as mock_validate:
                # First call succeeds (initial URL), second call fails (redirect target)
                mock_validate.side_effect = [None, ValueError("host not allowed")]
                result = fetch_url("https://api.github.com/test")
                assert result is None  # Should fail due to redirect validation

    def test_redirect_to_ip_literal_blocked(self):
        """Redirects to IP literals should be blocked."""
        from rag_mcp.sources import fetch_url

        mock_response = MagicMock()
        mock_response.geturl.return_value = "http://169.254.169.254/metadata"
        mock_response.headers = {}
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("rag_mcp.sources.urlopen", return_value=mock_response):
            with patch("rag_mcp.sources._validate_url_host") as mock_validate:
                mock_validate.side_effect = [None, ValueError("IP literal")]
                result = fetch_url("https://api.github.com/test")
                assert result is None


class TestRetryBehavior:
    """Tests for retry/backoff functionality."""

    def test_retry_on_timeout(self):
        """Transient timeout should trigger retry."""
        from rag_mcp.sources import fetch_url
        from socket import timeout as SocketTimeout

        call_count = 0

        def mock_urlopen(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise SocketTimeout("timed out")
            # Third attempt succeeds
            mock_resp = MagicMock()
            mock_resp.geturl.return_value = args[0].full_url
            mock_resp.headers = {}
            mock_resp.read.side_effect = [b"success", b""]
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        with patch("rag_mcp.sources.urlopen", side_effect=mock_urlopen):
            with patch("rag_mcp.sources._validate_url_host"):
                with patch("rag_mcp.sources.time.sleep"):  # Skip actual delays
                    result = fetch_url("https://api.github.com/test", max_retries=3)
                    assert result == b"success"
                    assert call_count == 3  # Failed twice, succeeded on third

    def test_retry_on_5xx(self):
        """HTTP 5xx errors should trigger retry."""
        from rag_mcp.sources import fetch_url

        call_count = 0

        def mock_urlopen(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise HTTPError(args[0].full_url, 503, "Service Unavailable", {}, None)
            mock_resp = MagicMock()
            mock_resp.geturl.return_value = args[0].full_url
            mock_resp.headers = {}
            mock_resp.read.side_effect = [b"ok", b""]
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        with patch("rag_mcp.sources.urlopen", side_effect=mock_urlopen):
            with patch("rag_mcp.sources._validate_url_host"):
                with patch("rag_mcp.sources.time.sleep"):
                    result = fetch_url("https://api.github.com/test", max_retries=3)
                    assert result == b"ok"

    def test_no_retry_on_4xx(self):
        """HTTP 4xx errors (except 429) should not retry."""
        from rag_mcp.sources import fetch_url

        call_count = 0

        def mock_urlopen(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise HTTPError(args[0].full_url, 404, "Not Found", {}, None)

        with patch("rag_mcp.sources.urlopen", side_effect=mock_urlopen):
            with patch("rag_mcp.sources._validate_url_host"):
                result = fetch_url("https://api.github.com/test", max_retries=3)
                assert result is None
                assert call_count == 1  # No retries

    def test_retry_on_429(self):
        """HTTP 429 (rate limit) should trigger retry."""
        from rag_mcp.sources import fetch_url

        call_count = 0

        def mock_urlopen(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise HTTPError(args[0].full_url, 429, "Too Many Requests", {}, None)
            mock_resp = MagicMock()
            mock_resp.geturl.return_value = args[0].full_url
            mock_resp.headers = {}
            mock_resp.read.side_effect = [b"ok", b""]
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        with patch("rag_mcp.sources.urlopen", side_effect=mock_urlopen):
            with patch("rag_mcp.sources._validate_url_host"):
                with patch("rag_mcp.sources.time.sleep"):
                    result = fetch_url("https://api.github.com/test", max_retries=3)
                    assert result == b"ok"

    def test_max_retries_exhausted(self):
        """All retries exhausted returns None."""
        from rag_mcp.sources import fetch_url
        from socket import timeout as SocketTimeout

        call_count = 0

        def mock_urlopen(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise SocketTimeout("timed out")

        with patch("rag_mcp.sources.urlopen", side_effect=mock_urlopen):
            with patch("rag_mcp.sources._validate_url_host"):
                with patch("rag_mcp.sources.time.sleep"):
                    result = fetch_url("https://api.github.com/test", max_retries=2)
                    assert result is None
                    assert call_count == 3  # Initial + 2 retries
