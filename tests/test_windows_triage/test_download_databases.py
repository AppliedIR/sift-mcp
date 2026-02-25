"""Tests for download_databases script — auth fallback and release fetching."""

import json
from unittest.mock import MagicMock, patch

import pytest
from windows_triage.scripts.download_databases import (
    _fetch_release,
    _github_headers,
)


class TestGithubHeaders:
    def test_uses_env_token(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        headers = _github_headers()
        assert headers["Authorization"] == "Bearer ghp_test123"

    def test_falls_back_to_gh_cli(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "ghp_from_cli\n"
        with patch(
            "windows_triage.scripts.download_databases.subprocess.run",
            return_value=mock_result,
        ) as mock_run:
            headers = _github_headers()
        assert headers["Authorization"] == "Bearer ghp_from_cli"
        mock_run.assert_called_once()

    def test_no_auth_when_gh_missing(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        with patch(
            "windows_triage.scripts.download_databases.subprocess.run",
            side_effect=FileNotFoundError,
        ):
            headers = _github_headers()
        assert "Authorization" not in headers

    def test_env_token_takes_priority(self, monkeypatch):
        """GITHUB_TOKEN env var is checked first; gh CLI is not called."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_env")
        with patch(
            "windows_triage.scripts.download_databases.subprocess.run"
        ) as mock_run:
            headers = _github_headers()
        assert headers["Authorization"] == "Bearer ghp_env"
        mock_run.assert_not_called()


class TestFetchRelease:
    def _mock_urlopen(self, data):
        """Create a mock context manager returning JSON data."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    def test_latest_succeeds_directly(self):
        """When /releases/latest works, use it."""
        release = {"tag_name": "v1.0", "assets": []}
        with (
            patch(
                "windows_triage.scripts.download_databases.urllib.request.urlopen",
                return_value=self._mock_urlopen(release),
            ),
            patch(
                "windows_triage.scripts.download_databases._github_headers",
                return_value={"Accept": "application/vnd.github+json"},
            ),
        ):
            result = _fetch_release("latest")
        assert result["tag_name"] == "v1.0"

    def test_latest_falls_back_to_releases_list(self):
        """When /releases/latest returns 404, fall back to /releases list."""
        import urllib.error

        releases_list = [{"tag_name": "triage-db-v2025.02", "assets": []}]

        call_count = 0

        def mock_urlopen(req, timeout=30):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
            return self._mock_urlopen(releases_list)

        with (
            patch(
                "windows_triage.scripts.download_databases.urllib.request.urlopen",
                side_effect=mock_urlopen,
            ),
            patch(
                "windows_triage.scripts.download_databases._github_headers",
                return_value={"Accept": "application/vnd.github+json"},
            ),
        ):
            result = _fetch_release("latest")
        assert result["tag_name"] == "triage-db-v2025.02"
        assert call_count == 2

    def test_latest_no_releases_raises(self):
        """When /releases/latest 404s and /releases is empty, raise ValueError."""
        import urllib.error

        call_count = 0

        def mock_urlopen(req, timeout=30):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
            return self._mock_urlopen([])

        with (
            patch(
                "windows_triage.scripts.download_databases.urllib.request.urlopen",
                side_effect=mock_urlopen,
            ),
            patch(
                "windows_triage.scripts.download_databases._github_headers",
                return_value={"Accept": "application/vnd.github+json"},
            ),
        ):
            with pytest.raises(ValueError, match="No releases found"):
                _fetch_release("latest")

    def test_specific_tag(self):
        """Specific tag hits /releases/tags/<tag> directly."""
        release = {"tag_name": "triage-db-v2025.02", "assets": []}
        with (
            patch(
                "windows_triage.scripts.download_databases.urllib.request.urlopen",
                return_value=self._mock_urlopen(release),
            ) as mock_open,
            patch(
                "windows_triage.scripts.download_databases._github_headers",
                return_value={"Accept": "application/vnd.github+json"},
            ),
        ):
            result = _fetch_release("triage-db-v2025.02")
        assert result["tag_name"] == "triage-db-v2025.02"
        url_called = mock_open.call_args[0][0].full_url
        assert "/releases/tags/triage-db-v2025.02" in url_called
