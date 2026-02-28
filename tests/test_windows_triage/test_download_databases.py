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

    def _db_release(self, tag="triage-db-v2026.02.25"):
        """Helper: a triage-db release with .db.zst assets."""
        return {
            "tag_name": tag,
            "assets": [
                {"name": "known_good.db.zst", "url": "https://x"},
                {"name": "context.db.zst", "url": "https://x"},
            ],
        }

    def test_latest_finds_triage_db_release(self):
        """Finds triage-db release among mixed releases."""
        releases = [
            {"tag_name": "v0.5.0", "assets": []},
            self._db_release("triage-db-v2026.02.25"),
            self._db_release("triage-db-v2026.01.15"),
        ]
        with (
            patch(
                "windows_triage.scripts.download_databases.urllib.request.urlopen",
                return_value=self._mock_urlopen(releases),
            ),
            patch(
                "windows_triage.scripts.download_databases._github_headers",
                return_value={"Accept": "application/vnd.github+json"},
            ),
        ):
            result = _fetch_release("latest")
        assert result["tag_name"] == "triage-db-v2026.02.25"

    def test_latest_skips_releases_without_assets(self):
        """Triage-db tag without .db.zst assets is skipped."""
        releases = [
            {"tag_name": "triage-db-v2026.03.01", "assets": []},
            self._db_release("triage-db-v2026.02.25"),
        ]
        with (
            patch(
                "windows_triage.scripts.download_databases.urllib.request.urlopen",
                return_value=self._mock_urlopen(releases),
            ),
            patch(
                "windows_triage.scripts.download_databases._github_headers",
                return_value={"Accept": "application/vnd.github+json"},
            ),
        ):
            result = _fetch_release("latest")
        assert result["tag_name"] == "triage-db-v2026.02.25"

    def test_latest_no_matching_releases(self):
        """No triage-db releases raises ValueError."""
        releases = [
            {"tag_name": "v0.5.0", "assets": []},
            {"tag_name": "v0.4.0", "assets": []},
        ]
        with (
            patch(
                "windows_triage.scripts.download_databases.urllib.request.urlopen",
                return_value=self._mock_urlopen(releases),
            ),
            patch(
                "windows_triage.scripts.download_databases._github_headers",
                return_value={"Accept": "application/vnd.github+json"},
            ),
        ):
            with pytest.raises(ValueError, match="No triage database releases"):
                _fetch_release("latest")

    def test_latest_skips_code_releases(self):
        """Code release (v0.5.0) is not returned even if it has assets."""
        releases = [
            {
                "tag_name": "v0.5.0",
                "assets": [{"name": "source.tar.gz", "url": "https://x"}],
            },
            self._db_release("triage-db-v2026.02.25"),
        ]
        with (
            patch(
                "windows_triage.scripts.download_databases.urllib.request.urlopen",
                return_value=self._mock_urlopen(releases),
            ),
            patch(
                "windows_triage.scripts.download_databases._github_headers",
                return_value={"Accept": "application/vnd.github+json"},
            ),
        ):
            result = _fetch_release("latest")
        assert result["tag_name"] == "triage-db-v2026.02.25"

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
