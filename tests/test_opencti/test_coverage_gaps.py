"""Tests to fill coverage gaps identified in exhaustive testing.

Covers:
- __main__.py entry point (was 0%)
- client.py uncovered search methods and error paths (was 47%)
- config.py token loading edge cases (was 70%)
- adaptive.py uncovered methods (was 82%)
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import pytest

from opencti_mcp.config import Config, SecretStr, _load_token, _load_token_file, _load_token_from_env_file
from opencti_mcp.errors import ConfigurationError, ConnectionError, QueryError
from opencti_mcp.feature_flags import FeatureFlags, reset_feature_flags


# =============================================================================
# __main__.py Tests
# =============================================================================

class TestMainEntryPoint:
    """Tests for the __main__.py entry point."""

    def test_main_with_missing_token(self):
        """Main exits with error when token is missing."""
        from opencti_mcp.__main__ import main

        with patch.dict(os.environ, {}, clear=True):
            with patch('opencti_mcp.__main__.Config.load') as mock_load:
                mock_load.side_effect = ConfigurationError("No token configured")

                with pytest.raises(SystemExit) as exc_info:
                    main()

                assert exc_info.value.code == 1

    def test_main_with_keyboard_interrupt(self):
        """Main handles keyboard interrupt gracefully."""
        from opencti_mcp.__main__ import main

        with patch('opencti_mcp.__main__.Config.load') as mock_load:
            mock_load.return_value = Config(
                opencti_url="http://localhost:8080",
                opencti_token=SecretStr("test-token")
            )
            with patch('opencti_mcp.__main__.get_feature_flags') as mock_flags:
                mock_flags.return_value = FeatureFlags(startup_validation=False)
                with patch('opencti_mcp.__main__.OpenCTIMCPServer') as mock_server:
                    mock_instance = Mock()
                    mock_instance.run = Mock(side_effect=KeyboardInterrupt)
                    mock_server.return_value = mock_instance

                    with patch('asyncio.run', side_effect=KeyboardInterrupt):
                        # Should not raise, just return
                        main()

    def test_main_with_startup_validation_enabled(self):
        """Main runs startup validation when enabled."""
        from opencti_mcp.__main__ import main

        config = Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("test-token")
        )

        with patch('opencti_mcp.__main__.Config.load', return_value=config):
            with patch('opencti_mcp.__main__.get_feature_flags') as mock_flags:
                mock_flags.return_value = FeatureFlags(startup_validation=True)
                with patch('opencti_mcp.__main__.OpenCTIClient') as mock_client_cls:
                    mock_client = Mock()
                    mock_client.validate_startup.return_value = {
                        'valid': True,
                        'warnings': ['Test warning'],
                        'errors': [],
                        'opencti_version': '6.1.0'
                    }
                    mock_client_cls.return_value = mock_client

                    with patch('opencti_mcp.__main__.OpenCTIMCPServer') as mock_server:
                        mock_instance = Mock()
                        mock_server.return_value = mock_instance

                        with patch('asyncio.run'):
                            main()

                        mock_client.validate_startup.assert_called_once()

    def test_main_with_startup_validation_errors(self):
        """Main logs errors but continues when validation has errors."""
        from opencti_mcp.__main__ import main

        config = Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("test-token")
        )

        with patch('opencti_mcp.__main__.Config.load', return_value=config):
            with patch('opencti_mcp.__main__.get_feature_flags') as mock_flags:
                mock_flags.return_value = FeatureFlags(startup_validation=True)
                with patch('opencti_mcp.__main__.OpenCTIClient') as mock_client_cls:
                    mock_client = Mock()
                    mock_client.validate_startup.return_value = {
                        'valid': False,
                        'warnings': [],
                        'errors': ['Connection failed'],
                        'opencti_version': None
                    }
                    mock_client_cls.return_value = mock_client

                    with patch('opencti_mcp.__main__.OpenCTIMCPServer') as mock_server:
                        mock_instance = Mock()
                        mock_server.return_value = mock_instance

                        with patch('asyncio.run'):
                            # Should not exit, should continue
                            main()

    def test_main_with_fatal_exception(self):
        """Main exits on fatal exception."""
        from opencti_mcp.__main__ import main

        with patch('opencti_mcp.__main__.Config.load') as mock_load:
            mock_load.side_effect = RuntimeError("Fatal error")

            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 1


# =============================================================================
# Config Token Loading Tests
# =============================================================================

class TestTokenLoading:
    """Tests for token loading edge cases."""

    def test_load_token_from_legacy_config(self):
        """Load token from legacy config location."""
        with tempfile.TemporaryDirectory() as tmpdir:
            legacy_path = Path(tmpdir) / ".config" / "rag"
            legacy_path.mkdir(parents=True)
            token_file = legacy_path / "opencti_token"
            token_file.write_text("legacy-token-123")
            os.chmod(token_file, 0o600)

            with patch.dict(os.environ, {}, clear=True):
                with patch('opencti_mcp.config.Path.home', return_value=Path(tmpdir)):
                    with patch('opencti_mcp.config.Path.cwd', return_value=Path(tmpdir)):
                        token = _load_token()
                        assert token == "legacy-token-123"

    def test_load_token_from_env_file(self):
        """Load token from .env file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("OPENCTI_TOKEN=env-file-token\n")
            os.chmod(env_file, 0o600)

            with patch.dict(os.environ, {}, clear=True):
                with patch('opencti_mcp.config.Path.home', return_value=Path(tmpdir)):
                    with patch('opencti_mcp.config.Path.cwd', return_value=Path(tmpdir)):
                        token = _load_token()
                        assert token == "env-file-token"

    def test_load_token_from_env_file_admin_token(self):
        """Load admin token from .env file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("OPENCTI_ADMIN_TOKEN=admin-token-123\n")
            os.chmod(env_file, 0o600)

            token = _load_token_from_env_file(env_file)
            assert token == "admin-token-123"

    def test_load_token_from_env_file_with_quotes(self):
        """Load token with quotes from .env file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text('OPENCTI_TOKEN="quoted-token"\n')
            os.chmod(env_file, 0o600)

            token = _load_token_from_env_file(env_file)
            assert token == "quoted-token"

    def test_load_token_from_env_file_with_single_quotes(self):
        """Load token with single quotes from .env file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("OPENCTI_TOKEN='single-quoted'\n")
            os.chmod(env_file, 0o600)

            token = _load_token_from_env_file(env_file)
            assert token == "single-quoted"

    def test_load_token_from_env_file_with_comments(self):
        """Load token skipping comments in .env file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("# Comment\nOPENCTI_TOKEN=token-after-comment\n")
            os.chmod(env_file, 0o600)

            token = _load_token_from_env_file(env_file)
            assert token == "token-after-comment"

    def test_load_token_file_insecure_permissions(self):
        """Reject token file with insecure permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            token_file = Path(tmpdir) / "token"
            token_file.write_text("insecure-token")
            os.chmod(token_file, 0o644)  # World-readable

            with pytest.raises(ConfigurationError) as exc_info:
                _load_token_file(token_file)

            assert "insecure permissions" in str(exc_info.value)

    def test_load_token_file_empty(self):
        """Return None for empty token file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            token_file = Path(tmpdir) / "token"
            token_file.write_text("")
            os.chmod(token_file, 0o600)

            token = _load_token_file(token_file)
            assert token is None

    def test_load_token_file_io_error(self):
        """Handle IO error when reading token file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            token_file = Path(tmpdir) / "token"
            token_file.write_text("token")
            os.chmod(token_file, 0o600)

            with patch.object(Path, 'read_text', side_effect=IOError("Read error")):
                token = _load_token_file(token_file)
                assert token is None

    def test_load_token_from_env_file_io_error(self):
        """Handle IO error when reading .env file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("OPENCTI_TOKEN=token")
            os.chmod(env_file, 0o600)

            with patch.object(Path, 'read_text', side_effect=OSError("Read error")):
                token = _load_token_from_env_file(env_file)
                assert token is None

    def test_load_token_from_env_file_world_readable_warns(self):
        """Warn when .env file is world-readable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("OPENCTI_TOKEN=token")
            os.chmod(env_file, 0o644)  # World-readable

            # Should not raise, just warn
            token = _load_token_from_env_file(env_file)
            assert token == "token"


# =============================================================================
# Client Search Method Tests
# =============================================================================

class TestClientSearchMethods:
    """Tests for uncovered client search methods."""

    @pytest.fixture
    def mock_config(self):
        return Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("test-token")
        )

    def test_search_campaigns(self, mock_config):
        """Test campaign search method."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.campaign.list.return_value = [
            {"id": "camp-1", "name": "Campaign 1", "description": "Test campaign"}
        ]

        with patch.object(client, 'connect', return_value=mock_pycti):
            results = client.search_campaigns("test", limit=10)

            assert isinstance(results, list)
            mock_pycti.campaign.list.assert_called_once()

    def test_search_campaigns_with_filters(self, mock_config):
        """Test campaign search with all filters."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.campaign.list.return_value = []

        with patch.object(client, 'connect', return_value=mock_pycti):
            results = client.search_campaigns(
                "test",
                limit=5,
                offset=10,
                labels=["apt"],
                confidence_min=70,
                created_after="2024-01-01",
                created_before="2024-12-31"
            )

            assert isinstance(results, list)

    def test_search_campaigns_error(self, mock_config):
        """Test campaign search error handling."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.campaign.list.side_effect = Exception("API error")

        with patch.object(client, 'connect', return_value=mock_pycti):
            with pytest.raises(QueryError):
                client.search_campaigns("test")

    def test_search_tools(self, mock_config):
        """Test tool search method."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.tool.list.return_value = [
            {"id": "tool-1", "name": "Mimikatz", "description": "Credential dumper"}
        ]

        with patch.object(client, 'connect', return_value=mock_pycti):
            results = client.search_tools("mimikatz", limit=10)

            assert isinstance(results, list)

    def test_search_tools_error(self, mock_config):
        """Test tool search error handling."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.tool.list.side_effect = Exception("API error")

        with patch.object(client, 'connect', return_value=mock_pycti):
            with pytest.raises(QueryError):
                client.search_tools("test")

    def test_search_infrastructure(self, mock_config):
        """Test infrastructure search method."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.infrastructure.list.return_value = [
            {"id": "infra-1", "name": "C2 Server", "description": "Command and control"}
        ]

        with patch.object(client, 'connect', return_value=mock_pycti):
            results = client.search_infrastructure("c2", limit=10)

            assert isinstance(results, list)

    def test_search_infrastructure_error(self, mock_config):
        """Test infrastructure search error handling."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.infrastructure.list.side_effect = Exception("API error")

        with patch.object(client, 'connect', return_value=mock_pycti):
            with pytest.raises(QueryError):
                client.search_infrastructure("test")

    def test_search_incidents(self, mock_config):
        """Test incident search method."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.incident.list.return_value = [
            {"id": "inc-1", "name": "Incident 1", "description": "Security incident"}
        ]

        with patch.object(client, 'connect', return_value=mock_pycti):
            results = client.search_incidents("breach", limit=10)

            assert isinstance(results, list)

    def test_search_courses_of_action(self, mock_config):
        """Test course of action search method."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.course_of_action.list.return_value = [
            {"id": "coa-1", "name": "Mitigation", "description": "Mitigation steps"}
        ]

        with patch.object(client, 'connect', return_value=mock_pycti):
            results = client.search_courses_of_action("mitigation", limit=10)

            assert isinstance(results, list)

    def test_search_groupings(self, mock_config):
        """Test grouping search method."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.grouping.list.return_value = [
            {"id": "grp-1", "name": "Analysis Group", "description": "Group of entities"}
        ]

        with patch.object(client, 'connect', return_value=mock_pycti):
            results = client.search_groupings("analysis", limit=10)

            assert isinstance(results, list)

    def test_search_notes(self, mock_config):
        """Test note search method."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.note.list.return_value = [
            {"id": "note-1", "attribute_abstract": "Note", "content": "Note content"}
        ]

        with patch.object(client, 'connect', return_value=mock_pycti):
            results = client.search_notes("analysis", limit=10)

            assert isinstance(results, list)

    def test_search_locations(self, mock_config):
        """Test location search method."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.location.list.return_value = [
            {"id": "loc-1", "name": "United States", "x_opencti_location_type": "Country"}
        ]

        with patch.object(client, 'connect', return_value=mock_pycti):
            results = client.search_locations("united states", limit=10)

            assert isinstance(results, list)


# =============================================================================
# Client Connection Tests
# =============================================================================

class TestClientConnection:
    """Tests for client connection edge cases."""

    @pytest.fixture
    def mock_config(self):
        return Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("test-token")
        )

    def test_connect_import_error(self, mock_config):
        """Test connection when pycti is not installed."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)
        client._client = None

        with patch.dict('sys.modules', {'pycti': None}):
            with patch('builtins.__import__', side_effect=ImportError("No module named pycti")):
                with pytest.raises(ConnectionError) as exc_info:
                    client.connect()

                assert "pycti not installed" in str(exc_info.value)

    def test_connect_generic_error(self, mock_config):
        """Test connection with generic error."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)
        client._client = None

        with patch('pycti.OpenCTIApiClient', side_effect=RuntimeError("Connection refused")):
            with pytest.raises(ConnectionError) as exc_info:
                client.connect()

            assert "Connection failed" in str(exc_info.value)

    def test_reconnect(self, mock_config):
        """Test reconnect method."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        with patch('pycti.OpenCTIApiClient', return_value=mock_pycti):
            # First connection
            client.connect()
            assert client._client is not None

            # Reconnect should clear and reconnect
            new_client = client.reconnect()
            assert new_client is not None


# =============================================================================
# Client Retry Logic Tests
# =============================================================================

class TestClientRetryLogic:
    """Tests for client retry logic with transient failures."""

    @pytest.fixture
    def mock_config(self):
        return Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("test-token"),
            max_retries=2
        )

    def test_retry_on_transient_error(self, mock_config):
        """Test retry on transient connection error."""
        from opencti_mcp.client import OpenCTIClient
        import requests

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        call_count = [0]

        def failing_then_success(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] < 2:
                raise requests.exceptions.ConnectionError("Transient failure")
            return [{"id": "test"}]

        mock_pycti.indicator.list = failing_then_success

        with patch.object(client, 'connect', return_value=mock_pycti):
            with patch('time.sleep'):  # Skip actual sleep
                results = client.search_indicators("test")

                assert call_count[0] == 2  # First failed, second succeeded

    def test_max_retries_exhausted(self, mock_config):
        """Test max retries exhausted."""
        from opencti_mcp.client import OpenCTIClient
        import requests

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.indicator.list.side_effect = requests.exceptions.ConnectionError("Persistent failure")

        with patch.object(client, 'connect', return_value=mock_pycti):
            with patch('time.sleep'):  # Skip actual sleep
                with pytest.raises(Exception):  # Should eventually raise
                    client.search_indicators("test")


# =============================================================================
# Adaptive Metrics Tests
# =============================================================================

class TestAdaptiveMetricsGaps:
    """Tests for uncovered adaptive metrics code."""

    def test_get_status_with_no_latency_data(self):
        """Test status with no latency data collected."""
        from opencti_mcp.adaptive import AdaptiveMetrics

        metrics = AdaptiveMetrics()
        status = metrics.get_status()

        assert 'sample_count' in status
        assert status['sample_count'] == 0

    def test_adaptive_config_with_poor_success_rate(self):
        """Test adaptive config recommendations with poor success rate."""
        from opencti_mcp.adaptive import AdaptiveMetrics

        metrics = AdaptiveMetrics()

        # Record many failures
        for _ in range(20):
            metrics.record_request(0.1, success=False, error_type="timeout")

        config = metrics.get_adaptive_config()

        # Should recommend more conservative settings
        assert config.recommended_max_retries >= 1

    def test_reset_metrics(self):
        """Test resetting all metrics."""
        from opencti_mcp.adaptive import AdaptiveMetrics

        metrics = AdaptiveMetrics()

        # Record some data
        metrics.record_request(0.5, success=True)
        metrics.record_request(0.3, success=True)

        # Reset
        metrics.reset()

        status = metrics.get_status()
        assert status['sample_count'] == 0


# =============================================================================
# Client Write Operations Tests
# =============================================================================

class TestClientWriteOperations:
    """Tests for client write operations (client methods still exist, server no longer exposes them)."""

    @pytest.fixture
    def mock_config(self):
        return Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("test-token"),
        )

    def test_create_indicator(self, mock_config):
        """Test create indicator method."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.indicator.create.return_value = {
            "id": "indicator--123",
            "name": "Test Indicator",
            "pattern": "[ipv4-addr:value = '1.2.3.4']"
        }

        with patch.object(client, 'connect', return_value=mock_pycti):
            result = client.create_indicator(
                name="Test Indicator",
                pattern="[ipv4-addr:value = '1.2.3.4']",
                pattern_type="stix"
            )

            assert result is not None
            mock_pycti.indicator.create.assert_called_once()

    def test_create_note(self, mock_config):
        """Test create note method."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.note.create.return_value = {
            "id": "note--123",
            "content": "Analysis note",
            "created": "2024-01-01T00:00:00Z"
        }

        with patch.object(client, 'connect', return_value=mock_pycti):
            result = client.create_note(
                content="Analysis note",
                entity_ids=["indicator--abc"]
            )

            assert result is not None
            assert result.get("success") is True

    def test_create_sighting(self, mock_config):
        """Test create sighting method."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        mock_pycti = Mock()
        mock_pycti.stix_sighting_relationship.create.return_value = {
            "id": "sighting--123",
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2024-01-01T00:00:00Z"
        }

        with patch.object(client, 'connect', return_value=mock_pycti):
            result = client.create_sighting(
                indicator_id="indicator--abc",
                sighted_by_id="identity--xyz",
                count=1
            )

            assert result is not None
            assert result.get("success") is True


# =============================================================================
# Client Formatting Tests
# =============================================================================

class TestClientFormatting:
    """Tests for client formatting methods."""

    @pytest.fixture
    def mock_config(self):
        return Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("test-token")
        )

    def test_format_campaigns(self, mock_config):
        """Test campaign formatting."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        campaigns = [
            {
                "id": "camp-1",
                "name": "Operation Test",
                "description": "Test campaign description",
                "first_seen": "2024-01-01T00:00:00Z",
                "last_seen": "2024-06-01T00:00:00Z",
                "confidence": 85,
                "objectLabel": [{"value": "apt"}]
            }
        ]

        formatted = client._format_campaigns(campaigns)

        assert len(formatted) == 1
        assert formatted[0]["name"] == "Operation Test"

    def test_format_tools(self, mock_config):
        """Test tool formatting."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        tools = [
            {
                "id": "tool-1",
                "name": "Mimikatz",
                "description": "Credential dumping tool"
            }
        ]

        formatted = client._format_tools(tools)

        assert len(formatted) == 1
        assert formatted[0]["name"] == "Mimikatz"

    def test_format_infrastructure(self, mock_config):
        """Test infrastructure formatting."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        infrastructure = [
            {
                "id": "infra-1",
                "name": "C2 Server",
                "description": "Command and control server",
                "infrastructure_types": ["command-and-control"]
            }
        ]

        formatted = client._format_infrastructure(infrastructure)

        assert len(formatted) == 1
        assert formatted[0]["name"] == "C2 Server"

    def test_format_incidents(self, mock_config):
        """Test incident formatting."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        incidents = [
            {
                "id": "inc-1",
                "name": "Security Breach",
                "description": "Data breach incident",
                "incident_type": "data-breach"
            }
        ]

        formatted = client._format_incidents(incidents)

        assert len(formatted) == 1
        assert formatted[0]["name"] == "Security Breach"

    def test_format_courses_of_action(self, mock_config):
        """Test course of action formatting."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        coas = [
            {
                "id": "coa-1",
                "name": "Patch System",
                "description": "Apply security patches"
            }
        ]

        formatted = client._format_courses_of_action(coas)

        assert len(formatted) == 1
        assert formatted[0]["name"] == "Patch System"

    def test_format_locations(self, mock_config):
        """Test location formatting."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        locations = [
            {
                "id": "loc-1",
                "name": "United States",
                "x_opencti_location_type": "Country",
                "latitude": 38.8951,
                "longitude": -77.0364
            }
        ]

        formatted = client._format_locations(locations)

        assert len(formatted) == 1
        assert formatted[0]["name"] == "United States"

    def test_format_groupings(self, mock_config):
        """Test grouping formatting."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        groupings = [
            {
                "id": "grp-1",
                "name": "APT Analysis",
                "description": "Analysis grouping",
                "context": "suspicious-activity"
            }
        ]

        formatted = client._format_groupings(groupings)

        assert len(formatted) == 1
        assert formatted[0]["name"] == "APT Analysis"

    def test_format_notes(self, mock_config):
        """Test note formatting."""
        from opencti_mcp.client import OpenCTIClient

        client = OpenCTIClient(mock_config)

        notes = [
            {
                "id": "note-1",
                "attribute_abstract": "Analysis Summary",
                "content": "Detailed analysis content",
                "note_types": ["analysis"]
            }
        ]

        formatted = client._format_notes(notes)

        assert len(formatted) == 1
        assert "analysis" in formatted[0].get("note_types", []) or formatted[0].get("abstract") == "Analysis Summary"


# =============================================================================
# Graceful Degradation Tests
# =============================================================================

class TestGracefulDegradationGaps:
    """Additional tests for graceful degradation."""

    @pytest.fixture
    def mock_config(self):
        return Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("test-token")
        )

    def test_fallback_returns_cached_when_degradation_enabled(self, mock_config):
        """Test fallback returns cached data when degradation is enabled."""
        from opencti_mcp.client import OpenCTIClient
        from opencti_mcp.cache import TTLCache

        with patch('opencti_mcp.client.get_feature_flags') as mock_flags:
            mock_flags.return_value = FeatureFlags(
                response_caching=True,
                graceful_degradation=True
            )
            client = OpenCTIClient(mock_config)

            # Prime the cache
            cache = TTLCache(ttl_seconds=60, name="test")
            cache.set("test_key", ["cached_result"])

            # Test fallback
            found, value, degraded = client._get_fallback(cache, "test_key")

            assert found is True
            assert value == ["cached_result"]
            assert degraded is True

    def test_fallback_returns_nothing_when_degradation_disabled(self, mock_config):
        """Test fallback returns nothing when degradation is disabled."""
        from opencti_mcp.client import OpenCTIClient
        from opencti_mcp.cache import TTLCache

        with patch('opencti_mcp.client.get_feature_flags') as mock_flags:
            mock_flags.return_value = FeatureFlags(
                response_caching=True,
                graceful_degradation=False
            )
            client = OpenCTIClient(mock_config)

            # Prime the cache
            cache = TTLCache(ttl_seconds=60, name="test")
            cache.set("test_key", ["cached_result"])

            # Test fallback - should not return cached data
            found, value, degraded = client._get_fallback(cache, "test_key")

            assert found is False


# =============================================================================
# Server Tool Dispatch Tests
# =============================================================================

class TestServerToolDispatchGaps:
    """Tests for server tool dispatch — admin and individual search tools removed."""

    @pytest.fixture
    def mock_config(self):
        return Config(
            opencti_url="http://localhost:8080",
            opencti_token=SecretStr("test-token"),
        )

    @pytest.mark.asyncio
    async def test_admin_tools_removed(self, mock_config):
        """Admin tools are no longer dispatched."""
        from opencti_mcp.server import OpenCTIMCPServer
        from opencti_mcp.errors import ValidationError

        server = OpenCTIMCPServer(mock_config)

        for tool in ["force_reconnect", "get_cache_stats", "list_connectors", "get_network_status"]:
            with pytest.raises(ValidationError, match="Unknown tool"):
                await server._dispatch_tool(tool, {})

    @pytest.mark.asyncio
    async def test_dispatch_search_entity_campaign(self, mock_config):
        """search_entity with type=campaign dispatches correctly."""
        from opencti_mcp.server import OpenCTIMCPServer

        server = OpenCTIMCPServer(mock_config)

        with patch.object(server.client, 'search_campaigns') as mock_search:
            mock_search.return_value = [{"id": "camp-1", "name": "Test Campaign"}]

            result = await server._dispatch_tool("search_entity", {
                "type": "campaign", "query": "test"
            })

            mock_search.assert_called_once()
            assert "results" in result

    @pytest.mark.asyncio
    async def test_dispatch_search_entity_tool(self, mock_config):
        """search_entity with type=tool dispatches correctly."""
        from opencti_mcp.server import OpenCTIMCPServer

        server = OpenCTIMCPServer(mock_config)

        with patch.object(server.client, 'search_tools') as mock_search:
            mock_search.return_value = [{"id": "tool-1", "name": "Mimikatz"}]

            result = await server._dispatch_tool("search_entity", {
                "type": "tool", "query": "mimikatz"
            })

            mock_search.assert_called_once()
            assert "results" in result

    @pytest.mark.asyncio
    async def test_dispatch_search_entity_infrastructure(self, mock_config):
        """search_entity with type=infrastructure dispatches correctly."""
        from opencti_mcp.server import OpenCTIMCPServer

        server = OpenCTIMCPServer(mock_config)

        with patch.object(server.client, 'search_infrastructure') as mock_search:
            mock_search.return_value = [{"id": "infra-1", "name": "C2 Server"}]

            result = await server._dispatch_tool("search_entity", {
                "type": "infrastructure", "query": "c2"
            })

            mock_search.assert_called_once()
            assert "results" in result
