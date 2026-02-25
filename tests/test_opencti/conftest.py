"""Pytest fixtures for OpenCTI MCP tests."""

from __future__ import annotations

from unittest.mock import MagicMock, Mock

import pytest
from opencti_mcp.adaptive import reset_global_metrics
from opencti_mcp.client import OpenCTIClient
from opencti_mcp.config import Config, SecretStr
from opencti_mcp.server import OpenCTIMCPServer


@pytest.fixture(autouse=True)
def reset_adaptive_metrics():
    """Reset global adaptive metrics before each test for isolation."""
    reset_global_metrics()
    yield
    reset_global_metrics()


@pytest.fixture
def mock_config() -> Config:
    """Create a test configuration."""
    return Config(
        opencti_url="http://localhost:8080",
        opencti_token=SecretStr("test-token-12345"),
        timeout_seconds=30,
        max_results=100,
    )


@pytest.fixture
def mock_pycti_client() -> Mock:
    """Create a mock pycti OpenCTIApiClient."""
    client = MagicMock()

    # Mock indicator methods
    client.indicator.list.return_value = [
        {
            "id": "indicator-1",
            "name": "Test IOC",
            "pattern": "[ipv4-addr:value = '192.168.1.1']",
            "pattern_type": "stix",
            "confidence": 85,
            "created": "2025-01-15T10:00:00Z",
            "objectLabel": [{"value": "malicious"}],
        }
    ]

    # Mock threat actor methods
    client.intrusion_set.list.return_value = [
        {
            "name": "APT29",
            "aliases": ["Cozy Bear", "The Dukes"],
            "description": "Russian threat actor",
            "sophistication": "expert",
            "resource_level": "government",
            "primary_motivation": "espionage",
        }
    ]
    client.threat_actor_group.list.return_value = []

    # Mock malware methods
    client.malware.list.return_value = [
        {
            "name": "Cobalt Strike",
            "aliases": ["BEACON"],
            "description": "Commercial adversary simulation tool",
            "malware_types": ["backdoor"],
            "is_family": True,
        }
    ]

    # Mock attack pattern methods
    client.attack_pattern.list.return_value = [
        {
            "name": "OS Credential Dumping",
            "x_mitre_id": "T1003",
            "description": "Credential access technique",
            "killChainPhases": [{"phase_name": "credential-access"}],
            "x_mitre_platforms": ["Windows"],
        }
    ]

    # Mock vulnerability methods
    client.vulnerability.list.return_value = [
        {
            "name": "CVE-2024-3400",
            "description": "Critical vulnerability",
            "x_opencti_cvss_base_score": 10.0,
            "x_opencti_cvss_base_severity": "CRITICAL",
        }
    ]

    # Mock report methods
    client.report.list.return_value = [
        {
            "name": "APT29 Campaign Report",
            "description": "Analysis of recent activity",
            "published": "2025-01-10",
            "report_types": ["threat-report"],
            "confidence": 90,
        }
    ]

    # Mock relationship methods
    client.stix_core_relationship.list.return_value = [
        {
            "relationship_type": "indicates",
            "to": {"entity_type": "Malware", "name": "SUNBURST"},
        }
    ]

    # Mock observable methods
    client.stix_cyber_observable.list.return_value = []

    return client


@pytest.fixture
def mock_opencti_client(mock_config: Config, mock_pycti_client: Mock) -> OpenCTIClient:
    """Create an OpenCTI client with mocked pycti."""
    client = OpenCTIClient(mock_config)
    client._client = mock_pycti_client
    return client


@pytest.fixture
def mock_server(
    mock_config: Config, mock_opencti_client: OpenCTIClient
) -> OpenCTIMCPServer:
    """Create an MCP server with mocked client."""
    server = OpenCTIMCPServer(mock_config)
    server.client = mock_opencti_client
    return server


# =============================================================================
# Test Data
# =============================================================================

VALID_IPV4 = [
    "192.168.1.1",
    "10.0.0.1",
    "8.8.8.8",
    "255.255.255.255",
    "0.0.0.0",
]

INVALID_IPV4 = [
    "256.1.1.1",
    "1.2.3",
    "1.2.3.4.5",
    "not.an.ip",
    "192.168.1",
    "01.02.03.04",  # Leading zeros
]

VALID_MD5 = [
    "d41d8cd98f00b204e9800998ecf8427e",
    "a" * 32,
    "0" * 32,
    "f" * 32,
]

VALID_SHA1 = [
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "a" * 40,
]

VALID_SHA256 = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "a" * 64,
]

INVALID_HASHES = [
    "xyz123",
    "tooshort",
    "g" * 64,  # Invalid hex
    "a" * 31,  # Wrong length
    "a" * 33,  # Wrong length
]

VALID_DOMAINS = [
    "example.com",
    "sub.example.com",
    "deep.sub.example.com",
    "test-site.org",
    "my-test.co.uk",
]

INVALID_DOMAINS = [
    ".example.com",
    "example.",
    "example..com",
    "-example.com",
    "example-.com",
    "a",  # No TLD
]

VALID_CVES = [
    "CVE-2024-3400",
    "cve-2021-44228",
    "CVE-2020-0001",
]

VALID_MITRE_IDS = [
    "T1003",
    "T1003.001",
    "t1059",
    "T1059.003",
]
