"""MCP Server for OpenCTI threat intelligence.

This module implements the Model Context Protocol server that exposes
OpenCTI queries as MCP tools for Claude Code and other clients.

Security:
- All inputs validated before processing
- Errors sanitized before returning to clients
- Rate limiting prevents abuse
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from mcp.server import Server
from mcp.types import Tool, TextContent

from .audit import AuditWriter, resolve_examiner
from .config import Config
from .client import OpenCTIClient
from .tool_metadata import TOOL_METADATA, DEFAULT_METADATA
from .errors import (
    OpenCTIMCPError,
    ConfigurationError,
    ValidationError,
    RateLimitError,
)
from .validation import (
    validate_length,
    validate_limit,
    validate_offset,
    validate_days,
    validate_ioc,
    validate_uuid,
    validate_uuid_list,
    validate_labels,
    validate_relationship_types,
    validate_stix_pattern,
    validate_observable_types,
    validate_note_types,
    validate_date_filter,
    validate_pattern_type,
    sanitize_for_log,
    MAX_QUERY_LENGTH,
    MAX_IOC_LENGTH,
    MAX_OFFSET,
)


logger = logging.getLogger(__name__)


class OpenCTIMCPServer:
    """MCP server for OpenCTI threat intelligence.

    Args:
        config: Server configuration. Set config.read_only=True for query-only mode,
                or config.read_only=False to enable write operations.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.client = OpenCTIClient(config)
        self.server = Server("opencti-mcp")
        self._audit = AuditWriter("opencti-mcp")
        self._register_tools()

        if config.read_only:
            logger.info("Server started in READ-ONLY mode (write tools disabled)")
        else:
            logger.info("Server started with WRITE operations ENABLED")

    def _register_tools(self) -> None:
        """Register MCP tools."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            # Build tool list - write tools added conditionally based on read_only mode
            tools = [
                Tool(
                    name="search_threat_intel",
                    description="Search OpenCTI for threat intelligence across all entity types (indicators, threat actors, malware, techniques, CVEs, reports).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search term (IOC, threat actor name, malware, CVE, etc.)",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results per entity type (default: 5, max: 20)",
                                "default": 5,
                                "minimum": 1,
                                "maximum": 20
                            },
                            "offset": {
                                "type": "integer",
                                "description": "Skip first N results (for pagination, max: 500)",
                                "default": 0,
                                "minimum": 0,
                                "maximum": 500
                            },
                            "labels": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter by labels (e.g., ['tlp:amber', 'malicious'])"
                            },
                            "confidence_min": {
                                "type": "integer",
                                "description": "Minimum confidence threshold (0-100)",
                                "minimum": 0,
                                "maximum": 100
                            },
                            "created_after": {
                                "type": "string",
                                "description": "Filter by created date >= (ISO format: 2024-01-01)"
                            },
                            "created_before": {
                                "type": "string",
                                "description": "Filter by created date <= (ISO format: 2024-12-31)"
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="lookup_ioc",
                    description="Get full context for a specific IOC (IP, hash, domain, URL) including related threat actors, malware, and MITRE techniques.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "ioc": {
                                "type": "string",
                                "description": "IOC value (IP address, file hash, domain, or URL)",
                                "maxLength": MAX_IOC_LENGTH
                            }
                        },
                        "required": ["ioc"]
                    }
                ),
                Tool(
                    name="search_threat_actor",
                    description="Search for threat actors and APT groups by name or alias.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Threat actor name or alias (e.g., 'APT29', 'Lazarus')",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            },
                            "offset": {
                                "type": "integer",
                                "description": "Skip first N results (for pagination)",
                                "default": 0,
                                "minimum": 0,
                                "maximum": 500
                            },
                            "labels": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter by labels"
                            },
                            "confidence_min": {
                                "type": "integer",
                                "description": "Minimum confidence (0-100)",
                                "minimum": 0,
                                "maximum": 100
                            },
                            "created_after": {
                                "type": "string",
                                "description": "Filter by created date >= (ISO format)"
                            },
                            "created_before": {
                                "type": "string",
                                "description": "Filter by created date <= (ISO format)"
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="search_malware",
                    description="Search for malware families by name or alias.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Malware name or alias (e.g., 'Cobalt Strike', 'Emotet')",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            },
                            "offset": {
                                "type": "integer",
                                "description": "Skip first N results (for pagination)",
                                "default": 0,
                                "minimum": 0,
                                "maximum": 500
                            },
                            "labels": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter by labels"
                            },
                            "confidence_min": {
                                "type": "integer",
                                "description": "Minimum confidence (0-100)",
                                "minimum": 0,
                                "maximum": 100
                            },
                            "created_after": {
                                "type": "string",
                                "description": "Filter by created date >= (ISO format)"
                            },
                            "created_before": {
                                "type": "string",
                                "description": "Filter by created date <= (ISO format)"
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="search_attack_pattern",
                    description="Search for MITRE ATT&CK techniques by ID or name.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "MITRE technique ID (e.g., 'T1003') or name (e.g., 'credential dumping')",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            },
                            "offset": {
                                "type": "integer",
                                "description": "Skip first N results (for pagination)",
                                "default": 0,
                                "minimum": 0,
                                "maximum": 500
                            },
                            "labels": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter by labels"
                            },
                            "created_after": {
                                "type": "string",
                                "description": "Filter by created date >= (ISO format)"
                            },
                            "created_before": {
                                "type": "string",
                                "description": "Filter by created date <= (ISO format)"
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="search_vulnerability",
                    description="Search for vulnerabilities (CVEs) by ID or keyword.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "CVE ID (e.g., 'CVE-2024-3400') or keyword",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            },
                            "offset": {
                                "type": "integer",
                                "description": "Skip first N results (for pagination)",
                                "default": 0,
                                "minimum": 0,
                                "maximum": 500
                            },
                            "labels": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter by labels"
                            },
                            "created_after": {
                                "type": "string",
                                "description": "Filter by created date >= (ISO format)"
                            },
                            "created_before": {
                                "type": "string",
                                "description": "Filter by created date <= (ISO format)"
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="get_recent_indicators",
                    description="Get recently added indicators (IOCs) from the last N days.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "days": {
                                "type": "integer",
                                "description": "Number of days to look back (default: 7, max: 90)",
                                "default": 7,
                                "minimum": 1,
                                "maximum": 90
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 20, max: 100)",
                                "default": 20,
                                "maximum": 100
                            }
                        }
                    }
                ),
                Tool(
                    name="search_reports",
                    description="Search for threat intelligence reports.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search term (campaign name, threat actor, etc.)",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="get_health",
                    description="Check OpenCTI server health and connectivity.",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="list_connectors",
                    description="List available enrichment connectors (VirusTotal, Shodan, etc.).",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="get_network_status",
                    description="Get network health metrics and adaptive configuration recommendations. Shows latency statistics (P50/P95/P99), success rates, circuit breaker state, and recommended timeout/retry settings based on observed network conditions.",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="force_reconnect",
                    description="Force reconnection to OpenCTI server. Clears health cache, resets circuit breaker, and attempts fresh connection. Use after configuration changes or to recover from persistent errors.",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="get_cache_stats",
                    description="Get cache statistics including hit rates, sizes, and evictions. Useful for debugging and performance tuning.",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                # === New Entity Search Tools ===
                Tool(
                    name="search_campaign",
                    description="Search for threat campaigns by name or keyword.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Campaign name or keyword",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="search_tool",
                    description="Search for tools (legitimate software used maliciously, e.g., PsExec, Mimikatz as a tool).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Tool name or keyword",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            },
                            "offset": {
                                "type": "integer",
                                "description": "Skip first N results (for pagination)",
                                "default": 0,
                                "minimum": 0,
                                "maximum": 500
                            },
                            "labels": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter by labels"
                            },
                            "created_after": {
                                "type": "string",
                                "description": "Filter by created date >= (ISO format)"
                            },
                            "created_before": {
                                "type": "string",
                                "description": "Filter by created date <= (ISO format)"
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="search_infrastructure",
                    description="Search for infrastructure (C2 servers, hosting, botnets, etc.).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Infrastructure name or keyword",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            },
                            "offset": {
                                "type": "integer",
                                "description": "Skip first N results (for pagination)",
                                "default": 0,
                                "minimum": 0,
                                "maximum": 500
                            },
                            "labels": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter by labels"
                            },
                            "created_after": {
                                "type": "string",
                                "description": "Filter by created date >= (ISO format)"
                            },
                            "created_before": {
                                "type": "string",
                                "description": "Filter by created date <= (ISO format)"
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="search_incident",
                    description="Search for security incidents.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Incident name or keyword",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="search_observable",
                    description="Search for observables (raw technical artifacts: IPs, domains, hashes, emails, etc.).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Observable value or keyword",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "observable_types": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter by types (e.g., ['IPv4-Addr', 'Domain-Name', 'StixFile'])"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="search_sighting",
                    description="Search for sightings (detection events where indicators were observed).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search keyword",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="search_organization",
                    description="Search for organizations (companies, government bodies, etc.).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Organization name or keyword",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="search_sector",
                    description="Search for sectors/industries (e.g., 'Energy', 'Healthcare', 'Finance').",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Sector name or keyword",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="search_location",
                    description="Search for locations (countries, regions, cities).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Location name",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="search_course_of_action",
                    description="Search for courses of action (mitigations for attack techniques).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Mitigation name or MITRE ID",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="search_grouping",
                    description="Search for groupings (analysis containers that group related entities).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Grouping name or keyword",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="search_note",
                    description="Search for analyst notes.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Note content or keyword",
                                "maxLength": MAX_QUERY_LENGTH
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="lookup_hash",
                    description="Look up a file hash (MD5, SHA1, SHA256) in OpenCTI.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "hash": {
                                "type": "string",
                                "description": "File hash (MD5, SHA1, or SHA256)",
                                "maxLength": 128
                            }
                        },
                        "required": ["hash"]
                    }
                ),
                # === Entity and Relationship Tools ===
                Tool(
                    name="get_entity",
                    description="Get full details of any entity by its OpenCTI ID.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "entity_id": {
                                "type": "string",
                                "description": "OpenCTI entity ID (UUID format)"
                            }
                        },
                        "required": ["entity_id"]
                    }
                ),
                Tool(
                    name="get_relationships",
                    description="Get relationships for an entity (who uses what, what indicates what, etc.).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "entity_id": {
                                "type": "string",
                                "description": "Entity ID to get relationships for"
                            },
                            "direction": {
                                "type": "string",
                                "enum": ["from", "to", "both"],
                                "description": "Relationship direction: 'from' (outgoing), 'to' (incoming), 'both' (default)",
                                "default": "both"
                            },
                            "relationship_types": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter by relationship types (e.g., ['indicates', 'uses', 'targets'])"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 50, max: 50)",
                                "default": 50,
                                "maximum": 50
                            }
                        },
                        "required": ["entity_id"]
                    }
                ),
            ]

            # === Write Operations (only if not in read_only mode) ===
            if not self.config.read_only:
                tools.extend([
                    Tool(
                        name="create_indicator",
                        description="Create a new indicator (IOC) in OpenCTI. Rate limited to prevent abuse.",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "name": {
                                    "type": "string",
                                    "description": "Indicator name",
                                    "maxLength": 256
                                },
                                "pattern": {
                                    "type": "string",
                                    "description": "STIX pattern (e.g., \"[ipv4-addr:value = '192.168.1.1']\")",
                                    "maxLength": 2048
                                },
                                "pattern_type": {
                                    "type": "string",
                                    "description": "Pattern type (default: 'stix')",
                                    "default": "stix"
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Description of the indicator",
                                    "maxLength": 5000
                                },
                                "confidence": {
                                    "type": "integer",
                                    "description": "Confidence level 0-100 (default: 50)",
                                    "default": 50,
                                    "minimum": 0,
                                    "maximum": 100
                                },
                                "labels": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Labels to apply (e.g., ['malicious', 'apt'])"
                                }
                            },
                            "required": ["name", "pattern"]
                        }
                    ),
                    Tool(
                        name="create_note",
                        description="Create an analyst note attached to one or more entities.",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "content": {
                                    "type": "string",
                                    "description": "Note content (analyst observations)",
                                    "maxLength": 10000
                                },
                                "entity_ids": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Entity IDs to attach note to (max 20)"
                                },
                                "note_types": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Note types (e.g., ['analysis', 'assessment'])"
                                },
                                "confidence": {
                                    "type": "integer",
                                    "description": "Confidence level 0-100 (default: 75)",
                                    "default": 75,
                                    "minimum": 0,
                                    "maximum": 100
                                },
                                "likelihood": {
                                    "type": "integer",
                                    "description": "Likelihood of assessment (1-100, optional)",
                                    "minimum": 1,
                                    "maximum": 100
                                }
                            },
                            "required": ["content", "entity_ids"]
                        }
                    ),
                    Tool(
                        name="create_sighting",
                        description="Create a sighting (detection event where an indicator was observed).",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "indicator_id": {
                                    "type": "string",
                                    "description": "ID of the indicator that was sighted"
                                },
                                "sighted_by_id": {
                                    "type": "string",
                                    "description": "ID of the identity/organization that observed it"
                                },
                                "first_seen": {
                                    "type": "string",
                                    "description": "First observation timestamp (ISO format)"
                                },
                                "last_seen": {
                                    "type": "string",
                                    "description": "Last observation timestamp (ISO format)"
                                },
                                "count": {
                                    "type": "integer",
                                    "description": "Number of times sighted (default: 1)",
                                    "default": 1,
                                    "minimum": 1
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Sighting description",
                                    "maxLength": 5000
                                },
                                "confidence": {
                                    "type": "integer",
                                    "description": "Confidence level 0-100 (default: 75)",
                                    "default": 75,
                                    "minimum": 0,
                                    "maximum": 100
                                }
                            },
                            "required": ["indicator_id", "sighted_by_id"]
                        }
                    ),
                    Tool(
                        name="trigger_enrichment",
                        description="Trigger enrichment for an entity via a specific connector (e.g., VirusTotal, Shodan).",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "entity_id": {
                                    "type": "string",
                                    "description": "Entity ID to enrich"
                                },
                                "connector_id": {
                                    "type": "string",
                                    "description": "Enrichment connector ID (get from list_connectors)"
                                }
                            },
                            "required": ["entity_id", "connector_id"]
                        }
                    ),
                ])

            return tools

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict) -> list[TextContent]:
            evidence_id = self._audit._next_evidence_id()
            start = time.monotonic()
            try:
                result = await self._dispatch_tool(name, arguments)
                elapsed_ms = (time.monotonic() - start) * 1000
                result = self._wrap_response(
                    name, arguments, result,
                    evidence_id=evidence_id, elapsed_ms=elapsed_ms,
                )
                return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]

            except ValidationError as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.warning("Validation failed", extra={
                    "tool": name,
                    "error": str(e),
                    "arguments": sanitize_for_log(arguments)
                })
                error_result = {"error": "validation_error", "message": str(e)}
                error_result = self._wrap_response(
                    name, arguments, error_result,
                    evidence_id=evidence_id, elapsed_ms=elapsed_ms,
                )
                return [TextContent(type="text", text=json.dumps(error_result))]

            except RateLimitError as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.warning("Rate limit exceeded", extra={
                    "tool": name,
                    "wait_seconds": e.wait_seconds,
                    "limit_type": e.limit_type
                })
                error_result = {"error": "rate_limit_exceeded", "message": e.safe_message, "wait_seconds": e.wait_seconds}
                error_result = self._wrap_response(
                    name, arguments, error_result,
                    evidence_id=evidence_id, elapsed_ms=elapsed_ms,
                )
                return [TextContent(type="text", text=json.dumps(error_result))]

            except ConfigurationError as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.error("Configuration error", extra={"error": str(e)})
                error_result = {"error": "configuration_error", "message": "OpenCTI is not properly configured. Check server settings."}
                error_result = self._wrap_response(
                    name, arguments, error_result,
                    evidence_id=evidence_id, elapsed_ms=elapsed_ms,
                )
                return [TextContent(type="text", text=json.dumps(error_result))]

            except OpenCTIMCPError as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.error("MCP error", extra={
                    "tool": name,
                    "error_type": type(e).__name__,
                    "error": str(e)
                })
                error_result = {"error": type(e).__name__.lower(), "message": e.safe_message}
                error_result = self._wrap_response(
                    name, arguments, error_result,
                    evidence_id=evidence_id, elapsed_ms=elapsed_ms,
                )
                return [TextContent(type="text", text=json.dumps(error_result))]

            except Exception as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.exception("Internal error", extra={
                    "tool": name,
                    "error_type": type(e).__name__
                })
                error_result = {"error": "internal_error", "message": "An unexpected error occurred. Check server logs."}
                error_result = self._wrap_response(
                    name, arguments, error_result,
                    evidence_id=evidence_id, elapsed_ms=elapsed_ms,
                )
                return [TextContent(type="text", text=json.dumps(error_result))]

    # Write operation tool names (for read_only mode enforcement)
    WRITE_TOOLS = frozenset({"create_indicator", "create_note", "create_sighting", "trigger_enrichment"})

    @staticmethod
    def _safe_results(results: list | None) -> list:
        """Safely handle None results from client methods.

        Client methods may return None on error. This ensures we always
        return a list for consistent response structure.
        """
        return results if results is not None else []

    @staticmethod
    def _validate_search_filters(
        offset: int | None,
        labels: list[str] | None,
        created_after: str | None,
        created_before: str | None
    ) -> tuple[int, list[str] | None, str | None, str | None]:
        """Validate common search filter parameters.

        Consolidates repeated validation logic across search handlers.

        Args:
            offset: Pagination offset (clamped to 0-MAX_OFFSET)
            labels: Label filters (validated for safe characters)
            created_after: ISO8601 date filter (validated)
            created_before: ISO8601 date filter (validated)

        Returns:
            Tuple of (validated_offset, validated_labels, validated_after, validated_before)
        """
        validated_offset = validate_offset(offset)
        validated_labels = validate_labels(labels) if labels else None
        validated_after = validate_date_filter(created_after, "created_after")
        validated_before = validate_date_filter(created_before, "created_before")
        return validated_offset, validated_labels, validated_after, validated_before

    @staticmethod
    def _error_response(error_code: str, message: str, **extra_fields: Any) -> list[TextContent]:
        """Format error response consistently.

        Args:
            error_code: Error type identifier (e.g., "validation_error")
            message: Human-readable error message
            **extra_fields: Additional fields to include (e.g., wait_seconds)

        Returns:
            List containing single TextContent with JSON error response
        """
        response: dict[str, Any] = {"error": error_code, "message": message}
        response.update(extra_fields)
        return [TextContent(type="text", text=json.dumps(response))]

    def _wrap_response(
        self, tool_name: str, arguments: dict[str, Any], result: dict[str, Any],
        evidence_id: str | None = None, elapsed_ms: float | None = None,
    ) -> dict[str, Any]:
        """Wrap tool result with evidence ID, caveats, and audit trail.

        Always generates evidence_id and writes audit — including for errors.
        """
        summary = result if "error" not in result else {"error": result["error"]}
        evidence_id = self._audit.log(
            tool=tool_name, params=arguments, result_summary=summary,
            evidence_id=evidence_id, elapsed_ms=elapsed_ms,
        )
        meta = TOOL_METADATA.get(tool_name, DEFAULT_METADATA)

        result["evidence_id"] = evidence_id
        result["examiner"] = resolve_examiner()
        if "error" not in result:
            result["caveats"] = meta["caveats"]
            result["interpretation_constraint"] = meta["interpretation_constraint"]
        return result

    async def _dispatch_tool(self, name: str, arguments: dict) -> dict[str, Any]:
        """Dispatch tool call to appropriate handler."""

        # Reject write operations in read_only mode
        if self.config.read_only and name in self.WRITE_TOOLS:
            raise ValidationError(
                f"Write operation '{name}' is not available in read-only mode. "
                f"Set OPENCTI_READ_ONLY=false to enable write operations."
            )

        if name == "search_threat_intel":
            query = arguments.get("query", "")
            confidence_min = arguments.get("confidence_min")
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(arguments.get("limit", 5), max_value=20)
            offset, labels, created_after, created_before = self._validate_search_filters(
                arguments.get("offset"), arguments.get("labels"),
                arguments.get("created_after"), arguments.get("created_before")
            )
            return await asyncio.to_thread(
                self.client.unified_search, query, limit, offset,
                labels, confidence_min, created_after, created_before
            )

        elif name == "lookup_ioc":
            ioc = arguments.get("ioc", "")
            validate_length(ioc, MAX_IOC_LENGTH, "ioc")
            is_valid, ioc_type = validate_ioc(ioc)
            result = await asyncio.to_thread(
                self.client.get_indicator_context, ioc
            )
            result["ioc_type"] = ioc_type
            return result

        elif name == "search_threat_actor":
            query = arguments.get("query", "")
            confidence_min = arguments.get("confidence_min")
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(arguments.get("limit", 10), max_value=50)
            offset, labels, created_after, created_before = self._validate_search_filters(
                arguments.get("offset"), arguments.get("labels"),
                arguments.get("created_after"), arguments.get("created_before")
            )
            results = await asyncio.to_thread(
                self.client.search_threat_actors, query, limit, offset,
                labels, confidence_min, created_after, created_before
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results), "offset": offset}

        elif name == "search_malware":
            query = arguments.get("query", "")
            confidence_min = arguments.get("confidence_min")
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(arguments.get("limit", 10), max_value=50)
            offset, labels, created_after, created_before = self._validate_search_filters(
                arguments.get("offset"), arguments.get("labels"),
                arguments.get("created_after"), arguments.get("created_before")
            )
            results = await asyncio.to_thread(
                self.client.search_malware, query, limit, offset,
                labels, confidence_min, created_after, created_before
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results), "offset": offset}

        elif name == "search_attack_pattern":
            query = arguments.get("query", "")
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(arguments.get("limit", 10), max_value=50)
            offset, labels, created_after, created_before = self._validate_search_filters(
                arguments.get("offset"), arguments.get("labels"),
                arguments.get("created_after"), arguments.get("created_before")
            )
            results = await asyncio.to_thread(
                self.client.search_attack_patterns, query, limit, offset,
                labels, created_after, created_before
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results), "offset": offset}

        elif name == "search_vulnerability":
            query = arguments.get("query", "")
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(arguments.get("limit", 10), max_value=50)
            offset, labels, created_after, created_before = self._validate_search_filters(
                arguments.get("offset"), arguments.get("labels"),
                arguments.get("created_after"), arguments.get("created_before")
            )
            results = await asyncio.to_thread(
                self.client.search_vulnerabilities, query, limit, offset,
                labels, created_after, created_before
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results), "offset": offset}

        elif name == "get_recent_indicators":
            days = arguments.get("days", 7)
            limit = arguments.get("limit", 20)
            days = validate_days(days, max_value=90)
            limit = validate_limit(limit)
            results = await asyncio.to_thread(
                self.client.get_recent_indicators, days, limit
            )
            results = self._safe_results(results)
            return {"days": days, "results": results, "total": len(results)}

        elif name == "search_reports":
            query = arguments.get("query", "")
            confidence_min = arguments.get("confidence_min")
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(arguments.get("limit", 10), max_value=50)
            offset, labels, created_after, created_before = self._validate_search_filters(
                arguments.get("offset"), arguments.get("labels"),
                arguments.get("created_after"), arguments.get("created_before")
            )
            results = await asyncio.to_thread(
                self.client.search_reports, query, limit, offset,
                labels, confidence_min, created_after, created_before
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results), "offset": offset}

        elif name == "get_health":
            available = await asyncio.to_thread(self.client.is_available)
            return {
                "status": "healthy" if available else "unavailable",
                "opencti_available": available,
            }

        elif name == "list_connectors":
            connectors = await asyncio.to_thread(
                self.client.list_enrichment_connectors
            )
            return {"connectors": connectors, "total": len(connectors)}

        elif name == "get_network_status":
            return await asyncio.to_thread(self.client.get_network_status)

        elif name == "force_reconnect":
            # Force reconnection - clear caches and reset circuit breaker
            await asyncio.to_thread(self.client.force_reconnect)
            # Check health after reconnection
            available = await asyncio.to_thread(self.client.is_available)
            return {
                "status": "reconnected" if available else "reconnection_attempted",
                "available": available,
                "message": "Connection refreshed" if available else "Reconnection attempted but service unavailable"
            }

        elif name == "get_cache_stats":
            return await asyncio.to_thread(self.client.get_cache_stats)

        # === New Entity Search Handlers ===
        elif name == "search_campaign":
            query = arguments.get("query", "")
            confidence_min = arguments.get("confidence_min")
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(arguments.get("limit", 10), max_value=50)
            offset, labels, created_after, created_before = self._validate_search_filters(
                arguments.get("offset"), arguments.get("labels"),
                arguments.get("created_after"), arguments.get("created_before")
            )
            results = await asyncio.to_thread(
                self.client.search_campaigns, query, limit, offset,
                labels, confidence_min, created_after, created_before
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results), "offset": offset}

        elif name == "search_tool":
            query = arguments.get("query", "")
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(arguments.get("limit", 10), max_value=50)
            offset, labels, created_after, created_before = self._validate_search_filters(
                arguments.get("offset"), arguments.get("labels"),
                arguments.get("created_after"), arguments.get("created_before")
            )
            results = await asyncio.to_thread(
                self.client.search_tools, query, limit, offset,
                labels, created_after, created_before
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results), "offset": offset}

        elif name == "search_infrastructure":
            query = arguments.get("query", "")
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(arguments.get("limit", 10), max_value=50)
            offset, labels, created_after, created_before = self._validate_search_filters(
                arguments.get("offset"), arguments.get("labels"),
                arguments.get("created_after"), arguments.get("created_before")
            )
            results = await asyncio.to_thread(
                self.client.search_infrastructure, query, limit, offset,
                labels, created_after, created_before
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results), "offset": offset}

        elif name == "search_incident":
            query = arguments.get("query", "")
            confidence_min = arguments.get("confidence_min")
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(arguments.get("limit", 10), max_value=50)
            offset, labels, created_after, created_before = self._validate_search_filters(
                arguments.get("offset"), arguments.get("labels"),
                arguments.get("created_after"), arguments.get("created_before")
            )
            results = await asyncio.to_thread(
                self.client.search_incidents, query, limit, offset,
                labels, confidence_min, created_after, created_before
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results), "offset": offset}

        elif name == "search_observable":
            query = arguments.get("query", "")
            observable_types = arguments.get("observable_types")
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(arguments.get("limit", 10), max_value=50)
            offset, labels, created_after, created_before = self._validate_search_filters(
                arguments.get("offset"), arguments.get("labels"),
                arguments.get("created_after"), arguments.get("created_before")
            )
            # Security: Validate observable types against allow-list
            observable_types = validate_observable_types(
                observable_types, extra_types=self.config.extra_observable_types
            )
            results = await asyncio.to_thread(
                self.client.search_observables, query, limit, offset,
                observable_types, labels, created_after, created_before
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results), "offset": offset}

        elif name == "search_sighting":
            query = arguments.get("query", "")
            limit = arguments.get("limit", 10)
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(limit, max_value=50)
            results = await asyncio.to_thread(
                self.client.search_sightings, query, limit
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results)}

        elif name == "search_organization":
            query = arguments.get("query", "")
            limit = arguments.get("limit", 10)
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(limit, max_value=50)
            results = await asyncio.to_thread(
                self.client.search_organizations, query, limit
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results)}

        elif name == "search_sector":
            query = arguments.get("query", "")
            limit = arguments.get("limit", 10)
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(limit, max_value=50)
            results = await asyncio.to_thread(
                self.client.search_sectors, query, limit
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results)}

        elif name == "search_location":
            query = arguments.get("query", "")
            limit = arguments.get("limit", 10)
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(limit, max_value=50)
            results = await asyncio.to_thread(
                self.client.search_locations, query, limit
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results)}

        elif name == "search_course_of_action":
            query = arguments.get("query", "")
            limit = arguments.get("limit", 10)
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(limit, max_value=50)
            results = await asyncio.to_thread(
                self.client.search_courses_of_action, query, limit
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results)}

        elif name == "search_grouping":
            query = arguments.get("query", "")
            limit = arguments.get("limit", 10)
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(limit, max_value=50)
            results = await asyncio.to_thread(
                self.client.search_groupings, query, limit
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results)}

        elif name == "search_note":
            query = arguments.get("query", "")
            limit = arguments.get("limit", 10)
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(limit, max_value=50)
            results = await asyncio.to_thread(
                self.client.search_notes, query, limit
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results)}

        elif name == "lookup_hash":
            hash_value = arguments.get("hash", "")
            validate_length(hash_value, 128, "hash")
            result = await asyncio.to_thread(
                self.client.lookup_hash, hash_value
            )
            if result is None:
                return {"found": False, "hash": hash_value}
            return result

        elif name == "get_entity":
            entity_id = arguments.get("entity_id", "")
            # Security: Validate UUID format to prevent injection
            entity_id = validate_uuid(entity_id, "entity_id")
            result = await asyncio.to_thread(
                self.client.get_entity, entity_id
            )
            if result is None:
                return {"found": False, "entity_id": entity_id}
            return {"found": True, "entity": result}

        elif name == "get_relationships":
            entity_id = arguments.get("entity_id", "")
            direction = arguments.get("direction", "both")
            relationship_types = arguments.get("relationship_types")
            limit = arguments.get("limit", 50)
            # Security: Validate UUID format
            entity_id = validate_uuid(entity_id, "entity_id")
            # Security: Validate relationship types
            relationship_types = validate_relationship_types(relationship_types)
            # Validate direction
            if direction not in ("from", "to", "both"):
                direction = "both"
            limit = validate_limit(limit, max_value=50)
            results = await asyncio.to_thread(
                self.client.get_relationships, entity_id, direction, relationship_types, limit
            )
            return {"entity_id": entity_id, "relationships": results, "total": len(results)}

        # === Write Operations ===
        elif name == "create_indicator":
            name_val = arguments.get("name", "")
            pattern = arguments.get("pattern", "")
            pattern_type = arguments.get("pattern_type", "stix")
            description = arguments.get("description", "")
            confidence = arguments.get("confidence", 50)
            labels = arguments.get("labels")
            validate_length(name_val, 256, "name")
            validate_length(description, 5000, "description")
            # Security: Validate STIX pattern syntax
            validate_stix_pattern(pattern)
            # Security: Validate labels
            labels = validate_labels(labels) if labels else None
            # Security: Validate pattern_type (raises on invalid)
            pattern_type = validate_pattern_type(
                pattern_type, extra_types=self.config.extra_pattern_types
            )
            return await asyncio.to_thread(
                self.client.create_indicator,
                name_val, pattern, pattern_type, description, confidence, labels
            )

        elif name == "create_note":
            content = arguments.get("content", "")
            entity_ids = arguments.get("entity_ids", [])
            note_types = arguments.get("note_types")
            confidence = arguments.get("confidence", 75)
            likelihood = arguments.get("likelihood")
            validate_length(content, 10000, "content")
            # Security: Validate all entity IDs are UUIDs
            entity_ids = validate_uuid_list(entity_ids, "entity_ids", max_items=20)
            # Security: Validate note types
            note_types = validate_note_types(note_types)
            return await asyncio.to_thread(
                self.client.create_note,
                content, entity_ids, note_types, confidence, likelihood
            )

        elif name == "create_sighting":
            indicator_id = arguments.get("indicator_id", "")
            sighted_by_id = arguments.get("sighted_by_id", "")
            first_seen = arguments.get("first_seen")
            last_seen = arguments.get("last_seen")
            count = arguments.get("count", 1)
            description = arguments.get("description", "")
            confidence = arguments.get("confidence", 75)
            # Security: Validate UUIDs
            indicator_id = validate_uuid(indicator_id, "indicator_id")
            sighted_by_id = validate_uuid(sighted_by_id, "sighted_by_id")
            validate_length(description, 5000, "description")
            # Security: Validate date parameters
            first_seen = validate_date_filter(first_seen, "first_seen")
            last_seen = validate_date_filter(last_seen, "last_seen")
            return await asyncio.to_thread(
                self.client.create_sighting,
                indicator_id, sighted_by_id, first_seen, last_seen, count, description, confidence
            )

        elif name == "trigger_enrichment":
            entity_id = arguments.get("entity_id", "")
            connector_id = arguments.get("connector_id", "")
            # Security: Validate UUIDs
            entity_id = validate_uuid(entity_id, "entity_id")
            connector_id = validate_uuid(connector_id, "connector_id")
            return await asyncio.to_thread(
                self.client.trigger_enrichment, entity_id, connector_id
            )

        else:
            raise ValidationError(f"Unknown tool: {name}")

    async def run(self) -> None:
        """Run the MCP server."""
        from mcp.server.stdio import stdio_server

        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )
