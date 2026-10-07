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
import ipaddress
import json
import logging
import time
from typing import Any

from mcp.server import Server
from mcp.types import TextContent, Tool
from sift_common.instructions import OPENCTI as _INSTRUCTIONS

from . import providers
from .audit import AuditWriter, resolve_examiner
from .client import OpenCTIClient, RateLimiter
from .config import Config
from .errors import (
    ConfigurationError,
    OpenCTIMCPError,
    RateLimitError,
    ValidationError,
)
from .providers import opencti as opencti_provider
from .tool_metadata import DEFAULT_METADATA, TOOL_METADATA
from .validation import (
    MAX_IOC_LENGTH,
    MAX_QUERY_LENGTH,
    sanitize_for_log,
    validate_date_filter,
    validate_days,
    validate_ioc,
    validate_labels,
    validate_length,
    validate_limit,
    validate_observable_types,
    validate_offset,
    validate_relationship_types,
    validate_uuid,
)

logger = logging.getLogger(__name__)


# Valid entity types for search_entity and their client method names.
# Types with confidence_min support are listed in _ENTITY_TYPES_WITH_CONFIDENCE.
_ENTITY_TYPE_METHODS = {
    "threat_actor": "search_threat_actors",
    "malware": "search_malware",
    "attack_pattern": "search_attack_patterns",
    "vulnerability": "search_vulnerabilities",
    "campaign": "search_campaigns",
    "tool": "search_tools",
    "infrastructure": "search_infrastructure",
    "incident": "search_incidents",
    "observable": "search_observables",
    "sighting": "search_sightings",
    "organization": "search_organizations",
    "sector": "search_sectors",
    "location": "search_locations",
    "course_of_action": "search_courses_of_action",
    "grouping": "search_groupings",
    "note": "search_notes",
}

# Entity types whose client methods accept confidence_min parameter
_ENTITY_TYPES_WITH_CONFIDENCE = frozenset(
    {
        "threat_actor",
        "malware",
        "campaign",
        "incident",
    }
)

# Entity types whose client methods accept full filter params (offset, labels, dates)
# vs. simple methods that only take (query, limit)
_ENTITY_TYPES_FULL_FILTERS = frozenset(
    {
        "threat_actor",
        "malware",
        "attack_pattern",
        "vulnerability",
        "campaign",
        "tool",
        "infrastructure",
        "incident",
        "observable",
    }
)

# Simple entity types: client methods only take (query, limit)
_ENTITY_TYPES_SIMPLE = frozenset(
    {
        "sighting",
        "organization",
        "sector",
        "location",
        "course_of_action",
        "grouping",
        "note",
    }
)

VALID_ENTITY_TYPES = frozenset(_ENTITY_TYPE_METHODS.keys())

# The tools other than lookup_ioc read OpenCTI alone.
_OPENCTI_TOOLS = frozenset(
    {
        "get_health",
        "search_threat_intel",
        "search_entity",
        "get_recent_indicators",
        "get_entity",
        "get_relationships",
        "search_reports",
    }
)


def _internal_address(ioc: str) -> str:
    """The reason an IP address isn't looked up, or "" for anything else."""
    try:
        ip = ipaddress.ip_address(ioc)
    except ValueError:
        return ""
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return f"Internal address ({ioc}) — not in threat intelligence scope."
    return ""


def _opencti_summary(ioc: str, answer: dict) -> dict[str, Any]:
    """The keys lookup_ioc carried before providers, summarised over every
    OpenCTI record that matched. They are compatibility summaries: the
    records under providers.opencti are the answer."""
    summary: dict[str, Any] = {}
    if answer.get("outcome") == providers.MATCH:
        records = answer["matches"]
        confidences = [
            r["confidence"] for r in records if isinstance(r.get("confidence"), int)
        ]
        created = [r["created"] for r in records if isinstance(r.get("created"), str)]
        labels = {
            label.get("value")
            for r in records
            for label in (r.get("objectLabel") or [])
            if isinstance(label, dict) and isinstance(label.get("value"), str)
        }
        summary.update(
            entity_type="indicator",
            name=ioc,
            confidence=max(confidences, default=0),
            labels=sorted(labels),
            created=min(created, default=""),
            source="opencti",
        )
        actors: list[str] = []
        malware: list[str] = []
        techniques: list[str] = []
        for rel in answer.get("relationships") or []:
            target = rel.get("to") or {}
            kind = target.get("entity_type", "")
            name = target.get("name", "")
            if kind in ("Threat-Actor-Group", "Intrusion-Set"):
                found_in = actors
            elif kind == "Malware":
                found_in = malware
            elif kind == "Attack-Pattern":
                found_in = techniques
                name = target.get("x_mitre_id") or name
            else:
                continue
            if name and name not in found_in:
                found_in.append(name)
        summary.update(
            related_threat_actors=actors,
            related_malware=malware,
            mitre_techniques=techniques,
        )
        if answer.get("relationships_unavailable"):
            summary["relationships_unavailable"] = answer["relationships_unavailable"]
    return summary


class OpenCTIMCPServer:
    """MCP server for OpenCTI threat intelligence (read-only)."""

    def __init__(
        self,
        config: Config | None,
        client: OpenCTIClient | None = None,
        provider_names: list[str] | None = None,
        opencti_reason: str = "",
    ) -> None:
        """Construct the MCP server.

        Args:
            config: Loaded OpenCTI configuration.
            client: Optional pre-built OpenCTIClient. When provided
                (the canonical path from __main__.py), the server reuses
                the same instance that validate_startup ran against —
                so the _degraded flag set during startup probe is
                visible to the connect() chokepoint when tools fire.
                When None (tests / direct construction), a fresh client
                is built but _degraded stays False (no startup probe
                was run; degraded-mode behavior is opt-in via
                client.validate_startup()).

                Fix for live-test BLOCKER 2026-05-11: __main__.py
                previously built one client for validation and the
                server built a second; degraded state set on the first
                never reached the tool-call path. Single shared
                instance closes the gap.
            provider_names: The threat-intel providers lookup_ioc asks
                (default: THREATINTEL_PROVIDERS, unset meaning OpenCTI).
            opencti_reason: Why OpenCTI can't be used, when it is listed
                but ``config`` is None.
        """
        self.config = config
        self.provider_names = (
            provider_names
            if provider_names is not None
            else providers.configured_names()
        )
        if config is None:
            self.client = None
            self._opencti_reason = opencti_reason or (
                "OpenCTI is not configured in this threat-intel backend."
            )
        else:
            self.client = client if client is not None else OpenCTIClient(config)
            self._opencti_reason = ""
        prebuilt: dict[str, Any] = {}
        if "opencti" in self.provider_names:
            prebuilt["opencti"] = (
                opencti_provider.create(config)
                if config is not None
                else providers.Unavailable(
                    f"opencti is not configured: {self._opencti_reason}"
                )
            )
        self.providers = providers.load(self.provider_names, prebuilt)
        # lookup_ioc shares OpenCTI's query limit when OpenCTI is configured.
        self._lookup_limiter = (
            self.client._query_limiter
            if self.client is not None
            else RateLimiter(max_calls=600, window_seconds=60)
        )
        self.server = Server("opencti-mcp", instructions=_INSTRUCTIONS)
        self._audit = AuditWriter("opencti-mcp")
        self._register_tools()

        logger.info("Server started in read-only mode")

    def _register_tools(self) -> None:
        """Register MCP tools."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            tools = [
                Tool(
                    name="get_health",
                    description="Check OpenCTI server connectivity and API health. Use before investigation to verify the threat intel source is available. Does not count against rate limits.",
                    inputSchema={"type": "object", "properties": {}},
                ),
                Tool(
                    name="search_threat_intel",
                    description="Broad search across all OpenCTI entity types: indicators, threat actors, malware, techniques, CVEs, and reports. Returns up to limit results per entity type (default 5, max 20). Use confidence_min (0-100) to filter low-quality matches. For type-specific searches with more results, use search_entity instead. Supports offset pagination (max 500).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search term (IOC, threat actor name, malware, CVE, etc.)",
                                "maxLength": MAX_QUERY_LENGTH,
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results per entity type (default: 5, max: 20)",
                                "default": 5,
                                "minimum": 1,
                                "maximum": 20,
                            },
                            "offset": {
                                "type": "integer",
                                "description": "Skip first N results (for pagination, max: 500)",
                                "default": 0,
                                "minimum": 0,
                                "maximum": 500,
                            },
                            "labels": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter by labels (e.g., ['tlp:amber', 'malicious'])",
                            },
                            "confidence_min": {
                                "type": "integer",
                                "description": "Minimum confidence threshold (0-100)",
                                "minimum": 0,
                                "maximum": 100,
                            },
                            "created_after": {
                                "type": "string",
                                "description": "Filter by created date >= (ISO format: 2024-01-01)",
                            },
                            "created_before": {
                                "type": "string",
                                "description": "Filter by created date <= (ISO format: 2024-12-31)",
                            },
                        },
                        "required": ["query"],
                    },
                ),
                Tool(
                    name="search_entity",
                    description="Search OpenCTI entities filtered by a single type. More precise than search_threat_intel — returns up to 50 results for one entity type instead of 20 across all types. Use for focused queries like 'all malware associated with APT28' or 'all vulnerabilities matching CVE-2024'. Supports confidence_min, label filtering, date range, and offset pagination (max 500). Valid types: threat_actor, malware, attack_pattern, vulnerability, campaign, tool, infrastructure, incident, observable, sighting, organization, sector, location, course_of_action, grouping, note.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "type": {
                                "type": "string",
                                "description": "Entity type to search",
                                "enum": sorted(VALID_ENTITY_TYPES),
                            },
                            "query": {
                                "type": "string",
                                "description": "Search term",
                                "maxLength": MAX_QUERY_LENGTH,
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50,
                            },
                            "offset": {
                                "type": "integer",
                                "description": "Pagination offset (default: 0)",
                                "default": 0,
                            },
                            "labels": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter by labels",
                            },
                            "confidence_min": {
                                "type": "integer",
                                "description": "Minimum confidence score (0-100)",
                            },
                            "created_after": {
                                "type": "string",
                                "description": "Filter entities created after this ISO date",
                            },
                            "created_before": {
                                "type": "string",
                                "description": "Filter entities created before this ISO date",
                            },
                        },
                        "required": ["type", "query"],
                    },
                ),
                Tool(
                    name="lookup_ioc",
                    description="Look up one IOC (IP, hash, domain, or URL) in every configured threat-intel platform. Each platform's records for an exact match are returned under providers.<name> as the platform holds them (for OpenCTI: revoked, valid_from, valid_until, x_opencti_score, confidence, labels and relationships), with outcome MATCH, NO_MATCH or UNAVAILABLE (the platform couldn't be asked, which is not a not-found). This is each platform's record, not a verdict. The top-level outcome is MATCH when any platform matched. found, confidence, labels, created, related_threat_actors, related_malware and mitre_techniques are compatibility summaries of OpenCTI's records; providers.* is the authoritative answer.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "ioc": {
                                "type": "string",
                                "description": "IOC value (IP address, file hash, domain, or URL)",
                                "maxLength": MAX_IOC_LENGTH,
                            }
                        },
                        "required": ["ioc"],
                    },
                ),
                Tool(
                    name="get_recent_indicators",
                    description="Get recently added IOCs from the last N days (default 7, max 90). Returns up to 100 indicators sorted by creation date. Use for situational awareness or to check if new intel has been ingested relevant to an ongoing investigation.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "days": {
                                "type": "integer",
                                "description": "Number of days to look back (default: 7, max: 90)",
                                "default": 7,
                                "minimum": 1,
                                "maximum": 90,
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 20, max: 100)",
                                "default": 20,
                                "maximum": 100,
                            },
                        },
                    },
                ),
                Tool(
                    name="get_entity",
                    description="Get full details for a specific entity by its OpenCTI UUID. Returns all fields including description, labels, confidence, external references, and creation/modification dates. Use after finding an entity via search to get complete context. The entity ID comes from search result fields.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "entity_id": {
                                "type": "string",
                                "description": "OpenCTI entity ID (UUID format)",
                            }
                        },
                        "required": ["entity_id"],
                    },
                ),
                Tool(
                    name="get_relationships",
                    description="Get relationships for an entity: who uses it, what it indicates, what it targets, etc. Filter by direction ('from' = outgoing, 'to' = incoming, 'both' = default) and relationship_types (e.g., 'indicates', 'uses', 'targets'). Returns up to 50 related entities. Use to map threat actor toolkits, malware capabilities, or indicator context.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "entity_id": {
                                "type": "string",
                                "description": "Entity ID to get relationships for",
                            },
                            "direction": {
                                "type": "string",
                                "enum": ["from", "to", "both"],
                                "description": "Relationship direction: 'from' (outgoing), 'to' (incoming), 'both' (default)",
                                "default": "both",
                            },
                            "relationship_types": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter by relationship types (e.g., ['indicates', 'uses', 'targets'])",
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 50, max: 50)",
                                "default": 50,
                                "maximum": 50,
                            },
                        },
                        "required": ["entity_id"],
                    },
                ),
                Tool(
                    name="search_reports",
                    description="Search threat intelligence reports by keyword (campaign name, threat actor, malware family, CVE). Returns report metadata, publication date, and associated entities. Reports often contain the analytical narrative that individual IOCs lack. Supports offset pagination, label filtering, confidence threshold, and date range.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search term (campaign name, threat actor, etc.)",
                                "maxLength": MAX_QUERY_LENGTH,
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max results (default: 10, max: 50)",
                                "default": 10,
                                "maximum": 50,
                            },
                            "offset": {
                                "type": "integer",
                                "description": "Skip first N results (for pagination, max: 500)",
                                "default": 0,
                                "minimum": 0,
                                "maximum": 500,
                            },
                            "labels": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter by labels (e.g., ['tlp:amber'])",
                            },
                            "confidence_min": {
                                "type": "integer",
                                "description": "Minimum confidence threshold (0-100)",
                                "minimum": 0,
                                "maximum": 100,
                            },
                            "created_after": {
                                "type": "string",
                                "description": "Filter reports created after this ISO date",
                            },
                            "created_before": {
                                "type": "string",
                                "description": "Filter reports created before this ISO date",
                            },
                        },
                        "required": ["query"],
                    },
                ),
            ]

            return tools

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict) -> list[TextContent]:
            audit_id = self._audit._next_audit_id()
            start = time.monotonic()
            try:
                result = await self._dispatch_tool(name, arguments)
                elapsed_ms = (time.monotonic() - start) * 1000
                result = self._wrap_response(
                    name,
                    arguments,
                    result,
                    audit_id=audit_id,
                    elapsed_ms=elapsed_ms,
                )
                return [
                    TextContent(
                        type="text", text=json.dumps(result, indent=2, default=str)
                    )
                ]

            except ValidationError as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.warning(
                    "Validation failed",
                    extra={
                        "tool": name,
                        "error": str(e),
                        "arguments": sanitize_for_log(arguments),
                    },
                )
                error_result = {"error": "validation_error", "message": str(e)}
                error_result = self._wrap_response(
                    name,
                    arguments,
                    error_result,
                    audit_id=audit_id,
                    elapsed_ms=elapsed_ms,
                )
                return [TextContent(type="text", text=json.dumps(error_result))]

            except RateLimitError as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.warning(
                    "Rate limit exceeded",
                    extra={
                        "tool": name,
                        "wait_seconds": e.wait_seconds,
                        "limit_type": e.limit_type,
                    },
                )
                error_result = {
                    "error": "rate_limit_exceeded",
                    "message": e.safe_message,
                    "wait_seconds": e.wait_seconds,
                }
                error_result = self._wrap_response(
                    name,
                    arguments,
                    error_result,
                    audit_id=audit_id,
                    elapsed_ms=elapsed_ms,
                )
                return [TextContent(type="text", text=json.dumps(error_result))]

            except ConfigurationError as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.error("Configuration error", extra={"error": str(e)})
                error_result = {
                    "error": "configuration_error",
                    "message": "OpenCTI is not properly configured. Check server settings.",
                }
                error_result = self._wrap_response(
                    name,
                    arguments,
                    error_result,
                    audit_id=audit_id,
                    elapsed_ms=elapsed_ms,
                )
                return [TextContent(type="text", text=json.dumps(error_result))]

            except OpenCTIMCPError as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.error(
                    "MCP error",
                    extra={
                        "tool": name,
                        "error_type": type(e).__name__,
                        "error": str(e),
                    },
                )
                error_result = {
                    "error": type(e).__name__.lower(),
                    "message": e.safe_message,
                }
                error_result = self._wrap_response(
                    name,
                    arguments,
                    error_result,
                    audit_id=audit_id,
                    elapsed_ms=elapsed_ms,
                )
                return [TextContent(type="text", text=json.dumps(error_result))]

            except Exception as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.exception(
                    "Internal error",
                    extra={"tool": name, "error_type": type(e).__name__},
                )
                error_result = {
                    "error": "internal_error",
                    "message": "An unexpected error occurred. Check server logs.",
                }
                error_result = self._wrap_response(
                    name,
                    arguments,
                    error_result,
                    audit_id=audit_id,
                    elapsed_ms=elapsed_ms,
                )
                return [TextContent(type="text", text=json.dumps(error_result))]

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
        created_before: str | None,
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
    def _error_response(
        error_code: str, message: str, **extra_fields: Any
    ) -> list[TextContent]:
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
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        audit_id: str | None = None,
        elapsed_ms: float | None = None,
    ) -> dict[str, Any]:
        """Wrap tool result with evidence ID, caveats, and audit trail.

        Always generates audit_id and writes audit -- including for errors.
        """
        summary = result if "error" not in result else {"error": result["error"]}
        audit_id = self._audit.log(
            tool=tool_name,
            params=arguments,
            result_summary=summary,
            audit_id=audit_id,
            elapsed_ms=elapsed_ms,
        )
        if audit_id is None:
            result["warning"] = "Audit write failed — action not recorded"
        # For search_entity, resolve metadata by the underlying entity type
        meta_key = tool_name
        if tool_name == "search_entity":
            entity_type = arguments.get("type", "")
            # Map to the old per-type tool name for metadata lookup
            _type_to_meta_key = {
                "threat_actor": "search_threat_actor",
                "malware": "search_malware",
                "attack_pattern": "search_attack_pattern",
                "vulnerability": "search_vulnerability",
                "campaign": "search_campaign",
                "tool": "search_tool",
                "infrastructure": "search_infrastructure",
                "incident": "search_incident",
                "observable": "search_observable",
                "sighting": "search_sighting",
                "organization": "search_organization",
                "sector": "search_sector",
                "location": "search_location",
                "course_of_action": "search_course_of_action",
                "grouping": "search_grouping",
                "note": "search_note",
            }
            meta_key = _type_to_meta_key.get(entity_type, tool_name)
        meta = TOOL_METADATA.get(meta_key, DEFAULT_METADATA)

        result["audit_id"] = audit_id
        result["examiner"] = resolve_examiner()
        if "error" not in result:
            result["caveats"] = meta["caveats"]
            result["interpretation_constraint"] = meta["interpretation_constraint"]
        return result

    async def _dispatch_search_entity(self, arguments: dict) -> dict[str, Any]:
        """Dispatch search_entity to the appropriate client method."""
        entity_type = arguments.get("type", "")
        if entity_type not in VALID_ENTITY_TYPES:
            raise ValidationError(
                f"Invalid entity type: '{entity_type}'. "
                f"Valid types: {', '.join(sorted(VALID_ENTITY_TYPES))}"
            )

        query = arguments.get("query", "")
        validate_length(query, MAX_QUERY_LENGTH, "query")
        limit = validate_limit(arguments.get("limit", 10), max_value=50)

        method_name = _ENTITY_TYPE_METHODS[entity_type]
        method = getattr(self.client, method_name)

        # Observable has a special parameter
        if entity_type == "observable":
            observable_types = arguments.get("observable_types")
            observable_types = validate_observable_types(
                observable_types, extra_types=self.config.extra_observable_types
            )
            results = await asyncio.to_thread(method, query, limit, 0, observable_types)
            results = self._safe_results(results)
            return {"type": entity_type, "results": results, "total": len(results)}

        # Full-filter types: support offset, labels, dates, and maybe confidence
        if entity_type in _ENTITY_TYPES_FULL_FILTERS:
            offset, labels, created_after, created_before = (
                self._validate_search_filters(
                    arguments.get("offset"),
                    arguments.get("labels"),
                    arguments.get("created_after"),
                    arguments.get("created_before"),
                )
            )
            if entity_type in _ENTITY_TYPES_WITH_CONFIDENCE:
                confidence_min = arguments.get("confidence_min")
                results = await asyncio.to_thread(
                    method,
                    query,
                    limit,
                    offset,
                    labels,
                    confidence_min,
                    created_after,
                    created_before,
                )
            else:
                results = await asyncio.to_thread(
                    method, query, limit, offset, labels, created_after, created_before
                )
            results = self._safe_results(results)
            return {
                "type": entity_type,
                "results": results,
                "total": len(results),
                "offset": offset,
            }

        # Simple types: only (query, limit)
        results = await asyncio.to_thread(method, query, limit)
        results = self._safe_results(results)
        return {"type": entity_type, "results": results, "total": len(results)}

    def _lookup_ioc(self, ioc: str, ioc_type: str) -> dict[str, Any]:
        """Ask every configured provider for its records on exactly this IOC.

        ``outcome`` is MATCH when any provider matched, else UNAVAILABLE when
        any couldn't be asked, else NO_MATCH; ``providers`` holds each one's
        answer as the platform gave it. No verdict is computed. When OpenCTI
        is configured, the keys the tool returned before providers are kept
        as summaries over OpenCTI's records.
        """
        internal = _internal_address(ioc)
        if internal:
            return {
                "found": False,
                "ioc": ioc,
                "outcome": providers.UNAVAILABLE,
                "reason": internal,
                "note": internal,
                "providers": {},
            }
        if not self._lookup_limiter.check_and_record():
            raise RateLimitError(self._lookup_limiter.wait_time(), "query")
        answers = providers.lookup_all(self.providers, ioc, ioc_type)
        outcome = providers.aggregate(answers)
        result: dict[str, Any] = {
            "ioc": ioc,
            "outcome": outcome,
            "found": outcome == providers.MATCH,
        }
        if outcome == providers.UNAVAILABLE:
            # A "note" also marks the answer unconfirmed to callers that
            # predate "outcome".
            result["reason"] = "; ".join(
                f"{name}: {answer['reason']}"
                for name, answer in answers.items()
                if answer["outcome"] == providers.UNAVAILABLE
            )
            result["note"] = f"Not answered: {result['reason']}"
        if "opencti" in answers:
            result.update(_opencti_summary(ioc, answers["opencti"]))
        result["providers"] = answers
        return result

    async def _dispatch_tool(self, name: str, arguments: dict) -> dict[str, Any]:
        """Dispatch tool call to appropriate handler."""

        if name in _OPENCTI_TOOLS and self.client is None:
            return {
                "error": "opencti_not_configured",
                "message": self._opencti_reason,
            }

        if name == "get_health":
            available = await asyncio.to_thread(self.client.is_available)
            return {
                "status": "healthy" if available else "unavailable",
                "opencti_available": available,
            }

        elif name == "search_threat_intel":
            query = arguments.get("query", "")
            confidence_min = arguments.get("confidence_min")
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(arguments.get("limit", 5), max_value=20)
            offset, labels, created_after, created_before = (
                self._validate_search_filters(
                    arguments.get("offset"),
                    arguments.get("labels"),
                    arguments.get("created_after"),
                    arguments.get("created_before"),
                )
            )
            return await asyncio.to_thread(
                self.client.unified_search,
                query,
                limit,
                offset,
                labels,
                confidence_min,
                created_after,
                created_before,
            )

        elif name == "search_entity":
            return await self._dispatch_search_entity(arguments)

        elif name == "lookup_ioc":
            ioc = arguments.get("ioc", "")
            validate_length(ioc, MAX_IOC_LENGTH, "ioc")
            is_valid, ioc_type = validate_ioc(ioc)
            result = await asyncio.to_thread(self._lookup_ioc, ioc.strip(), ioc_type)
            result["ioc_type"] = ioc_type
            return result

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

        elif name == "get_entity":
            entity_id = arguments.get("entity_id", "")
            # Security: Validate UUID format to prevent injection
            entity_id = validate_uuid(entity_id, "entity_id")
            result = await asyncio.to_thread(self.client.get_entity, entity_id)
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
                self.client.get_relationships,
                entity_id,
                direction,
                relationship_types,
                limit,
            )
            return {
                "entity_id": entity_id,
                "relationships": results,
                "total": len(results),
            }

        elif name == "search_reports":
            query = arguments.get("query", "")
            confidence_min = arguments.get("confidence_min")
            validate_length(query, MAX_QUERY_LENGTH, "query")
            limit = validate_limit(arguments.get("limit", 10), max_value=50)
            offset, labels, created_after, created_before = (
                self._validate_search_filters(
                    arguments.get("offset"),
                    arguments.get("labels"),
                    arguments.get("created_after"),
                    arguments.get("created_before"),
                )
            )
            results = await asyncio.to_thread(
                self.client.search_reports,
                query,
                limit,
                offset,
                labels,
                confidence_min,
                created_after,
                created_before,
            )
            results = self._safe_results(results)
            return {"results": results, "total": len(results), "offset": offset}

        else:
            raise ValidationError(f"Unknown tool: {name}")

    async def run(self) -> None:
        """Run the MCP server."""
        from mcp.server.stdio import stdio_server

        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream, write_stream, self.server.create_initialization_options()
            )


if __name__ == "__main__":
    from opencti_mcp.__main__ import main

    main()
