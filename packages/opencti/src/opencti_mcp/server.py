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
from mcp.types import TextContent, Tool
from sift_common.instructions import OPENCTI as _INSTRUCTIONS

from .audit import AuditWriter, resolve_examiner
from .client import OpenCTIClient
from .config import Config
from .errors import (
    ConfigurationError,
    OpenCTIMCPError,
    RateLimitError,
    ValidationError,
)
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


class OpenCTIMCPServer:
    """MCP server for OpenCTI threat intelligence (read-only)."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.client = OpenCTIClient(config)
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
                    description="Check OpenCTI server health and connectivity.",
                    inputSchema={"type": "object", "properties": {}},
                ),
                Tool(
                    name="search_threat_intel",
                    description="Search OpenCTI for threat intelligence across all entity types (indicators, threat actors, malware, techniques, CVEs, reports).",
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
                    description=(
                        "Search OpenCTI entities by type. "
                        "Valid types: threat_actor, malware, attack_pattern, vulnerability, "
                        "campaign, tool, infrastructure, incident, observable, sighting, "
                        "organization, sector, location, course_of_action, grouping, note"
                    ),
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
                    description="Get full context for a specific IOC (IP, hash, domain, URL) including related threat actors, malware, and MITRE techniques.",
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
                    name="lookup_hash",
                    description="Look up a file hash (MD5, SHA1, SHA256) in OpenCTI.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "hash": {
                                "type": "string",
                                "description": "File hash (MD5, SHA1, or SHA256)",
                                "maxLength": 128,
                            }
                        },
                        "required": ["hash"],
                    },
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
                                "description": "Skip first N results (for pagination)",
                                "default": 0,
                                "minimum": 0,
                                "maximum": 500,
                            },
                            "labels": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter by labels",
                            },
                            "created_after": {
                                "type": "string",
                                "description": "Filter by created date >= (ISO format)",
                            },
                            "created_before": {
                                "type": "string",
                                "description": "Filter by created date <= (ISO format)",
                            },
                        },
                        "required": ["query"],
                    },
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
                    description="Get full details of any entity by its OpenCTI ID.",
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
                    description="Get relationships for an entity (who uses what, what indicates what, etc.).",
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
                    description="Search for threat intelligence reports.",
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
                        },
                        "required": ["query"],
                    },
                ),
            ]

            return tools

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict) -> list[TextContent]:
            evidence_id = self._audit._next_evidence_id()
            start = time.monotonic()
            try:
                result = await self._dispatch_tool(name, arguments)
                elapsed_ms = (time.monotonic() - start) * 1000
                result = self._wrap_response(
                    name,
                    arguments,
                    result,
                    evidence_id=evidence_id,
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
                    evidence_id=evidence_id,
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
                    evidence_id=evidence_id,
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
                    evidence_id=evidence_id,
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
                    evidence_id=evidence_id,
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
                    evidence_id=evidence_id,
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
        evidence_id: str | None = None,
        elapsed_ms: float | None = None,
    ) -> dict[str, Any]:
        """Wrap tool result with evidence ID, caveats, and audit trail.

        Always generates evidence_id and writes audit -- including for errors.
        """
        summary = result if "error" not in result else {"error": result["error"]}
        evidence_id = self._audit.log(
            tool=tool_name,
            params=arguments,
            result_summary=summary,
            evidence_id=evidence_id,
            elapsed_ms=elapsed_ms,
        )
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

        result["evidence_id"] = evidence_id
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

    async def _dispatch_tool(self, name: str, arguments: dict) -> dict[str, Any]:
        """Dispatch tool call to appropriate handler."""

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
            result = await asyncio.to_thread(self.client.get_indicator_context, ioc)
            result["ioc_type"] = ioc_type
            return result

        elif name == "lookup_hash":
            hash_value = arguments.get("hash", "")
            validate_length(hash_value, 128, "hash")
            result = await asyncio.to_thread(self.client.lookup_hash, hash_value)
            if result is None:
                return {"found": False, "hash": hash_value}
            return result

        elif name == "search_attack_pattern":
            query = arguments.get("query", "")
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
                self.client.search_attack_patterns,
                query,
                limit,
                offset,
                labels,
                created_after,
                created_before,
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
