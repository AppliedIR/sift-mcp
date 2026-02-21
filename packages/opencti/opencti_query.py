#!/usr/bin/env python3
"""
OpenCTI Query Client - Threat Intelligence Lookup for Incident Response

This script provides a command-line interface for querying the local OpenCTI
threat intelligence platform. OpenCTI aggregates data from multiple sources
(MITRE ATT&CK, abuse.ch, CISA KEV, etc.) and provides relationship-aware
threat intelligence for IOCs, threat actors, malware, and vulnerabilities.

Architecture:
    User --> opencti_query.py --[GraphQL API]--> OpenCTI --[Connectors]--> Intel Sources

Features:
    - Unified search across all entity types
    - Specific searches by type (indicator, threat_actor, malware, etc.)
    - IOC context lookup with relationships
    - Recent indicator retrieval
    - On-demand enrichment via VirusTotal/Shodan
    - IOC format validation

Entity Types:
    - indicator: IOCs (IP addresses, hashes, domains, URLs)
    - threat_actor: APT groups, cybercriminal organizations
    - malware: Malware families and variants
    - attack_pattern: MITRE ATT&CK techniques
    - vulnerability: CVEs with CVSS scores
    - report: Threat intelligence reports

Usage:
    # Unified search
    python opencti_query.py "APT29"

    # Search by entity type
    python opencti_query.py "cobalt strike" --type malware
    python opencti_query.py "T1003" --type attack_pattern
    python opencti_query.py "CVE-2024-3400" --type vulnerability

    # IOC lookup with relationships
    python opencti_query.py "192.168.1.1" --type indicator --context

    # Recent indicators
    python opencti_query.py --recent 7 --limit 20

    # Trigger enrichment (uses API quota)
    python opencti_query.py "8.8.8.8" --enrich
    python opencti_query.py "evil.com" --enrich --connector Shodan

Dependencies:
    pip install pycti

Author: AppliedIncidentResponse.com
License: MIT
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from pycti import OpenCTIApiClient

# Configure logging
logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

# OpenCTI connection settings
# SECURITY: Token MUST be provided via environment variable or config file
OPENCTI_URL = os.getenv("OPENCTI_URL", "http://localhost:8080")

def _get_opencti_token() -> Optional[str]:
    """
    Get OpenCTI API token from environment or config file.

    Token is retrieved from (in order of precedence):
    1. OPENCTI_TOKEN environment variable
    2. ~/.config/rag/opencti_token file (XDG compliant)
    3. .env file in current working directory (OPENCTI_TOKEN or OPENCTI_ADMIN_TOKEN)

    Returns:
        str: API token, or None if not found
    """
    # 1. Try environment variable first (highest priority)
    token = os.getenv("OPENCTI_TOKEN")
    if token:
        return token

    # 2. Try config file in user's config directory (XDG compliant)
    xdg_config = os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")
    config_file = Path(xdg_config) / "rag" / "opencti_token"
    if config_file.exists():
        try:
            return config_file.read_text().strip()
        except (IOError, OSError):
            pass

    # 3. Try .env file in current working directory
    env_file = Path.cwd() / ".env"
    if env_file.exists():
        try:
            content = env_file.read_text()
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith("OPENCTI_TOKEN=") or line.startswith("OPENCTI_ADMIN_TOKEN="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
        except (IOError, OSError):
            pass

    return None

# Get token at module load time
OPENCTI_TOKEN: Optional[str] = _get_opencti_token()


# =============================================================================
# IOC Validation
# =============================================================================

def validate_ioc_format(query: str, ioc_type: str = "auto") -> tuple[bool, str, str]:
    """
    Validate IOC format and auto-detect IOC type.

    This function performs basic format validation to catch common mistakes
    before querying OpenCTI. It also auto-detects the IOC type for better
    search targeting.

    Supported IOC Types:
        - ipv4: IPv4 addresses (e.g., 192.168.1.1)
        - md5/sha1/sha256: File hashes (32/40/64 hex characters)
        - url: URLs starting with http://, https://, ftp://
        - domain: Domain names (e.g., evil.com)
        - cve: CVE identifiers (e.g., CVE-2024-1234)
        - mitre_technique: MITRE technique IDs (e.g., T1003, T1003.001)
        - text: General text search (default)

    Args:
        query: The IOC value to validate
        ioc_type: Expected type (for validation) or "auto" for detection

    Returns:
        Tuple of (is_valid, detected_type, warning_message)
        - is_valid: True if format is valid
        - detected_type: Auto-detected IOC type
        - warning_message: Empty string if valid, error message if invalid
    """
    query = query.strip()

    # -------------------------------------------------------------------------
    # IPv4 Address Validation
    # -------------------------------------------------------------------------
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, query):
        octets = query.split('.')
        if all(0 <= int(o) <= 255 for o in octets):
            return True, "ipv4", ""
        else:
            return False, "ipv4", f"Invalid IP format: octets must be 0-255"

    # -------------------------------------------------------------------------
    # Hash Validation (MD5=32, SHA1=40, SHA256=64 hex characters)
    # -------------------------------------------------------------------------
    if len(query) in (32, 40, 64):
        if re.match(r'^[0-9a-fA-F]+$', query):
            hash_types = {32: "md5", 40: "sha1", 64: "sha256"}
            return True, hash_types[len(query)], ""
        else:
            # Length matches hash but not valid hexadecimal
            return False, "hash", f"Invalid hash format: '{query}' is not valid hexadecimal"

    # -------------------------------------------------------------------------
    # URL Validation
    # -------------------------------------------------------------------------
    if query.startswith(('http://', 'https://', 'ftp://')):
        return True, "url", ""

    # -------------------------------------------------------------------------
    # Domain Validation (basic pattern matching)
    # -------------------------------------------------------------------------
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    if re.match(domain_pattern, query):
        return True, "domain", ""

    # -------------------------------------------------------------------------
    # CVE Validation
    # -------------------------------------------------------------------------
    if re.match(r'^CVE-\d{4}-\d+$', query, re.IGNORECASE):
        return True, "cve", ""

    # -------------------------------------------------------------------------
    # MITRE Technique ID Validation
    # -------------------------------------------------------------------------
    if re.match(r'^T\d{4}(\.\d{3})?$', query, re.IGNORECASE):
        return True, "mitre_technique", ""

    # -------------------------------------------------------------------------
    # General Text (threat actors, malware names, etc.)
    # -------------------------------------------------------------------------
    return True, "text", ""


# =============================================================================
# OpenCTI Query Class
# =============================================================================

class OpenCTIQuery:
    """
    Query interface for the local OpenCTI threat intelligence platform.

    This class provides methods to search and retrieve various entity types
    from OpenCTI, including:
    - Indicators (IOCs): IP addresses, hashes, domains, URLs
    - Threat Actors: APT groups, cybercriminal organizations
    - Malware: Malware families and tools
    - Attack Patterns: MITRE ATT&CK techniques
    - Reports: Threat intelligence reports
    - Vulnerabilities: CVEs with severity scores

    The class also supports:
    - Relationship traversal (get related entities)
    - On-demand enrichment via VirusTotal/Shodan
    - Time-based filtering for recent indicators

    Attributes:
        client: pycti OpenCTIApiClient instance
    """

    def __init__(
        self,
        url: str = OPENCTI_URL,
        token: Optional[str] = None
    ) -> None:
        """
        Initialize the OpenCTI client.

        Args:
            url: OpenCTI instance URL (default: http://localhost:8080)
            token: API token for authentication (uses config if not provided)

        Raises:
            ValueError: If no token is provided and none found in config
        """
        effective_token = token or OPENCTI_TOKEN
        if not effective_token:
            raise ValueError(
                "OpenCTI API token required. Set OPENCTI_TOKEN environment variable "
                "or create ~/.config/rag/opencti_token file."
            )
        self.client = OpenCTIApiClient(url, effective_token, log_level="error")

    # -------------------------------------------------------------------------
    # Search Methods by Entity Type
    # -------------------------------------------------------------------------

    def search_indicators(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """
        Search for indicators (IOCs) matching the query.

        Args:
            query: Search term (IP, hash, domain, etc.)
            limit: Maximum results to return

        Returns:
            list: Formatted indicator results
        """
        results = self.client.indicator.list(
            search=query,
            first=limit,
            orderBy="created",
            orderMode="desc"
        )
        return self._format_indicators(results)

    def search_threat_actors(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """
        Search for threat actors and APT groups.

        Note: In OpenCTI's STIX model, APT groups are typically stored as
        IntrusionSet entities, not ThreatActorGroup. This method searches
        both entity types to ensure comprehensive results.

        Args:
            query: Search term (APT name, alias, etc.)
            limit: Maximum results to return

        Returns:
            list: Formatted threat actor results
        """
        results = []

        # Search IntrusionSet (where most APT groups are stored)
        intrusion_sets = self.client.intrusion_set.list(
            search=query,
            first=limit
        )
        results.extend(intrusion_sets)

        # Also search ThreatActorGroup for completeness
        threat_actor_groups = self.client.threat_actor_group.list(
            search=query,
            first=limit
        )
        results.extend(threat_actor_groups)

        # Deduplicate by name (same actor may exist in both)
        seen_names = set()
        unique_results = []
        for r in results:
            name = r.get("name", "").lower()
            if name not in seen_names:
                seen_names.add(name)
                unique_results.append(r)

        return self._format_threat_actors(unique_results[:limit])

    def search_malware(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """
        Search for malware families and variants.

        Args:
            query: Search term (malware name, alias, etc.)
            limit: Maximum results to return

        Returns:
            list: Formatted malware results
        """
        results = self.client.malware.list(
            search=query,
            first=limit
        )
        return self._format_malware(results)

    def search_attack_patterns(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """
        Search for attack patterns (MITRE ATT&CK techniques).

        Args:
            query: Search term (technique name or ID like T1003)
            limit: Maximum results to return

        Returns:
            list: Formatted attack pattern results with MITRE IDs
        """
        results = self.client.attack_pattern.list(
            search=query,
            first=limit
        )
        return self._format_attack_patterns(results)

    def search_reports(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """
        Search for threat intelligence reports.

        Args:
            query: Search term (campaign name, threat actor, etc.)
            limit: Maximum results to return

        Returns:
            list: Formatted report results ordered by publication date
        """
        results = self.client.report.list(
            search=query,
            first=limit,
            orderBy="published",
            orderMode="desc"
        )
        return self._format_reports(results)

    def search_vulnerabilities(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """
        Search for vulnerabilities (CVEs).

        Args:
            query: Search term (CVE ID or description keywords)
            limit: Maximum results to return

        Returns:
            list: Formatted vulnerability results with CVSS scores
        """
        results = self.client.vulnerability.list(
            search=query,
            first=limit
        )
        return self._format_vulnerabilities(results)

    # -------------------------------------------------------------------------
    # Advanced Queries
    # -------------------------------------------------------------------------

    def get_recent_indicators(self, days: int = 7, limit: int = 20) -> list[dict[str, Any]]:
        """
        Get indicators created in the last N days.

        Useful for monitoring recent threat activity and new IOCs
        ingested from feeds.

        Args:
            days: Number of days to look back
            limit: Maximum results to return

        Returns:
            list: Recent indicators ordered by creation date (newest first)
        """
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
        results = self.client.indicator.list(
            first=limit,
            orderBy="created",
            orderMode="desc",
            filters={
                "mode": "and",
                "filters": [{
                    "key": "created",
                    "values": [since],
                    "operator": "gte"
                }],
                "filterGroups": []
            }
        )
        return self._format_indicators(results)

    def get_indicator_context(self, indicator_value: str) -> dict[str, Any]:
        """
        Get full context for a specific indicator including relationships.

        This method retrieves:
        - Indicator metadata (confidence, labels, description)
        - Related threat actors
        - Related malware families
        - Associated MITRE techniques

        Args:
            indicator_value: The IOC value (IP, hash, domain, etc.)

        Returns:
            dict: Full context including relationships, or {"found": False}
        """
        # Search for the indicator
        results = self.client.indicator.list(
            search=indicator_value,
            first=5
        )

        # pycti may return False instead of empty list
        if not results or not isinstance(results, list):
            return {"found": False, "indicator": indicator_value}

        indicator = results[0]
        context = {
            "found": True,
            "indicator": indicator_value,
            "type": indicator.get("pattern_type", "unknown"),
            "name": indicator.get("name", ""),
            "description": indicator.get("description", ""),
            "created": indicator.get("created", ""),
            "confidence": indicator.get("confidence", 0),
            "labels": [l.get("value") if isinstance(l, dict) else l for l in indicator.get("objectLabel", [])],
            "kill_chain_phases": [],
            "related_threats": [],
            "mitre_techniques": []
        }

        # Traverse relationships to find connected entities
        relations = self.client.stix_core_relationship.list(
            fromId=indicator.get("id"),
            first=20
        )
        if not relations or not isinstance(relations, list):
            relations = []

        for rel in relations:
            target = rel.get("to", {})
            target_type = target.get("entity_type", "")
            target_name = target.get("name", "")

            if target_type == "Threat-Actor-Group":
                context["related_threats"].append(target_name)
            elif target_type == "Malware":
                context["related_threats"].append(f"Malware: {target_name}")
            elif target_type == "Attack-Pattern":
                context["mitre_techniques"].append(target_name)

        return context

    def unified_search(self, query: str, limit: int = 10) -> dict[str, Any]:
        """
        Search across all entity types simultaneously.

        This provides a comprehensive view when the entity type is unknown.
        Results are organized by category.

        Args:
            query: Search term
            limit: Maximum results per category

        Returns:
            dict: Results organized by entity type
        """
        return {
            "query": query,
            "indicators": self.search_indicators(query, limit),
            "threat_actors": self.search_threat_actors(query, limit),
            "malware": self.search_malware(query, limit),
            "attack_patterns": self.search_attack_patterns(query, limit),
            "reports": self.search_reports(query, limit),
            "vulnerabilities": self.search_vulnerabilities(query, limit)
        }

    # -------------------------------------------------------------------------
    # Enrichment Methods
    # -------------------------------------------------------------------------

    def list_enrichment_connectors(self) -> list[dict[str, Any]]:
        """
        List available enrichment connectors (VirusTotal, Shodan, etc.).

        Returns:
            list: Connector info including name, scope, and status
        """
        query = '''
        query ConnectorsList {
          connectors {
            id
            name
            connector_type
            connector_scope
            auto
            active
          }
        }
        '''
        result = self.client.query(query)
        connectors = result.get("data", {}).get("connectors", [])
        enrichment = []
        for c in connectors:
            if c.get("connector_type") == "INTERNAL_ENRICHMENT":
                enrichment.append({
                    "id": c.get("id"),
                    "name": c.get("name"),
                    "scope": c.get("connector_scope", []),
                    "auto": c.get("auto", False),
                    "active": c.get("active", False)
                })
        return enrichment

    def find_observable(self, value: str) -> Optional[dict[str, Any]]:
        """
        Find an observable (IP, hash, domain) by its value.

        Args:
            value: The observable value to search for

        Returns:
            dict: Observable data if found, None otherwise
        """
        results = self.client.stix_cyber_observable.list(
            search=value,
            first=10
        )
        # Find exact or close match
        for obs in results:
            obs_value = obs.get("value") or obs.get("hashes", {}).get("SHA-256") or obs.get("hashes", {}).get("MD5")
            if obs_value and value.lower() in obs_value.lower():
                return obs
        return results[0] if results else None

    def enrich_observable(self, value: str, connector_name: str = "VirusTotal") -> dict[str, Any]:
        """
        Trigger enrichment on an observable.

        This sends a request to OpenCTI to enrich the observable using
        the specified connector (VirusTotal, Shodan, etc.). Note that
        this consumes API quota for the external service.

        Args:
            value: The observable value (IP, hash, domain, URL)
            connector_name: Name of enrichment connector (default: VirusTotal)

        Returns:
            dict: Status and details of the enrichment request
        """
        # Find the observable
        observable = self.find_observable(value)
        if not observable:
            return {
                "success": False,
                "error": f"Observable '{value}' not found in OpenCTI. Import it first.",
                "value": value
            }

        # Find the connector
        connectors = self.list_enrichment_connectors()
        connector = None
        for c in connectors:
            if connector_name.lower() in c["name"].lower():
                connector = c
                break

        if not connector:
            return {
                "success": False,
                "error": f"Connector '{connector_name}' not found. Available: {[c['name'] for c in connectors]}",
                "value": value
            }

        # Check if observable type is in connector scope
        obs_type = observable.get("entity_type", "")
        scope = connector.get("scope", [])
        if scope and obs_type not in scope:
            return {
                "success": False,
                "error": f"Observable type '{obs_type}' not in connector scope: {scope}",
                "value": value
            }

        # Trigger enrichment
        try:
            self.client.stix_cyber_observable.ask_for_enrichment(
                id=observable.get("id"),
                connector_id=connector["id"]
            )
            return {
                "success": True,
                "message": f"Enrichment requested via {connector['name']}",
                "value": value,
                "observable_id": observable.get("id"),
                "observable_type": obs_type,
                "connector": connector["name"]
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "value": value
            }

    def enrich_and_wait(
        self,
        value: str,
        connector_name: str = "VirusTotal",
        timeout: int = 30
    ) -> dict[str, Any]:
        """
        Trigger enrichment and wait for results.

        This method:
        1. Triggers enrichment via the specified connector
        2. Polls for updates until timeout
        3. Returns any new labels or references added by enrichment

        Args:
            value: The observable value
            connector_name: Enrichment connector name
            timeout: Maximum seconds to wait for enrichment

        Returns:
            dict: Enrichment results including labels and references
        """

        # Get current state
        observable = self.find_observable(value)
        if not observable:
            return {"success": False, "error": f"Observable '{value}' not found"}

        obs_id = observable.get("id")

        # Trigger enrichment
        result = self.enrich_observable(value, connector_name)
        if not result.get("success"):
            return result

        # Poll for updates
        start = time.time()
        while time.time() - start < timeout:
            time.sleep(3)
            updated = self.client.stix_cyber_observable.read(id=obs_id)
            if updated:
                # Check for new external references (VT adds these)
                ext_refs = updated.get("externalReferences", [])
                labels = [l.get("value") for l in updated.get("objectLabel", [])]
                if ext_refs or labels:
                    return {
                        "success": True,
                        "value": value,
                        "observable_type": updated.get("entity_type"),
                        "labels": labels,
                        "external_references": [
                            {"source": r.get("source_name"), "url": r.get("url")}
                            for r in ext_refs
                        ],
                        "enriched_by": connector_name
                    }

        return {
            "success": True,
            "message": "Enrichment requested, results pending",
            "value": value,
            "note": "Check OpenCTI UI for results or query again later"
        }

    # -------------------------------------------------------------------------
    # Result Formatting Methods
    # -------------------------------------------------------------------------

    def _format_indicators(self, results: list[Any]) -> list[dict[str, Any]]:
        """Format indicator results for output."""
        formatted = []
        for r in results:
            formatted.append({
                "type": "indicator",
                "name": r.get("name", ""),
                "pattern": r.get("pattern", ""),
                "pattern_type": r.get("pattern_type", ""),
                "description": r.get("description", "")[:500] if r.get("description") else "",
                "confidence": r.get("confidence", 0),
                "created": r.get("created", ""),
                "labels": [l.get("value") if isinstance(l, dict) else l for l in r.get("objectLabel", [])]
            })
        return formatted

    def _format_threat_actors(self, results: list[Any]) -> list[dict[str, Any]]:
        """Format threat actor results for output."""
        formatted = []
        for r in results:
            aliases = r.get("aliases") or []
            if isinstance(aliases, str):
                aliases = [aliases]
            formatted.append({
                "type": "threat_actor",
                "name": r.get("name", ""),
                "aliases": aliases,
                "description": r.get("description", "")[:500] if r.get("description") else "",
                "goals": r.get("goals") or [],
                "sophistication": r.get("sophistication", ""),
                "resource_level": r.get("resource_level", ""),
                "primary_motivation": r.get("primary_motivation", "")
            })
        return formatted

    def _format_malware(self, results: list[Any]) -> list[dict[str, Any]]:
        """Format malware results for output."""
        formatted = []
        for r in results:
            aliases = r.get("aliases") or []
            if isinstance(aliases, str):
                aliases = [aliases]
            formatted.append({
                "type": "malware",
                "name": r.get("name", ""),
                "aliases": aliases,
                "description": r.get("description", "")[:500] if r.get("description") else "",
                "malware_types": r.get("malware_types") or [],
                "is_family": r.get("is_family", False),
                "capabilities": r.get("capabilities") or []
            })
        return formatted

    def _format_attack_patterns(self, results: list[Any]) -> list[dict[str, Any]]:
        """Format attack pattern results for output."""
        formatted = []
        for r in results:
            formatted.append({
                "type": "attack_pattern",
                "name": r.get("name", ""),
                "x_mitre_id": r.get("x_mitre_id", ""),
                "description": r.get("description", "")[:500] if r.get("description") else "",
                "kill_chain_phases": [p.get("phase_name") if isinstance(p, dict) else p for p in r.get("killChainPhases", [])],
                "platforms": r.get("x_mitre_platforms", [])
            })
        return formatted

    def _format_reports(self, results: list[Any]) -> list[dict[str, Any]]:
        """Format report results for output."""
        formatted = []
        for r in results:
            formatted.append({
                "type": "report",
                "name": r.get("name", ""),
                "description": r.get("description", "")[:500] if r.get("description") else "",
                "published": r.get("published", ""),
                "report_types": r.get("report_types", []),
                "confidence": r.get("confidence", 0)
            })
        return formatted

    def _format_vulnerabilities(self, results: list[Any]) -> list[dict[str, Any]]:
        """Format vulnerability results for output."""
        formatted = []
        for r in results:
            formatted.append({
                "type": "vulnerability",
                "name": r.get("name", ""),
                "description": r.get("description", "")[:500] if r.get("description") else "",
                "cvss_score": r.get("x_opencti_cvss_base_score", ""),
                "cvss_severity": r.get("x_opencti_cvss_base_severity", "")
            })
        return formatted


# =============================================================================
# Output Formatting
# =============================================================================

def format_results(results: dict[str, Any], output_format: str = "text") -> str:
    """
    Format search results for display.

    Args:
        results: Dictionary of results by entity type
        output_format: Either "text" (human-readable) or "json"

    Returns:
        str: Formatted output string
    """
    if output_format == "json":
        return json.dumps(results, indent=2, default=str)

    lines = []

    for category, items in results.items():
        if category == "query":
            lines.append(f"Search: {items}")
            lines.append("=" * 60)
            continue

        if not items:
            continue

        lines.append(f"\n{category.upper().replace('_', ' ')} ({len(items)} results)")
        lines.append("-" * 40)

        for i, item in enumerate(items, 1):
            item_type = item.get("type", category)
            name = item.get("name", "Unknown")

            # Format based on entity type
            if item_type == "indicator":
                pattern = item.get("pattern", "")[:60]
                conf = item.get("confidence", 0)
                lines.append(f"[{i}] {name}")
                lines.append(f"    Pattern: {pattern}")
                lines.append(f"    Confidence: {conf}%")

            elif item_type == "threat_actor":
                aliases_list = item.get("aliases") or []
                aliases = ", ".join(aliases_list[:3]) if aliases_list else "None"
                lines.append(f"[{i}] {name}")
                lines.append(f"    Aliases: {aliases}")
                lines.append(f"    Motivation: {item.get('primary_motivation') or 'Unknown'}")

            elif item_type == "malware":
                types_list = item.get("malware_types") or []
                types = ", ".join(types_list) if types_list else "Unknown"
                lines.append(f"[{i}] {name}")
                lines.append(f"    Types: {types}")

            elif item_type == "attack_pattern":
                mitre_id = item.get("x_mitre_id", "")
                phases = ", ".join(item.get("kill_chain_phases", []))
                lines.append(f"[{i}] {mitre_id} - {name}")
                lines.append(f"    Kill Chain: {phases}")

            elif item_type == "report":
                published = item.get("published", "")[:10]
                lines.append(f"[{i}] {name}")
                lines.append(f"    Published: {published}")

            elif item_type == "vulnerability":
                cvss = item.get("cvss_score", "N/A")
                severity = item.get("cvss_severity", "Unknown")
                lines.append(f"[{i}] {name}")
                lines.append(f"    CVSS: {cvss} ({severity})")

            # Add truncated description if available
            desc = item.get("description", "")
            if desc:
                lines.append(f"    {desc[:100]}...")
            lines.append("")

    return "\n".join(lines)


# =============================================================================
# Main Entry Point
# =============================================================================

def main() -> None:
    """
    Main entry point for the OpenCTI query CLI.

    Handles argument parsing and dispatches to appropriate search methods.
    """
    parser = argparse.ArgumentParser(
        description="Query local OpenCTI instance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  opencti_query.py "APT29"
  opencti_query.py "cobalt strike" --type malware
  opencti_query.py "192.168.1.1" --type indicator --context
  opencti_query.py --recent 7
  opencti_query.py "T1003" --type attack_pattern

Enrichment examples:
  opencti_query.py --list-connectors
  opencti_query.py "8.8.8.8" --enrich
  opencti_query.py "44d88612fea8a8f36de82e1278abb02f" --enrich --connector VirusTotal
  opencti_query.py "evil.com" --enrich --wait
"""
    )

    # Positional argument: search query
    parser.add_argument("query", nargs="?", help="Search query")

    # Search options
    parser.add_argument("--type", "-t",
                        choices=["all", "indicator", "threat_actor", "malware",
                                "attack_pattern", "report", "vulnerability"],
                        default="all", help="Entity type to search")
    parser.add_argument("--limit", "-l", type=int, default=10,
                        help="Max results per category (default: 10)")
    parser.add_argument("--recent", "-r", type=int, metavar="DAYS",
                        help="Get indicators from last N days")
    parser.add_argument("--context", "-c", action="store_true",
                        help="Get full context for indicator")

    # Output options
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output as JSON")

    # Connection options
    parser.add_argument("--url", default=OPENCTI_URL,
                        help="OpenCTI URL")
    parser.add_argument("--token", default=None,
                        help="OpenCTI API token (or set OPENCTI_TOKEN env var)")

    # Enrichment options
    parser.add_argument("--enrich", "-e", action="store_true",
                        help="Trigger enrichment on observable (uses 1 API call)")
    parser.add_argument("--connector", default="VirusTotal",
                        help="Enrichment connector to use (default: VirusTotal)")
    parser.add_argument("--wait", "-w", action="store_true",
                        help="Wait for enrichment results (up to 30s)")
    parser.add_argument("--list-connectors", action="store_true",
                        help="List available enrichment connectors")

    args = parser.parse_args()

    # Validate arguments
    if not args.query and not args.recent and not args.list_connectors:
        parser.error("Either query, --recent, or --list-connectors is required")

    # Validate IOC format for indicator searches
    if args.query and args.type == "indicator":
        is_valid, detected_type, warning = validate_ioc_format(args.query)
        if not is_valid:
            print(f"Warning: {warning}", file=sys.stderr)
            print(f"Query may not return expected results.", file=sys.stderr)

    try:
        # Use provided token or fall back to configured token
        octi = OpenCTIQuery(url=args.url, token=args.token)

        # ---------------------------------------------------------------------
        # List Enrichment Connectors
        # ---------------------------------------------------------------------
        if args.list_connectors:
            connectors = octi.list_enrichment_connectors()
            if args.json:
                print(json.dumps(connectors, indent=2))
            else:
                print("Available Enrichment Connectors:")
                print("-" * 50)
                for c in connectors:
                    status = "active" if c["active"] else "inactive"
                    auto = "auto" if c["auto"] else "manual"
                    print(f"  {c['name']} ({status}, {auto})")
                    print(f"    Scope: {', '.join(c['scope'][:5])}")
            return

        # ---------------------------------------------------------------------
        # Enrichment Mode
        # ---------------------------------------------------------------------
        if args.enrich:
            if args.wait:
                results = octi.enrich_and_wait(args.query, args.connector)
            else:
                results = octi.enrich_observable(args.query, args.connector)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                if results.get("success"):
                    print(f"Enrichment: {results.get('message', 'Requested')}")
                    print(f"  Observable: {results.get('value')}")
                    print(f"  Type: {results.get('observable_type', 'unknown')}")
                    print(f"  Connector: {results.get('connector', args.connector)}")
                    if results.get("labels"):
                        print(f"  Labels: {', '.join(results['labels'])}")
                    if results.get("external_references"):
                        print("  References:")
                        for ref in results["external_references"]:
                            print(f"    - {ref['source']}: {ref['url']}")
                else:
                    print(f"Error: {results.get('error')}", file=sys.stderr)
                    sys.exit(1)
            return

        # ---------------------------------------------------------------------
        # Standard Search Modes
        # ---------------------------------------------------------------------
        if args.recent:
            # Get recent indicators
            results = {"recent_indicators": octi.get_recent_indicators(days=args.recent, limit=args.limit)}

        elif args.context and args.type == "indicator":
            # Get full context for a specific indicator
            context = octi.get_indicator_context(args.query)
            if args.json:
                print(json.dumps(context, indent=2, default=str))
            else:
                if context.get("found"):
                    print(f"Indicator: {context.get('indicator')}")
                    print(f"Type: {context.get('type')}")
                    print(f"Name: {context.get('name')}")
                    print(f"Confidence: {context.get('confidence')}%")
                    if context.get('description'):
                        print(f"Description: {context.get('description')[:200]}...")
                    if context.get('labels'):
                        print(f"Labels: {', '.join(context.get('labels', []))}")
                    if context.get('related_threats'):
                        print(f"Related Threats: {', '.join(context.get('related_threats', []))}")
                    if context.get('mitre_techniques'):
                        print(f"MITRE Techniques: {', '.join(context.get('mitre_techniques', []))}")
                else:
                    print(f"Indicator '{context.get('indicator')}' not found in OpenCTI")
            return

        elif args.type == "all":
            # Unified search across all entity types
            results = octi.unified_search(args.query, limit=args.limit)

        else:
            # Search specific entity type
            search_funcs = {
                "indicator": octi.search_indicators,
                "threat_actor": octi.search_threat_actors,
                "malware": octi.search_malware,
                "attack_pattern": octi.search_attack_patterns,
                "report": octi.search_reports,
                "vulnerability": octi.search_vulnerabilities
            }
            results = {args.type: search_funcs[args.type](args.query, args.limit)}

        # Output results
        output_format = "json" if args.json else "text"
        print(format_results(results, output_format))

    except ValueError as e:
        # Missing token or invalid configuration
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(2)
    except ConnectionError as e:
        print(f"Connection error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logger.exception("Unexpected error")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
