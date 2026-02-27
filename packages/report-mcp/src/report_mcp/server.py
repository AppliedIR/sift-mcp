"""AIIR report generation MCP server.

Exposes 6 tools for generating case reports, managing case metadata,
and persisting rendered reports. Data-driven profiles control what
data is included in each report type.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml
from aiir_cli.case_io import (
    load_case_meta,
    load_findings,
    load_timeline,
    load_todos,
)
from aiir_cli.commands.evidence import list_evidence_data
from mcp.server.fastmcp import FastMCP
from sift_common.audit import AuditWriter, resolve_examiner
from sift_common.instructions import REPORT_MCP as _INSTRUCTIONS
from sift_common.oplog import setup_logging

from report_mcp.profiles import PROFILES, STRIPPED_FINDING_FIELDS

logger = logging.getLogger(__name__)

_MAX_FILENAME = 200
_MAX_FIELD = 500
_MAX_REPORT_BYTES = 10 * 1024 * 1024  # 10 MB


def _validate_str_length(value: str | None, field: str, max_len: int) -> None:
    """Reject strings exceeding max_len or containing null bytes."""
    if value is not None and isinstance(value, str):
        if len(value) > max_len:
            raise ValueError(f"{field} exceeds maximum length of {max_len} characters")
        if "\x00" in value:
            raise ValueError(f"{field} contains invalid null byte")


# -- Metadata validation tables --

_ENUM_FIELDS: dict[str, set[str]] = {
    "incident_type": {
        "ransomware",
        "bec",
        "data_breach",
        "insider_threat",
        "supply_chain",
        "malware",
        "unauthorized_access",
        "dos",
        "other",
    },
    "severity": {"critical", "high", "medium", "low"},
    "tlp": {"WHITE", "GREEN", "AMBER", "AMBER+STRICT", "RED"},
}

_DATE_FIELDS = {
    "detected_at",
    "occurred_at",
    "reported_at",
    "contained_at",
    "eradicated_at",
    "recovered_at",
}

_LIST_FIELDS = {
    "affected_systems",
    "affected_accounts",
    "distribution_list",
    "tags",
    "related_cases",
}

_PROTECTED_FIELDS = {
    "case_id",
    "status",
    "created",
    "examiner",
    "closed",
    "close_summary",
    "name",
    "description",
}

# Free text fields that accept any string value
_TEXT_FIELDS = {"lead_examiner", "client", "point_of_contact", "impact_summary"}

# Valid filename characters
_FILENAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")


# -- Helper functions --


def _resolve_case_dir(case_id: str = "") -> Path:
    """Resolve case directory without sys.exit.

    Same priority as aiir CLI get_case_dir(), but raises ValueError
    instead of calling sys.exit().

    Side effect: sets AIIR_CASE_DIR env var so AuditWriter can find
    the audit directory.
    """
    if case_id:
        if ".." in case_id or "/" in case_id or "\\" in case_id:
            raise ValueError(f"Invalid case ID: {case_id}")
        cases_dir = Path(os.environ.get("AIIR_CASES_DIR", "cases"))
        case_dir = cases_dir / case_id
        if not case_dir.exists():
            raise ValueError(f"Case not found: {case_id}")
        os.environ["AIIR_CASE_DIR"] = str(case_dir)
        return case_dir

    env_dir = os.environ.get("AIIR_CASE_DIR")
    if env_dir:
        p = Path(env_dir)
        if not p.is_dir():
            raise ValueError(f"AIIR_CASE_DIR does not exist: {env_dir}")
        return p

    active_file = Path.home() / ".aiir" / "active_case"
    if active_file.exists():
        content = active_file.read_text().strip()
        if content:
            if os.path.isabs(content):
                case_dir = Path(content)
            else:
                if ".." in content or "/" in content or "\\" in content:
                    raise ValueError(
                        f"Invalid case ID in active_case: {content}"
                    )
                cases_dir = Path(os.environ.get("AIIR_CASES_DIR", "cases"))
                case_dir = cases_dir / content
            if not case_dir.is_dir():
                raise ValueError(
                    f"Case directory does not exist: {case_dir}"
                )
            os.environ["AIIR_CASE_DIR"] = str(case_dir)
            return case_dir

    raise ValueError("No active case. Use case_init or case_activate first.")


def _atomic_write(path: Path, content: str) -> None:
    """Write file atomically via temp file + rename."""
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _protected_write(path: Path, content: str) -> None:
    """Write to a chmod-444-protected case data file."""
    try:
        if path.exists():
            os.chmod(path, 0o644)
    except OSError:
        pass
    _atomic_write(path, content)
    try:
        os.chmod(path, 0o444)
    except OSError:
        pass


def _strip_finding(finding: dict) -> dict:
    """Remove internal fields from a finding for report output."""
    return {k: v for k, v in finding.items() if k not in STRIPPED_FINDING_FIELDS}


def _extract_all_iocs(
    findings: list[dict],
) -> dict[str, list[dict]]:
    """Extract IOCs from findings with cross-references to source finding IDs.

    Returns {type: [{value, source_findings: [ids]}]}.
    """
    # Collect: (type, value) -> set of finding IDs
    collected: dict[tuple[str, str], set[str]] = {}

    for f in findings:
        fid = f.get("id", "")

        # Structured IOC field
        iocs_field = f.get("iocs")
        if isinstance(iocs_field, dict):
            for ioc_type, values in iocs_field.items():
                if isinstance(values, list):
                    for v in values:
                        key = (ioc_type, str(v))
                        collected.setdefault(key, set()).add(fid)
                else:
                    key = (ioc_type, str(values))
                    collected.setdefault(key, set()).add(fid)
        elif isinstance(iocs_field, list):
            for ioc in iocs_field:
                if isinstance(ioc, dict):
                    ioc_type = ioc.get("type", "Unknown")
                    ioc_value = str(ioc.get("value", ""))
                    collected.setdefault((ioc_type, ioc_value), set()).add(fid)

        # Text extraction from description
        text = f.get("description", "")
        ipv4_pattern = (
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        )
        for ip in re.findall(ipv4_pattern, text):
            if not ip.startswith(("0.", "127.", "255.")):
                collected.setdefault(("IPv4", ip), set()).add(fid)
        for h in re.findall(r"\b[a-fA-F0-9]{64}\b", text):
            collected.setdefault(("SHA256", h.lower()), set()).add(fid)
        for h in re.findall(
            r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])", text
        ):
            collected.setdefault(("SHA1", h.lower()), set()).add(fid)
        for h in re.findall(
            r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])", text
        ):
            collected.setdefault(("MD5", h.lower()), set()).add(fid)
        for fp in re.findall(r"[A-Z]:\\(?:[^\s,;]+)", text):
            collected.setdefault(("File", fp), set()).add(fid)
        for d in re.findall(
            r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|cc|tk)\b",
            text,
        ):
            collected.setdefault(("Domain", d.lower()), set()).add(fid)

    # Group by type
    by_type: dict[str, list[dict]] = {}
    for (ioc_type, value), fids in sorted(collected.items()):
        by_type.setdefault(ioc_type, []).append(
            {"value": value, "source_findings": sorted(fids)}
        )

    return by_type


def _build_mitre_mapping(findings: list[dict]) -> dict[str, dict]:
    """Build MITRE ATT&CK mapping from findings.

    Returns {technique_id: {name, findings: [ids]}}.
    """
    mapping: dict[str, dict] = {}

    for f in findings:
        fid = f.get("id", "")
        techniques = f.get("mitre_techniques")
        if not techniques:
            continue
        if isinstance(techniques, list):
            for t in techniques:
                if isinstance(t, dict):
                    tid = t.get("id", t.get("technique_id", ""))
                    name = t.get("name", "")
                elif isinstance(t, str):
                    tid = t
                    name = ""
                else:
                    continue
                if tid:
                    if tid not in mapping:
                        mapping[tid] = {"name": name, "findings": []}
                    if fid and fid not in mapping[tid]["findings"]:
                        mapping[tid]["findings"].append(fid)
                    if name and not mapping[tid]["name"]:
                        mapping[tid]["name"] = name

    return mapping


def _build_summary(
    findings: list[dict],
    timeline: list[dict],
    todos: list[dict],
    evidence_count: int,
    iocs: dict,
) -> dict:
    """Build summary counts."""
    all_findings = findings  # Already loaded (may include non-approved for total count)
    approved_findings = [
        f for f in findings if f.get("status") == "APPROVED"
    ]
    approved_timeline = [
        t for t in timeline if t.get("status") == "APPROVED"
    ]
    ioc_count = sum(len(v) for v in iocs.values())
    open_todos = sum(1 for t in todos if t.get("status") == "open")

    return {
        "findings_total": len(all_findings),
        "findings_approved": len(approved_findings),
        "timeline_events": len(approved_timeline),
        "evidence_files": evidence_count,
        "ioc_count": ioc_count,
        "todos_open": open_todos,
    }


def _build_zeltser_guidance(
    profile_name: str, profile: dict, metadata: dict
) -> dict:
    """Construct Zeltser IR Writing MCP guidance for a profile."""
    tools = profile.get("zeltser_tools", [])
    if not tools:
        return {}

    guidance: dict = {
        "tools": tools,
        "workflow": [
            "1. Call ir_get_template() to get the IR report structure",
            "2. Call ir_load_context(incident_type=...) for case-specific guidance",
            "3. Call ir_get_guidelines() for writing best practices",
            "4. Write each narrative section using report_data and Zeltser guidance",
            "5. Call ir_review_report(sections=[...]) to review draft quality",
            "6. Call save_report(filename, content) to persist the final report",
        ],
        "parameters": {},
    }

    # Derive parameters from metadata
    incident_type = metadata.get("incident_type", "")
    if incident_type:
        guidance["parameters"]["ir_load_context"] = {
            "incident_type": incident_type
        }

    # Map profile to guidelines topic
    topic_map = {
        "full": "full_report",
        "executive": "executive_summary",
        "timeline": "timeline",
        "findings": "findings",
        "status": "status_brief",
    }
    topic = topic_map.get(profile_name)
    if topic:
        guidance["parameters"]["ir_get_guidelines"] = {"topic": topic}

    return guidance


def _generate(
    profile_name: str,
    case_dir: Path,
    finding_ids: list[str] | None = None,
    start_date: str = "",
    end_date: str = "",
) -> dict:
    """Core report generation logic."""
    profile = PROFILES[profile_name]

    # Load all data
    metadata = load_case_meta(case_dir)
    all_findings = load_findings(case_dir)
    all_timeline = load_timeline(case_dir)
    todos = load_todos(case_dir)

    # Evidence
    evidence_list: list[dict] = []
    try:
        ev_data = list_evidence_data(case_dir)
        evidence_list = ev_data.get("evidence", [])
    except (ValueError, OSError):
        pass
    evidence_count = len(evidence_list)

    # Filter approved only
    approved_findings = [
        f for f in all_findings if f.get("status") == "APPROVED"
    ]
    approved_timeline = [
        t for t in all_timeline if t.get("status") == "APPROVED"
    ]

    # Apply findings_mode
    findings_mode = profile.get("findings_mode", "all")
    if findings_mode == "all":
        report_findings = approved_findings
    elif findings_mode == "top_5":
        report_findings = approved_findings[:5]
    elif findings_mode == "count":
        report_findings = []
    elif findings_mode == "referenced":
        # Include findings referenced by other primary data
        report_findings = approved_findings
    else:
        report_findings = approved_findings

    # Apply finding_ids filter (findings profile)
    if finding_ids and profile.get("filterable", {}).get("finding_ids"):
        id_set = set(finding_ids)
        report_findings = [
            f for f in report_findings if f.get("id") in id_set
        ]

    # Apply timeline_mode
    timeline_mode = profile.get("timeline_mode", "all")
    if timeline_mode == "all":
        report_timeline = approved_timeline
    elif timeline_mode == "count":
        report_timeline = []
    elif timeline_mode == "referenced":
        report_timeline = approved_timeline
    elif timeline_mode == "none":
        report_timeline = []
    else:
        report_timeline = approved_timeline

    # Apply date filters (timeline profile)
    if start_date and profile.get("filterable", {}).get("start_date"):
        report_timeline = [
            t
            for t in report_timeline
            if t.get("timestamp", "") >= start_date
        ]
    if end_date and profile.get("filterable", {}).get("end_date"):
        report_timeline = [
            t
            for t in report_timeline
            if t.get("timestamp", "") <= end_date
        ]

    # Strip internal fields from findings
    stripped_findings = [_strip_finding(f) for f in report_findings]

    # IOC aggregation
    iocs = _extract_all_iocs(approved_findings)

    # MITRE mapping
    mitre = _build_mitre_mapping(approved_findings)

    # Open TODOs
    open_todos = [t for t in todos if t.get("status") == "open"]

    # Build summary with all findings (not just report-filtered)
    summary = _build_summary(
        all_findings, all_timeline, todos, evidence_count, iocs
    )

    # Assemble report_data based on profile's data_keys
    data_keys = profile.get("data_keys", [])
    report_data: dict = {}
    if "metadata" in data_keys:
        report_data["metadata"] = metadata
    if "findings" in data_keys:
        if findings_mode == "count":
            report_data["findings_count"] = len(approved_findings)
        else:
            report_data["findings"] = stripped_findings
    elif findings_mode == "count":
        # Count-only mode: emit count even if "findings" not in data_keys
        report_data["findings_count"] = len(approved_findings)
    if "timeline" in data_keys:
        if timeline_mode == "count":
            report_data["timeline_count"] = len(approved_timeline)
        else:
            report_data["timeline"] = report_timeline
    elif timeline_mode == "count":
        # Count-only mode: emit count even if "timeline" not in data_keys
        report_data["timeline_count"] = len(approved_timeline)
    if "iocs" in data_keys:
        report_data["iocs"] = iocs
    if "mitre_mapping" in data_keys:
        report_data["mitre_mapping"] = mitre
    if "evidence" in data_keys:
        report_data["evidence"] = evidence_list
    if "todos" in data_keys:
        if findings_mode == "count" or timeline_mode == "count":
            # Status/executive: include open count or full list
            report_data["todos"] = open_todos
        else:
            report_data["todos"] = open_todos
    if "summary" in data_keys:
        report_data["summary"] = summary

    # Build sections
    sections = profile.get("sections", [])

    # Build Zeltser guidance
    zeltser_guidance = _build_zeltser_guidance(
        profile_name, profile, metadata
    )

    result: dict = {
        "profile": profile_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_data": report_data,
        "sections": sections,
    }
    if zeltser_guidance:
        result["zeltser_guidance"] = zeltser_guidance

    # Verification ledger reconciliation
    case_id = metadata.get("case_id", "")
    if case_id:
        try:
            alerts = _reconcile_verification(
                case_id, approved_findings, approved_timeline
            )
            if alerts:
                result["verification_alerts"] = alerts
        except Exception:
            pass  # Non-fatal — ledger may not be available

    return result


VERIFICATION_DIR = Path("/var/lib/aiir/verification")


def _reconcile_verification(
    case_id: str,
    approved_findings: list[dict],
    approved_timeline: list[dict],
) -> list[dict]:
    """Bidirectional check: approved items vs verification ledger.

    No PIN needed — this checks structural consistency (item counts,
    description text matches) not cryptographic HMAC validity.
    """
    ledger_path = VERIFICATION_DIR / f"{case_id}.jsonl"
    if not ledger_path.exists():
        return [{"alert": "NO_VERIFICATION_LEDGER", "detail": "No ledger found"}]

    ledger_entries: list[dict] = []
    try:
        for line in ledger_path.read_text().splitlines():
            if line.strip():
                ledger_entries.append(json.loads(line))
    except (OSError, json.JSONDecodeError):
        return [{"alert": "LEDGER_READ_ERROR", "detail": "Could not read ledger"}]

    ledger_by_id = {e["finding_id"]: e for e in ledger_entries}
    all_approved = approved_findings + approved_timeline
    items_by_id = {i["id"]: i for i in all_approved}
    all_ids = set(items_by_id) | set(ledger_by_id)

    results: list[dict] = []
    for item_id in sorted(all_ids):
        item = items_by_id.get(item_id)
        entry = ledger_by_id.get(item_id)
        if item and not entry:
            results.append({"id": item_id, "status": "APPROVED_NO_VERIFICATION"})
        elif entry and not item:
            results.append({"id": item_id, "status": "VERIFICATION_NO_FINDING"})
        elif item and entry:
            # Construct text the same way approve.py does for HMAC signing
            if item_id.startswith("T-"):
                live_text = item.get("description", "")
            else:
                live_text = item.get("observation", "") + "\n" + item.get("interpretation", "")
            if live_text != entry.get("description_snapshot", ""):
                results.append({"id": item_id, "status": "DESCRIPTION_MISMATCH"})
            else:
                results.append({"id": item_id, "status": "VERIFIED"})

    if len(all_approved) != len(ledger_entries):
        results.append({
            "id": "_summary",
            "status": "COUNT_MISMATCH",
            "detail": f"approved={len(all_approved)}, ledger={len(ledger_entries)}",
        })
    return results


def _validate_iso8601(value: str) -> bool:
    """Check if value looks like an ISO 8601 datetime."""
    try:
        datetime.fromisoformat(value)
        return True
    except (ValueError, TypeError):
        return False


def create_server() -> FastMCP:
    """Create and configure the report generation MCP server."""
    server = FastMCP("report-mcp", instructions=_INSTRUCTIONS)
    audit = AuditWriter(mcp_name="report-mcp")

    server._audit = audit

    # ------------------------------------------------------------------
    # Tool 1: generate_report
    # ------------------------------------------------------------------
    @server.tool()
    def generate_report(
        profile: str,
        case_id: str = "",
        finding_ids: list[str] | None = None,
        start_date: str = "",
        end_date: str = "",
    ) -> str:
        """Generate a structured report with case data filtered by profile.

        Available profiles: full, executive, timeline, ioc, findings, status.
        Use list_profiles() to see descriptions and Zeltser tool mappings.

        Returns structured JSON with report_data, sections template, and
        Zeltser IR Writing MCP guidance for narrative sections.

        Optional filters:
        - finding_ids: limit findings profile to specific finding IDs
        - start_date/end_date: limit timeline profile by ISO 8601 date range
        """
        try:
            if profile not in PROFILES:
                return json.dumps(
                    {
                        "error": f"Unknown profile: {profile}. "
                        f"Valid profiles: {', '.join(sorted(PROFILES))}"
                    }
                )
            case_dir = _resolve_case_dir(case_id)
            result = _generate(
                profile, case_dir, finding_ids, start_date, end_date
            )
            audit.log(
                tool="generate_report",
                params={
                    "profile": profile,
                    "finding_ids": finding_ids,
                    "start_date": start_date,
                    "end_date": end_date,
                },
                result_summary={
                    "profile": profile,
                    "findings": len(
                        result.get("report_data", {}).get("findings", [])
                    ),
                },
            )
            return json.dumps(result, default=str)
        except (ValueError, OSError) as e:
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool 2: set_case_metadata
    # ------------------------------------------------------------------
    @server.tool()
    def set_case_metadata(field: str, value: str | list = "") -> str:
        """Set a single metadata field in CASE.yaml.

        Validated fields: incident_type, severity, tlp (enums);
        detected_at, occurred_at, etc. (ISO 8601 dates);
        affected_systems, tags, etc. (lists).

        Protected fields (case_id, status, name, etc.) are rejected.
        Unknown fields are accepted and stored as-is.
        """
        try:
            _validate_str_length(field, "field", _MAX_FIELD)
            if isinstance(value, str):
                _validate_str_length(value, "value", 10_000)
            if field in _PROTECTED_FIELDS:
                return json.dumps(
                    {
                        "error": f"Field '{field}' is protected and cannot "
                        f"be set via this tool. Protected fields: "
                        f"{', '.join(sorted(_PROTECTED_FIELDS))}"
                    }
                )

            # Validate enum fields
            if field in _ENUM_FIELDS:
                if value not in _ENUM_FIELDS[field]:
                    return json.dumps(
                        {
                            "error": f"Invalid value for {field}: {value}. "
                            f"Valid values: {', '.join(sorted(_ENUM_FIELDS[field]))}"
                        }
                    )

            # Validate date fields
            if field in _DATE_FIELDS:
                if not isinstance(value, str) or not _validate_iso8601(value):
                    return json.dumps(
                        {
                            "error": f"Field '{field}' requires an ISO 8601 "
                            f"datetime string."
                        }
                    )

            # Validate list fields
            if field in _LIST_FIELDS:
                if not isinstance(value, list):
                    return json.dumps(
                        {
                            "error": f"Field '{field}' requires a list value."
                        }
                    )

            case_dir = _resolve_case_dir()
            meta_file = case_dir / "CASE.yaml"
            meta = load_case_meta(case_dir)
            meta[field] = value

            _atomic_write(
                meta_file, yaml.dump(meta, default_flow_style=False)
            )

            audit.log(
                tool="set_case_metadata",
                params={"field": field, "value": value},
                result_summary={"status": "set", "field": field},
            )
            return json.dumps(
                {"status": "set", "field": field, "value": value},
                default=str,
            )
        except (ValueError, OSError) as e:
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool 3: get_case_metadata
    # ------------------------------------------------------------------
    @server.tool()
    def get_case_metadata(field: str = "") -> str:
        """Retrieve case metadata from CASE.yaml.

        If field is empty, returns all metadata. If field is specified,
        returns that field's value (or null if not set).
        """
        try:
            case_dir = _resolve_case_dir()
            meta = load_case_meta(case_dir)

            if not field:
                return json.dumps(meta, default=str)

            return json.dumps(
                {"field": field, "value": meta.get(field)}, default=str
            )
        except (ValueError, OSError) as e:
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool 4: list_profiles
    # ------------------------------------------------------------------
    @server.tool()
    def list_profiles() -> str:
        """List available report profiles with descriptions and
        Zeltser tool mappings."""
        profiles = []
        for name, profile in PROFILES.items():
            profiles.append(
                {
                    "name": name,
                    "description": profile["description"],
                    "zeltser_tools": profile.get("zeltser_tools", []),
                }
            )
        return json.dumps({"profiles": profiles})

    # ------------------------------------------------------------------
    # Tool 5: save_report
    # ------------------------------------------------------------------
    @server.tool()
    def save_report(
        filename: str, content: str, profile: str = ""
    ) -> str:
        """Persist a rendered report to the case reports/ directory.

        Filename is sanitized: only alphanumeric characters, hyphens,
        underscores, and dots are allowed. Path traversal is blocked.
        """
        try:
            _validate_str_length(filename, "filename", _MAX_FILENAME)
            if len(content.encode("utf-8", errors="replace")) > _MAX_REPORT_BYTES:
                return json.dumps(
                    {"error": f"Report content exceeds maximum size of 10 MB."}
                )
            # Block path traversal
            if ".." in filename or "/" in filename or "\\" in filename:
                return json.dumps(
                    {"error": "Invalid filename: path traversal not allowed."}
                )

            # Sanitize filename
            sanitized = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)
            if not sanitized:
                return json.dumps({"error": "Filename is empty after sanitization."})

            case_dir = _resolve_case_dir()
            reports_dir = case_dir / "reports"
            reports_dir.mkdir(exist_ok=True)

            report_path = reports_dir / sanitized

            _atomic_write(report_path, content)

            audit.log(
                tool="save_report",
                params={
                    "filename": sanitized,
                    "profile": profile,
                    "characters": len(content),
                },
                result_summary={"status": "saved", "filename": sanitized},
            )
            return json.dumps(
                {
                    "status": "saved",
                    "path": str(report_path),
                    "filename": sanitized,
                    "profile": profile,
                    "characters": len(content),
                }
            )
        except (ValueError, OSError) as e:
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool 6: list_reports
    # ------------------------------------------------------------------
    @server.tool()
    def list_reports() -> str:
        """List saved reports in the case reports/ directory."""
        try:
            case_dir = _resolve_case_dir()
            reports_dir = case_dir / "reports"

            if not reports_dir.exists():
                return json.dumps({"reports": []})

            reports = []
            for p in sorted(reports_dir.iterdir()):
                if p.is_file():
                    stat = p.stat()
                    reports.append(
                        {
                            "filename": p.name,
                            "size_bytes": stat.st_size,
                            "created_at": datetime.fromtimestamp(
                                stat.st_ctime, tz=timezone.utc
                            ).isoformat(),
                        }
                    )
            return json.dumps({"reports": reports})
        except (ValueError, OSError) as e:
            return json.dumps({"error": str(e)})

    return server


def main() -> None:
    """Run the report-mcp server."""
    setup_logging("report-mcp")
    logger.info("Starting report-mcp server")
    server = create_server()
    server.run()
