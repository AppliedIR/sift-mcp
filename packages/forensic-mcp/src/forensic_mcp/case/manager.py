"""Case manager: investigation records, TODOs, evidence listing, grounding.

Local-first: each examiner owns a flat case directory. Case lifecycle
(init, close, activate) is handled by case-mcp and the vhir CLI.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from forensic_mcp.audit import resolve_examiner
from forensic_mcp.discipline.validation import validate as validate_finding_data

logger = logging.getLogger(__name__)


def _atomic_write(path: Path, content: str) -> None:
    """Write file atomically via temp file + rename to prevent data loss on crash."""
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _protected_write(path: Path, content: str) -> None:
    """Write to a chmod-444-protected case data file.

    Uses atomic write (tempfile + rename), then locks (0o444).
    The temp file is created writable, so we only need to unlock the
    existing file for _atomic_write's rename to succeed on the same inode.
    """
    try:
        if path.exists():
            os.chmod(path, 0o644)
    except OSError:
        pass  # May already be writable or on non-POSIX fs
    try:
        _atomic_write(path, content)
    finally:
        # Always re-lock, even if the write failed partway
        try:
            if path.exists():
                os.chmod(path, 0o444)
        except OSError:
            pass  # Non-POSIX filesystem


CASES_DIR_ENV = "VHIR_CASES_DIR"
DEFAULT_CASES_DIR = str(Path.home() / "cases")
_ACTIVE_CASE_FILE = Path.home() / ".vhir" / "active_case"

# Audit ID format: prefix-examiner-YYYYMMDD-NNN (all lowercase alphanumeric + hyphens)
_AUDIT_ID_PATTERN = re.compile(r"^[a-z]+-[a-z0-9]+-[0-9]{8}-[0-9]{3,}\Z")

# Allowlist: only these fields pass through from user-supplied finding data
_ALLOWED_FINDING_FIELDS = {
    "title",
    "observation",
    "interpretation",
    "confidence",
    "confidence_justification",
    "type",
    "audit_ids",
    "mitre_ids",
    "iocs",
    "event_type",
    "artifact_ref",
    "related_findings",
    "host",
    "event_timestamp",
    "affected_account",
}
_PROTECTED_EVENT_FIELDS = {
    "id",
    "status",
    "staged",
    "modified_at",
    "created_by",
    "examiner",
}

# Keys excluded from content hash — volatile/derived fields
_HASH_EXCLUDE_KEYS = {
    "status",
    "approved_at",
    "approved_by",
    "rejected_at",
    "rejected_by",
    "rejection_reason",
    "examiner_notes",
    "examiner_modifications",
    "content_hash",
    "verification",
    "modified_at",
    "provenance",
    "provenance_warnings",
    "timeline_event_id",
    "source_evidence",
}


def _compute_content_hash(item: dict) -> str:
    """SHA-256 of canonical JSON excluding volatile fields.

    Duplicated from vhir-cli case_io.py — forensic-mcp does NOT depend on
    vhir-cli. Kept in sync manually.
    """
    hashable = {k: v for k, v in item.items() if k not in _HASH_EXCLUDE_KEYS}
    canonical = json.dumps(hashable, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _next_seq(items: list[dict], id_field: str, prefix: str, examiner: str) -> int:
    """Find max sequence number for IDs matching {prefix}-{examiner}-NNN."""
    pattern = f"{prefix}-{examiner}-"
    max_num = 0
    for item in items:
        item_id = item.get(id_field, "")
        if item_id.startswith(pattern):
            try:
                num = int(item_id[len(pattern) :])
                max_num = max(max_num, num)
            except ValueError:
                pass
    return max_num + 1


def _resolve_source_evidence_static(
    input_files: list[str],
    audit_entries: list[dict],
    evidence_registry: set[str],
    visited: set[str] | None = None,
    depth: int = 0,
    max_depth: int = 10,
    evidence_by_hash: dict[str, str] | None = None,
) -> str:
    """Walk input files backward through audit trail to find registered evidence.

    Tries path matching first, then falls back to hash matching for
    cross-platform paths (e.g., Windows UNC vs Linux local).
    """
    if depth >= max_depth:
        return ""
    if visited is None:
        visited = set()
    for path in input_files:
        resolved = str(Path(path).resolve())
        if resolved in visited:
            continue
        visited.add(resolved)
        if resolved in evidence_registry:
            return resolved
        # Hash-based fallback: match input_sha256s against evidence hashes
        if evidence_by_hash:
            for entry in audit_entries:
                entry_inputs = entry.get("input_files", [])
                entry_hashes = entry.get("input_sha256s", [])
                for i, inp in enumerate(entry_inputs):
                    if str(Path(inp).resolve()) == resolved and i < len(entry_hashes):
                        h = entry_hashes[i]
                        if h and h in evidence_by_hash:
                            return evidence_by_hash[h]
        for entry in audit_entries:
            output = entry.get("result_summary", {}).get("output_file", "")
            if output and str(Path(output).resolve()) == resolved:
                parent_inputs = entry.get("input_files", [])
                if parent_inputs:
                    result = _resolve_source_evidence_static(
                        parent_inputs,
                        audit_entries,
                        evidence_registry,
                        visited,
                        depth + 1,
                        max_depth,
                        evidence_by_hash,
                    )
                    if result:
                        return result
    return ""


# --- IOC helpers ---

_CONF_RANKS = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "SPECULATIVE": 3}


def _conf_rank(conf: str) -> int:
    return _CONF_RANKS.get(conf.upper() if conf else "", 99)


def _refang_ioc(value: str) -> str:
    """Refang defanged IOC values."""
    v = value.replace("[.]", ".").replace("hxxp", "http")
    v = re.sub(r"\[(\W)\]", r"\1", v)
    return v


def _normalize_ioc(value: str) -> str:
    """Normalize IOC value for dedup comparison."""
    v = value.strip()
    if re.match(r"^[a-fA-F0-9]{32,64}$", v):
        return v.lower()
    if "." in v and not v.replace(".", "").isdigit():
        return v.lower().rstrip(".")
    if "\\" in v:
        return v.lower()
    return v


def _detect_ioc_type(value: str) -> tuple[str, str]:
    """Auto-detect IOC type and category from value pattern."""
    v = value.strip()

    # URL (before domain check)
    if re.match(r"^https?://", v, re.IGNORECASE):
        return "url", "network"

    # Email
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
        return "email-addr", "network"

    # File hashes (most specific first)
    if re.match(r"^[a-fA-F0-9]{64}$", v):
        return "file:hash:sha256", "host"
    if re.match(r"^[a-fA-F0-9]{40}$", v):
        return "file:hash:sha1", "host"
    if re.match(r"^[a-fA-F0-9]{32}$", v):
        return "file:hash:md5", "host"

    # IPv4 (strip CIDR/port for detection, store original)
    stripped = re.sub(r"[:/]\d{1,5}$", "", v)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", stripped):
        octets = stripped.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            return "ipv4-addr", "network"

    # IPv6
    if re.match(r"^[0-9a-fA-F:]{6,}$", v) and v.count(":") >= 2:
        return "ipv6-addr", "network"

    # Registry key
    if re.match(r"^HK(EY_|LM|CU|CR|U\\)", v, re.IGNORECASE):
        return "registry-key", "system"

    # Scheduled task
    if v.startswith("\\Microsoft\\") or v.startswith("\\Windows\\"):
        return "scheduled-task", "system"

    # User account (domain\user or UPN)
    if re.match(r"^[a-zA-Z0-9._-]+\\[a-zA-Z0-9._-]+$", v):
        return "user-account", "identity"

    # File name with executable extension (before domain — .exe/.sys/.dll match domain regex)
    _EXE_EXTS = (
        ".exe",
        ".sys",
        ".dll",
        ".bat",
        ".ps1",
        ".cmd",
        ".vbs",
        ".js",
        ".msi",
        ".scr",
    )
    if "." in v and v.lower().endswith(_EXE_EXTS) and "/" not in v and "\\" not in v:
        return "file:name", "host"

    # Domain name
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$", v):
        return "domain-name", "network"

    # Process command line
    if ".exe " in v.lower() or ".exe\t" in v.lower():
        return "process:command-line", "system"

    # File path
    if "/" in v or "\\" in v:
        return "file:path", "host"

    # File name (has extension)
    if re.match(r"^[^/\\]+\.[a-zA-Z0-9]{1,10}$", v):
        return "file:name", "host"

    # Service name (strict: alphanumeric, 3-30 chars)
    if re.match(r"^[a-zA-Z][a-zA-Z0-9]{2,29}$", v) and (
        v.lower().endswith("svc") or v.lower().endswith("service")
    ):
        return "service-name", "system"

    return "unknown", "unknown"


def _compute_ioc_hash(ioc: dict) -> str:
    """Compute content hash for IOC using whitelist of stable fields."""
    hashable = {
        k: ioc.get(k)
        for k in (
            "value",
            "type",
            "category",
            "description",
            "tags",
            "mitre_techniques",
        )
        if ioc.get(k) is not None
    }
    canonical = json.dumps(hashable, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _validate_case_id(case_id: str) -> None:
    """Validate case_id to prevent path traversal."""
    if not case_id or not case_id.strip():
        raise ValueError("Case ID cannot be empty")
    if "\x00" in case_id:
        raise ValueError("Case ID contains null byte")
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        raise ValueError(f"Invalid case ID (path traversal characters): {case_id}")


def _validate_examiner(examiner: str) -> None:
    """Validate examiner slug: lowercase alphanumeric + hyphens, max 20 chars."""
    if not examiner:
        raise ValueError("Examiner identity cannot be empty")
    if not re.match(r"^[a-z0-9][a-z0-9-]{0,19}$", examiner):
        raise ValueError(
            f"Invalid examiner '{examiner}': must be lowercase alphanumeric + hyphens, max 20 chars"
        )


# MITRE tactic → event_type mapping for auto-created timeline events
_MITRE_EVENT_TYPE = {
    "T10": "execution",  # T1059 etc.
    "T11": "persistence",  # T1136 etc.
    "T12": "execution",  # T1204 etc.
    "T13": "persistence",  # T1353 etc.
    "T14": "execution",  # T1489 etc.
    "T15": "other",  # T15xx varies
    "T1003": "execution",  # Credential Dumping
    "T1021": "lateral",  # Remote Services
    "T1047": "execution",  # WMI
    "T1053": "persistence",  # Scheduled Task
    "T1055": "execution",  # Process Injection
    "T1059": "execution",  # Command Interpreter
    "T1078": "auth",  # Valid Accounts
    "T1098": "persistence",  # Account Manipulation
    "T1110": "auth",  # Brute Force
    "T1190": "network",  # Exploit Public App
    "T1543": "persistence",  # Create/Modify Service
    "T1547": "persistence",  # Boot/Logon Autostart
    "T1548": "execution",  # Abuse Elevation
    "T1562": "other",  # Impair Defenses
    "T1566": "network",  # Phishing
    "T1570": "lateral",  # Lateral Tool Transfer
}


def _infer_event_type(sanitized: dict) -> str:
    """Best-effort event_type from MITRE technique IDs."""
    mitre_ids = sanitized.get("mitre_ids", [])
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]
    for mid in mitre_ids:
        mid = mid.strip().upper()
        # Try exact match first (T1021), then prefix (T10)
        if mid in _MITRE_EVENT_TYPE:
            return _MITRE_EVENT_TYPE[mid]
        prefix = mid[:3]  # T10, T11, etc.
        if prefix in _MITRE_EVENT_TYPE:
            return _MITRE_EVENT_TYPE[prefix]
    return ""


class CaseManager:
    """Manages forensic investigation cases."""

    def __init__(self) -> None:
        self._active_case_id: str | None = None
        self._active_case_path: Path | None = None

    @property
    def cases_dir(self) -> Path:
        return Path(os.environ.get(CASES_DIR_ENV, DEFAULT_CASES_DIR))

    @property
    def active_case_dir(self) -> Path | None:
        if self._active_case_path:
            return self._active_case_path
        if not self._active_case_id:
            return None
        return self.cases_dir / self._active_case_id

    @property
    def examiner(self) -> str:
        return resolve_examiner()

    def _require_active_case(self) -> Path:
        # Re-read active_case file on every call to detect case switches
        active_file = _ACTIVE_CASE_FILE
        if active_file.exists():
            try:
                content = active_file.read_text().strip()
            except OSError:
                content = ""
            if content:
                if os.path.isabs(content):
                    case_dir = Path(content)
                    new_id = case_dir.name
                else:
                    _validate_case_id(content)
                    case_dir = self.cases_dir / content
                    new_id = content
                if case_dir.is_dir() and (case_dir / "CASE.yaml").exists():
                    if (
                        new_id != self._active_case_id
                        and self._active_case_id is not None
                    ):
                        logger.info(
                            "Case switched: %s → %s", self._active_case_id, new_id
                        )
                    self._active_case_id = new_id
                    self._active_case_path = case_dir
        d = self.active_case_dir
        if d is None or not d.exists():
            raise ValueError("No active case. Run 'vhir case activate <id>' first.")
        # Safety belt: refuse closed cases
        meta_file = d / "CASE.yaml"
        if meta_file.exists():
            try:
                meta = yaml.safe_load(meta_file.read_text()) or {}
                if meta.get("status") == "closed":
                    raise ValueError(
                        f"Case {self._active_case_id} is closed. "
                        f"Run 'vhir case reopen {self._active_case_id}' or "
                        f"'vhir case activate <id>' to work on a different case."
                    )
            except yaml.YAMLError:
                pass
        return d

    def _effective_examiner(self, override: str = "") -> str:
        """Return override if non-empty, otherwise self.examiner.

        Used by gateway to propagate per-request examiner identity.
        """
        return (
            override.strip().lower() if override and override.strip() else self.examiner
        )

    def get_case_status(self, case_id: str | None = None) -> dict:
        """Get investigation summary."""
        case_dir = self._resolve_case_dir(case_id)
        meta = self._load_case_meta(case_dir)
        findings = self._load_findings(case_dir)
        timeline = self._load_timeline(case_dir)
        evidence = self._load_evidence_registry(case_dir)
        todos = self._load_todos(case_dir)

        resp = {
            "case_id": meta["case_id"],
            "name": meta.get("name", ""),
            "status": meta.get("status", "unknown"),
            "examiner": meta.get("examiner", ""),
            "findings": {
                "total": len(findings),
                "draft": sum(1 for f in findings if f.get("status") == "DRAFT"),
                "approved": sum(1 for f in findings if f.get("status") == "APPROVED"),
                "rejected": sum(1 for f in findings if f.get("status") == "REJECTED"),
            },
            "timeline_events": len(timeline),
            "evidence_files": len(evidence.get("files", [])),
            "todos": {
                "total": len(todos),
                "open": sum(1 for t in todos if t.get("status") == "open"),
                "completed": sum(1 for t in todos if t.get("status") == "completed"),
            },
        }

        # Layer 4: platform capabilities detection
        import importlib.util

        capabilities = {
            "opensearch": importlib.util.find_spec("opensearch_mcp") is not None,
            "remnux": False,
            "wintools": False,
            "forensic_rag": importlib.util.find_spec("rag_mcp") is not None,
            "opencti": importlib.util.find_spec("opencti_mcp") is not None,
            "sift_tools": True,
        }
        try:
            gw_path = Path.home() / ".vhir" / "gateway.yaml"
            if gw_path.exists():
                gw_config = yaml.safe_load(gw_path.read_text()) or {}
                backends = gw_config.get("backends", {})
                capabilities["remnux"] = "remnux-mcp" in backends
                capabilities["wintools"] = "wintools-mcp" in backends
        except Exception:
            pass
        resp["platform_capabilities"] = capabilities

        guidance = ["Available investigation capabilities:"]
        guidance.append("- SIFT forensic tools via run_command (65+ tools)")
        if capabilities["opensearch"]:
            guidance.append(
                "- Evidence indexing: idx_ingest for structured querying at scale"
            )
        if capabilities["remnux"]:
            guidance.append(
                "- Malware analysis: upload_from_host + analyze_file on REMnux"
            )
        if capabilities["wintools"]:
            guidance.append(
                "- Windows offline analysis: run_windows_command on forensic workstation"
            )
        if capabilities["forensic_rag"]:
            guidance.append(
                "- Knowledge search: search_knowledge (Sigma, MITRE ATT&CK, KAPE)"
            )
        if capabilities["opencti"]:
            guidance.append(
                "- Threat intel: lookup_ioc, search_threat_intel on OpenCTI"
            )
        guidance.append("")
        guidance.append(
            "Do not rely solely on OpenSearch queries. "
            "Call suggest_tools(artifact_type='...') for deep analysis recommendations."
        )
        resp["investigation_guidance"] = "\n".join(guidance)

        return resp

    def list_cases(self) -> list[dict]:
        """List all cases."""
        if not self.cases_dir.exists():
            return []
        results = []
        for case_dir in sorted(self.cases_dir.iterdir()):
            if case_dir.is_dir() and (case_dir / "CASE.yaml").exists():
                meta = self._load_case_meta(case_dir)
                results.append(
                    {
                        "case_id": meta["case_id"],
                        "name": meta.get("name", ""),
                        "status": meta.get("status", "unknown"),
                        "created": meta.get("created", ""),
                        "examiner": meta.get("examiner", ""),
                    }
                )
        return results

    # --- Investigation Records ---

    def record_action(
        self,
        description: str,
        tool: str = "",
        command: str = "",
        examiner_override: str = "",
    ) -> dict:
        """Append action to actions.jsonl."""
        case_dir = self._require_active_case()
        ts = datetime.now(timezone.utc).isoformat()
        exam = self._effective_examiner(examiner_override)

        entry: dict[str, Any] = {
            "ts": ts,
            "description": description,
            "examiner": exam,
        }
        if tool:
            entry["tool"] = tool
        if command:
            entry["command"] = command

        try:
            with open(case_dir / "actions.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            logger.warning("Failed to write action log: %s", e)
            return {"status": "write_failed", "timestamp": ts, "error": str(e)}

        return {"status": "recorded", "timestamp": ts}

    def record_finding(
        self,
        finding: dict,
        examiner_override: str = "",
        supporting_commands: list[dict] | None = None,
        artifacts: list[dict] | None = None,
        audit: Any | None = None,
    ) -> dict:
        """Validate and stage finding as DRAFT.

        Args:
            finding: Finding data dict.
            examiner_override: Override examiner identity.
            supporting_commands: List of shell commands that produced evidence.
                Each dict must have command, output_excerpt, purpose.
            audit: AuditWriter instance (needed for shell audit ID generation).
        """
        case_dir = self._require_active_case()

        # Validate via discipline module
        validation = validate_finding_data(finding)
        if not validation.get("valid", False):
            return {
                "status": "VALIDATION_FAILED",
                "errors": validation.get("errors", []),
            }
        # Carry forward validation warnings
        validation_warnings = validation.get("warnings", [])

        exam = self._effective_examiner(examiner_override)

        # Auto-extract supporting_commands/artifacts if LLM passed them inline
        if supporting_commands is None and isinstance(
            finding.get("supporting_commands"), list
        ):
            supporting_commands = finding.pop("supporting_commands")
        if artifacts is None and isinstance(finding.get("artifacts"), list):
            artifacts = finding.pop("artifacts")

        findings = self._load_findings(case_dir)
        seq = _next_seq(findings, "id", "F", exam)
        finding_id = f"F-{exam}-{seq:03d}"
        now = datetime.now(timezone.utc).isoformat()
        today = datetime.now(timezone.utc).strftime("%Y%m%d")

        # Allowlist: only accepted fields pass through from user input
        sanitized = {k: v for k, v in finding.items() if k in _ALLOWED_FINDING_FIELDS}

        # Truncate string fields with explicit limits
        if sanitized.get("host"):
            sanitized["host"] = str(sanitized["host"])[:200]
        if sanitized.get("affected_account"):
            sanitized["affected_account"] = str(sanitized["affected_account"])[:200]

        # Process supporting_commands — generate shell audit IDs
        shell_audit_ids: list[str] = []
        validated_commands: list[dict] = []
        audit_warnings: list[str] = []
        if supporting_commands:
            for _i, cmd in enumerate(supporting_commands[:5]):
                if not isinstance(cmd, dict):
                    continue
                command = cmd.get("command", "")
                output_excerpt = cmd.get("output_excerpt", "")
                purpose = cmd.get("purpose", "")
                if not command or not purpose:
                    continue
                # Truncate output_excerpt
                if len(output_excerpt) > 2000:
                    output_excerpt = output_excerpt[:2000]
                shell_seq = self._next_shell_seq(case_dir, exam, today)
                shell_eid = f"shell-{exam}-{today}-{shell_seq:03d}"
                shell_audit_ids.append(shell_eid)
                validated_cmd = {
                    "command": command,
                    "output_excerpt": output_excerpt,
                    "purpose": purpose,
                }
                validated_commands.append(validated_cmd)
                # Write audit entry for this shell command
                if audit:
                    logged_id = audit.log(
                        tool="supporting_command",
                        params={"command": command, "purpose": purpose},
                        result_summary={"output_excerpt": output_excerpt[:200]},
                        source="shell_self_report",
                        audit_id=shell_eid,
                    )
                    if logged_id is None:
                        audit_warnings.append(
                            f"Audit write failed for shell evidence {shell_eid}"
                        )

        # Validate artifacts — parameter wins over finding dict (dedup)
        validated_artifacts: list[dict] = []
        raw_artifacts = (
            artifacts if artifacts is not None else sanitized.get("artifacts", [])
        )
        if isinstance(raw_artifacts, str):
            try:
                raw_artifacts = json.loads(raw_artifacts)
            except (json.JSONDecodeError, TypeError):
                raw_artifacts = []
        if isinstance(raw_artifacts, list):
            for art in raw_artifacts[:10]:
                if not isinstance(art, dict):
                    continue
                source = art.get("source", "").strip()
                extraction = art.get("extraction", "").strip()
                content = art.get("content", "").strip()
                if not content:
                    content = art.get("raw_data", "").strip()
                if not source or not extraction or not content:
                    continue
                validated_artifacts.append(
                    {
                        "source": source[:500],
                        "extraction": extraction[:2000],
                        "content": content[:5000],
                        "content_type": str(art.get("content_type", ""))[:50],
                        "purpose": str(art.get("purpose", ""))[:500],
                        "audit_id": str(art.get("audit_id", ""))[:100],
                        "output_ref": str(art.get("output_ref", ""))[:500],
                    }
                )
        if validated_artifacts:
            sanitized["artifacts"] = validated_artifacts
        else:
            sanitized.pop("artifacts", None)
        dropped_artifact_count = (
            len(raw_artifacts) - len(validated_artifacts)
            if isinstance(raw_artifacts, list)
            else 0
        )

        # Validate artifact audit_ids: required and must exist in audit trail
        provenance_warnings: list[str] = []
        if validated_artifacts:
            # Build audit_id index from audit trail
            audit_dir = case_dir / "audit"
            eid_set: set[str] = set()
            all_audit_entries: list[dict] = []
            if audit_dir.is_dir():
                for jsonl_file in audit_dir.glob("*.jsonl"):
                    try:
                        with open(jsonl_file, encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    entry = json.loads(line)
                                    aid = entry.get("audit_id", "")
                                    if aid:
                                        eid_set.add(aid)
                                    all_audit_entries.append(entry)
                                except json.JSONDecodeError:
                                    continue
                    except OSError:
                        continue

            for art in validated_artifacts:
                aid = art.get("audit_id", "")
                if not aid:
                    return {
                        "status": "REJECTED",
                        "error": (
                            "Artifact missing audit_id — pass the audit_id "
                            "from the tool response you just received."
                        ),
                    }
                if aid not in eid_set:
                    # Two-strike: flush race condition
                    time.sleep(0.1)
                    eid_set.clear()
                    if audit_dir.is_dir():
                        for jsonl_file in audit_dir.glob("*.jsonl"):
                            try:
                                with open(jsonl_file, encoding="utf-8") as f:
                                    for line in f:
                                        line = line.strip()
                                        if not line:
                                            continue
                                        try:
                                            entry = json.loads(line)
                                            a = entry.get("audit_id", "")
                                            if a:
                                                eid_set.add(a)
                                        except json.JSONDecodeError:
                                            continue
                            except OSError:
                                continue
                    if aid not in eid_set:
                        return {
                            "status": "REJECTED",
                            "error": (
                                f"audit_id '{aid}' not found in audit trail. "
                                "Pass the audit_id from the tool response."
                            ),
                        }

            # Auto-merge artifact audit_ids into finding audit_ids
            artifact_aids = [
                a["audit_id"] for a in validated_artifacts if a.get("audit_id")
            ]
        else:
            artifact_aids = []
            all_audit_entries = []

        # Extend audit_ids with shell audit IDs + artifact audit IDs
        audit_ids = list(sanitized.get("audit_ids", []))
        audit_ids.extend(shell_audit_ids)
        audit_ids.extend(artifact_aids)
        sanitized["audit_ids"] = list(dict.fromkeys(audit_ids))

        # Auto-resolve source_evidence from audit trail
        if all_audit_entries and sanitized["audit_ids"]:
            raw_ev = self._load_evidence_registry(case_dir)
            evidence = (
                raw_ev.get("files", []) if isinstance(raw_ev, dict) else (raw_ev or [])
            )
            registered = {
                str(Path(e.get("path", "")).resolve())
                for e in evidence
                if e.get("path")
            }
            # Hash→path lookup for cross-platform fallback (UNC → local)
            ev_by_hash = {}
            for e in evidence:
                h = e.get("sha256", "")
                p = e.get("path", "")
                if h and p:
                    ev_by_hash[h] = str(Path(p).resolve())
            audit_by_id = {
                e["audit_id"]: e for e in all_audit_entries if e.get("audit_id")
            }
            # Collect input_files from referenced audit entries
            input_files = []
            for aid in sanitized["audit_ids"]:
                entry = audit_by_id.get(aid)
                if entry:
                    input_files.extend(entry.get("input_files", []))
            if input_files:
                try:
                    source_ev = _resolve_source_evidence_static(
                        input_files,
                        all_audit_entries,
                        registered,
                        evidence_by_hash=ev_by_hash,
                    )
                    if source_ev:
                        sanitized["source_evidence"] = source_ev
                except OSError:
                    provenance_warnings.append(
                        "Failed to resolve source evidence (filesystem error)"
                    )

            # Hard reject: artifact sources must be in evidence registry
            unregistered_sources = []
            for art in validated_artifacts:
                src = art.get("source", "")
                if not src:
                    continue
                try:
                    resolved = str(Path(src).resolve())
                except OSError:
                    continue
                if resolved not in registered:
                    case_relative = src
                    case_dir_str = str(case_dir)
                    if resolved.startswith(case_dir_str + "/"):
                        case_relative = resolved[len(case_dir_str) + 1 :]
                    unregistered_sources.append(
                        {
                            "source": src,
                            "action": f"evidence_register(path='{case_relative}')",
                            "hint": (
                                f"If external: ln -s {src} evidence/{Path(src).name}"
                            ),
                        }
                    )
            if unregistered_sources:
                fid = sanitized.get("finding_id", "unknown")
                return {
                    "status": "REJECTED",
                    "error": (
                        "Artifact sources not in evidence registry. "
                        "Register first, then resubmit."
                    ),
                    "unregistered_sources": unregistered_sources,
                    "finding_held": f"{fid} (not staged -- fix sources and resubmit)",
                }

        if provenance_warnings:
            sanitized["provenance_warnings"] = provenance_warnings

        # Classify provenance
        provenance = self._classify_provenance(sanitized["audit_ids"], case_dir)

        # Hard gate: reject if all NONE and no supporting_commands
        if provenance["summary"] == "NONE" and not validated_commands:
            return {
                "status": "REJECTED",
                "error": (
                    "Finding rejected: no evidence trail. Every finding needs provenance. "
                    "Options: (1) Pass audit_ids from MCP tool responses. "
                    "(2) Pass supporting_commands as a SEPARATE PARAMETER (not inside the finding dict) "
                    "with command, purpose, and output_excerpt for each shell command used. "
                    "(3) For analytical findings without tool evidence, use "
                    "command='analytical reasoning' in supporting_commands."
                ),
            }

        finding_record = {
            **sanitized,
            "id": finding_id,
            "status": "DRAFT",
            "staged": now,
            "modified_at": now,
            "created_by": exam,
            "examiner": exam,
            "provenance": provenance["summary"],
        }

        # Store supporting_commands if provided
        if validated_commands:
            finding_record["supporting_commands"] = validated_commands

        # Response warnings (accumulated through remaining steps)
        warnings: list[str] = []

        # Auto-create timeline event for type=finding with event_timestamp
        timeline_event_id = ""
        finding_type = sanitized.get("type", "")
        event_ts = sanitized.get("event_timestamp", "")
        if finding_type == "finding" and event_ts:
            timeline = self._load_timeline(case_dir)
            tl_seq = _next_seq(timeline, "id", "T", exam)
            timeline_event_id = f"T-{exam}-{tl_seq:03d}"
            finding_record["timeline_event_id"] = timeline_event_id
        # Warning for missing event_timestamp handled by validation.py
        # (validation_warnings already added to warnings list)

        # Compute content hash at staging
        finding_record["content_hash"] = _compute_content_hash(finding_record)

        findings.append(finding_record)
        self._save_findings(case_dir, findings)

        # Create auto-linked timeline event (try/except — never blocks finding)
        if timeline_event_id:
            try:
                tl_event = {
                    "id": timeline_event_id,
                    "timestamp": event_ts,
                    "description": sanitized.get("title", ""),
                    "source": sanitized.get("source_evidence", "")
                    or sanitized.get("artifact_ref", "")
                    or (
                        sanitized.get("audit_ids", [""])[0]
                        if sanitized.get("audit_ids")
                        else ""
                    ),
                    "event_type": sanitized.get("event_type")
                    or _infer_event_type(sanitized)
                    or "other",
                    "related_findings": [finding_id],
                    "auto_created_from": finding_id,
                    "status": "DRAFT",
                    "staged": now,
                    "modified_at": now,
                    "created_by": exam,
                    "examiner": exam,
                    "audit_ids": list(sanitized.get("audit_ids", [])),
                }
                tl_event["content_hash"] = _compute_content_hash(tl_event)
                timeline.append(tl_event)
                self._save_timeline(case_dir, timeline)
            except Exception as exc:
                logger.warning("Auto-timeline creation failed: %s", exc)
                warnings.append(f"Timeline auto-creation failed: {exc}")

        # IOC auto-extraction (try/except — never blocks finding save)
        iocs_extracted = 0
        try:
            iocs_extracted = self._process_iocs(finding_record, case_dir)
        except Exception as exc:
            logger.warning("IOC processing failed: %s", exc)
            warnings.append(f"IOC processing failed: {exc}")

        # IOC completeness check — warn if text mentions IOCs not in the list
        try:
            text = (
                f"{finding.get('observation', '')} {finding.get('interpretation', '')}"
            )
            submitted = {
                str(i).lower().strip()
                for i in (finding.get("iocs") or [])
                if isinstance(i, str)
            }
            mentioned_ips = set(
                re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
            )
            mentioned_hashes = set(re.findall(r"\b[a-fA-F0-9]{32,64}\b", text))
            missing = (mentioned_ips | mentioned_hashes) - submitted
            if missing:
                warnings.append(
                    f"IOC completeness: {len(missing)} value(s) in text but not in iocs list: "
                    + ", ".join(sorted(missing)[:5])
                )
        except Exception:
            pass

        result = {
            "status": "STAGED",
            "finding_id": finding_id,
            "provenance_detail": provenance,
        }
        if timeline_event_id:
            result["timeline_event_id"] = timeline_event_id
        if iocs_extracted:
            result["iocs_extracted"] = iocs_extracted
        if dropped_artifact_count > 0:
            warnings.append(
                f"{dropped_artifact_count} artifact(s) dropped — each artifact requires "
                "source, extraction, and content fields (not raw_data)."
            )
        dropped_cmd_count = (
            len(supporting_commands) - len(validated_commands)
            if supporting_commands
            else 0
        )
        if dropped_cmd_count > 0:
            warnings.append(
                f"{dropped_cmd_count} supporting_command(s) dropped (missing command or purpose)"
            )
        warnings.extend(audit_warnings)
        warnings.extend(validation_warnings)
        if warnings:
            result["warning"] = " ".join(warnings)
        return result

    def _next_shell_seq(self, case_dir: Path, examiner: str, today: str) -> int:
        """Find next sequence number for shell-{examiner}-{today}-NNN audit IDs."""
        audit_dir = case_dir / "audit"
        prefix = f"shell-{examiner}-{today}-"
        max_num = 0
        if audit_dir.is_dir():
            for jsonl_file in audit_dir.glob("*.jsonl"):
                try:
                    with open(jsonl_file, encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                                eid = entry.get("audit_id", "")
                                if eid.startswith(prefix):
                                    try:
                                        num = int(eid[len(prefix) :])
                                        max_num = max(max_num, num)
                                    except ValueError:
                                        pass
                            except json.JSONDecodeError:
                                continue
                except OSError:
                    continue
        return max_num + 1

    def record_timeline_event(self, event: dict, examiner_override: str = "") -> dict:
        """Validate and stage timeline event as DRAFT."""
        case_dir = self._require_active_case()

        # Basic validation
        required = ["timestamp", "description"]
        missing = [k for k in required if not event.get(k)]
        if missing:
            return {
                "status": "VALIDATION_FAILED",
                "errors": [f"Missing required fields: {missing}"],
            }

        exam = self._effective_examiner(examiner_override)
        timeline = self._load_timeline(case_dir)
        seq = _next_seq(timeline, "id", "T", exam)
        event_id = f"T-{exam}-{seq:03d}"
        now = datetime.now(timezone.utc).isoformat()

        # Strip protected fields from user input for defense-in-depth
        sanitized = {k: v for k, v in event.items() if k not in _PROTECTED_EVENT_FIELDS}
        event_record = {
            **sanitized,
            "id": event_id,
            "status": "DRAFT",
            "staged": now,
            "modified_at": now,
            "created_by": exam,
            "examiner": exam,
        }
        event_record["content_hash"] = _compute_content_hash(event_record)
        timeline.append(event_record)
        self._save_timeline(case_dir, timeline)

        return {"status": "STAGED", "event_id": event_id}

    def get_findings(self, status: str | None = None) -> list[dict]:
        """Return local findings."""
        case_dir = self._require_active_case()
        findings = self._load_findings(case_dir)
        if status:
            findings = [f for f in findings if f.get("status") == status.upper()]
        return findings

    def get_timeline(
        self,
        status: str | None = None,
        source: str | None = None,
        examiner: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        event_type: str | None = None,
    ) -> list[dict]:
        """Return local timeline, sorted chronologically.

        Optional filters narrow the result set:
        - status: DRAFT, APPROVED, REJECTED
        - source: substring match against event source field
        - examiner: exact match against examiner field
        - start_date: ISO date/datetime lower bound on timestamp
        - end_date: ISO date/datetime upper bound on timestamp
        - event_type: exact match against event_type field
        """
        case_dir = self._require_active_case()
        events = self._load_timeline(case_dir)
        events.sort(key=lambda t: t.get("timestamp", ""))
        if status:
            events = [e for e in events if e.get("status") == status.upper()]
        if source:
            events = [
                e for e in events if source.lower() in e.get("source", "").lower()
            ]
        if examiner:
            events = [e for e in events if e.get("examiner") == examiner]
        if start_date:
            events = [e for e in events if e.get("timestamp", "") >= start_date]
        if end_date:
            events = [e for e in events if e.get("timestamp", "") <= end_date]
        if event_type:
            events = [e for e in events if e.get("event_type", "") == event_type]
        return events

    def get_actions(self, limit: int = 50) -> list[dict]:
        """Return recent actions from actions.jsonl."""
        case_dir = self._require_active_case()
        entries = []
        actions_file = case_dir / "actions.jsonl"
        if actions_file.exists():
            try:
                with open(actions_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                entries.append(json.loads(line))
                            except json.JSONDecodeError:
                                logger.warning("Corrupt JSONL line in %s", actions_file)
            except OSError as e:
                logger.warning("Failed to read actions file %s: %s", actions_file, e)
        entries.sort(key=lambda e: e.get("ts", ""))
        return entries[-limit:]

    # --- TODOs ---

    def add_todo(
        self,
        description: str,
        assignee: str = "",
        priority: str = "medium",
        related_findings: list[str] | None = None,
        examiner_override: str = "",
    ) -> dict:
        """Create a new TODO item."""
        case_dir = self._require_active_case()
        exam = self._effective_examiner(examiner_override)
        todos = self._load_todos(case_dir)
        seq = _next_seq(todos, "todo_id", "TODO", exam)
        todo_id = f"TODO-{exam}-{seq:03d}"

        todo = {
            "todo_id": todo_id,
            "description": description,
            "status": "open",
            "priority": priority if priority in ("high", "medium", "low") else "medium",
            "assignee": assignee,
            "related_findings": related_findings or [],
            "created_by": exam,
            "examiner": exam,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "notes": [],
            "completed_at": None,
        }
        todos.append(todo)
        self._save_todos(case_dir, todos)

        return {"status": "created", "todo_id": todo_id}

    def list_todos(self, status: str = "open", assignee: str = "") -> list[dict]:
        """List local TODOs, filtered by status and/or assignee."""
        case_dir = self._require_active_case()
        todos = self._load_todos(case_dir)

        if status != "all":
            todos = [t for t in todos if t.get("status") == status]
        if assignee:
            todos = [t for t in todos if t.get("assignee") == assignee]

        return todos

    def update_todo(
        self,
        todo_id: str,
        status: str = "",
        note: str = "",
        assignee: str = "",
        priority: str = "",
        examiner_override: str = "",
    ) -> dict:
        """Update a TODO item."""
        case_dir = self._require_active_case()
        todos = self._load_todos(case_dir)
        exam = self._effective_examiner(examiner_override)

        for todo in todos:
            if todo["todo_id"] == todo_id:
                if status and status in ("open", "completed"):
                    todo["status"] = status
                    if status == "completed":
                        todo["completed_at"] = datetime.now(timezone.utc).isoformat()
                if assignee:
                    todo["assignee"] = assignee
                if priority and priority in ("high", "medium", "low"):
                    todo["priority"] = priority
                if note:
                    todo["notes"].append(
                        {
                            "note": note,
                            "by": exam,
                            "at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                self._save_todos(case_dir, todos)
                return {"status": "updated", "todo_id": todo_id}

        return {"status": "not_found", "todo_id": todo_id}

    def complete_todo(self, todo_id: str, examiner_override: str = "") -> dict:
        """Mark a TODO as completed."""
        return self.update_todo(
            todo_id, status="completed", examiner_override=examiner_override
        )

    # --- Evidence ---

    def list_evidence(self) -> list[dict]:
        case_dir = self._require_active_case()
        return self._load_evidence_registry(case_dir).get("files", [])

    # --- Grounding Score ---

    # MCP audit files that count as grounding sources
    _GROUNDING_MCPS = ("forensic-rag-mcp", "windows-triage-mcp", "opencti-mcp")

    def _score_grounding(self, finding: dict) -> dict:
        """Score how well a finding is grounded by external reference MCPs.

        Scans the case audit directory for evidence of forensic-rag-mcp,
        windows-triage-mcp, and opencti-mcp usage. Returns WEAK/PARTIAL/STRONG
        with suggestions for unconsulted sources.

        Returns empty dict when STRONG (2+ sources consulted).
        """
        case_dir = self.active_case_dir
        if case_dir is None or not case_dir.exists():
            return {}

        audit_dir = case_dir / "audit"
        if not audit_dir.is_dir():
            return self._grounding_result([], finding)

        consulted = []
        available = []
        for mcp_name in self._GROUNDING_MCPS:
            audit_file = audit_dir / f"{mcp_name}.jsonl"
            if audit_file.exists():
                available.append(mcp_name)
                if audit_file.stat().st_size > 0:
                    consulted.append(mcp_name)

        return self._grounding_result(consulted, finding, available)

    def _grounding_result(
        self,
        consulted: list[str],
        finding: dict,
        available: list[str] | None = None,
    ) -> dict:
        """Build grounding score result from consulted sources list."""
        if len(consulted) >= 2:
            return {}  # STRONG — don't clutter

        # Only flag backends that are actually deployed (have audit files)
        check_set = available if available is not None else list(self._GROUNDING_MCPS)
        missing = [m for m in check_set if m not in consulted]
        # No deployed grounding backends — nothing to flag
        if not consulted and not missing:
            return {}
        # If finding has provenance chain to registered evidence, at least PARTIAL
        has_provenance = bool(finding.get("source_evidence"))
        level = "PARTIAL" if consulted or has_provenance else "WEAK"

        # Load corroboration suggestions from FK for unconsulted sources
        suggestions = []
        finding_type = finding.get("type", "")
        if finding_type:
            try:
                from forensic_knowledge import loader

                checks = loader.get_corroboration(finding_type)
                if checks:
                    for check in checks:
                        check_text = check.get("check", "")
                        # Only suggest checks from missing MCPs
                        for mcp in missing:
                            short_name = mcp.replace("-mcp", "")
                            if short_name in check_text.lower():
                                reason = check.get("reason", "")
                                suggestions.append(
                                    f"{check_text} — {reason}" if reason else check_text
                                )
            except Exception:
                pass  # FK not available — skip suggestions

        result: dict[str, Any] = {
            "level": level,
            "sources_consulted": consulted,
            "sources_missing": missing,
        }
        if suggestions:
            result["suggestions"] = suggestions

        return result

    # --- Provenance Classification ---

    # Provenance tier priority: MCP > HOOK > SHELL
    _PROVENANCE_TIERS = ("MCP", "HOOK", "SHELL")

    def _classify_provenance(self, audit_ids: list[str], case_dir: Path) -> dict:
        """Classify audit IDs by provenance tier.

        Scans audit/*.jsonl to determine where each audit_id came from:
        - MCP: found in any audit file except claude-code.jsonl
        - HOOK: found in claude-code.jsonl
        - NONE: not found in any audit file or malformed ID

        Evidence IDs must match the format: prefix-examiner-YYYYMMDD-NNN.
        Malformed IDs (path traversal, unicode, injection) are classified as NONE.

        Returns {"summary": tier, "mcp": [...], "hook": [...], "shell": [...], "none": [...]}.
        """
        audit_dir = case_dir / "audit"

        # Build audit_id -> source lookup from audit files
        eid_source: dict[str, str] = {}
        if audit_dir.is_dir():
            for jsonl_file in audit_dir.glob("*.jsonl"):
                source = "HOOK" if jsonl_file.name == "claude-code.jsonl" else "MCP"
                try:
                    with open(jsonl_file, encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                                eid = entry.get("audit_id", "")
                                if not eid:
                                    continue
                                existing = eid_source.get(eid)
                                if existing is None:
                                    eid_source[eid] = source
                                elif source == "MCP":
                                    # MCP > HOOK priority
                                    eid_source[eid] = "MCP"
                            except json.JSONDecodeError:
                                continue
                except OSError:
                    continue

        # Classify each audit_id
        result: dict[str, list[str]] = {
            "mcp": [],
            "hook": [],
            "shell": [],
            "none": [],
        }
        for eid in audit_ids:
            # Reject malformed audit IDs (path traversal, homoglyphs, injection)
            if not _AUDIT_ID_PATTERN.match(eid):
                result["none"].append(eid)
                continue
            source = eid_source.get(eid)
            if source:
                result[source.lower()].append(eid)
            else:
                result["none"].append(eid)

        # Compute summary tier
        tiers_present = set()
        if result["mcp"]:
            tiers_present.add("MCP")
        if result["hook"]:
            tiers_present.add("HOOK")
        if result["shell"]:
            tiers_present.add("SHELL")
        has_none = bool(result["none"])

        if not tiers_present:
            summary = "NONE"
        elif len(tiers_present) == 1 and not has_none:
            summary = next(iter(tiers_present))
        else:
            # Mixed tiers or any NONE with other tiers
            summary = "MIXED"

        result["summary"] = summary  # type: ignore[assignment]
        return result

    # --- Internal helpers ---

    def _resolve_case_dir(self, case_id: str | None) -> Path:
        if case_id:
            _validate_case_id(case_id)
            d = self.cases_dir / case_id
            if not d.exists():
                raise ValueError(f"Case not found: {case_id}")
            return d
        return self._require_active_case()

    def _load_case_meta(self, case_dir: Path) -> dict:
        try:
            with open(case_dir / "CASE.yaml") as f:
                return yaml.safe_load(f) or {}
        except (yaml.YAMLError, OSError) as e:
            logger.warning("Failed to load CASE.yaml from %s: %s", case_dir, e)
            return {}

    # --- Data I/O (case root) ---

    def _load_findings(self, case_dir: Path) -> list[dict]:
        return self._load_json_file(case_dir / "findings.json", [])

    def _save_findings(self, case_dir: Path, findings: list[dict]) -> None:
        _protected_write(
            case_dir / "findings.json", json.dumps(findings, indent=2, default=str)
        )

    def _load_timeline(self, case_dir: Path) -> list[dict]:
        return self._load_json_file(case_dir / "timeline.json", [])

    def _save_timeline(self, case_dir: Path, timeline: list[dict]) -> None:
        _protected_write(
            case_dir / "timeline.json", json.dumps(timeline, indent=2, default=str)
        )

    def _load_iocs(self, case_dir: Path) -> list[dict]:
        return self._load_json_file(case_dir / "iocs.json", [])

    def _save_iocs(self, case_dir: Path, iocs: list[dict]) -> None:
        _protected_write(
            case_dir / "iocs.json", json.dumps(iocs, indent=2, default=str)
        )

    def _process_iocs(self, finding: dict, case_dir: Path) -> int:
        """Extract IOCs from finding, create/update IOC records. Returns count."""
        raw_iocs = finding.get("iocs", [])
        if not raw_iocs:
            return 0
        # Flatten dict format: {"IPv4": ["10.0.1.5"]} → ["10.0.1.5"]
        if isinstance(raw_iocs, dict):
            raw_iocs = [
                v
                for vals in raw_iocs.values()
                for v in (vals if isinstance(vals, list) else [vals])
            ]
        if not isinstance(raw_iocs, list):
            return 0

        host = finding.get("host", "")
        finding_id = finding.get("id", "")
        examiner = finding.get("examiner", "")
        confidence = finding.get("confidence", "")
        mitre_ids = finding.get("mitre_ids", [])
        now = datetime.now(timezone.utc).isoformat()

        iocs = self._load_iocs(case_dir)
        ioc_by_value = {_normalize_ioc(ioc["value"]): ioc for ioc in iocs}

        # Contextual hints for ambiguous IOC classification
        affected_account = finding.get("affected_account", "")
        account_names = set()
        if affected_account:
            account_names.add(affected_account.lower().strip())
            # Also add bare username if domain\user format
            if "\\" in affected_account:
                account_names.add(affected_account.split("\\", 1)[1].lower().strip())

        for raw in raw_iocs[:100]:
            # Support explicit type: {"value": "rsydow-a", "type": "user-account"}
            if isinstance(raw, dict) and "value" in raw:
                value = _refang_ioc(str(raw["value"]).strip())
                explicit_type = raw.get("type", "")
            else:
                value = _refang_ioc(str(raw).strip())
                explicit_type = ""
            if not value:
                continue
            # Strip port from IPv4 before dedup (10.0.0.1:8443 → 10.0.0.1)
            if explicit_type:
                ioc_type = explicit_type
                category = "identity" if "account" in explicit_type else "host"
            else:
                ioc_type, category = _detect_ioc_type(value)
                # Override unknown → user-account if value matches affected_account
                if ioc_type == "unknown" and value.lower() in account_names:
                    ioc_type, category = "user-account", "identity"
            if ioc_type == "ipv4-addr" and re.search(r":\d{1,5}$", value):
                value = re.sub(r":\d{1,5}$", "", value)
            dedup_key = _normalize_ioc(value)

            if dedup_key in ioc_by_value:
                existing = ioc_by_value[dedup_key]
                if finding_id not in existing.get("source_findings", []):
                    existing.setdefault("source_findings", []).append(finding_id)
                sighting = {"host": host, "finding_id": finding_id}
                if sighting not in existing.get("sightings", []):
                    existing.setdefault("sightings", []).append(sighting)
                if _conf_rank(confidence) < _conf_rank(existing.get("confidence", "")):
                    existing["confidence"] = confidence
                for mid in mitre_ids or []:
                    if mid not in existing.get("mitre_techniques", []):
                        existing.setdefault("mitre_techniques", []).append(mid)
                existing["modified_at"] = now
                existing["content_hash"] = _compute_ioc_hash(existing)
            else:
                seq = _next_seq(iocs, "id", "IOC", examiner)
                new_ioc = {
                    "id": f"IOC-{examiner}-{seq:03d}",
                    "value": value,
                    "type": ioc_type,
                    "category": category,
                    "description": "",
                    "status": "DRAFT",
                    "confidence": confidence,
                    "source_findings": [finding_id],
                    "sightings": [{"host": host, "finding_id": finding_id}]
                    if host
                    else [{"host": "", "finding_id": finding_id}],
                    "mitre_techniques": list(mitre_ids) if mitre_ids else [],
                    "tags": [],
                    "manually_reviewed": False,
                    "examiner": examiner,
                    "created_at": now,
                    "modified_at": now,
                }
                new_ioc["content_hash"] = _compute_ioc_hash(new_ioc)
                iocs.append(new_ioc)
                ioc_by_value[dedup_key] = new_ioc

        self._save_iocs(case_dir, iocs)
        return len(raw_iocs)

    def _load_todos(self, case_dir: Path) -> list[dict]:
        return self._load_json_file(case_dir / "todos.json", [])

    def _save_todos(self, case_dir: Path, todos: list[dict]) -> None:
        _atomic_write(case_dir / "todos.json", json.dumps(todos, indent=2, default=str))

    def _load_evidence_registry(self, case_dir: Path) -> dict:
        return self._load_json_file(case_dir / "evidence.json", {"files": []})

    # --- Generic helpers ---

    def _load_json_file(self, path: Path, default: Any) -> Any:
        """Load a JSON file, returning default on missing or corrupt.

        If the file exists and has content but fails to parse, raises
        ValueError to prevent silent data loss on the next write.
        """
        if not path.exists():
            return default
        try:
            data = path.read_text()
        except OSError as e:
            logger.error("Failed to read JSON file %s: %s", path, e)
            raise ValueError(f"Cannot read {path.name}: {e}") from e
        if not data.strip():
            return default
        try:
            return json.loads(data)
        except json.JSONDecodeError as e:
            logger.error("Corrupt JSON file: %s", path)
            raise ValueError(
                f"{path.name} is corrupt (invalid JSON). "
                f"Refusing to overwrite — fix or restore from backup."
            ) from e
