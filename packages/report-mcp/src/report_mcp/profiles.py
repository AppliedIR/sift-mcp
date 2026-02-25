"""Data-driven report profile definitions.

Adding a new profile = adding a dict entry. No code changes required.
"""

from __future__ import annotations

# Fields stripped from findings in report output. These are internal
# working notes for the examiner's pre-approval review. Once approved,
# a finding stands on its own merits.
STRIPPED_FINDING_FIELDS = {
    "provenance",
    "confidence",
    "confidence_justification",
    "supporting_commands",
    "content_hash",
    "evidence_ids",
    "staged",
    "modified_at",
    "approved_by",
    "approved_at",
    "rejected_by",
    "rejected_at",
    "rejection_reason",
    "verification",
    "created_by",
}

PROFILES: dict[str, dict] = {
    "full": {
        "description": "Comprehensive IR report with all approved data",
        "data_keys": [
            "metadata",
            "findings",
            "timeline",
            "iocs",
            "mitre_mapping",
            "evidence",
            "todos",
            "summary",
        ],
        "findings_mode": "all",
        "timeline_mode": "all",
        "sections": [
            {"name": "Executive Summary", "type": "narrative"},
            {"name": "Incident Overview", "type": "narrative"},
            {
                "name": "Timeline of Events",
                "type": "data_narrative",
                "data_key": "timeline",
            },
            {
                "name": "Findings",
                "type": "data_narrative",
                "data_key": "findings",
            },
            {"name": "Root Cause Analysis", "type": "narrative"},
            {
                "name": "Indicators of Compromise",
                "type": "data",
                "data_key": "iocs",
            },
            {
                "name": "MITRE ATT&CK Mapping",
                "type": "data",
                "data_key": "mitre_mapping",
            },
            {"name": "Containment & Eradication", "type": "narrative"},
            {"name": "Recovery & Lessons Learned", "type": "narrative"},
            {"name": "Recommendations", "type": "narrative"},
        ],
        "zeltser_tools": [
            "ir_get_template",
            "ir_get_guidelines",
            "ir_load_context",
            "ir_review_report",
        ],
    },
    "executive": {
        "description": "Management briefing (1-2 pages, non-technical)",
        "data_keys": ["metadata", "findings", "todos", "summary"],
        "findings_mode": "top_5",
        "timeline_mode": "count",
        "sections": [
            {"name": "Situation Summary", "type": "narrative"},
            {"name": "Business Impact", "type": "narrative"},
            {"name": "Current Status", "type": "data", "data_key": "summary"},
            {"name": "Actions Required", "type": "narrative"},
        ],
        "zeltser_tools": [
            "ir_get_guidelines",
            "ir_load_context",
            "ir_review_report",
        ],
    },
    "timeline": {
        "description": "Chronological event narrative",
        "data_keys": ["metadata", "timeline", "summary"],
        "findings_mode": "referenced",
        "timeline_mode": "all",
        "filterable": {"start_date": True, "end_date": True},
        "sections": [
            {
                "name": "Timeline",
                "type": "data_narrative",
                "data_key": "timeline",
            },
        ],
        "zeltser_tools": ["ir_get_guidelines", "ir_load_context"],
    },
    "ioc": {
        "description": "Structured IOC export with MITRE mapping",
        "data_keys": ["metadata", "iocs", "mitre_mapping", "summary"],
        "findings_mode": "referenced",
        "timeline_mode": "none",
        "sections": [
            {
                "name": "Indicators of Compromise",
                "type": "data",
                "data_key": "iocs",
            },
            {
                "name": "MITRE ATT&CK Mapping",
                "type": "data",
                "data_key": "mitre_mapping",
            },
        ],
        "zeltser_tools": [],
    },
    "findings": {
        "description": "Detailed approved findings",
        "data_keys": ["metadata", "findings", "summary"],
        "findings_mode": "all",
        "timeline_mode": "referenced",
        "filterable": {"finding_ids": True},
        "sections": [
            {
                "name": "Findings Detail",
                "type": "data_narrative",
                "data_key": "findings",
            },
        ],
        "zeltser_tools": ["ir_get_guidelines", "ir_review_report"],
    },
    "status": {
        "description": "Quick status for standups",
        "data_keys": ["metadata", "todos", "summary"],
        "findings_mode": "count",
        "timeline_mode": "count",
        "sections": [
            {"name": "Status", "type": "data", "data_key": "summary"},
            {"name": "Open Items", "type": "data", "data_key": "todos"},
        ],
        "zeltser_tools": [],
    },
}
