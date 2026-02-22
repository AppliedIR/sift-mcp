"""Per-tool caveats and interpretation constraints for structured responses."""

TOOL_METADATA: dict[str, dict[str, list[str] | str]] = {
    # === Search / lookup tools ===
    "search_threat_intel": {
        "caveats": [
            "Results depend on OpenCTI instance data completeness",
            "Absence of results does not mean absence of threat",
        ],
        "interpretation_constraint": "Threat intel is point-in-time and instance-specific",
    },
    "lookup_ioc": {
        "caveats": [
            "Threat intel is point-in-time, may be stale",
            "IOC context depends on feeds ingested into this instance",
        ],
        "interpretation_constraint": "Absence from CTI does not mean benign",
    },
    "search_threat_actor": {
        "caveats": [
            "Attribution is probabilistic, never certain from a single source",
            "Actor names and aliases vary across vendors",
        ],
        "interpretation_constraint": "Matching TTPs do not confirm attribution",
    },
    "search_malware": {
        "caveats": [
            "Malware family classification varies across vendors",
            "Coverage depends on feeds ingested into this instance",
        ],
        "interpretation_constraint": "Family match requires corroborating indicators",
    },
    "search_attack_pattern": {
        "caveats": [
            "MITRE ATT&CK mappings may lag behind real-world TTPs",
        ],
        "interpretation_constraint": "Technique match requires evidence of actual execution",
    },
    "search_vulnerability": {
        "caveats": [
            "CVE data depends on feeds and may not include latest advisories",
            "Exploitability depends on target environment configuration",
        ],
        "interpretation_constraint": "Vulnerability presence does not confirm exploitation",
    },
    "get_recent_indicators": {
        "caveats": [
            "Recency depends on feed ingestion schedule",
        ],
        "interpretation_constraint": "Recent indicators may not yet be fully contextualized",
    },
    "search_reports": {
        "caveats": [
            "Report availability depends on ingested feeds and sharing agreements",
        ],
        "interpretation_constraint": "Reports reflect analyst assessments at time of writing",
    },
    "search_campaign": {
        "caveats": [
            "Campaign boundaries are analytical constructs, not ground truth",
        ],
        "interpretation_constraint": "Campaign attribution requires multiple corroborating data points",
    },
    "search_tool": {
        "caveats": [
            "Tools listed are dual-use — presence does not imply malicious use",
        ],
        "interpretation_constraint": "Tool presence requires contextual analysis of usage",
    },
    "search_infrastructure": {
        "caveats": [
            "Infrastructure may be shared across multiple threat actors",
            "IP/domain reputation changes over time",
        ],
        "interpretation_constraint": "Infrastructure association is temporal, not permanent",
    },
    "search_incident": {
        "caveats": [
            "Incident records reflect reported events, may be incomplete",
        ],
        "interpretation_constraint": "Incident similarity does not confirm same actor or method",
    },
    "search_observable": {
        "caveats": [
            "Observables are raw artifacts without inherent malicious context",
        ],
        "interpretation_constraint": "Observable presence requires indicator or context enrichment",
    },
    "search_sighting": {
        "caveats": [
            "Sightings are detection events, may include false positives",
        ],
        "interpretation_constraint": "Sighting confirms detection, not confirmed compromise",
    },
    "search_organization": {
        "caveats": [
            "Organization data reflects CTI reporting, may be incomplete",
        ],
        "interpretation_constraint": "Targeted organization lists may not be exhaustive",
    },
    "search_sector": {
        "caveats": [
            "Sector targeting is derived from CTI reports",
        ],
        "interpretation_constraint": "Sector targeting is probabilistic, not deterministic",
    },
    "search_location": {
        "caveats": [
            "Geographic attribution has high uncertainty",
        ],
        "interpretation_constraint": "Location data reflects reporting, not confirmed origin",
    },
    "search_course_of_action": {
        "caveats": [
            "Mitigations are general guidance, not environment-specific",
        ],
        "interpretation_constraint": "Applicability depends on target environment",
    },
    "search_grouping": {
        "caveats": [
            "Groupings are analytical containers created by analysts",
        ],
        "interpretation_constraint": "Grouping membership reflects analyst judgment",
    },
    "search_note": {
        "caveats": [
            "Notes are analyst assessments, not automated findings",
        ],
        "interpretation_constraint": "Notes reflect individual analyst perspective",
    },
    "lookup_hash": {
        "caveats": [
            "Hash lookup depends on OpenCTI instance data",
            "Absence does not mean file is safe",
        ],
        "interpretation_constraint": "Hash match requires validation of file context",
    },
    "get_entity": {
        "caveats": [
            "Entity details reflect current OpenCTI state",
        ],
        "interpretation_constraint": "Entity data may be updated as new intelligence arrives",
    },
    "get_relationships": {
        "caveats": [
            "Relationships reflect CTI modeling, not ground truth",
        ],
        "interpretation_constraint": "Relationship strength varies — check confidence scores",
    },
    # === Operational tools ===
    "get_health": {
        "caveats": [
            "Health check reflects current connectivity state",
        ],
        "interpretation_constraint": "Health status is point-in-time",
    },
    # search_entity resolves metadata by looking up the per-type key above
    "search_entity": {
        "caveats": [
            "Results depend on OpenCTI instance data completeness",
        ],
        "interpretation_constraint": "Entity search results are instance-specific and point-in-time",
    },
}

DEFAULT_METADATA: dict[str, list[str] | str] = {
    "caveats": ["No specific caveats"],
    "interpretation_constraint": "Interpret results in context of the specific investigation",
}
