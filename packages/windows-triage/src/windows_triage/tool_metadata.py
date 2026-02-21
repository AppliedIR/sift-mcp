"""Per-tool caveats and interpretation constraints for structured responses."""

TOOL_METADATA: dict[str, dict[str, list[str] | str]] = {
    "check_file": {
        "caveats": [
            "Baseline covers default Windows installations only",
            "Third-party software will not appear in baseline",
        ],
        "interpretation_constraint": "UNKNOWN means not-in-database, NOT suspicious",
    },
    "check_process_tree": {
        "caveats": [
            "Expected parent-child relationships vary by Windows version",
            "Custom enterprise software may create unusual process trees",
        ],
        "interpretation_constraint": "Unexpected parent does not confirm malice",
    },
    "check_service": {
        "caveats": [
            "Baseline services vary between Windows versions",
            "Third-party services are not in baseline",
        ],
        "interpretation_constraint": "Unknown service requires context — may be legitimate software",
    },
    "check_scheduled_task": {
        "caveats": [
            "Baseline tasks vary between Windows versions",
            "Enterprise management tools create legitimate tasks",
        ],
        "interpretation_constraint": "Unknown task requires context — may be legitimate software",
    },
    "check_autorun": {
        "caveats": [
            "Baseline autoruns vary between Windows versions",
            "Many legitimate applications add autorun entries",
        ],
        "interpretation_constraint": "Unknown autorun requires context — may be legitimate software",
    },
    "check_registry": {
        "caveats": [
            "Requires optional known_good_registry.db (12GB)",
            "Registry baselines are OS-version specific",
        ],
        "interpretation_constraint": "Unknown registry key does not indicate malicious activity",
    },
    "check_hash": {
        "caveats": [
            "Checks vulnerable driver database (LOLDrivers) only",
            "Does not check general malware — use threat intel for that",
        ],
        "interpretation_constraint": "Not found does not mean safe",
    },
    "analyze_filename": {
        "caveats": [
            "Heuristic analysis — Unicode and typosquatting detection",
            "May flag legitimate filenames with unusual characters",
        ],
        "interpretation_constraint": "Flagged characteristics are indicators, not confirmations",
    },
    "check_lolbin": {
        "caveats": [
            "LOLBins are legitimate Windows tools with abuse potential",
            "Presence alone does not indicate compromise",
        ],
        "interpretation_constraint": "LOLBin usage requires contextual analysis of command-line arguments",
    },
    "check_hijackable_dll": {
        "caveats": [
            "DLL hijacking vulnerability database may not be exhaustive",
        ],
        "interpretation_constraint": "Hijackable DLL requires analysis of loading application context",
    },
    "check_pipe": {
        "caveats": [
            "Named pipe database covers known C2 and Windows default pipes",
            "Custom enterprise applications may use unlisted pipes",
        ],
        "interpretation_constraint": "Unknown pipe requires context — may be legitimate application",
    },
    "get_db_stats": {
        "caveats": [
            "Statistics reflect local database state",
        ],
        "interpretation_constraint": "Database coverage depends on imported baselines",
    },
    "get_health": {
        "caveats": [
            "Health check reflects current server state",
        ],
        "interpretation_constraint": "Health status is point-in-time",
    },
}

DEFAULT_METADATA: dict[str, list[str] | str] = {
    "caveats": ["No specific caveats"],
    "interpretation_constraint": "Interpret results in context of the specific investigation",
}
