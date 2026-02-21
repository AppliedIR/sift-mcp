"""Per-tool caveats and interpretation constraints for structured responses."""

TOOL_METADATA: dict[str, dict[str, list[str] | str]] = {
    "search": {
        "caveats": [
            "Results are reference knowledge, not case-specific evidence",
            "Relevance scores are semantic similarity, not confidence levels",
        ],
        "interpretation_constraint": "Detection rules require validation in target environment",
    },
    "list_sources": {
        "caveats": [
            "Source availability depends on index build configuration",
        ],
        "interpretation_constraint": "Source list reflects indexed content, not all available knowledge",
    },
    "get_stats": {
        "caveats": [
            "Statistics reflect the local index state",
        ],
        "interpretation_constraint": "Document counts may not reflect latest upstream updates",
    },
}

DEFAULT_METADATA: dict[str, list[str] | str] = {
    "caveats": ["No specific caveats"],
    "interpretation_constraint": "Interpret results in context of the specific investigation",
}
