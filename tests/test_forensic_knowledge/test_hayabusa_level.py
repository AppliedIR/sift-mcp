"""Hayabusa's Level column, as the knowledge base serves it: timeline output
abbreviates the level by default (med, info; crit and emer), full words appear
only with abbreviations disabled, and the alert queries match both forms."""

from __future__ import annotations

import pytest
from forensic_knowledge import loader

LEVEL = (
    "Alert severity. Timeline output abbreviates it by default: crit, high, med, "
    "low, info, plus emer (emergency) from v3.1 on configured critical systems. "
    "Full words appear only when abbreviations are disabled, on v3.4 or later. "
    "get_tool_help shows that option for the installed version. Query for both forms."
)
LEVELS = "Level:(emer OR emergency OR crit OR critical OR high)"


@pytest.fixture(autouse=True)
def _fresh():
    loader.clear_cache()
    yield
    loader.clear_cache()


def test_the_level_field_says_both_forms_appear():
    assert loader.get_tool("Hayabusa")["field_meanings"]["Level"] == LEVEL


def test_the_alert_queries_match_both_forms():
    queries = [
        p["query"]
        for p in loader.get_artifact("hayabusa_alerts")["investigation_patterns"]
        if p["query"].startswith("Level:")
    ]
    assert queries == [LEVELS, f"{LEVELS} AND user.name.keyword:<username>"]
