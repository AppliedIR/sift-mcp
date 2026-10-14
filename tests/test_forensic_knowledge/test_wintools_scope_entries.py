"""wintools-mcp analyses data already in the case. The knowledge base keeps no
entry for a tool it no longer runs that has no use on collected data
(HollowsHunter and Moneta scan live processes, DumpIt acquires memory), keeps
WinPmem (it can decompress an image already in the case), and tells the AI
what wintools refuses."""

from __future__ import annotations

import pytest
from forensic_knowledge import loader


@pytest.fixture(autouse=True)
def _fresh():
    loader.clear_cache()
    yield
    loader.clear_cache()


@pytest.mark.parametrize("name", ["HollowsHunter", "Moneta", "DumpIt"])
def test_no_entry_for_a_live_scanning_or_acquisition_tool(name):
    assert loader.get_tool(name) is None


def test_winpmem_stays():
    assert loader.get_tool("WinPmem") is not None


def test_kape_is_described_as_module_runs_only():
    kape = loader.get_tool("KAPE")
    assert "Target runs are refused." in kape["description"]
    assert kape["output_notes"]["key_fields"] == ["processed_output", "execution_log"]


def test_an_injection_check_is_run_on_the_memory_image_in_the_case():
    checks = [c["check"] for c in loader.get_corroboration("process_injection")]
    assert not [c for c in checks if "hollows_hunter" in c or "moneta" in c]
    assert any(
        c.startswith("Volatility 3 windows.malfind and windows.hollowprocesses")
        for c in checks
    )


AUTORUNSC_ADVICE = [
    "Scan all auto-start location types, not a subset.",
    "Ask for CSV output. It is easier to sort, filter and compare than the default text output.",
    "Include file hashes in the output, so entries can be checked against threat intelligence.",
    "Include signature checks in the output. An unsigned entry is a lead to examine. It is not "
    "proof of malicious persistence.",
    "Hiding Microsoft-signed entries narrows the output to third-party and unsigned items. A "
    "legitimate binary can be hijacked, so review the hidden entries too.",
]
AUTORUNSC_STEPS = [
    "Ask for CSV output with file hashes, for structured analysis. get_windows_tool_help shows "
    "these options for the installed version.",
    "Include signature checks, to see which entries are signed.",
    "Hide Microsoft-signed entries only for a first triage pass. Then review the full results.",
]


def test_autorunsc_advice_is_in_words_for_offline_runs():
    tool = loader.get_tool("autorunsc")
    assert tool["advisories"][:5] == AUTORUNSC_ADVICE
    assert all(step in tool["investigation_sequence"] for step in AUTORUNSC_STEPS)
