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
