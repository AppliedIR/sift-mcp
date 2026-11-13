"""The gateway unit setup-sift.sh writes: a tool killed at the memory limit
never takes the gateway with it."""

from pathlib import Path

TEXT = (Path(__file__).resolve().parents[1] / "setup-sift.sh").read_text()


def test_the_unit_caps_memory_at_75_percent_and_keeps_the_gateway_on_a_kill():
    unit = TEXT.split('vhir-gateway.service" << SERVICE\n', 1)[1]
    unit = unit.split("\nSERVICE\n", 1)[0]
    memory = [ln for ln in unit.splitlines() if ln.startswith(("Memory", "OOM"))]
    assert memory == ["MemoryMax=75%", "OOMPolicy=continue"]
