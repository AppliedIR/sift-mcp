"""Every backend setup-sift.sh registers with the gateway has an allow rule in
the shipped full-tier Claude Code settings, so a fresh install never prompts
for (or silently lacks) one of its own backends."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent

# The installer's two gateway backend lists, as (name, module) pairs: the one a
# new gateway config is written from, and the one an existing config is merged
# with. (Its package list has pairs too, with pip names, so it is left out.)
_SPANS = (
    ("core_backends = [", "for name, module in core_backends + optional:"),
    ("expected = [", "added = []"),
)
_PAIR = re.compile(r'\("([a-z0-9-]+)",\s*"[a-z_]+"\)')


def _span_backends():
    text = (ROOT / "setup-sift.sh").read_text()
    for start, end in _SPANS:
        i = text.index(start)
        yield set(_PAIR.findall(text[i : text.index(end, i)]))


def _registered_backends():
    return set().union(*_span_backends())


def test_the_installer_backends_are_found():
    for names in _span_backends():
        assert len(names) >= 8, names
        assert {"forensic-mcp", "opensearch-mcp", "threatintel-mcp"} <= names


def test_every_registered_backend_is_allowed():
    settings = json.loads((ROOT / "claude-code" / "full" / "settings.json").read_text())
    allow = settings["permissions"]["allow"]
    missing = sorted(n for n in _registered_backends() if f"mcp__{n}__*" not in allow)
    assert not missing, f"no allow rule for {missing}"
