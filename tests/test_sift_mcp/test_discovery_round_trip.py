"""suggest_tools' no-match hint lists names suggest_tools accepts.

It listed artifact display names ("NTFS Alternate Data Streams"); lookup takes
file keys, so feeding a listed name back gave "No tools found" again.
"""

from __future__ import annotations

from sift_mcp.tools.discovery import suggest_tools


def test_every_listed_artifact_returns_suggestions():
    miss = suggest_tools("no-such-artifact")
    listed = miss["available_artifacts"]
    assert listed
    dead = [name for name in listed if not suggest_tools(name)["suggestions"]]
    assert not dead, (
        f"{len(dead)} of {len(listed)} listed artifacts give no suggestions: {dead[:5]}"
    )
