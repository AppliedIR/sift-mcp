"""Investigation playbooks — loaded from forensic-knowledge YAML.

Thin wrapper: all data comes from forensic-knowledge package.
Functions preserve the same API as before for backward compatibility.
"""

from __future__ import annotations

from forensic_knowledge import loader


def list_all() -> list[dict]:
    """List available playbooks."""
    return loader.list_playbooks()


def get_by_name(name: str) -> dict:
    """Get a specific playbook."""
    result = loader.get_playbook(name)
    if result is None:
        available = [p["name"] for p in loader.list_playbooks()]
        return {"error": f"Unknown playbook '{name}'", "available": available}
    return result


def get_checklist(artifact_type: str) -> dict:
    """Get collection checklist for an artifact type."""
    result = loader.get_collection_checklist(artifact_type)
    if result is None:
        # List what's available
        available = []
        for at in ("registry", "event_logs", "memory", "filesystem"):
            if loader.get_collection_checklist(at) is not None:
                available.append(at)
        return {"error": f"Unknown artifact type '{artifact_type}'", "available": sorted(available)}
    return result
