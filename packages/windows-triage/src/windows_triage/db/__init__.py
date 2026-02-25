"""Database interfaces for forensic triage (v2 hybrid schema).

This module provides offline forensic triage against local baselines:
- known_good.db: Windows file/service/task baselines from VanillaWindowsReference
- known_good_registry.db: Full registry baselines (optional, 12GB)
- context.db: Risk enrichment (LOLBins, vulnerable drivers, process rules)

For threat intelligence (hash/IOC reputation), use opencti-mcp separately.
"""

from .context import ContextDB
from .known_good import KnownGoodDB
from .registry import RegistryDB
from .schemas import (
    CONTEXT_INITIAL_DATA,
    CONTEXT_SCHEMA,
    KNOWN_GOOD_SCHEMA,
    REGISTRY_FULL_SCHEMA,
)

__all__ = [
    "KNOWN_GOOD_SCHEMA",
    "REGISTRY_FULL_SCHEMA",
    "CONTEXT_SCHEMA",
    "CONTEXT_INITIAL_DATA",
    "KnownGoodDB",
    "ContextDB",
    "RegistryDB",
]
