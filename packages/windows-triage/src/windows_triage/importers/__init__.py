"""Data importers for populating databases (v2).

context.db importers (used by import_context.py):
- LOLBAS (LOLBins)
- LOLDrivers (vulnerable drivers)
- HijackLibs (hijackable DLLs)
- Process expectations (from MemProcFS + SANS Hunt Evil)

known_good.db imports are handled by scripts:
- import_files.py (VanillaWindowsReference)
- import_registry_extractions.py (services, tasks, autoruns)
"""

from .lolbas import (
    import_lolbas,
    get_lolbin_functions,
)

from .loldrivers import (
    import_loldrivers,
)

from .hijacklibs import (
    import_hijacklibs,
    get_hijack_types,
)

from .process_expectations import (
    import_process_expectations,
    load_process_expectations,
    get_process_tree,
    get_system_processes,
    get_user_processes,
)

__all__ = [
    'import_lolbas',
    'get_lolbin_functions',
    'import_loldrivers',
    'import_hijacklibs',
    'get_hijack_types',
    'import_process_expectations',
    'load_process_expectations',
    'get_process_tree',
    'get_system_processes',
    'get_user_processes',
]
