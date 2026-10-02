"""Both installers expand the held-package array in the bash 3.2-safe form.

`"${LOCK_HELD[@]}"` on an empty array is an "unbound variable" error under
`set -u` in bash older than 4.4 (macOS ships 3.2), so the installers use
`${LOCK_HELD[@]+"${LOCK_HELD[@]}"}`. CI's bash (5.x) can't reproduce the
failure, not even with BASH_COMPAT, so this checks the form itself: every
expansion of the array on a non-comment line is the guarded one, and each
installer has at least one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
GUARDED = '${LOCK_HELD[@]+"${LOCK_HELD[@]}"}'


@pytest.mark.parametrize("installer", ["setup-sift.sh", "quickstart-lite.sh"])
def test_every_lock_held_expansion_is_guarded(installer):
    code = [
        line
        for line in (ROOT / installer).read_text().splitlines()
        if not line.lstrip().startswith("#")
    ]
    guarded = sum(line.count(GUARDED) for line in code)
    bare = [line for line in code if "${LOCK_HELD[" in line.replace(GUARDED, "")]
    assert guarded >= 1, f"{installer}: no expansion of LOCK_HELD found"
    assert not bare, f"{installer}: unguarded expansion: {bare}"
