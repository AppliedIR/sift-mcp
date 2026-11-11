"""Every test session works on a private copy of the RAG index.

Two data dirs are shared: the one the RAG package uses (RAG_INDEX_DIR if it is
set and not empty, else the package's own data dir) and the package's own
data dir itself, which in an editable install is the source tree's, the one
the installed server reads. Opening an index with chromadb can write to it, so
a test that opened a shared one could change what the server and every later
run read. The root conftest calls isolate() when it is imported, before any
test module: the data dir is copied to a private one, RAG_INDEX_DIR points
there, and both shared dirs are hashed. At the end of the session changed()
says which of their files are not byte for byte as they were, and the session
fails if any are.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import stat
from pathlib import Path

ENV = "RAG_INDEX_DIR"

Guard = list[tuple[Path, dict[str, str]]]


def package_data_dir() -> Path | None:
    """rag_mcp.utils.PACKAGE_DATA_DIR, found without importing rag_mcp
    (importing it loads chromadb and the model code into every session)."""
    try:
        spec = importlib.util.find_spec("rag_mcp")
    except (ImportError, ValueError):
        return None
    if spec is None or not spec.origin:
        return None
    return (Path(spec.origin).parent.parent.parent / "data").resolve()


def shared_dir() -> Path | None:
    """The data dir rag_mcp.utils.resolve_data_dir() gives with no argument."""
    value = os.environ.get(ENV) or package_data_dir()
    if not value:
        return None
    return Path(value).expanduser().resolve()


def manifest(root: Path) -> dict[str, str]:
    """Each file and link under root, by relative path: a file's sha256, a
    link's target. Empty when root does not exist."""
    out: dict[str, str] = {}
    if not root.is_dir():
        return out
    for top, dirs, files in os.walk(root):
        for name in dirs + files:
            path = Path(top, name)
            rel = str(path.relative_to(root))
            if path.is_symlink():
                out[rel] = "link " + os.readlink(path)
            elif path.is_file():
                digest = hashlib.sha256()
                with open(path, "rb") as fh:
                    while block := fh.read(1 << 20):
                        digest.update(block)
                out[rel] = digest.hexdigest()
    return out


def isolate(private_root: Path) -> Guard:
    """Hash the shared dirs, copy the data dir to private_root/rag-index (made
    writable by its owner) and point RAG_INDEX_DIR at the copy. Returns each shared dir with its hashes;
    empty when there is no rag_mcp to find. When the data dir does not exist
    the copy does not either, so the session sees no index, as it would have."""
    shared = shared_dir()
    if shared is None:
        return []
    dirs = [shared]
    package = package_data_dir()
    if package is not None and package != shared:
        dirs.append(package)
    guard = [(d, manifest(d)) for d in dirs]
    private = private_root / "rag-index"
    if shared.is_dir():
        shutil.copytree(shared, private, symlinks=True)
        _owner_writable(private)
    os.environ[ENV] = str(private)
    return guard


def _owner_writable(root: Path) -> None:
    """chmod u+w on root and every dir and file under it, so a copy of a
    read-only index (a packaged install, a CI cache) can be written. Links are
    left alone: chmod would follow one out of the copy."""
    root.chmod(root.stat().st_mode | stat.S_IWUSR)
    for top, dirs, files in os.walk(root):
        for name in dirs + files:
            path = Path(top, name)
            if not path.is_symlink():
                path.chmod(path.stat().st_mode | stat.S_IWUSR)


def changed(guard: Guard) -> list[str]:
    """Each file added, removed or changed under a shared dir since isolate()."""
    out = []
    for root, before in guard:
        after = manifest(root)
        for rel in sorted(before.keys() | after.keys()):
            if before.get(rel) != after.get(rel):
                out.append(str(root / rel))
    return out
