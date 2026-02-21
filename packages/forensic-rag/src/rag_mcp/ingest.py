"""
User Document Ingestion - Process watched and one-time ingested documents.

Two modes:
1. Watched: Files in knowledge/ folder, auto-sync on refresh
2. Ingested: One-time import from anywhere, tracked by friendly name
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .utils import atomic_write_json, compute_file_hash

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent.parent
DEFAULT_KNOWLEDGE_DIR = PROJECT_ROOT / "knowledge"
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
USER_STATE_FILE = DEFAULT_DATA_DIR / "user_state.json"
INGESTED_STATE_FILE = DEFAULT_DATA_DIR / "ingested_state.json"

# Accepted formats
SUPPORTED_FORMATS = {".txt", ".md", ".json", ".jsonl"}

# Rejection messages for unsupported formats
REJECTION_MESSAGES = {
    ".pdf": "Convert to .txt first: pdftotext file.pdf or copy/paste",
    ".docx": "File > Save As > Plain Text (.txt)",
    ".doc": "File > Save As > Plain Text (.txt)",
    ".xlsx": "Export relevant data to .jsonl",
    ".xls": "Export relevant data to .jsonl",
    ".html": "Save As > Plain Text or convert to .md",
    ".htm": "Save As > Plain Text or convert to .md",
    ".pptx": "Copy text content to .txt or .md",
    ".ppt": "Copy text content to .txt or .md",
    ".rtf": "Save As > Plain Text (.txt)",
    ".odt": "File > Save As > Plain Text (.txt)",
}

# Bundled content marker (directories shipped with the repo)
BUNDLED_MARKER = ".bundled"

# Chunking settings
CHUNK_TARGET = 1000  # Target characters per chunk
CHUNK_MIN = 500      # Minimum chunk size
CHUNK_MAX = 1500     # Maximum chunk size

# Security: File size limit (10MB)
MAX_FILE_SIZE = 10 * 1024 * 1024

# Security: ID sanitization pattern (alphanumeric, underscore, hyphen only)
SAFE_ID_PATTERN = re.compile(r'[^a-zA-Z0-9_-]')


def _sanitize_id(name: str) -> str:
    """Sanitize a string for use in record IDs.

    Security: Only allows alphanumeric, underscore, and hyphen characters.
    Prevents ID injection and path traversal in ID handling.
    """
    return SAFE_ID_PATTERN.sub('_', name)


def _validate_file_size(path: Path) -> None:
    """Validate file size is within limits.

    Security: Prevents memory exhaustion from very large files.
    """
    size = path.stat().st_size
    if size > MAX_FILE_SIZE:
        raise ValueError(
            f"File size ({size:,} bytes) exceeds maximum allowed "
            f"({MAX_FILE_SIZE:,} bytes)"
        )


@dataclass
class IngestResult:
    """Result of ingesting a document."""
    path: str
    status: str  # "success", "error", "skipped"
    records: int = 0
    record_ids: Optional[list[str]] = None
    message: str = ""

    def __post_init__(self) -> None:
        if self.record_ids is None:
            self.record_ids = []


@dataclass
class ScanResult:
    """Result of scanning knowledge folder."""
    supported: list[Path]
    unsupported: list[tuple[Path, str]]  # (path, rejection message)


@dataclass
class ChangeSet:
    """Changes detected in knowledge folder."""
    new: list[Path]
    modified: list[Path]
    deleted: list[str]  # relative paths


# =============================================================================
# Format Validation
# =============================================================================

def validate_format(path: Path) -> tuple[bool, str]:
    """
    Check if file format is supported.

    Returns:
        (ok, message) - ok=True if supported, message is rejection reason if not
    """
    suffix = path.suffix.lower()

    if suffix in SUPPORTED_FORMATS:
        return True, ""

    message = REJECTION_MESSAGES.get(suffix, f"Unsupported format: {suffix}")
    return False, message


def _is_in_bundled_dir(path: Path, root: Path) -> bool:
    """Check if a file is inside a directory marked with .bundled."""
    # Walk from the file's parent up to (but not including) root
    current = path.parent
    while current != root and current != current.parent:
        if (current / BUNDLED_MARKER).exists():
            return True
        current = current.parent
    return False


def scan_knowledge_folder(
    folder: Optional[Path] = None,
    skip_bundled: bool = False
) -> ScanResult:
    """
    Scan folder for supported and unsupported files.

    Args:
        folder: Knowledge directory to scan
        skip_bundled: If True, skip files in directories containing a .bundled marker

    Returns:
        ScanResult with lists of supported and unsupported files
    """
    folder = folder or DEFAULT_KNOWLEDGE_DIR
    supported = []
    unsupported = []

    if not folder.exists():
        return ScanResult(supported=[], unsupported=[])

    for path in folder.rglob("*"):
        if path.is_file():
            # Skip symlinks (could escape knowledge/ directory)
            if path.is_symlink():
                continue
            # Skip hidden files (e.g., .gitkeep, .bundled)
            if path.name.startswith("."):
                continue
            # Skip bundled content when requested
            if skip_bundled and _is_in_bundled_dir(path, folder):
                continue
            ok, message = validate_format(path)
            if ok:
                supported.append(path)
            else:
                unsupported.append((path, message))

    return ScanResult(supported=supported, unsupported=unsupported)


# =============================================================================
# State Management
# =============================================================================

def load_user_state() -> dict[str, Any]:
    """Load watched documents state."""
    if USER_STATE_FILE.exists():
        try:
            with open(USER_STATE_FILE, encoding="utf-8") as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            pass
    return {"version": 1, "files": {}}


def save_user_state(state: dict[str, Any]) -> None:
    """Save watched documents state.

    Security: Uses atomic write to prevent corruption from concurrent access.
    """
    atomic_write_json(USER_STATE_FILE, state)


def load_ingested_state() -> dict[str, Any]:
    """Load ingested documents state."""
    if INGESTED_STATE_FILE.exists():
        try:
            with open(INGESTED_STATE_FILE, encoding="utf-8") as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            pass
    return {"version": 1, "documents": {}}


def save_ingested_state(state: dict[str, Any]) -> None:
    """Save ingested documents state.

    Security: Uses atomic write to prevent corruption from concurrent access.
    """
    atomic_write_json(INGESTED_STATE_FILE, state)


# =============================================================================
# Text Chunking
# =============================================================================

def chunk_text(text: str, file_path: str, source_prefix: str = "user") -> list[dict]:
    """
    Split text into chunks at semantic boundaries.

    Strategy by format:
    - .md: Split on headers (##), then paragraphs
    - .txt: Split on double-newlines (paragraphs)
    - Never split mid-sentence where possible

    Returns:
        List of {id, text, metadata} dicts
    """
    path = Path(file_path)
    ext = path.suffix.lower()

    # Determine split strategy
    if ext == ".md":
        # Split on markdown headers first
        sections = re.split(r'\n(?=#{1,3} )', text)
    else:
        # Split on paragraph breaks
        sections = re.split(r'\n\n+', text)

    # Remove empty sections
    sections = [s.strip() for s in sections if s.strip()]

    chunks = []
    current_chunk = ""
    chunk_num = 0

    # Security: Generate safe ID prefix from path using sanitization
    safe_path = _sanitize_id(path.stem)
    id_prefix = f"{source_prefix}_{safe_path}"

    for section in sections:
        # If adding this section exceeds max, flush current chunk
        if len(current_chunk) + len(section) > CHUNK_MAX and current_chunk:
            chunks.append(_make_chunk(current_chunk, id_prefix, chunk_num, file_path, source_prefix))
            chunk_num += 1
            current_chunk = ""

        current_chunk += section + "\n\n"

        # If we've hit target size, flush
        if len(current_chunk) >= CHUNK_TARGET:
            chunks.append(_make_chunk(current_chunk, id_prefix, chunk_num, file_path, source_prefix))
            chunk_num += 1
            current_chunk = ""

    # Don't forget the last chunk
    if current_chunk.strip():
        if len(current_chunk) >= CHUNK_MIN or not chunks:
            chunks.append(_make_chunk(current_chunk, id_prefix, chunk_num, file_path, source_prefix))
        elif chunks:
            # Append tiny remainder to last chunk
            chunks[-1]["text"] += "\n" + current_chunk.strip()

    return chunks


def _make_chunk(text: str, id_prefix: str, chunk_num: int, file_path: str, source_prefix: str) -> dict:
    """Create a chunk record."""
    return {
        "id": f"{id_prefix}_{chunk_num}",
        "text": text.strip(),
        "metadata": {
            "source": f"{source_prefix}_{Path(file_path).stem}",
            "file": file_path,
            "chunk": chunk_num
        }
    }


# =============================================================================
# JSON Processing
# =============================================================================

def process_json_file(path: Path, source_prefix: str = "user") -> list[dict]:
    """
    Process a .json file based on structure.

    Supported structures:
    1. Single object with "text" field -> 1 record
    2. Array of objects with "text" fields -> N records
    3. Object with "items"/"records"/"data" array -> N records
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    # Security: Sanitize ID prefix
    safe_name = _sanitize_id(path.stem)
    id_prefix = f"{source_prefix}_{safe_name}"

    records = []

    if isinstance(data, list):
        # Array of objects
        for i, item in enumerate(data):
            record = _normalize_record(item, id_prefix, i, str(path), source_prefix)
            if record:
                records.append(record)

    elif isinstance(data, dict):
        # Check for common array keys
        for key in ["items", "records", "data", "entries", "documents"]:
            if key in data and isinstance(data[key], list):
                for i, item in enumerate(data[key]):
                    record = _normalize_record(item, id_prefix, i, str(path), source_prefix)
                    if record:
                        records.append(record)
                return records

        # Single object with text
        record = _normalize_record(data, id_prefix, 0, str(path), source_prefix)
        if record:
            records.append(record)

    return records


def process_jsonl_file(path: Path, source_prefix: str = "user") -> list[dict]:
    """Process a .jsonl file (one JSON object per line)."""
    # Security: Sanitize ID prefix
    safe_name = _sanitize_id(path.stem)
    id_prefix = f"{source_prefix}_{safe_name}"
    records = []

    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                record = _normalize_record(item, id_prefix, i, str(path), source_prefix)
                if record:
                    records.append(record)
            except json.JSONDecodeError:
                logger.debug(f"Invalid JSON on line {i+1} of {path}")
                continue

    return records


def _normalize_record(item: dict, id_prefix: str, index: int, file_path: str, source_prefix: str) -> Optional[dict]:
    """Normalize a record to have required fields."""
    if not isinstance(item, dict):
        return None

    # Find text content
    text = None
    for key in ["text", "content", "description", "body", "value"]:
        if key in item and isinstance(item[key], str):
            text = item[key]
            break

    if not text:
        return None

    # Merge existing metadata
    metadata = item.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    metadata["source"] = metadata.get("source", f"{source_prefix}_{Path(file_path).stem}")
    metadata["file"] = file_path

    return {
        "id": f"{id_prefix}_{index}",
        "text": text,
        "metadata": metadata
    }


# =============================================================================
# Document Processing
# =============================================================================

def process_document(path: Path, source_prefix: str = "user") -> IngestResult:
    """
    Process a single document into records.

    Args:
        path: Path to document
        source_prefix: Prefix for source metadata (e.g., "user" or "ingested")

    Returns:
        IngestResult with records
    """
    ok, message = validate_format(path)
    if not ok:
        return IngestResult(path=str(path), status="error", message=message)

    try:
        # Security: Check file size before reading
        _validate_file_size(path)

        ext = path.suffix.lower()

        if ext == ".jsonl":
            records = process_jsonl_file(path, source_prefix)
        elif ext == ".json":
            records = process_json_file(path, source_prefix)
        else:
            # Text files (.txt, .md)
            with open(path, encoding="utf-8") as f:
                text = f.read()
            records = chunk_text(text, str(path), source_prefix)

        record_ids = [r["id"] for r in records]

        return IngestResult(
            path=str(path),
            status="success",
            records=len(records),
            record_ids=record_ids
        )

    except Exception as e:
        return IngestResult(path=str(path), status="error", message=str(e))


def get_document_records(path: Path, source_prefix: str = "user") -> list[dict]:
    """
    Get the actual records from a document (for adding to ChromaDB).

    Args:
        path: Path to document
        source_prefix: Prefix for source metadata

    Returns:
        List of record dicts with id, text, metadata

    Security:
        - Validates file format
        - Enforces file size limits
    """
    ok, _ = validate_format(path)
    if not ok:
        return []

    try:
        # Security: Check file size before reading
        _validate_file_size(path)

        ext = path.suffix.lower()

        if ext == ".jsonl":
            return process_jsonl_file(path, source_prefix)
        elif ext == ".json":
            return process_json_file(path, source_prefix)
        else:
            with open(path, encoding="utf-8") as f:
                text = f.read()
            return chunk_text(text, str(path), source_prefix)

    except ValueError as e:
        logger.warning(f"File validation failed for {path.name}: {e}")
        return []
    except Exception:
        return []


# =============================================================================
# Watched Documents (knowledge/ folder)
# =============================================================================

def check_for_changes(
    folder: Optional[Path] = None,
    skip_bundled: bool = False
) -> ChangeSet:
    """
    Compare knowledge folder against state to find changes.

    Args:
        folder: Knowledge directory to scan
        skip_bundled: If True, skip files in directories containing a .bundled marker

    Returns:
        ChangeSet with new, modified, and deleted files
    """
    folder = folder or DEFAULT_KNOWLEDGE_DIR
    state = load_user_state()
    files_state = state.get("files", {})

    new = []
    modified = []
    deleted = []

    # Get current supported files
    scan = scan_knowledge_folder(folder, skip_bundled=skip_bundled)
    current_files = set()

    for path in scan.supported:
        rel_path = str(path.relative_to(folder))
        current_files.add(rel_path)

        if rel_path not in files_state:
            new.append(path)
        else:
            # Check if modified (hash changed)
            current_hash = compute_file_hash(path)
            if current_hash != files_state[rel_path].get("hash"):
                modified.append(path)

    # Find deleted files
    for rel_path in files_state:
        if rel_path not in current_files:
            deleted.append(rel_path)

    return ChangeSet(new=new, modified=modified, deleted=deleted)


def update_watched_state(rel_path: str, path: Path, record_ids: list[str]) -> None:
    """Update state for a watched file."""
    state = load_user_state()
    state.setdefault("files", {})[rel_path] = {
        "hash": compute_file_hash(path),
        "size": path.stat().st_size,
        "id_prefix": f"user_{path.stem}",
        "records": len(record_ids),
        "record_ids": record_ids,
        "processed_at": datetime.now().isoformat()
    }
    save_user_state(state)


def remove_watched_state(rel_path: str) -> list[str]:
    """Remove a file from watched state. Returns record IDs to delete."""
    state = load_user_state()
    if rel_path in state.get("files", {}):
        record_ids = state["files"][rel_path].get("record_ids", [])
        del state["files"][rel_path]
        save_user_state(state)
        return record_ids
    return []


# =============================================================================
# Ingested Documents (one-time import)
# =============================================================================

def ingest_document(path: Path, name: str) -> IngestResult:
    """
    Ingest a document with a friendly name.

    If name already exists, replaces previous version.

    Args:
        path: Path to file (can be anywhere)
        name: Friendly name for tracking

    Returns:
        IngestResult
    """
    ok, message = validate_format(path)
    if not ok:
        return IngestResult(path=str(path), status="error", message=message)

    # Check if replacing existing
    state = load_ingested_state()
    existing = state.get("documents", {}).get(name)
    replaced = existing is not None

    try:
        # Security: Check file size before processing
        _validate_file_size(path)

        # Process document
        records = get_document_records(path, source_prefix="ingested")

        # Security: Sanitize the friendly name for use in IDs
        safe_name = _sanitize_id(name)
        for i, rec in enumerate(records):
            rec["id"] = f"ingested_{safe_name}_{i}"
            rec["metadata"]["source"] = f"ingested_{safe_name}"

        record_ids = [r["id"] for r in records]

        # Update state
        state.setdefault("documents", {})[name] = {
            "original_filename": path.name,
            "records": len(records),
            "record_ids": record_ids,
            "ingested_at": datetime.now().isoformat()
        }
        save_ingested_state(state)

        result = IngestResult(
            path=str(path),
            status="success",
            records=len(records),
            record_ids=record_ids
        )
        if replaced:
            result.message = f"Replaced existing '{name}'"

        return result

    except Exception as e:
        return IngestResult(path=str(path), status="error", message=str(e))


def get_ingested_records(path: Path, name: str) -> list[dict]:
    """Get records for an ingested document (for adding to ChromaDB)."""
    records = get_document_records(path, source_prefix="ingested")

    # Security: Sanitize the friendly name for use in IDs
    safe_name = _sanitize_id(name)
    for i, rec in enumerate(records):
        rec["id"] = f"ingested_{safe_name}_{i}"
        rec["metadata"]["source"] = f"ingested_{safe_name}"

    return records


def list_ingested() -> list[dict]:
    """List all ingested documents."""
    state = load_ingested_state()
    result = []

    for name, info in state.get("documents", {}).items():
        result.append({
            "name": name,
            "original_filename": info.get("original_filename", ""),
            "records": info.get("records", 0),
            "ingested_at": info.get("ingested_at", "")
        })

    return sorted(result, key=lambda x: x["ingested_at"], reverse=True)


def get_ingested_record_ids(name: str) -> list[str]:
    """Get record IDs for an ingested document (for deletion)."""
    state = load_ingested_state()
    doc = state.get("documents", {}).get(name)
    if doc:
        return doc.get("record_ids", [])
    return []


def remove_ingested(name: str) -> tuple[bool, list[str]]:
    """
    Remove an ingested document.

    Returns:
        (success, record_ids) - record_ids to delete from ChromaDB
    """
    state = load_ingested_state()
    if name not in state.get("documents", {}):
        return False, []

    record_ids = state["documents"][name].get("record_ids", [])
    del state["documents"][name]
    save_ingested_state(state)

    return True, record_ids


def remove_all_ingested() -> tuple[int, list[str]]:
    """
    Remove all ingested documents.

    Returns:
        (count, record_ids) - count of docs removed, all record_ids to delete
    """
    state = load_ingested_state()
    docs = state.get("documents", {})

    count = len(docs)
    all_ids = []
    for doc in docs.values():
        all_ids.extend(doc.get("record_ids", []))

    state["documents"] = {}
    save_ingested_state(state)

    return count, all_ids
