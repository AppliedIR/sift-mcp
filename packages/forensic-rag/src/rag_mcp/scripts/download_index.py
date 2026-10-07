"""Download pre-built RAG index from GitHub releases.

Downloads a ChromaDB bundle containing the full IR knowledge base index,
avoiding the 1-3 hour build-from-source step on first install.

Usage:
    python -m rag_mcp.scripts.download_index [--dest DIR] [--tag TAG]

Authentication:
    For private repos, set GITHUB_TOKEN or have ``gh`` CLI authenticated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = "AppliedIR/sift-mcp"
ASSETS = ("rag-index.tar.zst", "rag-checksums.sha256")
MAX_ATTEMPTS = 3
CHUNK_SIZE = 1024 * 1024  # 1 MB
TAG_PREFIX = "rag-index-"
# What a bundle may install: the shipped store. Anything else (a user/ tree,
# say) is skipped and named, so the examiner's store is never overwritten.
SHIPPED_MEMBERS = ("chroma", "sources", "metadata.json", "user_state.json")


def _github_headers() -> dict[str, str]:
    """Build HTTP headers for GitHub API, including token if available.

    Token sources (in order): GITHUB_TOKEN env var, ``gh auth token`` CLI.
    """
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                token = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_release(tag: str = "latest") -> dict:
    """Fetch release metadata from GitHub API.

    When tag is "latest", finds the most recent rag-index-* release
    that contains the expected assets. Otherwise fetches the exact tag.
    """
    headers = _github_headers()

    if tag == "latest":
        url = f"https://api.github.com/repos/{REPO}/releases?per_page=100"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            releases = json.loads(resp.read())
            matching = [
                r
                for r in releases
                if r["tag_name"].startswith(TAG_PREFIX)
                and any(a["name"] == "rag-index.tar.zst" for a in r.get("assets", []))
            ]
            if matching:
                return matching[0]  # GitHub returns most recent first
            raise ValueError(
                "No RAG index releases found. "
                f"Expected releases with tag prefix '{TAG_PREFIX}' "
                "containing rag-index.tar.zst assets."
            )
    else:
        url = f"https://api.github.com/repos/{REPO}/releases/tags/{tag}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())


def _get_asset_url(release: dict, asset_name: str) -> str | None:
    """Extract the API download URL for a named asset."""
    for asset in release.get("assets", []):
        if asset["name"] == asset_name:
            return asset["url"]
    return None


def _download_asset(url: str, dest: Path) -> None:
    """Download a single asset to dest with progress indication."""
    headers = _github_headers()
    headers["Accept"] = "application/octet-stream"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=300) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(CHUNK_SIZE)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if total > 0:
                    pct = downloaded * 100 // total
                    mb = downloaded / (1024 * 1024)
                    print(
                        f"\r  {dest.name}: {mb:.1f} MB ({pct}%)",
                        end="",
                        flush=True,
                    )
        print()


def _verify_checksums(temp_dir: Path) -> bool:
    """Verify SHA-256 checksums of downloaded files."""
    checksum_file = temp_dir / "rag-checksums.sha256"
    if not checksum_file.is_file():
        print("  No checksums file. Skipping verification.")
        return True

    ok = True
    for line in checksum_file.read_text().strip().splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        expected_hash = parts[0]
        file_name = parts[1]
        file_path = temp_dir / file_name
        if not file_path.is_file():
            continue
        actual_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
        if actual_hash == expected_hash:
            print(f"  OK: {file_name}")
        else:
            print(f"  FAILED: {file_name}")
            print(f"    expected: {expected_hash}")
            print(f"    got:      {actual_hash}")
            ok = False
    return ok


def _shipped_member(name: str) -> bool:
    name = name[2:] if name.startswith("./") else name
    top = name.split("/", 1)[0]
    return top in SHIPPED_MEMBERS and (top in ("chroma", "sources") or name == top)


def _extract_bundle(src: Path, dest: Path) -> list[str]:
    """Extract a .tar.zst archive's shipped members to dest; returns the
    names of the members it skipped."""
    import zstandard as zstd

    skipped: list[str] = []

    def shipped(tar):
        for member in tar:
            if _shipped_member(member.name):
                yield member
                continue
            # A skipped member that would leave dest is still refused
            if hasattr(tarfile, "data_filter"):
                tarfile.data_filter(member, str(dest))
            skipped.append(member.name)

    dctx = zstd.ZstdDecompressor()
    with open(src, "rb") as compressed:
        with dctx.stream_reader(compressed) as reader:
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                # The "data" filter refuses members that leave dest: Python 3.12+,
                # and the 3.10.12+/3.11.4+ backports
                if hasattr(tarfile, "data_filter"):
                    tar.extractall(path=dest, members=shipped(tar), filter="data")
                else:
                    tar.extractall(path=dest, members=shipped(tar))
    return skipped


def _verify_index(data_dir: Path) -> bool:
    """Verify the extracted index is usable.

    Checks:
    1. ChromaDB loads and collection has > 20000 records
    2. HNSW test query returns results
    3. Model in metadata matches DEFAULT_MODEL_NAME
    """
    import chromadb
    from sentence_transformers import SentenceTransformer

    from ..utils import DEFAULT_MODEL_NAME

    # Check model match
    metadata_path = data_dir / "metadata.json"
    if metadata_path.exists():
        try:
            with open(metadata_path, encoding="utf-8") as f:
                metadata = json.load(f)
            bundle_model = metadata.get("model", "")
            if bundle_model and bundle_model != DEFAULT_MODEL_NAME:
                print(
                    f"  Model mismatch: bundle uses '{bundle_model}' "
                    f"but this install uses '{DEFAULT_MODEL_NAME}'"
                )
                return False
        except (OSError, json.JSONDecodeError) as e:
            print(f"  Could not read metadata.json: {e}")
            return False

    # Load ChromaDB and verify count
    chroma_path = data_dir / "chroma"
    if not chroma_path.exists():
        print("  ChromaDB directory not found after extraction")
        return False

    try:
        client = chromadb.PersistentClient(path=str(chroma_path))
        collection = client.get_collection("ir_knowledge")
        count = collection.count()
        if count < 20000:
            print(f"  Collection has only {count:,} records (expected 20,000+)")
            return False
        print(f"  Collection: {count:,} records")
    except Exception as e:
        print(f"  ChromaDB load failed: {e}")
        return False

    # HNSW test query — suppress noisy model loading output
    try:
        import logging
        import warnings

        for _name in ("sentence_transformers", "transformers", "huggingface_hub"):
            logging.getLogger(_name).setLevel(logging.ERROR)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            model = SentenceTransformer(DEFAULT_MODEL_NAME)
        test_embedding = model.encode("test").tolist()
        results = collection.query(query_embeddings=[test_embedding], n_results=1)
        if not results["ids"][0]:
            print("  HNSW test query returned no results")
            return False
        print("  HNSW test query: OK")
    except Exception as e:
        print(f"  HNSW test query failed: {e}")
        return False

    return True


def download_index(dest_dir: str | Path, tag: str = "latest") -> bool:
    """Download and verify RAG index bundle.

    Args:
        dest_dir: Directory to place the extracted index (the data/ dir).
        tag: GitHub release tag (default: "latest").

    Returns:
        True on success, False on failure.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    # Every Chroma client in this process must see the same settings: one
    # opened with telemetry on refuses a later one on the same path
    os.environ["ANONYMIZED_TELEMETRY"] = "False"

    # Preserve user state files before extraction
    ingested_state_backup = None
    ingested_state_path = dest / "ingested_state.json"
    has_ingested_content = False

    if ingested_state_path.exists():
        try:
            with open(ingested_state_path, encoding="utf-8") as f:
                ingested_state = json.load(f)
            ingested_docs = ingested_state.get("documents", {})
            if ingested_docs:
                has_ingested_content = True
                ingested_state_backup = ingested_state_path.read_bytes()
                total_records = sum(
                    info.get("records", 0) for info in ingested_docs.values()
                )
                print(
                    f"  WARNING: {len(ingested_docs)} ingested document(s) "
                    f"({total_records} records) will be replaced."
                )
                print("  Re-ingest after download if needed.")
        except (OSError, json.JSONDecodeError):
            pass

    print(f"Fetching release info from {REPO}...")
    try:
        release = _fetch_release(tag)
    except Exception as e:
        print(f"Failed to fetch release: {e}")
        return False

    tag_name = release.get("tag_name", tag)
    print(f"Release: {tag_name}")

    # The examiner's own documents live in their own store, which the bundle
    # never replaces. Bring it in line with the knowledge folder and commit it
    # before anything is extracted; if that fails, the index is left as it is.
    try:
        kept = _sync_examiner_store(dest)
    except Exception as e:
        print(f"Your documents could not be put in their own store: {e}")
        print("Nothing was downloaded or changed. Fix the cause, then run")
        print("  python -m rag_mcp.refresh --skip-online")
        print("and download again.")
        return False

    for attempt in range(1, MAX_ATTEMPTS + 1):
        temp_dir = Path(tempfile.mkdtemp(prefix="rag-index-"))
        try:
            # Download assets
            print(f"\nDownloading (attempt {attempt}/{MAX_ATTEMPTS})...")
            download_ok = True
            for asset_name in ASSETS:
                url = _get_asset_url(release, asset_name)
                if not url:
                    print(f"  Asset not found in release: {asset_name}")
                    download_ok = False
                    continue
                try:
                    _download_asset(url, temp_dir / asset_name)
                except Exception as e:
                    print(f"  Download failed for {asset_name}: {e}")
                    download_ok = False

            if not download_ok:
                if attempt < MAX_ATTEMPTS:
                    wait = attempt * 5
                    print(f"  Retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                print("All download attempts failed.")
                return False

            # Verify checksums
            print("\nVerifying checksums...")
            if not _verify_checksums(temp_dir):
                if attempt < MAX_ATTEMPTS:
                    wait = attempt * 5
                    print(f"  Checksum mismatch. Retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                print("Checksum verification failed after all attempts.")
                return False

            # Extract bundle
            print("\nExtracting bundle...")
            skipped = _extract_bundle(temp_dir / "rag-index.tar.zst", dest)
            for name in skipped:
                print(f"  Skipped (not part of the shipped index): {name}")
            print("  Extraction complete")

            # Keep the bundle's user_state.json: it lists what the new index
            # holds, so the refresh below re-embeds the user's documents
            if ingested_state_backup is not None:
                ingested_state_path.write_bytes(ingested_state_backup)
                print("  Restored ingested_state.json")

            # Verify index
            print("\nVerifying index...")
            if not _verify_index(dest):
                print("Index verification failed.")
                return False

            # Update metadata with download info
            metadata_path = dest / "metadata.json"
            if metadata_path.exists():
                try:
                    with open(metadata_path, encoding="utf-8") as f:
                        metadata = json.load(f)
                    metadata["install_method"] = "download"
                    metadata["bundle_tag"] = tag_name
                    with open(metadata_path, "w", encoding="utf-8") as f:
                        json.dump(metadata, f, indent=2)
                except (OSError, json.JSONDecodeError):
                    pass

            # Bundled knowledge files newer than the bundle's copies
            if _bundled_drift(dest):
                print("\nUpdating bundled documents in the downloaded index...")
                try:
                    from ..refresh import refresh

                    result = refresh(skip_online=True, data_dir=dest)
                    if result.status not in ("success", "no_changes"):
                        print(
                            f"  Warning: refresh returned {result.status}: "
                            f"{result.errors}"
                        )
                except Exception as e:
                    print(f"  Warning: could not update bundled documents: {e}")
                    print("  Run 'python -m rag_mcp.refresh --skip-online' manually")

            print(f"\nYour documents: {kept} record(s) kept in their own store.")

            print("\nRAG index installed successfully.")
            return True

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    return False


def _knowledge_dir() -> Path:
    from ..ingest import DEFAULT_KNOWLEDGE_DIR

    return Path(os.environ.get("RAG_KNOWLEDGE_DIR", DEFAULT_KNOWLEDGE_DIR))


def _sync_examiner_store(dest: Path) -> int:
    """Commit the examiner store from the knowledge folder; returns its
    record count. The model is the index's, and another is refused."""
    from ..stores import guard_model, sync_examiner_store

    model_name = guard_model(dest)
    model = None

    def encode(texts: list[str]) -> list[list[float]]:
        nonlocal model
        if model is None:
            from sentence_transformers import SentenceTransformer

            model = SentenceTransformer(model_name)
        return model.encode(texts).tolist()

    sync = sync_examiner_store(dest, _knowledge_dir(), model_name, encode)
    for label, rels in (
        ("Added", sync.new),
        ("Updated", sync.modified),
        ("Removed", sync.deleted),
    ):
        for rel in rels:
            print(f"  {label}: {rel}")
    return sync.record_count


def _bundled_drift(dest: Path) -> bool:
    from ..ingest import check_for_changes

    changes = check_for_changes(_knowledge_dir(), data_dir=dest, only_bundled=True)
    return bool(changes.new or changes.modified or changes.deleted)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download pre-built RAG index from GitHub releases.",
    )
    parser.add_argument(
        "--dest",
        default=None,
        help="Destination directory (default: data/ relative to package)",
    )
    parser.add_argument(
        "--tag",
        default="latest",
        help="Release tag to download (default: latest)",
    )
    args = parser.parse_args()

    from ..utils import resolve_data_dir

    dest = resolve_data_dir(args.dest)

    if download_index(dest, args.tag):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
