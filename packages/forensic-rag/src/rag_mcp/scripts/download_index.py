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


def _extract_bundle(src: Path, dest: Path) -> None:
    """Extract a .tar.zst archive to dest directory."""
    import sys

    import zstandard as zstd

    dctx = zstd.ZstdDecompressor()
    with open(src, "rb") as compressed:
        with dctx.stream_reader(compressed) as reader:
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                if sys.version_info >= (3, 12):
                    tar.extractall(path=dest, filter="data")
                else:
                    tar.extractall(path=dest)


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

    # Preserve user state files before extraction
    user_state_backup = None
    ingested_state_backup = None
    user_state_path = dest / "user_state.json"
    ingested_state_path = dest / "ingested_state.json"
    has_user_content = False
    has_ingested_content = False

    if user_state_path.exists():
        try:
            with open(user_state_path, encoding="utf-8") as f:
                user_state = json.load(f)
            if user_state.get("files"):
                has_user_content = True
                user_state_backup = user_state_path.read_bytes()
        except (OSError, json.JSONDecodeError):
            pass

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
            _extract_bundle(temp_dir / "rag-index.tar.zst", dest)
            print("  Extraction complete")

            # Restore user state files
            if user_state_backup is not None:
                user_state_path.write_bytes(user_state_backup)
                print("  Restored user_state.json")
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

            # If user content existed, re-embed it into the new index
            if has_user_content:
                print("\nRe-embedding user documents into downloaded index...")
                try:
                    os.environ["ANONYMIZED_TELEMETRY"] = "False"
                    from ..refresh import refresh

                    result = refresh(skip_online=True, data_dir=dest)
                    if result.status in ("success", "no_changes"):
                        print("  User documents re-embedded")
                    else:
                        print(
                            f"  Warning: refresh returned {result.status}: "
                            f"{result.errors}"
                        )
                except Exception as e:
                    print(f"  Warning: could not re-embed user documents: {e}")
                    print("  Run 'python -m rag_mcp.refresh --skip-online' manually")

            print("\nRAG index installed successfully.")
            return True

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    return False


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

    if args.dest:
        dest = Path(args.dest)
    else:
        # Default: data/ directory relative to the forensic-rag package
        pkg_root = Path(__file__).resolve().parent.parent.parent.parent
        dest = pkg_root / "data"

    if download_index(dest, args.tag):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
