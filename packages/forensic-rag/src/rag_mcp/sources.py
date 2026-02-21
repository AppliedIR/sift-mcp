"""
Online Source Management - Fetch, parse, and cache authoritative sources.

Manages 23 authoritative upstream sources:
- Detection rules: Sigma, Elastic, Splunk, Chainsaw, Hayabusa
- Attack frameworks: MITRE ATT&CK, MITRE CAR, MITRE D3FEND, MITRE ATLAS, MITRE Engage, CAPEC, MBC
- Red team: Atomic Red Team, Stratus Red Team
- Forensic artifacts: ForensicArtifacts, KAPE, Velociraptor
- LOLBins: LOLBAS, GTFOBins, HijackLibs, LOLDrivers
- Threat intel: CISA KEV
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from socket import timeout as SocketTimeout
from typing import Any, Callable, Optional
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

import toml
import yaml

from .utils import compute_file_hash, atomic_write_json

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent.parent
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
SOURCES_DIR = DEFAULT_DATA_DIR / "sources"
SOURCES_STATE_FILE = DEFAULT_DATA_DIR / "sources_state.json"
SOURCES_CONFIG_FILE = DEFAULT_DATA_DIR / "sources_config.json"


@dataclass
class SourceConfig:
    """Configuration for an upstream source."""
    name: str
    description: str
    source_type: str  # "github_commits", "github_releases", "json_feed"
    repo: str  # GitHub "owner/repo" or feed URL
    branch: str = "main"
    parser: str = "default"  # Parser function name
    paths: list[str] = field(default_factory=list)  # Paths within repo to parse


@dataclass
class FetchResult:
    """Result of fetching and parsing a source."""
    source: str
    status: str  # "success", "error", "skipped"
    records: int = 0
    message: str = ""
    version: str = ""
    cache_hash: str = ""


@dataclass
class SourceStatus:
    """Status of a source including update availability."""
    name: str
    current_version: str
    latest_version: str
    has_update: bool
    last_sync: str
    records: int
    error: str = ""


# =============================================================================
# Source Registry (23 sources)
# =============================================================================

SOURCES: dict[str, SourceConfig] = {
    "sigma": SourceConfig(
        name="sigma",
        description="SigmaHQ Detection Rules",
        source_type="github_commits",
        repo="SigmaHQ/sigma",
        branch="master",
        parser="parse_sigma",
        paths=["rules/"]
    ),
    "atomic": SourceConfig(
        name="atomic",
        description="Atomic Red Team Tests",
        source_type="github_commits",
        repo="redcanaryco/atomic-red-team",
        branch="master",
        parser="parse_atomic",
        paths=["atomics/"]
    ),
    "mitre_attack": SourceConfig(
        name="mitre_attack",
        description="MITRE ATT&CK Framework",
        source_type="github_releases",
        repo="mitre-attack/attack-stix-data",
        branch="master",  # Not main!
        parser="parse_stix",
        paths=["enterprise-attack/"]
    ),
    "mitre_car": SourceConfig(
        name="mitre_car",
        description="MITRE Cyber Analytics Repository",
        source_type="github_commits",
        repo="mitre-attack/car",
        branch="master",
        parser="parse_car",
        paths=["analytics/"]
    ),
    "mitre_d3fend": SourceConfig(
        name="mitre_d3fend",
        description="MITRE D3FEND Defensive Techniques",
        source_type="json_feed",
        repo="https://d3fend.mitre.org/ontologies/d3fend.json",
        parser="parse_d3fend"
    ),
    "stratus_red_team": SourceConfig(
        name="stratus_red_team",
        description="Stratus Red Team Cloud Attack Techniques",
        source_type="github_releases",
        repo="DataDog/stratus-red-team",
        parser="parse_stratus",
        paths=["docs/attack-techniques/"]
    ),
    "cisa_kev": SourceConfig(
        name="cisa_kev",
        description="CISA Known Exploited Vulnerabilities",
        source_type="json_feed",
        repo="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        parser="parse_kev"
    ),
    "elastic": SourceConfig(
        name="elastic",
        description="Elastic Detection Rules",
        source_type="github_releases",
        repo="elastic/detection-rules",
        branch="main",
        parser="parse_elastic",
        paths=["rules/"]
    ),
    "splunk_security": SourceConfig(
        name="splunk_security",
        description="Splunk Security Content",
        source_type="github_releases",
        repo="splunk/security_content",
        parser="parse_splunk",
        paths=["detections/"]
    ),
    "lolbas": SourceConfig(
        name="lolbas",
        description="LOLBAS Project",
        source_type="github_commits",
        repo="LOLBAS-Project/LOLBAS",
        branch="master",
        parser="parse_lolbas",
        paths=["yml/"]
    ),
    "gtfobins": SourceConfig(
        name="gtfobins",
        description="GTFOBins",
        source_type="github_commits",
        repo="GTFOBins/GTFOBins.github.io",
        branch="master",
        parser="parse_gtfobins",
        paths=["_gtfobins/"]
    ),
    "hijacklibs": SourceConfig(
        name="hijacklibs",
        description="HijackLibs DLL Hijacking Database",
        source_type="github_commits",
        repo="wietze/HijackLibs",
        branch="main",
        parser="parse_hijacklibs",
        paths=["yml/"]
    ),
    "forensic_artifacts": SourceConfig(
        name="forensic_artifacts",
        description="ForensicArtifacts Definitions",
        source_type="github_commits",
        repo="ForensicArtifacts/artifacts",
        branch="main",
        parser="parse_forensic_artifacts",
        paths=["data/"]
    ),
    "kape": SourceConfig(
        name="kape",
        description="KAPE Targets & Modules",
        source_type="github_commits",
        repo="EricZimmerman/KapeFiles",
        branch="master",
        parser="parse_kape",
        paths=["Targets/", "Modules/"]
    ),
    "velociraptor": SourceConfig(
        name="velociraptor",
        description="Velociraptor Artifact Exchange",
        source_type="github_commits",
        repo="Velocidex/velociraptor-docs",
        branch="master",
        parser="parse_velociraptor",
        paths=["content/exchange/artifacts/"]
    ),
    "mitre_atlas": SourceConfig(
        name="mitre_atlas",
        description="MITRE ATLAS AI/ML Attack Framework",
        source_type="github_commits",
        repo="mitre-atlas/atlas-data",
        branch="main",
        parser="parse_atlas",
        paths=["data/"]
    ),
    "mitre_engage": SourceConfig(
        name="mitre_engage",
        description="MITRE Engage Adversary Engagement Framework",
        source_type="github_commits",
        repo="mitre/engage",
        branch="main",
        parser="parse_engage",
        paths=["Data/json/"]
    ),
    "loldrivers": SourceConfig(
        name="loldrivers",
        description="LOLDrivers Vulnerable Driver Database",
        source_type="github_commits",
        repo="magicsword-io/LOLDrivers",
        branch="main",
        parser="parse_loldrivers",
        paths=["yaml/"]
    ),
    "capec": SourceConfig(
        name="capec",
        description="MITRE CAPEC Attack Patterns",
        source_type="github_releases",
        repo="mitre/cti",
        branch="master",
        parser="parse_capec",
        paths=["capec/"]
    ),
    "mbc": SourceConfig(
        name="mbc",
        description="MITRE MBC Malware Behavior Catalog",
        source_type="github_commits",
        repo="MBCProject/mbc-stix2.1",
        branch="main",
        parser="parse_mbc",
        paths=["mbc/"]
    ),
    "chainsaw": SourceConfig(
        name="chainsaw",
        description="Chainsaw Forensic Detection Rules (EVTX + MFT)",
        source_type="github_commits",
        repo="WithSecureLabs/chainsaw",
        branch="master",
        parser="parse_chainsaw",
        paths=["rules/"]
    ),
    "hayabusa": SourceConfig(
        name="hayabusa",
        description="Hayabusa Built-in Detection Rules",
        source_type="github_commits",
        repo="Yamato-Security/hayabusa-rules",
        branch="main",
        parser="parse_hayabusa",
        paths=["hayabusa/"]
    ),
    "forensic_clarifications": SourceConfig(
        name="forensic_clarifications",
        description="Authoritative Forensic Artifact Clarifications",
        source_type="embedded",
        repo="",  # Not a repo - embedded in package
        branch="",
        parser="parse_forensic_clarifications",
        paths=[]
    ),
}


# =============================================================================
# GitHub API Helpers
# =============================================================================

def get_github_headers() -> dict[str, str]:
    """Get headers for GitHub API requests."""
    headers = {"User-Agent": "rag-mcp/2.0"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def _is_ip_literal(hostname: str) -> bool:
    """Check if hostname is an IP address literal.

    Also detects octal IP notation (e.g., 0177.0.0.1) which Python's
    ipaddress module does not parse but could bypass allowlist checks.
    """
    import ipaddress
    import re
    if not hostname:
        return False
    # Detect octal IP notation (e.g., 0177.0.0.1 for 127.0.0.1)
    if re.match(r'^0\d+\.', hostname):
        return True
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _validate_url_host(url: str) -> None:
    """Validate URL host against allowlist (SSRF protection).

    Security checks:
    1. Hostname must be in ALLOWED_URL_HOSTS
    2. Scheme must be https (unless RAG_ALLOW_HTTP=1)
    3. IP literal hostnames are blocked (prevent SSRF via IP)
    """
    parsed = urlparse(url)

    # Block IP literal hostnames (SSRF protection)
    if _is_ip_literal(parsed.hostname or ""):
        raise ValueError(f"IP literal URLs not allowed: {parsed.hostname}")

    # Check hostname allowlist
    if parsed.hostname not in ALLOWED_URL_HOSTS:
        raise ValueError(f"URL host not allowed: {parsed.hostname}")

    # Enforce HTTPS-only by default
    if HTTPS_ONLY and parsed.scheme != "https":
        raise ValueError(f"HTTPS required (got {parsed.scheme}). Set RAG_ALLOW_HTTP=1 to allow HTTP.")
    elif parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL scheme not allowed: {parsed.scheme}")


class DownloadTooLargeError(Exception):
    """Raised when download exceeds maximum size."""
    pass


def _is_retryable_error(error: Exception) -> bool:
    """Check if an error is retryable (transient)."""
    # Retry on timeouts
    if isinstance(error, (SocketTimeout, TimeoutError)):
        return True

    # Retry on connection errors
    if isinstance(error, URLError):
        reason = str(error.reason).lower()
        if any(x in reason for x in ["connection reset", "connection refused",
                                      "temporary failure", "timed out"]):
            return True

    # Retry on HTTP 429 (rate limit) or 5xx (server errors)
    if isinstance(error, HTTPError):
        return error.code == 429 or error.code >= 500

    return False


def _fetch_url_once(
    url: str,
    headers: Optional[dict] = None,
    max_bytes: Optional[int] = None
) -> bytes:
    """Single fetch attempt (internal). Raises on error."""
    if max_bytes is None:
        max_bytes = MAX_DOWNLOAD_BYTES
    req = Request(url, headers=headers or get_github_headers())
    with urlopen(req, timeout=30) as response:
        # Security: Validate final URL after redirects (SSRF protection)
        final_url = response.geturl()
        if final_url != url:
            logger.debug(f"Redirect detected: {url} -> {final_url}")
            _validate_url_host(final_url)  # Raises ValueError if invalid

        # Check Content-Length header if present
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                length = int(content_length)
                if length > max_bytes:
                    raise DownloadTooLargeError(
                        f"Content-Length {length} exceeds limit {max_bytes}"
                    )
            except ValueError:
                pass  # Invalid Content-Length, will check during streaming

        # Stream and check size
        chunks = []
        total_bytes = 0
        chunk_size = 65536  # 64 KB chunks

        while True:
            chunk = response.read(chunk_size)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > max_bytes:
                raise DownloadTooLargeError(
                    f"Download exceeded {max_bytes} bytes limit"
                )
            chunks.append(chunk)

        return b"".join(chunks)


def fetch_url(
    url: str,
    headers: Optional[dict] = None,
    max_bytes: Optional[int] = None,
    max_retries: Optional[int] = None
) -> Optional[bytes]:
    """Fetch URL content with retry, error handling, and size limits.

    Security features:
    - Validates URL host against allowlist (SSRF protection)
    - Validates final URL after redirects
    - Enforces HTTPS-only by default
    - Blocks IP literal URLs
    - Limits download size to prevent memory exhaustion

    Reliability features:
    - Retries on transient failures (timeouts, 429, 5xx)
    - Exponential backoff with jitter

    Args:
        url: URL to fetch
        headers: Optional HTTP headers
        max_bytes: Maximum bytes to download (default: MAX_DOWNLOAD_BYTES)
        max_retries: Maximum retry attempts (default: FETCH_MAX_RETRIES)

    Returns:
        Response bytes or None on error
    """
    if max_bytes is None:
        max_bytes = MAX_DOWNLOAD_BYTES
    if max_retries is None:
        max_retries = FETCH_MAX_RETRIES

    # Security: Validate URL before any fetch attempt
    try:
        _validate_url_host(url)
    except ValueError as e:
        logger.error(f"URL validation failed: {e}")
        return None

    last_error: Optional[Exception] = None

    for attempt in range(max_retries + 1):
        try:
            return _fetch_url_once(url, headers, max_bytes)

        except DownloadTooLargeError as e:
            # Don't retry size limit errors
            logger.error(f"Download too large: {e}")
            return None

        except ValueError as e:
            # Don't retry validation errors (e.g., redirect to bad host)
            logger.error(f"Validation failed: {e}")
            return None

        except HTTPError as e:
            last_error = e
            if e.code == 403:
                logger.error("Rate limited. Set GITHUB_TOKEN for higher limits.")
                return None  # Don't retry 403
            elif e.code == 429 or e.code >= 500:
                # Retryable
                if attempt < max_retries:
                    delay = FETCH_RETRY_BASE_DELAY * (2 ** attempt) + random.uniform(0, 0.5)
                    logger.warning(f"HTTP {e.code}, retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries + 1})")
                    time.sleep(delay)
                    continue
            else:
                # Other 4xx - don't retry
                logger.error(f"HTTP {e.code} fetching URL")
                return None

        except (URLError, SocketTimeout, TimeoutError) as e:
            last_error = e
            if _is_retryable_error(e) and attempt < max_retries:
                delay = FETCH_RETRY_BASE_DELAY * (2 ** attempt) + random.uniform(0, 0.5)
                logger.warning(f"Fetch failed ({type(e).__name__}), retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries + 1})")
                time.sleep(delay)
                continue
            else:
                logger.error(f"Failed to fetch URL: {e}")
                return None

    # All retries exhausted
    logger.error(f"Failed to fetch URL after {max_retries + 1} attempts: {last_error}")
    return None


def get_latest_commit(repo: str, branch: str) -> Optional[str]:
    """Get latest commit SHA for a GitHub repo branch."""
    url = f"https://api.github.com/repos/{repo}/commits/{branch}"
    data = fetch_url(url)
    if data:
        try:
            info = json.loads(data)
            return info.get("sha", "")[:12]
        except json.JSONDecodeError:
            pass
    return None


def get_latest_release(repo: str) -> Optional[str]:
    """Get latest release tag for a GitHub repo."""
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    data = fetch_url(url)
    if data:
        try:
            info = json.loads(data)
            return info.get("tag_name", "")
        except json.JSONDecodeError:
            pass
    return None


def get_feed_version(url: str) -> Optional[str]:
    """Get version from a JSON feed (e.g., CISA KEV catalogVersion)."""
    data = fetch_url(url, headers={"User-Agent": "rag-mcp/2.0"})
    if data:
        try:
            feed = json.loads(data)
            # CISA KEV specific
            if "catalogVersion" in feed:
                return feed["catalogVersion"]
            # Generic: use count as version proxy
            if "vulnerabilities" in feed:
                return f"count:{len(feed['vulnerabilities'])}"
            # JSON-LD format (D3FEND): use @graph count as version proxy
            if "@graph" in feed:
                return f"count:{len(feed['@graph'])}"
        except json.JSONDecodeError:
            pass
    return None


def get_latest_version(source: SourceConfig) -> Optional[str]:
    """Get latest version for a source without downloading."""
    if source.source_type == "github_commits":
        return get_latest_commit(source.repo, source.branch)
    elif source.source_type == "github_releases":
        return get_latest_release(source.repo)
    elif source.source_type == "json_feed":
        return get_feed_version(source.repo)
    elif source.source_type == "embedded":
        return "embedded"  # Static version, no remote check needed
    return None


# Security: Allowed hosts for URL fetching (SSRF protection)
ALLOWED_URL_HOSTS = frozenset({
    "api.github.com",
    "raw.githubusercontent.com",
    "www.cisa.gov",
    "github.com",
    "d3fend.mitre.org",
    "atlas.mitre.org",
})

# Security: Maximum download size (60 MB default - MITRE ATT&CK STIX is ~50MB)
MAX_DOWNLOAD_BYTES = int(os.environ.get("RAG_MAX_DOWNLOAD_BYTES", 60 * 1024 * 1024))

# Security: Only allow HTTPS by default (set RAG_ALLOW_HTTP=1 to enable HTTP)
HTTPS_ONLY = os.environ.get("RAG_ALLOW_HTTP", "").lower() not in ("1", "true", "yes")

# Retry configuration for transient failures
FETCH_MAX_RETRIES = int(os.environ.get("RAG_FETCH_MAX_RETRIES", 3))
FETCH_RETRY_BASE_DELAY = float(os.environ.get("RAG_FETCH_RETRY_DELAY", 0.5))  # seconds

# Security: Regex patterns for validating git parameters
REPO_PATTERN = re.compile(r'^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$')
BRANCH_PATTERN = re.compile(r'^[a-zA-Z0-9_./=-]+$')


def _validate_repo_format(repo: str) -> None:
    """Validate GitHub repo format (owner/repo)."""
    if not REPO_PATTERN.match(repo):
        raise ValueError(f"Invalid repo format: {repo}. Expected 'owner/repo'.")


def _validate_branch_format(branch: str) -> None:
    """Validate git branch name format."""
    if not BRANCH_PATTERN.match(branch):
        raise ValueError(f"Invalid branch format: {branch}")
    # Prevent git option injection
    if branch.startswith('-'):
        raise ValueError(f"Invalid branch format: {branch}")


def clone_repo(repo: str, branch: str, dest: Path) -> bool:
    """Clone a GitHub repo to destination.

    Security: Validates repo and branch format to prevent command injection.
    """
    # Security: Validate inputs
    _validate_repo_format(repo)
    _validate_branch_format(branch)

    url = f"https://github.com/{repo}.git"
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, url, str(dest)],
            check=True,
            capture_output=True,
            timeout=300
        )
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to clone {repo}: {e.stderr.decode()[:200]}")
        return False
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout cloning {repo}")
        return False


# =============================================================================
# State Management
# =============================================================================

def load_sources_state() -> dict[str, Any]:
    """Load sources state from file."""
    if SOURCES_STATE_FILE.exists():
        try:
            with open(SOURCES_STATE_FILE, encoding="utf-8") as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            pass
    return {"version": 1, "sources": {}}


def save_sources_state(state: dict[str, Any]) -> None:
    """Save sources state to file.

    Security: Uses atomic write to prevent corruption from concurrent access.
    """
    atomic_write_json(SOURCES_STATE_FILE, state)


def load_disabled_sources() -> set[str]:
    """Load disabled sources from config file."""
    if SOURCES_CONFIG_FILE.exists():
        try:
            with open(SOURCES_CONFIG_FILE, encoding="utf-8") as f:
                config = json.load(f)
                return set(config.get("disabled_sources", []))
        except (IOError, json.JSONDecodeError):
            pass
    return set()


# =============================================================================
# Parsers - Convert source data to JSONL records
# =============================================================================

def parse_sigma(repo_dir: Path, output_path: Path) -> int:
    """Parse Sigma rules from cloned repo."""
    records = []
    rules_dir = repo_dir / "rules"

    for yaml_file in rules_dir.rglob("*.yml"):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                content = f.read()
                # Handle multi-document YAML
                for doc in yaml.safe_load_all(content):
                    if doc and isinstance(doc, dict) and "title" in doc:
                        text = f"""Sigma Detection Rule: {doc.get('title', 'Untitled')}

Status: {doc.get('status', 'unknown')}
Level: {doc.get('level', 'unknown')}
Author: {doc.get('author', 'unknown')}

Description: {doc.get('description', 'No description')}

Detection Logic:
{yaml.dump(doc.get('detection', {}), default_flow_style=False)}

References:
{chr(10).join(doc.get('references', []) or ['None'])}

Tags: {', '.join(doc.get('tags', []) or ['None'])}
"""
                        # Extract MITRE techniques from tags
                        techniques = []
                        for tag in doc.get('tags', []) or []:
                            if tag.startswith('attack.t'):
                                techniques.append(tag.replace('attack.', '').upper())

                        records.append({
                            "text": text,
                            "metadata": {
                                "source": "sigma",
                                "title": doc.get("title", ""),
                                "mitre_techniques": ",".join(techniques),
                                "level": doc.get("level", ""),
                                "status": doc.get("status", "")
                            }
                        })
        except Exception as e:
            logger.debug(f"Error parsing {yaml_file}: {e}")
            continue

    _write_jsonl(records, output_path)
    return len(records)


def parse_atomic(repo_dir: Path, output_path: Path) -> int:
    """Parse Atomic Red Team tests."""
    records = []
    atomics_dir = repo_dir / "atomics"

    for yaml_file in atomics_dir.rglob("*.yaml"):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
                if not doc or "atomic_tests" not in doc:
                    continue

                technique_id = doc.get("attack_technique", "")
                technique_name = doc.get("display_name", "")

                for test in doc.get("atomic_tests", []):
                    text = f"""Atomic Red Team Test: {test.get('name', 'Untitled')}

MITRE Technique: {technique_id} - {technique_name}
Platform: {', '.join(test.get('supported_platforms', []))}

Description: {test.get('description', 'No description')}

Executor: {test.get('executor', {}).get('name', 'unknown')}
Command:
{test.get('executor', {}).get('command', 'No command')}

Cleanup:
{test.get('executor', {}).get('cleanup_command', 'No cleanup')}
"""
                    records.append({
                        "text": text,
                        "metadata": {
                            "source": "atomic",
                            "title": test.get("name", ""),
                            "mitre_techniques": technique_id,
                            "platform": ",".join(test.get("supported_platforms", []))
                        }
                    })
        except Exception as e:
            logger.debug(f"Error parsing {yaml_file}: {e}")
            continue

    _write_jsonl(records, output_path)
    return len(records)


def parse_stix(repo_dir: Path, output_path: Path) -> int:
    """Parse MITRE ATT&CK STIX data."""
    records = []

    # MITRE ATT&CK STIX data is best fetched directly (single large JSON file)
    # rather than cloning the entire repo
    stix_file = repo_dir / "enterprise-attack.json" if repo_dir else None

    if not stix_file or not stix_file.exists():
        # Download directly - this is more reliable
        url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        logger.info("  Downloading ATT&CK STIX data directly...")
        data = fetch_url(url, headers={"User-Agent": "rag-mcp/2.0"})
        if not data:
            logger.error("Could not download ATT&CK STIX data")
            return 0
        bundle = json.loads(data)
    else:
        with open(stix_file, encoding="utf-8") as f:
            bundle = json.load(f)

    for obj in bundle.get("objects", []):
        obj_type = obj.get("type", "")

        if obj_type == "attack-pattern":
            # Technique
            ext_refs = obj.get("external_references", [])
            technique_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    break

            # Extract tactics from kill chain phases
            tactics = [p.get('phase_name', '') for p in obj.get('kill_chain_phases', []) if p.get('phase_name')]

            text = f"""MITRE ATT&CK Technique: {obj.get('name', 'Unknown')}

ID: {technique_id}

Description: {obj.get('description', 'No description')}

Platforms: {', '.join(obj.get('x_mitre_platforms', []))}
Tactics: {', '.join(tactics)}

Detection: {obj.get('x_mitre_detection', 'No detection guidance')}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "mitre_attack",
                    "title": obj.get("name", ""),
                    "mitre_techniques": technique_id,
                    "platform": ",".join(obj.get("x_mitre_platforms", []))
                }
            })

        elif obj_type == "malware" or obj_type == "tool":
            text = f"""MITRE ATT&CK {obj_type.title()}: {obj.get('name', 'Unknown')}

Description: {obj.get('description', 'No description')}

Aliases: {', '.join(obj.get('aliases', []) or [obj.get('name', '')])}
Platforms: {', '.join(obj.get('x_mitre_platforms', []))}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "mitre_attack",
                    "title": obj.get("name", ""),
                    "type": obj_type
                }
            })

        elif obj_type == "intrusion-set":
            # Threat actor groups
            ext_refs = obj.get("external_references", [])
            group_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    group_id = ref.get("external_id", "")
                    break

            aliases = obj.get("aliases", []) or []
            # Add name to aliases if not already present
            if obj.get("name") and obj.get("name") not in aliases:
                aliases = [obj.get("name")] + aliases

            text = f"""MITRE ATT&CK Threat Actor Group: {obj.get('name', 'Unknown')}

ID: {group_id}

Description: {obj.get('description', 'No description')}

Aliases: {', '.join(aliases)}

First Seen: {obj.get('first_seen', 'Unknown')}
Last Seen: {obj.get('last_seen', 'Unknown')}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "mitre_attack",
                    "title": obj.get("name", ""),
                    "group_id": group_id,
                    "type": "threat_actor"
                }
            })

        elif obj_type == "campaign":
            # Named threat campaigns (e.g., SolarWinds, Operation Wocao)
            ext_refs = obj.get("external_references", [])
            campaign_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    campaign_id = ref.get("external_id", "")
                    break

            text = f"""MITRE ATT&CK Campaign: {obj.get('name', 'Unknown')}

ID: {campaign_id}

Description: {obj.get('description', 'No description')}

First Seen: {obj.get('first_seen', 'Unknown')}
Last Seen: {obj.get('last_seen', 'Unknown')}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "mitre_attack",
                    "title": obj.get("name", ""),
                    "campaign_id": campaign_id,
                    "type": "campaign"
                }
            })

        elif obj_type == "course-of-action":
            # Mitigations
            ext_refs = obj.get("external_references", [])
            mitigation_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    mitigation_id = ref.get("external_id", "")
                    break

            text = f"""MITRE ATT&CK Mitigation: {obj.get('name', 'Unknown')}

ID: {mitigation_id}

Description: {obj.get('description', 'No description')}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "mitre_attack",
                    "title": obj.get("name", ""),
                    "mitigation_id": mitigation_id,
                    "type": "mitigation"
                }
            })

    _write_jsonl(records, output_path)
    return len(records)


def parse_car(repo_dir: Path, output_path: Path) -> int:
    """Parse MITRE CAR analytics."""
    records = []
    analytics_dir = repo_dir / "analytics"

    for yaml_file in analytics_dir.rglob("*.yaml"):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
                if not doc:
                    continue

                text = f"""MITRE CAR Analytic: {doc.get('title', 'Untitled')}

ID: {doc.get('id', 'Unknown')}
Submission Date: {doc.get('submission_date', 'Unknown')}

Description: {doc.get('description', 'No description')}

ATT&CK Coverage:
{chr(10).join(f"- {c.get('technique', '')} ({c.get('coverage', '')})" for c in doc.get('coverage', []))}

Implementations:
{chr(10).join(f"- {i.get('type', 'unknown')}: {i.get('description', '')}" for i in doc.get('implementations', []))}

Data Model References: {', '.join(doc.get('data_model_references', []))}
"""
                techniques = [c.get('technique', '') for c in doc.get('coverage', []) if c.get('technique')]

                records.append({
                    "text": text,
                    "metadata": {
                        "source": "mitre_car",
                        "title": doc.get("title", ""),
                        "mitre_techniques": ",".join(techniques),
                        "car_id": doc.get("id", "")
                    }
                })
        except Exception as e:
            logger.debug(f"Error parsing {yaml_file}: {e}")
            continue

    _write_jsonl(records, output_path)
    return len(records)


def parse_stratus(repo_dir: Path, output_path: Path) -> int:
    """Parse Stratus Red Team attack techniques."""
    records = []
    docs_dir = repo_dir / "docs" / "attack-techniques"

    if not docs_dir.exists():
        docs_dir = repo_dir

    for md_file in docs_dir.rglob("*.md"):
        try:
            with open(md_file, encoding="utf-8") as f:
                content = f.read()

            # Extract title from first heading
            title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
            title = title_match.group(1) if title_match else md_file.stem

            # Extract MITRE technique from content
            technique_match = re.search(r'(T\d{4}(?:\.\d{3})?)', content)
            technique = technique_match.group(1) if technique_match else ""

            # Extract platform from path
            platform = ""
            if "aws" in str(md_file).lower():
                platform = "AWS"
            elif "azure" in str(md_file).lower():
                platform = "Azure"
            elif "gcp" in str(md_file).lower():
                platform = "GCP"

            text = f"""Stratus Red Team Attack Technique: {title}

Platform: {platform}
MITRE Technique: {technique}

{content[:3000]}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "stratus_red_team",
                    "title": title,
                    "mitre_techniques": technique,
                    "platform": platform
                }
            })
        except Exception as e:
            logger.debug(f"Error parsing {md_file}: {e}")
            continue

    _write_jsonl(records, output_path)
    return len(records)


def parse_kev(repo_dir: Path, output_path: Path) -> int:
    """Parse CISA Known Exploited Vulnerabilities feed."""
    # For feeds, repo_dir is actually the URL
    source = SOURCES["cisa_kev"]
    data = fetch_url(source.repo, headers={"User-Agent": "rag-mcp/2.0"})
    if not data:
        return 0

    feed = json.loads(data)
    records = []

    for vuln in feed.get("vulnerabilities", []):
        text = f"""CISA Known Exploited Vulnerability: {vuln.get('cveID', 'Unknown')}

Vendor: {vuln.get('vendorProject', 'Unknown')}
Product: {vuln.get('product', 'Unknown')}
Vulnerability: {vuln.get('vulnerabilityName', 'Unknown')}

Description: {vuln.get('shortDescription', 'No description')}

Required Action: {vuln.get('requiredAction', 'No action specified')}
Due Date: {vuln.get('dueDate', 'Unknown')}

Date Added: {vuln.get('dateAdded', 'Unknown')}
Known Ransomware Use: {vuln.get('knownRansomwareCampaignUse', 'Unknown')}
"""
        records.append({
            "text": text,
            "metadata": {
                "source": "cisa_kev",
                "cve_id": vuln.get("cveID", ""),
                "vendor": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
                "date_added": vuln.get("dateAdded", "")
            }
        })

    _write_jsonl(records, output_path)
    return len(records)


def parse_d3fend(repo_dir: Path, output_path: Path) -> int:
    """Parse MITRE D3FEND defensive techniques from ontology JSON."""
    source = SOURCES["mitre_d3fend"]
    data = fetch_url(source.repo, headers={"User-Agent": "rag-mcp/2.0"})
    if not data:
        return 0

    ontology = json.loads(data)
    records = []

    # D3FEND uses JSON-LD format with @graph containing all entities
    for obj in ontology.get("@graph", []):
        obj_id = obj.get("@id", "")

        # Only process D3FEND techniques (D3-xxx or D3A-xxx IDs)
        d3fend_id = obj.get("d3f:d3fend-id", "")
        if not d3fend_id:
            continue

        # Skip if no definition
        definition = obj.get("d3f:definition", "")
        if not definition:
            continue

        name = obj.get("rdfs:label", "Unknown")
        kb_article = obj.get("d3f:kb-article", "")

        text = f"""D3FEND Defensive Technique: {name}
D3FEND ID: {d3fend_id}

Definition: {definition}
"""
        if kb_article:
            # Truncate long KB articles
            text += f"\nKnowledge Base: {kb_article[:2000]}"

        records.append({
            "text": text,
            "metadata": {
                "source": "mitre_d3fend",
                "d3fend_id": d3fend_id,
                "title": name
            }
        })

    _write_jsonl(records, output_path)
    return len(records)


def parse_elastic(repo_dir: Path, output_path: Path) -> int:
    """Parse Elastic detection rules."""
    records = []
    rules_dir = repo_dir / "rules"

    for toml_file in rules_dir.rglob("*.toml"):
        try:
            with open(toml_file, encoding="utf-8") as f:
                doc = toml.load(f)

            rule = doc.get("rule", doc)

            text = f"""Elastic Detection Rule: {rule.get('name', 'Untitled')}

Type: {rule.get('type', 'unknown')}
Severity: {rule.get('severity', 'unknown')}
Risk Score: {rule.get('risk_score', 'unknown')}

Description: {rule.get('description', 'No description')}

Query:
{rule.get('query', 'No query')}

Tags: {', '.join(rule.get('tags', []))}
References: {chr(10).join(rule.get('references', []) or ['None'])}
"""
            # Extract MITRE techniques from tags
            techniques = []
            for tag in rule.get('tags', []):
                match = re.search(r'(T\d{4}(?:\.\d{3})?)', tag)
                if match:
                    techniques.append(match.group(1))

            records.append({
                "text": text,
                "metadata": {
                    "source": "elastic",
                    "title": rule.get("name", ""),
                    "mitre_techniques": ",".join(techniques),
                    "severity": rule.get("severity", "")
                }
            })
        except Exception as e:
            logger.debug(f"Error parsing {toml_file}: {e}")
            continue

    _write_jsonl(records, output_path)
    return len(records)


def parse_splunk(repo_dir: Path, output_path: Path) -> int:
    """Parse Splunk Security Content detections."""
    records = []
    detections_dir = repo_dir / "detections"

    for yaml_file in detections_dir.rglob("*.yml"):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)

            # Splunk uses different type values: TTP, Anomaly, Hunting, etc.
            if not doc or not doc.get("name"):
                continue

            data_source = doc.get('data_source', [])
            if isinstance(data_source, list):
                data_source = ', '.join(data_source) if data_source else 'unknown'

            text = f"""Splunk Detection: {doc.get('name', 'Untitled')}

Type: {doc.get('type', 'unknown')}
Data Source: {data_source}
Status: {doc.get('status', 'unknown')}

Description: {doc.get('description', 'No description')}

Search:
{doc.get('search', 'No search query')}

How to Implement: {doc.get('how_to_implement', 'No implementation notes')}

Known False Positives: {doc.get('known_false_positives', 'None documented')}

References: {chr(10).join(doc.get('references', []) or ['None'])}
"""
            # Extract MITRE techniques from tags
            techniques = []
            tags = doc.get('tags', {})
            if isinstance(tags, dict):
                for tag in tags.get('mitre_attack_id', []) or []:
                    techniques.append(tag)

            records.append({
                "text": text,
                "metadata": {
                    "source": "splunk_security",
                    "title": doc.get("name", ""),
                    "mitre_techniques": ",".join(techniques),
                    "status": doc.get("status", "")
                }
            })
        except Exception as e:
            logger.debug(f"Error parsing {yaml_file}: {e}")
            continue

    _write_jsonl(records, output_path)
    return len(records)


def parse_lolbas(repo_dir: Path, output_path: Path) -> int:
    """Parse LOLBAS entries."""
    records = []
    yml_dir = repo_dir / "yml" / "OSBinaries"

    for yaml_file in yml_dir.rglob("*.yml"):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)

            if not doc:
                continue

            commands_text = ""
            for cmd in doc.get("Commands", []) or []:
                commands_text += f"\n- {cmd.get('Command', '')}\n  Category: {cmd.get('Category', '')}\n  Description: {cmd.get('Description', '')}"

            text = f"""LOLBAS: {doc.get('Name', 'Unknown')}

Description: {doc.get('Description', 'No description')}

Author: {doc.get('Author', 'Unknown')}

Commands:{commands_text}

Paths:
{chr(10).join(f"- {p.get('Path', '')}" for p in doc.get('Full_Path', []) or [])}

Detection:
{chr(10).join(f"- {d.get('IOC', '')}" for d in doc.get('Detection', []) or [])}

Resources:
{chr(10).join(f"- {r.get('Link', '')}" for r in doc.get('Resources', []) or [])}
"""
            # Extract MITRE techniques
            techniques = []
            for cmd in doc.get("Commands", []) or []:
                if cmd.get("MitreID"):
                    techniques.append(cmd["MitreID"])

            records.append({
                "text": text,
                "metadata": {
                    "source": "lolbas",
                    "title": doc.get("Name", ""),
                    "mitre_techniques": ",".join(set(techniques)),
                    "platform": "windows"
                }
            })
        except Exception as e:
            logger.debug(f"Error parsing {yaml_file}: {e}")
            continue

    _write_jsonl(records, output_path)
    return len(records)


def parse_gtfobins(repo_dir: Path, output_path: Path) -> int:
    """Parse GTFOBins entries."""
    records = []
    bins_dir = repo_dir / "_gtfobins"

    if not bins_dir.exists():
        logger.warning(f"GTFOBins directory not found: {bins_dir}")
        return 0

    # GTFOBins files have no extension - they're YAML front matter
    for bin_file in bins_dir.iterdir():
        if bin_file.is_file() and not bin_file.name.startswith('.'):
            try:
                with open(bin_file, encoding="utf-8") as f:
                    content = f.read()

                name = bin_file.name

                # Parse YAML front matter
                try:
                    doc = yaml.safe_load(content)
                    if doc and isinstance(doc, dict):
                        functions_text = ""
                        for func_name, func_data in doc.get("functions", {}).items():
                            functions_text += f"\n{func_name.upper()}:\n"
                            if isinstance(func_data, list):
                                for item in func_data:
                                    if isinstance(item, dict):
                                        functions_text += f"  Code: {item.get('code', 'N/A')}\n"
                                        if item.get('comment'):
                                            functions_text += f"  Note: {item.get('comment')}\n"

                        text = f"""GTFOBins: {name}

Binary: {name}
Functions: {', '.join(doc.get('functions', {}).keys())}

{functions_text}
"""
                    else:
                        text = f"""GTFOBins: {name}

{content[:2000]}
"""
                except yaml.YAMLError:
                    text = f"""GTFOBins: {name}

{content[:2000]}
"""

                records.append({
                    "text": text,
                    "metadata": {
                        "source": "gtfobins",
                        "title": name,
                        "platform": "linux"
                    }
                })
            except Exception as e:
                logger.debug(f"Error parsing {bin_file}: {e}")
                continue

    _write_jsonl(records, output_path)
    return len(records)


def parse_hijacklibs(repo_dir: Path, output_path: Path) -> int:
    """Parse HijackLibs DLL hijacking database."""
    records = []
    yml_dir = repo_dir / "yml"

    for yaml_file in yml_dir.rglob("*.yml"):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)

            if not doc:
                continue

            text = f"""HijackLibs DLL Hijack: {doc.get('Name', 'Unknown')}

Author: {doc.get('Author', 'Unknown')}

Expected Path: {doc.get('ExpectedLocations', ['Unknown'])}
Vulnerable Executables:
{chr(10).join(f"- {v.get('Path', '')} ({v.get('Type', '')})" for v in doc.get('VulnerableExecutables', []) or [])}

Description: {doc.get('Description', 'No description')}

Resources:
{chr(10).join(doc.get('Resources', []) or ['None'])}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "hijacklibs",
                    "title": doc.get("Name", ""),
                    "platform": "windows"
                }
            })
        except Exception as e:
            logger.debug(f"Error parsing {yaml_file}: {e}")
            continue

    _write_jsonl(records, output_path)
    return len(records)


def parse_forensic_artifacts(repo_dir: Path, output_path: Path) -> int:
    """Parse ForensicArtifacts definitions."""
    records = []
    # Artifacts are in artifacts/data/ not data/
    data_dir = repo_dir / "artifacts" / "data"
    if not data_dir.exists():
        data_dir = repo_dir / "data"  # Fallback

    for yaml_file in data_dir.rglob("*.yaml"):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                content = f.read()
                for doc in yaml.safe_load_all(content):
                    if not doc or "name" not in doc:
                        continue

                    sources_text = ""
                    for src in doc.get("sources", []) or []:
                        sources_text += f"\n- Type: {src.get('type', 'unknown')}"
                        if src.get('attributes', {}).get('paths'):
                            sources_text += f"\n  Paths: {', '.join(src['attributes']['paths'])}"
                        if src.get('attributes', {}).get('keys'):
                            sources_text += f"\n  Keys: {', '.join(src['attributes']['keys'])}"

                    text = f"""Forensic Artifact: {doc.get('name', 'Unknown')}

Description: {doc.get('doc', 'No description')}

Supported OS: {', '.join(doc.get('supported_os', []))}

Sources:{sources_text}

Labels: {', '.join(doc.get('labels', []))}
URLs: {chr(10).join(doc.get('urls', []) or ['None'])}
"""
                    records.append({
                        "text": text,
                        "metadata": {
                            "source": "forensic_artifacts",
                            "title": doc.get("name", ""),
                            "platform": ",".join(doc.get("supported_os", []))
                        }
                    })
        except Exception as e:
            logger.debug(f"Error parsing {yaml_file}: {e}")
            continue

    _write_jsonl(records, output_path)
    return len(records)


def parse_kape(repo_dir: Path, output_path: Path) -> int:
    """Parse KAPE targets and modules."""
    records = []

    # Parse Targets
    targets_dir = repo_dir / "Targets"
    for tkape_file in targets_dir.rglob("*.tkape"):
        try:
            with open(tkape_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)

            if not doc:
                continue

            paths_text = ""
            for target in doc.get("Targets", []) or []:
                paths_text += f"\n- {target.get('Name', 'Unknown')}: {target.get('Path', '')} ({target.get('Mask', '*')})"

            text = f"""KAPE Target: {doc.get('Description', 'Unknown')}

Author: {doc.get('Author', 'Unknown')}
Version: {doc.get('Version', 'Unknown')}
Category: {tkape_file.parent.name}

Paths to Collect:{paths_text}

ID: {doc.get('Id', 'Unknown')}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "kape",
                    "title": doc.get("Description", ""),
                    "type": "target",
                    "platform": "windows"
                }
            })
        except Exception as e:
            logger.debug(f"Error parsing {tkape_file}: {e}")
            continue

    # Parse Modules
    modules_dir = repo_dir / "Modules"
    for mkape_file in modules_dir.rglob("*.mkape"):
        try:
            with open(mkape_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)

            if not doc:
                continue

            text = f"""KAPE Module: {doc.get('Description', 'Unknown')}

Author: {doc.get('Author', 'Unknown')}
Version: {doc.get('Version', 'Unknown')}
Category: {mkape_file.parent.name}

Executable: {doc.get('Executable', 'Unknown')}
Command Line: {doc.get('CommandLine', 'None')}

ID: {doc.get('Id', 'Unknown')}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "kape",
                    "title": doc.get("Description", ""),
                    "type": "module",
                    "platform": "windows"
                }
            })
        except Exception as e:
            logger.debug(f"Error parsing {mkape_file}: {e}")
            continue

    _write_jsonl(records, output_path)
    return len(records)


def parse_velociraptor(repo_dir: Path, output_path: Path) -> int:
    """Parse Velociraptor artifact exchange."""
    records = []
    artifacts_dir = repo_dir / "content" / "exchange" / "artifacts"

    if not artifacts_dir.exists():
        artifacts_dir = repo_dir

    for yaml_file in artifacts_dir.rglob("*.yaml"):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)

            if not doc or "name" not in doc:
                continue

            text = f"""Velociraptor Artifact: {doc.get('name', 'Unknown')}

Author: {doc.get('author', 'Unknown')}
Type: {doc.get('type', 'unknown')}

Description: {doc.get('description', 'No description')}

Parameters:
{chr(10).join(f"- {p.get('name', '')}: {p.get('description', '')}" for p in doc.get('parameters', []) or [])}

Sources:
{chr(10).join(f"- {s.get('name', 'default')}" for s in doc.get('sources', []) or [])}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "velociraptor",
                    "title": doc.get("name", ""),
                    "type": doc.get("type", "")
                }
            })
        except Exception as e:
            logger.debug(f"Error parsing {yaml_file}: {e}")
            continue

    _write_jsonl(records, output_path)
    return len(records)


def parse_atlas(repo_dir: Path, output_path: Path) -> int:
    """Parse MITRE ATLAS AI/ML attack techniques."""
    records = []
    data_dir = repo_dir / "data"

    # Parse techniques from YAML files
    techniques_dir = data_dir / "techniques"
    if techniques_dir.exists():
        for yaml_file in techniques_dir.rglob("*.yaml"):
            try:
                with open(yaml_file, encoding="utf-8") as f:
                    doc = yaml.safe_load(f)

                if not doc:
                    continue

                technique_id = doc.get("id", "")
                tactics = doc.get("tactics", [])
                if isinstance(tactics, list):
                    tactics_str = ", ".join(tactics)
                else:
                    tactics_str = str(tactics)

                text = f"""MITRE ATLAS AI/ML Attack Technique: {doc.get('name', 'Unknown')}

ID: {technique_id}
Tactics: {tactics_str}

Description: {doc.get('description', 'No description')}

Procedure Examples:
{chr(10).join(f"- {p}" for p in (doc.get('procedure-examples', []) or [])[:5])}

Mitigations:
{chr(10).join(f"- {m}" for m in (doc.get('mitigations', []) or [])[:5])}
"""
                records.append({
                    "text": text,
                    "metadata": {
                        "source": "mitre_atlas",
                        "title": doc.get("name", ""),
                        "atlas_id": technique_id,
                        "tactics": tactics_str
                    }
                })
            except Exception as e:
                logger.debug(f"Error parsing {yaml_file}: {e}")
                continue

    # Parse case studies
    case_studies_dir = data_dir / "case-studies"
    if case_studies_dir.exists():
        for yaml_file in case_studies_dir.rglob("*.yaml"):
            try:
                with open(yaml_file, encoding="utf-8") as f:
                    doc = yaml.safe_load(f)

                if not doc:
                    continue

                techniques = doc.get("techniques", [])
                if isinstance(techniques, list):
                    techniques_str = ", ".join(techniques)
                else:
                    techniques_str = str(techniques)

                text = f"""MITRE ATLAS Case Study: {doc.get('name', 'Unknown')}

ID: {doc.get('id', 'Unknown')}
Summary: {doc.get('summary', 'No summary')}

Techniques Used: {techniques_str}

Incident Date: {doc.get('incident-date', 'Unknown')}
Reporter: {doc.get('reporter', 'Unknown')}

References:
{chr(10).join(f"- {r.get('title', 'N/A')}: {r.get('url', '')}" for r in (doc.get('references', []) or [])[:3])}
"""
                records.append({
                    "text": text,
                    "metadata": {
                        "source": "mitre_atlas",
                        "title": doc.get("name", ""),
                        "type": "case_study",
                        "atlas_techniques": techniques_str
                    }
                })
            except Exception as e:
                logger.debug(f"Error parsing {yaml_file}: {e}")
                continue

    _write_jsonl(records, output_path)
    return len(records)


def parse_engage(repo_dir: Path, output_path: Path) -> int:
    """Parse MITRE Engage adversary engagement framework."""
    records = []
    json_dir = repo_dir / "Data" / "json"

    if not json_dir.exists():
        logger.warning(f"Engage data directory not found: {json_dir}")
        return 0

    # Load ATT&CK mappings for cross-reference (maps Engage activity ID -> ATT&CK techniques)
    attack_mappings = {}
    attack_mapping_file = json_dir / "attack_mapping.json"
    if attack_mapping_file.exists():
        try:
            with open(attack_mapping_file, encoding="utf-8") as f:
                attack_data = json.load(f)
                # attack_mapping.json is a list with attack_id -> eac_id mappings
                # We need to reverse this: eac_id -> list of attack_ids
                for mapping in attack_data:
                    activity_id = mapping.get("eac_id", "")
                    attack_id = mapping.get("attack_id", "")
                    if activity_id and attack_id:
                        if activity_id not in attack_mappings:
                            attack_mappings[activity_id] = set()
                        attack_mappings[activity_id].add(attack_id)
                # Convert sets to sorted lists
                attack_mappings = {k: sorted(v) for k, v in attack_mappings.items()}
        except Exception as e:
            logger.debug(f"Error loading attack mappings: {e}")

    # Parse activities (dict keyed by Engage ID)
    activities_file = json_dir / "activity_details.json"
    if activities_file.exists():
        try:
            with open(activities_file, encoding="utf-8") as f:
                activities = json.load(f)

            for activity_id, activity in activities.items():
                techniques = attack_mappings.get(activity_id, [])
                techniques_str = ", ".join(techniques) if techniques else ""

                text = f"""MITRE Engage Activity: {activity.get('name', 'Unknown')}

Engage ID: {activity_id}
Description: {activity.get('description', 'No description')}

Long Description: {activity.get('long_description', '')}

ATT&CK Techniques: {techniques_str if techniques_str else 'None mapped'}
"""
                records.append({
                    "text": text,
                    "metadata": {
                        "source": "mitre_engage",
                        "title": activity.get("name", ""),
                        "engage_id": activity_id,
                        "type": "activity",
                        "mitre_techniques": techniques_str
                    }
                })
        except Exception as e:
            logger.debug(f"Error parsing activities: {e}")

    # Parse approaches (dict keyed by Engage ID)
    approaches_file = json_dir / "approach_details.json"
    if approaches_file.exists():
        try:
            with open(approaches_file, encoding="utf-8") as f:
                approaches = json.load(f)

            for approach_id, approach in approaches.items():
                text = f"""MITRE Engage Approach: {approach.get('name', 'Unknown')}

Engage ID: {approach_id}
Description: {approach.get('description', 'No description')}

Long Description: {approach.get('long_description', '')}
"""
                records.append({
                    "text": text,
                    "metadata": {
                        "source": "mitre_engage",
                        "title": approach.get("name", ""),
                        "engage_id": approach_id,
                        "type": "approach"
                    }
                })
        except Exception as e:
            logger.debug(f"Error parsing approaches: {e}")

    # Parse goals (dict keyed by Engage ID)
    goals_file = json_dir / "goal_details.json"
    if goals_file.exists():
        try:
            with open(goals_file, encoding="utf-8") as f:
                goals = json.load(f)

            for goal_id, goal in goals.items():
                text = f"""MITRE Engage Goal: {goal.get('name', 'Unknown')}

Engage ID: {goal_id}
Description: {goal.get('description', 'No description')}

Long Description: {goal.get('long_description', '')}
"""
                records.append({
                    "text": text,
                    "metadata": {
                        "source": "mitre_engage",
                        "title": goal.get("name", ""),
                        "engage_id": goal_id,
                        "type": "goal"
                    }
                })
        except Exception as e:
            logger.debug(f"Error parsing goals: {e}")

    _write_jsonl(records, output_path)
    return len(records)


def parse_loldrivers(repo_dir: Path, output_path: Path) -> int:
    """Parse LOLDrivers vulnerable/malicious driver database."""
    records = []
    yaml_dir = repo_dir / "yaml"

    if not yaml_dir.exists():
        yaml_dir = repo_dir / "drivers"  # Alternative path

    for yaml_file in yaml_dir.rglob("*.yaml"):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)

            if not doc:
                continue

            # Extract known vulnerable drivers info
            known_vuln = doc.get("KnownVulnerableSamples", []) or []
            vuln_hashes = []
            for sample in known_vuln[:5]:  # Limit to first 5
                if sample.get("SHA256"):
                    vuln_hashes.append(sample["SHA256"])
                elif sample.get("SHA1"):
                    vuln_hashes.append(sample["SHA1"])
                elif sample.get("MD5"):
                    vuln_hashes.append(sample["MD5"])

            commands_text = ""
            for cmd in doc.get("Commands", []) or []:
                if isinstance(cmd, dict):
                    commands_text += f"\n- {cmd.get('Command', '')} ({cmd.get('Description', '')})"

            category = doc.get("Category", "Unknown")
            if isinstance(category, list):
                category = ", ".join(category)

            text = f"""LOLDrivers Vulnerable Driver: {doc.get('Name', yaml_file.stem)}

Category: {category}
Author: {doc.get('Author', 'Unknown')}

Description: {doc.get('Description', 'No description')}

MitreID: {doc.get('MitreID', 'N/A')}

Known Vulnerable Sample Hashes:
{chr(10).join(f"- {h}" for h in vuln_hashes) if vuln_hashes else "No hashes available"}

Commands/Capabilities:{commands_text if commands_text else " N/A"}

Detection:
{chr(10).join(f"- {d.get('type', 'unknown')}: {d.get('value', '')}" for d in (doc.get('Detection', []) or [])[:3])}

Resources:
{chr(10).join(f"- {r.get('Link', r) if isinstance(r, dict) else r}" for r in (doc.get('Resources', []) or [])[:3])}
"""
            # Extract MITRE techniques
            mitre_id = doc.get("MitreID", "")
            if isinstance(mitre_id, list):
                mitre_id = ",".join(mitre_id)

            records.append({
                "text": text,
                "metadata": {
                    "source": "loldrivers",
                    "title": doc.get("Name", yaml_file.stem),
                    "category": category if isinstance(category, str) else ",".join(category) if category else "",
                    "mitre_techniques": mitre_id,
                    "platform": "windows"
                }
            })
        except Exception as e:
            logger.debug(f"Error parsing {yaml_file}: {e}")
            continue

    _write_jsonl(records, output_path)
    return len(records)


def parse_capec(repo_dir: Path, output_path: Path) -> int:
    """Parse MITRE CAPEC attack patterns from STIX JSON."""
    records = []

    # Download CAPEC STIX directly (more reliable than cloning large repo)
    url = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
    logger.info("  Downloading CAPEC STIX data directly...")
    data = fetch_url(url, headers={"User-Agent": "rag-mcp/2.0"})
    if not data:
        logger.error("Could not download CAPEC STIX data")
        return 0

    bundle = json.loads(data)

    for obj in bundle.get("objects", []):
        obj_type = obj.get("type", "")

        if obj_type == "attack-pattern":
            # CAPEC attack pattern
            ext_refs = obj.get("external_references", [])
            capec_id = ""
            cwe_ids = []
            for ref in ext_refs:
                if ref.get("source_name") == "capec":
                    capec_id = ref.get("external_id", "")
                elif ref.get("source_name") == "cwe":
                    cwe_ids.append(ref.get("external_id", ""))

            # Get custom CAPEC properties
            prerequisites = obj.get("x_capec_prerequisites", [])
            if isinstance(prerequisites, list):
                prerequisites = "; ".join(prerequisites)

            consequences = obj.get("x_capec_consequences", {})
            if isinstance(consequences, dict):
                consequence_list = []
                for scope, impacts in consequences.items():
                    if isinstance(impacts, list):
                        consequence_list.append(f"{scope}: {', '.join(impacts)}")
                consequences = "; ".join(consequence_list)

            likelihood = obj.get("x_capec_likelihood_of_attack", "Unknown")
            severity = obj.get("x_capec_typical_severity", "Unknown")

            text = f"""CAPEC Attack Pattern: {obj.get('name', 'Unknown')}

ID: {capec_id}
Likelihood: {likelihood}
Severity: {severity}

Description: {obj.get('description', 'No description')}

Prerequisites: {prerequisites or 'None specified'}

Consequences: {consequences or 'None specified'}

Related Weaknesses (CWE): {', '.join(cwe_ids) if cwe_ids else 'None'}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "capec",
                    "title": obj.get("name", ""),
                    "capec_id": capec_id,
                    "cwe_ids": ",".join(cwe_ids),
                    "severity": severity,
                    "type": "attack_pattern"
                }
            })

        elif obj_type == "course-of-action":
            # CAPEC mitigation
            ext_refs = obj.get("external_references", [])
            capec_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "capec":
                    capec_id = ref.get("external_id", "")
                    break

            text = f"""CAPEC Mitigation: {obj.get('name', 'Unknown')}

ID: {capec_id}

Description: {obj.get('description', 'No description')}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "capec",
                    "title": obj.get("name", ""),
                    "capec_id": capec_id,
                    "type": "mitigation"
                }
            })

    _write_jsonl(records, output_path)
    return len(records)


def parse_mbc(repo_dir: Path, output_path: Path) -> int:
    """Parse MITRE MBC (Malware Behavior Catalog) from STIX 2.1 JSON."""
    records = []

    # Download MBC STIX directly
    url = "https://raw.githubusercontent.com/MBCProject/mbc-stix2.1/main/mbc/mbc.json"
    logger.info("  Downloading MBC STIX data directly...")
    data = fetch_url(url, headers={"User-Agent": "rag-mcp/2.0"})
    if not data:
        logger.error("Could not download MBC STIX data")
        return 0

    bundle = json.loads(data)

    for obj in bundle.get("objects", []):
        obj_type = obj.get("type", "")

        if obj_type == "malware-behavior":
            # MBC behavior (e.g., "Anti-Behavioral Analysis", "Defense Evasion")
            obj_defn = obj.get("obj_defn", {})
            mbc_id = obj_defn.get("external_id", "")

            text = f"""MBC Malware Behavior: {obj.get('name', 'Unknown')}

ID: {mbc_id}

Description: {obj_defn.get('description', 'No description')}

URL: {obj_defn.get('url', '')}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "mbc",
                    "title": obj.get("name", ""),
                    "mbc_id": mbc_id,
                    "type": "behavior"
                }
            })

        elif obj_type == "malware-method":
            # MBC method (specific malware techniques)
            obj_defn = obj.get("obj_defn", {})
            mbc_id = obj_defn.get("external_id", "")

            # Get related ATT&CK techniques if present
            attack_refs = []
            for ref in obj_defn.get("external_references", []) or []:
                if ref.get("source_name") == "mitre-attack":
                    attack_refs.append(ref.get("external_id", ""))

            text = f"""MBC Malware Method: {obj.get('name', 'Unknown')}

ID: {mbc_id}

Description: {obj_defn.get('description', 'No description')}

Related ATT&CK: {', '.join(attack_refs) if attack_refs else 'None'}

URL: {obj_defn.get('url', '')}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "mbc",
                    "title": obj.get("name", ""),
                    "mbc_id": mbc_id,
                    "mitre_techniques": ",".join(attack_refs),
                    "type": "method"
                }
            })

        elif obj_type == "malware-objective":
            # MBC objective (high-level goals like "Anti-Behavioral Analysis")
            obj_defn = obj.get("obj_defn", {})
            mbc_id = obj_defn.get("external_id", "")

            text = f"""MBC Malware Objective: {obj.get('name', 'Unknown')}

ID: {mbc_id}

Description: {obj_defn.get('description', 'No description')}

URL: {obj_defn.get('url', '')}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "mbc",
                    "title": obj.get("name", ""),
                    "mbc_id": mbc_id,
                    "type": "objective"
                }
            })

        elif obj_type == "malware":
            # Specific malware samples with MBC mappings
            name = obj.get("name", "Unknown")
            description = obj.get("description", "")

            # Skip if no useful content
            if not description:
                continue

            text = f"""MBC Malware: {name}

Description: {description}

Malware Types: {', '.join(obj.get('malware_types', []))}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "mbc",
                    "title": name,
                    "type": "malware"
                }
            })

    _write_jsonl(records, output_path)
    return len(records)


def parse_chainsaw(repo_dir: Path, output_path: Path) -> int:
    """Parse Chainsaw detection rules (EVTX and MFT)."""
    records = []
    rules_dir = repo_dir / "rules"

    for yaml_file in rules_dir.rglob("*.yml"):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)

            if not doc or not isinstance(doc, dict):
                continue

            title = doc.get("title", "Untitled")
            kind = doc.get("kind", "unknown")  # evtx or mft
            group = doc.get("group", "")
            description = doc.get("description", "")
            level = doc.get("level", "info")
            authors = doc.get("authors", [])

            # Build filter description
            filter_info = doc.get("filter", {})
            filter_text = yaml.dump(filter_info, default_flow_style=False) if filter_info else "N/A"

            text = f"""Chainsaw {kind.upper()} Detection Rule: {title}

Group: {group}
Level: {level}
Authors: {', '.join(authors) if authors else 'Unknown'}

Description: {description}

Detection Filter:
{filter_text}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "chainsaw",
                    "title": title,
                    "category": kind,
                    "level": level,
                    "group": group
                }
            })
        except Exception as e:
            logger.debug(f"Error parsing {yaml_file}: {e}")
            continue

    _write_jsonl(records, output_path)
    return len(records)


def parse_hayabusa(repo_dir: Path, output_path: Path) -> int:
    """Parse Hayabusa built-in detection rules (excludes Sigma duplicates)."""
    records = []
    # Only parse hayabusa/builtin and hayabusa/sysmon - not sigma/
    builtin_dir = repo_dir / "hayabusa"

    for yaml_file in builtin_dir.rglob("*.yml"):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)

            if not doc or not isinstance(doc, dict):
                continue

            # Skip if it's actually a Sigma rule (has logsource.product)
            ruletype = doc.get("ruletype", "")
            if ruletype.lower() == "sigma":
                continue

            title = doc.get("title", "Untitled")
            description = doc.get("description", "")
            level = doc.get("level", "informational")
            author = doc.get("author", "Unknown")
            details = doc.get("details", "")

            # Get detection info
            detection = doc.get("detection", {})
            detection_text = yaml.dump(detection, default_flow_style=False) if detection else "N/A"

            # Get logsource info
            logsource = doc.get("logsource", {})
            channel = logsource.get("service", logsource.get("description", ""))

            # Tags
            tags = doc.get("tags", [])

            text = f"""Hayabusa Detection Rule: {title}

Level: {level}
Author: {author}
Log Source: {channel}

Description: {description}

Output Details: {details}

Detection Logic:
{detection_text}

Tags: {', '.join(tags) if tags else 'None'}
"""
            records.append({
                "text": text,
                "metadata": {
                    "source": "hayabusa",
                    "title": title,
                    "level": level,
                    "category": "builtin"
                }
            })
        except Exception as e:
            logger.debug(f"Error parsing {yaml_file}: {e}")
            continue

    _write_jsonl(records, output_path)
    return len(records)


def _write_jsonl(records: list[dict], output_path: Path) -> None:
    """Write records to JSONL file (atomic: tmpfile + rename)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=output_path.parent,
        prefix=f".{output_path.name}.",
        suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        os.replace(tmp_path, output_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def parse_forensic_clarifications(repo_dir: Path, output_path: Path) -> int:
    """Parse embedded forensic clarifications (bundled with package)."""
    # Source is embedded in package, not from a repo
    import shutil
    embedded_path = Path(__file__).parent / "data" / "forensic_clarifications.jsonl"

    if not embedded_path.exists():
        return 0

    # Copy to output location
    output_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(embedded_path, output_path)

    # Count records
    count = 0
    with open(output_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                count += 1

    return count


# Parser registry
PARSERS: dict[str, Callable[[Path, Path], int]] = {
    "parse_sigma": parse_sigma,
    "parse_atomic": parse_atomic,
    "parse_stix": parse_stix,
    "parse_car": parse_car,
    "parse_d3fend": parse_d3fend,
    "parse_stratus": parse_stratus,
    "parse_kev": parse_kev,
    "parse_elastic": parse_elastic,
    "parse_splunk": parse_splunk,
    "parse_lolbas": parse_lolbas,
    "parse_gtfobins": parse_gtfobins,
    "parse_hijacklibs": parse_hijacklibs,
    "parse_forensic_artifacts": parse_forensic_artifacts,
    "parse_kape": parse_kape,
    "parse_velociraptor": parse_velociraptor,
    "parse_atlas": parse_atlas,
    "parse_engage": parse_engage,
    "parse_loldrivers": parse_loldrivers,
    "parse_capec": parse_capec,
    "parse_mbc": parse_mbc,
    "parse_chainsaw": parse_chainsaw,
    "parse_hayabusa": parse_hayabusa,
    "parse_forensic_clarifications": parse_forensic_clarifications,
}


# =============================================================================
# Main Functions
# =============================================================================

def fetch_and_parse(source: SourceConfig, output_path: Path) -> FetchResult:
    """Fetch source and parse to JSONL."""
    result = FetchResult(source=source.name, status="error")

    # JSON feeds don't need cloning
    if source.source_type == "json_feed":
        parser = PARSERS.get(source.parser)
        if parser:
            try:
                count = parser(Path(), output_path)  # No repo dir for feeds
                result.status = "success"
                result.records = count
                result.version = get_latest_version(source) or "unknown"
                result.cache_hash = compute_file_hash(output_path) if output_path.exists() else ""
            except Exception as e:
                result.message = str(e)
        return result

    # Special case: MITRE ATT&CK downloads directly (no clone needed)
    if source.name == "mitre_attack":
        parser = PARSERS.get(source.parser)
        if parser:
            try:
                count = parser(Path(), output_path)
                result.status = "success"
                result.records = count
                result.version = get_latest_version(source) or "unknown"
                result.cache_hash = compute_file_hash(output_path) if output_path.exists() else ""
            except Exception as e:
                result.message = str(e)
        return result

    # Embedded sources are bundled with the package
    if source.source_type == "embedded":
        parser = PARSERS.get(source.parser)
        if parser:
            try:
                count = parser(Path(), output_path)  # No repo dir for embedded
                result.status = "success"
                result.records = count
                result.version = "embedded"
                result.cache_hash = compute_file_hash(output_path) if output_path.exists() else ""
            except Exception as e:
                result.message = str(e)
        return result

    # Clone GitHub repo to temp directory
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir) / source.name

        logger.info(f"  Cloning {source.repo}...")
        if not clone_repo(source.repo, source.branch, repo_dir):
            result.message = "Failed to clone repository"
            return result

        # Run parser
        parser = PARSERS.get(source.parser)
        if not parser:
            result.message = f"Unknown parser: {source.parser}"
            return result

        try:
            logger.info(f"  Parsing {source.name}...")
            count = parser(repo_dir, output_path)
            result.status = "success"
            result.records = count
            result.version = get_latest_version(source) or "unknown"
            result.cache_hash = compute_file_hash(output_path) if output_path.exists() else ""
        except Exception as e:
            result.message = str(e)
            logger.error(f"  Error parsing {source.name}: {e}")

    return result


def check_source_updates() -> list[SourceStatus]:
    """Check all sources for available updates."""
    state = load_sources_state()
    disabled = load_disabled_sources()
    results = []

    for name, source in SOURCES.items():
        if name in disabled:
            continue

        source_state = state.get("sources", {}).get(name, {})
        current = source_state.get("version", "unknown")
        latest = get_latest_version(source)

        results.append(SourceStatus(
            name=name,
            current_version=current,
            latest_version=latest or "unknown",
            has_update=latest is not None and current != latest and current != "unknown",
            last_sync=source_state.get("last_sync", "never"),
            records=source_state.get("records", 0),
            error="" if latest else "Failed to check version"
        ))

    return results


def sync_source(name: str, force: bool = False) -> FetchResult:
    """Sync a single source."""
    if name not in SOURCES:
        return FetchResult(source=name, status="error", message=f"Unknown source: {name}")

    source = SOURCES[name]
    disabled = load_disabled_sources()

    if name in disabled:
        return FetchResult(source=name, status="skipped", message="Source is disabled")

    state = load_sources_state()
    source_state = state.get("sources", {}).get(name, {})
    current_version = source_state.get("version")

    # Check if update needed
    if not force:
        latest = get_latest_version(source)
        if latest and latest == current_version:
            return FetchResult(
                source=name,
                status="skipped",
                message="Already up to date",
                version=current_version,
                records=source_state.get("records", 0)
            )

    # Fetch and parse
    output_path = SOURCES_DIR / f"{name}.jsonl"
    logger.info(f"Syncing {name}...")
    result = fetch_and_parse(source, output_path)

    # Update state
    if result.status == "success":
        state.setdefault("sources", {})[name] = {
            "version": result.version,
            "last_sync": datetime.now().isoformat(),
            "records": result.records,
            "cache_hash": result.cache_hash
        }
        save_sources_state(state)
        logger.info(f"  Synced {name}: {result.records} records")

    return result


def sync_all_sources(force: bool = False) -> list[FetchResult]:
    """Sync all enabled sources."""
    disabled = load_disabled_sources()
    results = []

    for name in SOURCES:
        if name in disabled:
            results.append(FetchResult(source=name, status="skipped", message="Disabled"))
            continue

        result = sync_source(name, force=force)
        results.append(result)

    return results


def get_cached_sources() -> dict[str, Path]:
    """Get paths to all cached JSONL files."""
    sources = {}
    for name in SOURCES:
        path = SOURCES_DIR / f"{name}.jsonl"
        if path.exists():
            sources[name] = path
    return sources
