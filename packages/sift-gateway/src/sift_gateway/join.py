"""Join code state management for multi-machine credential distribution.

Join codes are one-time-use, time-limited tokens that allow remote machines
to exchange for gateway credentials without pre-sharing bearer tokens.
Codes are bcrypt-hashed before storage; plaintext is never persisted.

State file: ~/.aiir/.join_state.json
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import bcrypt

logger = logging.getLogger(__name__)

# No ambiguous characters (0/O, 1/l/I)
_JOIN_CHARSET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

# Rate limiting: max failures per window
_MAX_FAILURES = 3
_FAILURE_WINDOW_SECONDS = 15 * 60  # 15 minutes

_STATE_DIR = Path.home() / ".aiir"
_STATE_FILE = _STATE_DIR / ".join_state.json"


def _load_state() -> dict:
    if not _STATE_FILE.exists():
        return {"codes": {}, "failures": {}}
    try:
        state = json.loads(_STATE_FILE.read_text())
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load join state: %s", e)
        return {"codes": {}, "failures": {}}
    # Prune expired and used codes
    now = time.time()
    codes = state.get("codes", {})
    state["codes"] = {
        h: info
        for h, info in codes.items()
        if not info.get("used", False) and now <= info.get("expires_ts", 0)
    }
    # Prune stale failure entries (legacy — new failures are in-memory)
    failures = state.get("failures", {})
    state["failures"] = {
        ip: [ts for ts in timestamps if now - ts < _FAILURE_WINDOW_SECONDS]
        for ip, timestamps in failures.items()
        if any(now - ts < _FAILURE_WINDOW_SECONDS for ts in timestamps)
    }
    return state


def _save_state(state: dict) -> None:
    _STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(_STATE_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=2)


def generate_join_code() -> str:
    """Generate an 8-character join code in XXXX-XXXX format."""
    chars = [secrets.choice(_JOIN_CHARSET) for _ in range(8)]
    return "".join(chars[:4]) + "-" + "".join(chars[4:])


def store_join_code(code: str, expires_hours: int = 2) -> None:
    """Hash and store a join code with expiry."""
    state = _load_state()
    # bcrypt hash of the code
    code_bytes = code.encode("utf-8")
    hashed = bcrypt.hashpw(code_bytes, bcrypt.gensalt()).decode("utf-8")
    now_ts = time.time()
    expires_ts = now_ts + (expires_hours * 3600)
    state["codes"][hashed] = {
        "created": datetime.now(timezone.utc).isoformat(),
        "expires_ts": expires_ts,
        "used": False,
    }
    _save_state(state)


def validate_join_code(code: str) -> str | None:
    """Check if code matches any stored hash. Returns the hash key if valid, None otherwise."""
    state = _load_state()
    code_bytes = code.encode("utf-8")
    now = time.time()

    for hashed, info in state["codes"].items():
        if info.get("used", False):
            continue
        if now > info.get("expires_ts", 0):
            continue
        try:
            if bcrypt.checkpw(code_bytes, hashed.encode("utf-8")):
                return hashed
        except (ValueError, TypeError):
            continue
    return None


def mark_code_used(code: str) -> None:
    """Mark a join code as used."""
    state = _load_state()
    code_bytes = code.encode("utf-8")

    for hashed, info in state["codes"].items():
        try:
            if bcrypt.checkpw(code_bytes, hashed.encode("utf-8")):
                info["used"] = True
                info["used_at"] = datetime.now(timezone.utc).isoformat()
                _save_state(state)
                return
        except (ValueError, TypeError):
            continue


def validate_and_consume_join_code(code: str) -> str | None:
    """Atomically validate and mark a join code as used. Thread-safe."""
    with _join_code_lock:
        matched_hash = validate_join_code(code)
        if matched_hash:
            mark_code_used(code)
        return matched_hash


_join_code_lock = threading.Lock()

_join_failures: dict[str, list[float]] = {}
_join_failures_lock = threading.Lock()


def check_join_rate_limit(client_ip: str) -> bool:
    """Return True if the client is allowed to attempt. In-memory, thread-safe."""
    with _join_failures_lock:
        now = time.monotonic()
        timestamps = _join_failures.get(client_ip, [])
        recent = [t for t in timestamps if now - t < _FAILURE_WINDOW_SECONDS]
        _join_failures[client_ip] = recent
        return len(recent) < _MAX_FAILURES


def record_join_failure(client_ip: str) -> None:
    """Record a failed join attempt. In-memory, thread-safe."""
    with _join_failures_lock:
        if client_ip not in _join_failures:
            _join_failures[client_ip] = []
        _join_failures[client_ip].append(time.monotonic())
