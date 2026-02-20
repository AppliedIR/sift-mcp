"""Configuration for sift-mcp."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SiftConfig:
    """Runtime configuration loaded from environment."""

    # Tool binary search paths
    tool_paths: list[str] = field(default_factory=lambda: [
        "/usr/local/bin",
        "/usr/bin",
        "/opt/zimmerman",
        "/opt/volatility3",
    ])

    # Default execution timeout (seconds)
    default_timeout: int = 600

    # Max output bytes before truncation
    max_output_bytes: int = 50000

    # Hayabusa install location
    hayabusa_dir: str = "/opt/hayabusa"

    # Case directory (from env)
    case_dir: str = ""

    @classmethod
    def from_env(cls) -> SiftConfig:
        cfg = cls()
        cfg.case_dir = os.environ.get("AIIR_CASE_DIR", "")

        extra_paths = os.environ.get("SIFT_TOOL_PATHS", "")
        if extra_paths:
            cfg.tool_paths = extra_paths.split(":") + cfg.tool_paths

        timeout = os.environ.get("SIFT_TIMEOUT")
        if timeout and timeout.isdigit():
            cfg.default_timeout = int(timeout)

        hayabusa = os.environ.get("SIFT_HAYABUSA_DIR")
        if hayabusa:
            cfg.hayabusa_dir = hayabusa

        return cfg


def get_config() -> SiftConfig:
    return SiftConfig.from_env()
