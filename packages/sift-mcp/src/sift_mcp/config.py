"""Configuration for sift-mcp."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class SiftConfig:
    """Runtime configuration loaded from environment."""

    # Tool binary search paths
    tool_paths: list[str] = field(
        default_factory=lambda: [
            "/usr/local/bin",
            "/usr/bin",
            "/opt/zimmerman",
            "/opt/volatility3",
        ]
    )

    # Default execution timeout (seconds)
    default_timeout: int = 600

    # Max bytes captured from subprocess (safety limit for runaway processes)
    max_output_bytes: int = 52_428_800  # 50MB

    # Max bytes of tool output returned in MCP response (~2,500 tokens)
    response_byte_budget: int = 10_240  # 10KB

    # Hayabusa install location
    hayabusa_dir: str = "/opt/hayabusa"

    # Case directory (from env)
    case_dir: str = ""

    # SMB share mount point for wintools extraction files
    share_root: str = ""

    @classmethod
    def from_env(cls) -> SiftConfig:
        cfg = cls()
        cfg.case_dir = os.environ.get("AIIR_CASE_DIR", "")
        cfg.share_root = os.environ.get("AIIR_SHARE_ROOT", "")

        extra_paths = os.environ.get("SIFT_TOOL_PATHS", "")
        if extra_paths:
            cfg.tool_paths = extra_paths.split(":") + cfg.tool_paths

        timeout = os.environ.get("SIFT_TIMEOUT")
        if timeout and timeout.isdigit():
            cfg.default_timeout = int(timeout)

        hayabusa = os.environ.get("SIFT_HAYABUSA_DIR")
        if hayabusa:
            cfg.hayabusa_dir = hayabusa

        if os.environ.get("SIFT_RESPONSE_BUDGET"):
            try:
                cfg.response_byte_budget = int(os.environ["SIFT_RESPONSE_BUDGET"])
            except ValueError:
                pass

        if os.environ.get("SIFT_MAX_OUTPUT"):
            try:
                cfg.max_output_bytes = int(os.environ["SIFT_MAX_OUTPUT"])
            except ValueError:
                pass

        return cfg


def get_config() -> SiftConfig:
    return SiftConfig.from_env()
