"""YAML config loading with environment variable interpolation."""

import logging
import os
import re
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


_ENV_VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _interpolate_env(value: str) -> str:
    """Replace ${VAR} patterns with environment variable values.

    If a referenced variable is not set, the placeholder is replaced with
    an empty string to prevent literal '${VAR}' from leaking into configs.
    """

    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, "")

    return _ENV_VAR_PATTERN.sub(_replace, value)


def _walk_and_interpolate(obj):
    """Recursively walk a parsed YAML structure and interpolate strings."""
    if isinstance(obj, str):
        return _interpolate_env(obj)
    if isinstance(obj, dict):
        return {k: _walk_and_interpolate(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk_and_interpolate(item) for item in obj]
    return obj


def load_config(path: str) -> dict:
    """Load a YAML config file with env var interpolation.

    Args:
        path: Path to the YAML config file.

    Returns:
        Parsed and interpolated config dict.

    Raises:
        FileNotFoundError: If the config file does not exist.
        yaml.YAMLError: If the file is not valid YAML.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    try:
        with open(config_path) as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        logger.error("Invalid YAML in config file %s: %s", path, e)
        raise
    except OSError as e:
        logger.error("Cannot read config file %s: %s", path, e)
        raise

    if raw is None:
        return {}

    if not isinstance(raw, dict):
        raise ValueError(f"Config file must contain a YAML mapping, got {type(raw).__name__}: {path}")

    return _walk_and_interpolate(raw)
