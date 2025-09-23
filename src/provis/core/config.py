"""Configuration helpers and feature flag evaluation."""

from __future__ import annotations

import os
from functools import lru_cache


_TRUE_VALUES = {"1", "true", "yes", "on"}


@lru_cache(maxsize=None)
def feature_enabled(name: str, default: bool = False) -> bool:
    """Return True when the named feature flag is enabled via environment variable.

    Feature names map to environment variables using the pattern:
        feature.step1.provenance_v2 → PROVIS_FEATURE_STEP1_PROVENANCE_V2
    Values are interpreted case-insensitively; "1", "true", "yes", "on" enable the flag.
    """

    env_key = "PROVIS_" + name.upper().replace(".", "_")
    raw = os.getenv(env_key)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUE_VALUES
