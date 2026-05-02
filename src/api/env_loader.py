from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILES = (PROJECT_ROOT / ".env", PROJECT_ROOT / ".env.local")
PLACEHOLDER_VALUES = {
    "",
    "your_minimax_api_key_here",
    "changeme",
    "replace_me",
}


def _parse_env_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None

    key, value = stripped.split("=", 1)
    key = key.strip()
    value = value.strip()

    if not key:
        return None

    if value and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]

    return key, value


def load_root_env() -> None:
    """Load root .env files into process env without overriding explicit env vars."""
    for env_file in ENV_FILES:
        if not env_file.exists():
            continue

        for line in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            parsed = _parse_env_line(line)
            if not parsed:
                continue

            key, value = parsed
            os.environ.setdefault(key, value)


def has_valid_env_value(key: str) -> bool:
    value = (os.environ.get(key) or "").strip()
    return value.lower() not in PLACEHOLDER_VALUES
