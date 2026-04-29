from __future__ import annotations

import os
from pathlib import Path


def load_env_file(path: str | Path = ".env") -> None:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return

    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue

        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]

        os.environ.setdefault(key, value)


def get_ai_analysis_batch_size(default: int = 1) -> int:
    """Read AI analysis batch size from env and clamp it to safe bounds (1-5)."""
    raw_value = str(os.getenv("AI_ANALYSIS_BATCH_SIZE", "")).strip()
    try:
        value = int(raw_value) if raw_value else int(default)
    except Exception:
        value = int(default)
    return max(1, min(5, value))

