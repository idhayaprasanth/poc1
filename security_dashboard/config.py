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


def get_analysis_prompt_template_version(default: str = "1.1") -> str:
    """
    Get the prompt template version for asset analysis.
    
    Allows A/B testing by swapping template versions via .env:
        ANALYSIS_PROMPT_TEMPLATE_VERSION=1.0  # Use old version
        ANALYSIS_PROMPT_TEMPLATE_VERSION=1.1  # Use token-optimized version (default)
    
    Args:
        default: Default version if not set (default: "1.1" - token-optimized)
    
    Returns:
        Template version string (e.g., "1.0", "1.1")
    """
    version = str(os.getenv("ANALYSIS_PROMPT_TEMPLATE_VERSION", "")).strip()
    return version if version else default


def get_chatbot_prompt_template_version(default: str = "1.0") -> str:
    """
    Get the prompt template version for chatbot.
    
    Allows A/B testing by swapping template versions via .env:
        CHATBOT_PROMPT_TEMPLATE_VERSION=1.0
    
    Args:
        default: Default version if not set (default: "1.0")
    
    Returns:
        Template version string
    """
    version = str(os.getenv("CHATBOT_PROMPT_TEMPLATE_VERSION", "")).strip()
    return version if version else default


def use_outlines_orchestration(default: bool = True) -> bool:
    """
    Feature flag to enable/disable outlines-based orchestration.
    
    Allows gradual rollout and easy rollback:
        USE_OUTLINES_ORCHESTRATION=false  (to use old system)
    
    Args:
        default: Default value (True = use outlines)
    
    Returns:
        Boolean indicating whether to use outlines
    """
    raw_value = str(os.getenv("USE_OUTLINES_ORCHESTRATION", "")).strip().lower()
    
    if raw_value in ("true", "1", "yes", "enabled"):
        return True
    elif raw_value in ("false", "0", "no", "disabled"):
        return False
    else:
        return default

