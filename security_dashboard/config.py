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


def get_ollama_base_url(default: str = "http://localhost:11434") -> str:
    """
    Get the Ollama base URL.
    
    Configuration via .env:
        OLLAMA_BASE_URL=http://localhost:11434  (local development)
        OLLAMA_BASE_URL=http://ollama-server:11434  (remote server)
    
    Args:
        default: Default Ollama URL if not set (default: "http://localhost:11434")
    
    Returns:
        Base URL string
    """
    url = str(os.getenv("OLLAMA_BASE_URL", "")).strip()
    return url if url else default


def get_ollama_model(default: str = "neural-chat") -> str:
    """
    Get the Ollama model name.
    
    Configuration via .env:
        OLLAMA_MODEL=neural-chat  (default, 7B model optimized for instruction following)
        OLLAMA_MODEL=mistral     (7B model, higher quality)
        OLLAMA_MODEL=llama2      (7B/13B model)
    
    Args:
        default: Default model if not set (default: "neural-chat")
    
    Returns:
        Model name string
    """
    model = str(os.getenv("OLLAMA_MODEL", "")).strip()
    return model if model else default

