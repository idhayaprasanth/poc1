import ast
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)


def _env(name, default):
    return (os.getenv(name) or str(default)).strip()


_RATE_LIMIT_WINDOW_SECONDS = 60.0
_REQUESTS_PER_MINUTE = max(1, int(_env("GEMINI_FREE_TIER_RPM", 10)))
_MIN_GEMINI_INTERVAL_SECONDS = max(
    float(
        _env(
            "GEMINI_MIN_INTERVAL_SECONDS",
            _RATE_LIMIT_WINDOW_SECONDS / _REQUESTS_PER_MINUTE,
        )
    ),
    0.0,
)
_QUOTA_EXHAUSTED_COOLDOWN_SECONDS = max(
    float(_env("GEMINI_QUOTA_EXHAUSTED_COOLDOWN_SECONDS", 1800)),
    0.0,
)
_RATE_LIMIT_STATE_FILE = (
    Path(__file__).resolve().parents[1] / "data" / "gemini_rate_limit_state.json"
)
_GEMINI_DEBUG_LOG_FILE = (
    Path(__file__).resolve().parents[1] / "data" / "gemini_api_debug.jsonl"
)

_STATE_CACHE = None
_JSON_RE = re.compile(r"(\{.*\}|\[.*\])", re.DOTALL)


def _load_rate_limit_state():
    global _STATE_CACHE
    if _STATE_CACHE is not None:
        return _STATE_CACHE
    if not _RATE_LIMIT_STATE_FILE.exists():
        _STATE_CACHE = {}
        return _STATE_CACHE
    try:
        _STATE_CACHE = json.loads(_RATE_LIMIT_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        _STATE_CACHE = {}
    return _STATE_CACHE


def _save_rate_limit_state(state):
    global _STATE_CACHE
    _STATE_CACHE = state
    try:
        _RATE_LIMIT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _RATE_LIMIT_STATE_FILE.write_text(json.dumps(state), encoding="utf-8")
    except Exception as exc:
        logger.warning("State save failed: %s", exc)


def _extract_json_payload(text: str) -> str:
    if not text:
        return ""
    match = _JSON_RE.search(text)
    return match.group(0).strip() if match else text.strip()


def _repair_json_string_newlines(text: str) -> str:
    if not text:
        return ""

    repaired = []
    in_string = False
    escape = False
    quote_char = ""

    for ch in text:
        if escape:
            repaired.append(ch)
            escape = False
            continue

        if in_string and ch == "\\":
            repaired.append(ch)
            escape = True
            continue

        if ch in {'"', "'"}:
            if not in_string:
                in_string = True
                quote_char = ch
            elif ch == quote_char:
                in_string = False
                quote_char = ""
            repaired.append(ch)
            continue

        if in_string and ch in {"\r", "\n"}:
            repaired.append("\\n")
            continue

        repaired.append(ch)

    return "".join(repaired)


def _is_truncated_json(text: str) -> bool:
    if not text:
        return False
    try:
        json.loads(text)
        return False
    except Exception:
        return text.strip().startswith(("{", "["))


def _remaining_pause_seconds() -> float:
    state = _load_rate_limit_state()
    pause_until = float(state.get("pause_until", 0.0) or 0.0)
    return max(0.0, pause_until - time.time())


def get_gemini_pause_status():
    state = _load_rate_limit_state()
    remaining_seconds = _remaining_pause_seconds()
    return {
        "active": remaining_seconds > 0,
        "remaining_seconds": remaining_seconds,
        "pause_until": float(state.get("pause_until", 0.0) or 0.0),
        "quota_scope": str(state.get("quota_scope", "") or ""),
        "reason": str(state.get("reason", "") or ""),
    }


def _should_skip_gemini() -> bool:
    return get_gemini_pause_status()["active"]


def _set_gemini_pause(seconds: float, *, quota_scope: str = "", reason: str = ""):
    seconds = max(float(seconds or 0.0), 0.0)
    pause_until = time.time() + seconds if seconds > 0 else 0.0
    _save_rate_limit_state(
        {
            "pause_until": pause_until,
            "quota_scope": quota_scope,
            "reason": reason,
            "updated_at": time.time(),
        }
    )


def _clear_gemini_pause():
    _save_rate_limit_state({})


def _parse_retry_after_seconds(headers) -> float:
    if not headers:
        return 0.0
    raw_value = headers.get("Retry-After") or headers.get("retry-after")
    if not raw_value:
        return 0.0
    try:
        return max(float(raw_value), 0.0)
    except Exception:
        return 0.0


def _infer_quota_scope(message: str) -> str:
    lowered = (message or "").lower()
    if "billing" in lowered:
        return "billing"
    if "daily" in lowered or "per day" in lowered or "day" in lowered:
        return "day"
    if "token" in lowered:
        return "tokens"
    if "minute" in lowered or "per minute" in lowered or "rpm" in lowered:
        return "minute"
    return ""


def _cooldown_for_scope(scope: str, retry_after_seconds: float) -> float:
    if scope in {"day", "billing"}:
        return max(retry_after_seconds, _QUOTA_EXHAUSTED_COOLDOWN_SECONDS)
    if scope == "tokens":
        return max(retry_after_seconds, _MIN_GEMINI_INTERVAL_SECONDS)
    return max(retry_after_seconds, _RATE_LIMIT_WINDOW_SECONDS)


class _TruncatedResponseError(Exception):
    pass


class GeminiRateLimitError(Exception):
    pass


class GeminiBaseClient:
    def __init__(self, api_key=None, model=None, timeout_s=45):
        self.api_key = api_key or _env("GEMINI_API_KEY", "")
        self.model = model or _env("GEMINI_MODEL", "")
        self.api_version = _env("GEMINI_API_VERSION", "v1beta")
        self.timeout_s = timeout_s

    def enabled(self):
        return bool(self.api_key)

    def _preferred_versions(self):
        versions = [self.api_version, "v1beta"]
        return [version for version in dict.fromkeys(versions) if version]

    def _preferred_models(self):
        models = [
            self.model,
            _env("GEMINI_MODEL_FALLBACK", ""),
            "gemini-2.5-flash",
            "gemini-3.1-pro-preview",
            "gemini-3-flash-preview"
        ]
        return [model for model in dict.fromkeys(models) if model]

    def _url(self, version, path):
        return (
            f"https://generativelanguage.googleapis.com/{version}/{path}"
            f"?key={self.api_key}"
        )

    def _read_http_error_body(self, error: urllib.error.HTTPError) -> str:
        try:
            body = error.read()
        except Exception:
            return ""
        try:
            return body.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _write_debug_log(self, event: dict):
        """Append structured Gemini request/response debug logs with timestamp."""
        try:
            _GEMINI_DEBUG_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            payload = dict(event or {})
            payload["logged_at"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
            with _GEMINI_DEBUG_LOG_FILE.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
        except Exception as exc:
            logger.warning("Gemini debug log write failed: %s", exc)

    def _raise_rate_limit(self, error: urllib.error.HTTPError):
        body = self._read_http_error_body(error)
        reason = body or str(error)
        scope = _infer_quota_scope(reason)
        retry_after_seconds = _parse_retry_after_seconds(error.headers)
        cooldown = _cooldown_for_scope(scope, retry_after_seconds)
        _set_gemini_pause(cooldown, quota_scope=scope, reason=reason[:500])
        raise GeminiRateLimitError(reason or "Gemini rate limited")

    def _try_generate(self, api_version, model_name, payload):
        url = self._url(api_version, f"models/{model_name}:generateContent")
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
            data = json.loads(response.read().decode("utf-8"))

        parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
        text = "".join(part.get("text", "") for part in parts).strip()
        return text or "No response"

    def _attempt(self, *, api_version, model_name, payload):
        if not model_name:
            return "Gemini model is not configured.", False

        try:
            text = self._try_generate(api_version, model_name, payload)
            self._write_debug_log(
                {
                    "event": "attempt_success",
                    "api_version": api_version,
                    "model_name": model_name,
                    "response_preview": text[:1200],
                }
            )
            _clear_gemini_pause()
            return text, True
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                self._raise_rate_limit(exc)
            body = self._read_http_error_body(exc)
            self._write_debug_log(
                {
                    "event": "attempt_http_error",
                    "api_version": api_version,
                    "model_name": model_name,
                    "http_code": exc.code,
                    "error_body_preview": (body or str(exc))[:1200],
                }
            )
            return body or f"Gemini request failed with HTTP {exc.code}.", False
        except urllib.error.URLError as exc:
            self._write_debug_log(
                {
                    "event": "attempt_url_error",
                    "api_version": api_version,
                    "model_name": model_name,
                    "error_reason": str(exc.reason),
                }
            )
            return f"Gemini request failed: {exc.reason}", False
        except Exception as exc:
            logger.exception(
                "Unexpected Gemini request failure for %s/%s",
                api_version,
                model_name,
            )
            self._write_debug_log(
                {
                    "event": "attempt_exception",
                    "api_version": api_version,
                    "model_name": model_name,
                    "error": str(exc),
                }
            )
            return str(exc), False

    def _generate(self, payload):
        first_error = ""
        for api_version in self._preferred_versions():
            for model_name in self._preferred_models():
                text, ok = self._attempt(
                    api_version=api_version,
                    model_name=model_name,
                    payload=payload,
                )
                if ok:
                    return text
                if text and not first_error:
                    first_error = text
        return first_error or "Gemini failed"

    def _extract_json_payload(self, text: str) -> str:
        return _extract_json_payload(text)

    def _parse_json_like(self, text: str):
        cleaned = self._extract_json_payload(text)
        if _is_truncated_json(cleaned):
            raise _TruncatedResponseError("Truncated JSON")
        try:
            return json.loads(cleaned)
        except Exception:
            repaired = _repair_json_string_newlines(cleaned)
            if repaired != cleaned:
                try:
                    return json.loads(repaired)
                except Exception:
                    pass
            try:
                return ast.literal_eval(repaired)
            except Exception as exc:
                self._write_debug_log(
                    {
                        "event": "json_parse_failed",
                        "cleaned_preview": cleaned[:1200],
                    }
                )
                logger.warning(
                    "Gemini returned malformed JSON payload: %s",
                    cleaned[:300].replace("\n", "\\n"),
                )
                raise ValueError("Gemini failed to return valid JSON.") from exc

    def generate_text(self, system_instruction, user_prompt):
        payload = {
            "system_instruction": {"parts": [{"text": system_instruction}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 800,
            },
        }

        text = self._generate(payload)
        if text.startswith("Gemini"):
            return text

        cleaned = self._extract_json_payload(text)
        if _is_truncated_json(cleaned):
            raise _TruncatedResponseError("Truncated JSON")

        try:
            return json.loads(cleaned)
        except Exception:
            return text
