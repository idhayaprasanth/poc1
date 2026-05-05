import json
import os
import time
from pathlib import Path
from typing import Any

import requests

from security_dashboard.services.structured_output_validator import StructuredOutputValidator
from security_dashboard.services.schemas import ValidationResult


_OLLAMA_DEBUG_LOG_FILE = Path(__file__).resolve().parents[1] / "data" / "sagemaker_api_debug.jsonl"


def _env(name: str, default: str) -> str:
    return (os.getenv(name) or str(default)).strip()


class OllamaBaseClient:
    def __init__(self, base_url: str | None = None, model: str | None = None, debug: bool = False):
        self.base_url = (base_url or _env("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self.model = model or _env("OLLAMA_MODEL", "neural-chat")
        self.debug = debug
        self._session = None  # Connection pooling: reuse requests session
        self._validator = StructuredOutputValidator(debug=debug)

    def enabled(self) -> bool:
        return bool(self.base_url and self.model)

    def _http_session(self) -> requests.Session:
        """Get or create cached requests session (connection pooling)."""
        if self._session is None:
            self._session = requests.Session()
            self._session.timeout = 120  # Default timeout: 120 seconds
        return self._session

    def _write_debug_log(self, event: dict):
        try:
            _OLLAMA_DEBUG_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            payload = dict(event or {})
            payload["logged_at"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
            with _OLLAMA_DEBUG_LOG_FILE.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
        except Exception as exc:
            print(f"[ollama] debug log write failed: {type(exc).__name__}: {exc}")

    def _invoke_endpoint(self, prompt: str, *, max_new_tokens: int = 1500, temperature: float = 0.2, max_retries: int = 3, use_json_schema: bool = True):
        """
        Invoke Ollama endpoint with automatic retry on transient failures.
        
        Args:
            prompt: System prompt for the model
            max_new_tokens: Maximum tokens in response
            temperature: Model temperature (0.0-1.0)
            max_retries: Number of retry attempts (exponential backoff: 1s, 2s, 4s)
            use_json_schema: Ignored for Ollama (parameter kept for API compatibility with SageMaker)
        
        Returns:
            Model response (dict)
        
        Raises:
            ValueError: If Ollama not configured
            Exception: After max_retries exhausted
        """
        if not self.enabled():
            raise ValueError(f"Ollama is not configured. Set OLLAMA_BASE_URL and OLLAMA_MODEL. Currently: base_url={self.base_url}, model={self.model}")

        # Ollama /api/generate endpoint expects prompt in 'prompt' field
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_new_tokens,
            },
        }

        session = self._http_session()
        endpoint_url = f"{self.base_url}/api/generate"
        last_error = None
        
        for attempt in range(max_retries):
            start = time.time()
            print(
                "[ollama] request start "
                f"url={endpoint_url} "
                f"model={self.model} "
                f"prompt_chars={len(prompt)} "
                f"max_new_tokens={max_new_tokens} "
                f"attempt={attempt + 1}/{max_retries}"
            )
            try:
                response = session.post(
                    endpoint_url,
                    json=payload,
                    timeout=120,
                )
                response.raise_for_status()
                decoded = response.json()
                elapsed = time.time() - start
                self._write_debug_log(
                    {
                        "event": "invoke_success",
                        "provider": "ollama",
                        "model": self.model,
                        "endpoint": endpoint_url,
                        "elapsed_seconds": round(elapsed, 3),
                        "attempt": attempt + 1,
                        "request_payload": payload,
                        "raw_response_body": response.text,
                        "decoded_response": decoded,
                    }
                )
                print(f"[ollama] request success model={self.model} elapsed={elapsed:.2f}s attempt={attempt + 1}")
                return decoded
            except Exception as exc:
                elapsed = time.time() - start
                last_error = exc
                is_transient = self._is_transient_error(exc)
                should_retry = is_transient and attempt < max_retries - 1
                
                self._write_debug_log(
                    {
                        "event": "invoke_error",
                        "provider": "ollama",
                        "model": self.model,
                        "endpoint": endpoint_url,
                        "elapsed_seconds": round(elapsed, 3),
                        "attempt": attempt + 1,
                        "is_transient": is_transient,
                        "will_retry": should_retry,
                        "request_payload": payload,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    }
                )
                
                if should_retry:
                    backoff_seconds = 2 ** attempt  # 1s, 2s, 4s
                    print(
                        "[ollama] transient error, retrying in "
                        f"{backoff_seconds}s attempt={attempt + 1}/{max_retries} "
                        f"error={type(exc).__name__}: {exc}"
                    )
                    time.sleep(backoff_seconds)
                else:
                    print(
                        "[ollama] request error (no retry) "
                        f"model={self.model} elapsed={elapsed:.2f}s "
                        f"attempt={attempt + 1}/{max_retries} "
                        f"error={type(exc).__name__}: {exc}"
                    )
                    raise

        # Should not reach here, but just in case
        raise last_error or Exception("Ollama invocation failed after all retries")

    @staticmethod
    def _is_transient_error(exc: Exception) -> bool:
        """
        Check if error is transient (retryable) vs permanent.
        
        Transient errors:
        - ConnectionError (network unavailable)
        - Timeout (request took too long)
        - 5xx errors (server errors)
        
        Permanent errors:
        - 4xx errors (client errors, except 408/429)
        - Invalid model name, etc.
        """
        error_type = type(exc).__name__
        error_msg = str(exc).lower()
        
        transient_types = {
            "ConnectionError",
            "ReadTimeoutError",
            "ConnectTimeoutError",
            "Timeout",
            "TimeoutError",
            "RemoteDisconnected",
            "BrokenPipeError",
        }
        
        if error_type in transient_types:
            return True
        
        # Check for HTTP errors
        if isinstance(exc, requests.HTTPError):
            status_code = exc.response.status_code
            # 5xx errors and 408 (timeout), 429 (too many requests) are transient
            if status_code >= 500 or status_code in (408, 429):
                return True
            # 4xx errors are generally permanent
            return False
        
        # Check error message for transient indicators
        transient_phrases = [
            "connection refused",
            "connection reset",
            "timeout",
            "temporarily",
            "unavailable",
            "service is unavailable",
            "connection error",
            "network unreachable",
        ]
        
        return any(phrase in error_msg for phrase in transient_phrases)

    @staticmethod
    def _extract_generated_text(response) -> str:
        """Extract generated text from Ollama response."""
        if isinstance(response, dict):
            return str(response.get("response", ""))
        return str(response or "")

    def validate_asset_analysis_response(
        self,
        response: Any,
        include_raw_response: bool = False
    ) -> ValidationResult:
        """
        Validate an Ollama response as an asset analysis.
        
        Uses StructuredOutputValidator to:
        1. Extract JSON from response text
        2. Normalize field names
        3. Validate against AssetAnalysisOutput schema
        
        Args:
            response: Ollama response (dict from HTTP POST)
            include_raw_response: Include raw response in result
        
        Returns:
            ValidationResult with either valid AssetAnalysisOutput or per-field errors
        """
        response_text = self._extract_generated_text(response)
        return self._validator.validate_asset_analysis(
            response_text,
            include_raw_response=include_raw_response
        )
    
    def validate_asset_analysis_with_retry(
        self,
        response: Any,
        asset_id: str = "unknown",
        include_raw_response: bool = False
    ) -> ValidationResult:
        """
        Validate asset analysis response with schema-guided retry fallback.
        
        Flow:
        1. Attempt initial validation
        2. If validation fails, optionally retry with schema-guidance prompt
        3. Return best result (initial or retry)
        
        Args:
            response: Ollama response (dict from HTTP POST)
            asset_id: Asset ID for logging
            include_raw_response: Include raw response in result
        
        Returns:
            ValidationResult (either valid or with detailed errors)
        """
        response_text = self._extract_generated_text(response)
        
        # Attempt initial validation
        result = self._validator.validate_asset_analysis(
            response_text,
            include_raw_response=include_raw_response
        )
        
        # If valid, return immediately
        if result.is_valid:
            return result
        
        # Log validation failure for debugging
        error_details = "; ".join([
            f"{err.field}: {err.error_message}" for err in result.errors
        ]) if result.errors else "Unknown validation error"
        
        if self.debug:
            print(f"[ollama] validation failed: asset_id={asset_id} errors={error_details}")
            print(f"[ollama] response_text preview: {response_text[:200]}")
        
        # For now, return the failed result with detailed error info
        return result
