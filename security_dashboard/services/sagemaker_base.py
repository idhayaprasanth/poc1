import json
import os
import time
from pathlib import Path
from typing import Any

import boto3

from security_dashboard.services.structured_output_validator import StructuredOutputValidator
from security_dashboard.services.schemas import ValidationResult


_SAGEMAKER_DEBUG_LOG_FILE = Path(__file__).resolve().parents[1] / "data" / "sagemaker_api_debug.jsonl"


def _env(name: str, default: str) -> str:
    return (os.getenv(name) or str(default)).strip()


class SageMakerBaseClient:
    def __init__(self, endpoint_name: str | None = None, region_name: str | None = None, debug: bool = False):
        self.endpoint_name = endpoint_name or _env("SAGEMAKER_ENDPOINT_NAME", "")
        self.region_name = region_name or _env("AWS_REGION", "")
        self.debug = debug
        self._client = None  # Connection pooling: reuse boto3 client
        self._validator = StructuredOutputValidator(debug=debug)

    def enabled(self) -> bool:
        return bool(self.endpoint_name)

    def _runtime_client(self):
        """Get or create cached boto3 client (connection pooling)."""
        if self._client is None:
            kwargs: dict[str, Any] = {}
            if self.region_name:
                kwargs["region_name"] = self.region_name
            self._client = boto3.client("sagemaker-runtime", **kwargs)
        return self._client

    def _write_debug_log(self, event: dict):
        try:
            _SAGEMAKER_DEBUG_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            payload = dict(event or {})
            payload["logged_at"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
            with _SAGEMAKER_DEBUG_LOG_FILE.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
        except Exception as exc:
            print(f"[sagemaker] debug log write failed: {type(exc).__name__}: {exc}")

    def _invoke_endpoint(self, prompt: str, *, max_new_tokens: int = 1500, temperature: float = 0.2, max_retries: int = 3, use_json_schema: bool = True):
        """
        Invoke SageMaker endpoint with automatic retry on transient failures.
        
        Args:
            prompt: System prompt for the model
            max_new_tokens: Maximum tokens in response
            temperature: Model temperature (0.0-1.0)
            max_retries: Number of retry attempts (exponential backoff: 1s, 2s, 4s)
            use_json_schema: Whether to use TGI JSON schema constraint (enforces valid JSON at generation time)
        
        Returns:
            Model response (dict)
        
        Raises:
            ValueError: If endpoint not configured
            Exception: After max_retries exhausted
        """
        if not self.enabled():
            raise ValueError("SageMaker endpoint is not configured. Set SAGEMAKER_ENDPOINT_NAME.")

        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": max_new_tokens,
                "temperature": temperature,
                "return_full_text": False,
            },
        }
        
        # Add TGI JSON schema constraint if supported (enforces JSON-only output at generation)
        if use_json_schema:
            # TGI supports grammar-based constraints; a simple JSON schema constraint
            # tells the model to only generate valid JSON objects
            payload["parameters"]["schema"] = {
                "type": "object",
                "properties": {
                    "asset_name": {"type": "string"},
                    "asset_id": {"type": "string"},
                    "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
                    "anomaly_score": {"type": "integer", "minimum": 0, "maximum": 100},
                    "priority": {"type": "integer", "minimum": 1, "maximum": 5},
                    "risk_level": {"type": "string", "enum": ["High", "Medium", "Low"]},
                    "threat_status": {"type": "string"},
                    "severity_validation": {"type": "string"},
                    "asset_bucket": {"type": "string"},
                    "ai_reason": {"type": "string"},
                    "remediation": {"type": "string"},
                    "tenable_remediation": {"type": "string"},
                    "defender_remediation": {"type": "string"},
                    "splunk_remediation": {"type": "string"},
                    "bigfix_remediation": {"type": "string"},
                    "ai_analysis_source": {"type": "string"},
                },
                "required": ["asset_id", "risk_score", "priority", "risk_level"],
            }

        runtime = self._runtime_client()
        last_error = None
        
        for attempt in range(max_retries):
            start = time.time()
            schema_info = " with JSON schema constraint" if use_json_schema else ""
            print(
                "[sagemaker] request start "
                f"endpoint={self.endpoint_name} "
                f"prompt_chars={len(prompt)} "
                f"max_new_tokens={max_new_tokens} "
                f"attempt={attempt + 1}/{max_retries}{schema_info}"
            )
            try:
                response = runtime.invoke_endpoint(
                    EndpointName=self.endpoint_name,
                    ContentType="application/json",
                    Body=json.dumps(payload),
                )
                raw_body = response["Body"].read().decode()
                decoded = json.loads(raw_body)
                elapsed = time.time() - start
                self._write_debug_log(
                    {
                        "event": "invoke_success",
                        "endpoint": self.endpoint_name,
                        "elapsed_seconds": round(elapsed, 3),
                        "attempt": attempt + 1,
                        "request_payload": payload,
                        "raw_response_body": raw_body,
                        "decoded_response": decoded,
                    }
                )
                print(f"[sagemaker] request success endpoint={self.endpoint_name} elapsed={elapsed:.2f}s attempt={attempt + 1}")
                return decoded
            except Exception as exc:
                elapsed = time.time() - start
                last_error = exc
                is_transient = self._is_transient_error(exc)
                should_retry = is_transient and attempt < max_retries - 1
                
                self._write_debug_log(
                    {
                        "event": "invoke_error",
                        "endpoint": self.endpoint_name,
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
                        "[sagemaker] transient error, retrying in "
                        f"{backoff_seconds}s attempt={attempt + 1}/{max_retries} "
                        f"error={type(exc).__name__}: {exc}"
                    )
                    time.sleep(backoff_seconds)
                else:
                    print(
                        "[sagemaker] request error (no retry) "
                        f"endpoint={self.endpoint_name} elapsed={elapsed:.2f}s "
                        f"attempt={attempt + 1}/{max_retries} "
                        f"error={type(exc).__name__}: {exc}"
                    )
                    raise

        # Should not reach here, but just in case
        raise last_error or Exception("SageMaker invocation failed after all retries")

    @staticmethod
    def _is_transient_error(exc: Exception) -> bool:
        """
        Check if error is transient (retryable) vs permanent.
        
        Transient errors:
        - ThrottlingException (rate limit)
        - ReadTimeoutError (network timeout)
        - ServiceUnavailableException (endpoint temporarily down)
        
        Permanent errors:
        - EndpointNotFound, ValidationException, etc.
        """
        error_type = type(exc).__name__
        error_msg = str(exc).lower()
        
        transient_types = {
            "ThrottlingException",
            "ReadTimeoutError",
            "ConnectTimeoutError",
            "ServiceUnavailableException",
            "InternalServerError",
            "TimeoutError",
        }
        
        if error_type in transient_types:
            return True
        
        # Check error message for transient indicators
        transient_phrases = [
            "rate exceeded",
            "throttled",
            "timeout",
            "temporarily",
            "unavailable",
            "service is unavailable",
        ]
        
        return any(phrase in error_msg for phrase in transient_phrases)

    @staticmethod
    def _extract_generated_text(response) -> str:
        """Extract generated text from SageMaker response."""
        if isinstance(response, list) and response:
            return str(response[0].get("generated_text", ""))
        if isinstance(response, dict):
            return str(response.get("generated_text", ""))
        return str(response or "")

    def validate_asset_analysis_response(
        self,
        response: Any,
        include_raw_response: bool = False
    ) -> ValidationResult:
        """
        Validate a SageMaker response as an asset analysis.
        
        Uses StructuredOutputValidator to:
        1. Extract JSON from response text
        2. Normalize field names
        3. Validate against AssetAnalysisOutput schema
        
        Args:
            response: SageMaker response (dict from boto3)
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
            response: SageMaker response (dict from boto3)
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
            print(f"[sagemaker] validation failed: asset_id={asset_id} errors={error_details}")
            print(f"[sagemaker] response_text preview: {response_text[:200]}")
        
        # For now, return the failed result with detailed error info
        # Future: implement retry with schema-guidance prompt if needed
        return result
    
    def validate_chatbot_response(
        self,
        response_dict: dict,
        include_raw_response: bool = False
    ) -> ValidationResult:
        """
        Validate a SageMaker response as a chatbot response.
        
        Args:
            response_dict: Parsed response dictionary
            include_raw_response: Include raw response in result
        
        Returns:
            ValidationResult with either valid ChatbotResponse or errors
        """
        return self._validator.validate_chatbot_response(
            response_dict,
            include_raw_response=include_raw_response
        )
    
    def generate_text(self, system_instruction: str, user_prompt: str) -> str:
        """
        Generate text using SageMaker endpoint (simple text generation).
        
        Used for chatbot responses without structured validation.
        
        Args:
            system_instruction: System prompt
            user_prompt: User input
        
        Returns:
            Generated text response
        """
        prompt = f"{system_instruction}\n\n{user_prompt}"
        response = self._invoke_endpoint(prompt, max_new_tokens=700, temperature=0.2)
        return self._extract_generated_text(response).strip()
