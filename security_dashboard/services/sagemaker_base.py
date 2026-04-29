import ast
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import boto3


_JSON_RE = re.compile(r"(\{.*\}|\[.*\])", re.DOTALL)
_SAGEMAKER_DEBUG_LOG_FILE = Path(__file__).resolve().parents[1] / "data" / "sagemaker_api_debug.jsonl"


def _env(name: str, default: str) -> str:
    return (os.getenv(name) or str(default)).strip()


class SageMakerBaseClient:
    def __init__(self, endpoint_name: str | None = None, region_name: str | None = None):
        self.endpoint_name = endpoint_name or _env("SAGEMAKER_ENDPOINT_NAME", "")
        self.region_name = region_name or _env("AWS_REGION", "")

    def enabled(self) -> bool:
        return bool(self.endpoint_name)

    def _runtime_client(self):
        kwargs: dict[str, Any] = {}
        if self.region_name:
            kwargs["region_name"] = self.region_name
        return boto3.client("sagemaker-runtime", **kwargs)

    def _write_debug_log(self, event: dict):
        try:
            _SAGEMAKER_DEBUG_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            payload = dict(event or {})
            payload["logged_at"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
            with _SAGEMAKER_DEBUG_LOG_FILE.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
        except Exception as exc:
            print(f"[sagemaker] debug log write failed: {type(exc).__name__}: {exc}")

    def _invoke_endpoint(self, prompt: str, *, max_new_tokens: int = 1500, temperature: float = 0.2):
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

        runtime = self._runtime_client()
        start = time.time()
        print(
            "[sagemaker] request start "
            f"endpoint={self.endpoint_name} "
            f"prompt_chars={len(prompt)} "
            f"max_new_tokens={max_new_tokens}"
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
                    "request_payload": payload,
                    "raw_response_body": raw_body,
                    "decoded_response": decoded,
                }
            )
            print(f"[sagemaker] request success endpoint={self.endpoint_name} elapsed={elapsed:.2f}s")
            return decoded
        except Exception as exc:
            elapsed = time.time() - start
            self._write_debug_log(
                {
                    "event": "invoke_error",
                    "endpoint": self.endpoint_name,
                    "elapsed_seconds": round(elapsed, 3),
                    "request_payload": payload,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            )
            print(
                "[sagemaker] request error "
                f"endpoint={self.endpoint_name} elapsed={elapsed:.2f}s error={type(exc).__name__}: {exc}"
            )
            raise

    @staticmethod
    def _extract_generated_text(response) -> str:
        if isinstance(response, list) and response:
            return str(response[0].get("generated_text", ""))
        if isinstance(response, dict):
            return str(response.get("generated_text", ""))
        return str(response or "")

    @staticmethod
    def _extract_json_payload(text: str) -> str:
        if not text:
            return ""
        cleaned = re.sub(r"</?think>", "", text, flags=re.IGNORECASE).strip()
        start = cleaned.find("{")
        end = cleaned.rfind("}") + 1
        if start >= 0 and end > start:
            cleaned = cleaned[start:end]
        cleaned = cleaned.replace("\\n", "").replace("\n", "")
        if '\\"' in cleaned:
            cleaned = cleaned.replace('\\"', '"')
        match = _JSON_RE.search(cleaned)
        return match.group(0).strip() if match else cleaned

    def _parse_json_like(self, response):
        text = response if isinstance(response, str) else self._extract_generated_text(response)
        cleaned = self._extract_json_payload(text)
        try:
            return json.loads(cleaned)
        except Exception:
            try:
                return ast.literal_eval(cleaned)
            except Exception as exc:
                self._write_debug_log(
                    {
                        "event": "parse_error",
                        "endpoint": self.endpoint_name,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                        "raw_text": text,
                        "cleaned_text": cleaned,
                    }
                )
                raise ValueError(f"SageMaker failed to return valid JSON: {exc}") from exc

    def generate_text(self, system_instruction: str, user_prompt: str) -> str:
        prompt = f"{system_instruction}\n\n{user_prompt}"
        response = self._invoke_endpoint(prompt, max_new_tokens=700, temperature=0.2)
        return self._extract_generated_text(response).strip()
