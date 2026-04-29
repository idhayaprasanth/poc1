import ast
import json
import os
import re
from typing import Any

import boto3


_JSON_RE = re.compile(r"(\{.*\}|\[.*\])", re.DOTALL)


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
        response = runtime.invoke_endpoint(
            EndpointName=self.endpoint_name,
            ContentType="application/json",
            Body=json.dumps(payload),
        )
        return json.loads(response["Body"].read().decode())

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
                raise ValueError(f"SageMaker failed to return valid JSON: {exc}") from exc

    def generate_text(self, system_instruction: str, user_prompt: str) -> str:
        prompt = f"{system_instruction}\n\n{user_prompt}"
        response = self._invoke_endpoint(prompt, max_new_tokens=700, temperature=0.2)
        return self._extract_generated_text(response).strip()
