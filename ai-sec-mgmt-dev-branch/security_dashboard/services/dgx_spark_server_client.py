import json
import logging
import math
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from datetime import datetime
from pathlib import Path

import requests
from requests.exceptions import RequestException

SOURCES = ["tenable", "splunk"]
PRIORITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
RISK_LEVEL_BY_PRIORITY = {
    "Critical": "High",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
}
ASSET_BUCKET_BY_RISK = {
    "High": "High Risk",
    "Medium": "Medium Risk",
    "Low": "Low Risk",
}
PRIORITY_BY_RISK = {
    "High": "Immediate",
    "Medium": "Planned",
    "Low": "Monitor",
}
CHAT_SYSTEM_PROMPT = (
    "You are a cybersecurity assistant. Answer only security-related questions. "
    "Use the provided context, stay concise, and do not invent data."
)
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[0;36m"
YELLOW = "\033[0;33m"
GREEN = "\033[0;32m"
RED = "\033[0;31m"
PRIORITY_COLOR = {
    "Critical": "\033[1;31m",
    "High": "\033[0;31m",
    "Medium": "\033[0;33m",
    "Low": "\033[0;32m",
}
ANALYSIS_SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. Analyse the vulnerability and log data and return "
    "ONLY a valid JSON object - no markdown, no code fences, no explanation, "
    "All risk scores must be a float between 0.0 and 10.0.\n"
    "3. Priority level must match risk score exactly:\n"
    "   Critical = score >= 9.0\n"
    "   High     = score >= 7.0 and < 9.0\n"
    "   Medium   = score >= 4.0 and < 7.0\n"
    "   Low      = score < 4.0\n"
    "no preamble, and do not repeat the response.\n\n"
    "Required JSON structure:\n"
    "{\n"
    '  "host_name": "<hostname>",\n'
    '  "tenable":  {"risk_score": <0-10 float>, "priority_level": "<Critical|High|Medium|Low>", "remediation": "<concise action>"},\n'
    '  "splunk":   {"risk_score": <0-10 float>, "priority_level": "<Critical|High|Medium|Low>", "remediation": "<concise action>"},\n'
    '  "overall_risk_score": <0-10 float>,\n'
    '  "overall_priority_level": "<Critical|High|Medium|Low>",\n'
    '  "ai_summary": "<2-3 sentence executive summary of the asset security posture and recommended next steps>"\n'
    "}"
)
SECURITY_KEYWORDS = tuple(
    keyword.lower()
    for keyword in [
        "security", "cyber", "cybersecurity", "infosec", "vulnerability", "vuln",
        "cve", "risk", "threat", "incident", "malware", "ransomware", "phishing",
        "exploit", "patch", "edr", "siem", "soc", "ids", "ips", "waf", "firewall",
        "splunk", "tenable", "defender", "bigfix", "ioc", "attack", "breach",
        "mitre", "tactic", "remediation", "remediate", "severity", "critical",
        "high", "medium", "low", "asset", "hostname", "server", "virus",
        "antivirus", "secure", "protect", "endpoint", "windows defender",
    ]
)


class DGXSparkServerInvocationError(Exception):
    pass


def is_security_question(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return any(keyword in lowered for keyword in SECURITY_KEYWORDS)


def get_dgx_spark_server_status() -> dict[str, Any]:
    endpoint_name = str(os.getenv("DGX_SPARK_SERVER_ENDPOINT_NAME", "")).strip()
    endpoint_url = (
        str(os.getenv("DGX_SPARK_SERVER_ENDPOINT_URL", "")).strip()
        or endpoint_name
    )
    return {
        "configured": bool(endpoint_url),
        "endpoint_name": endpoint_url,
        "region": str(os.getenv("AWS_REGION", "us-gov-west-1")).strip() or "us-gov-west-1",
    }


class DGXSparkServerClient:
    def __init__(self):
        endpoint_name = str(os.getenv("DGX_SPARK_SERVER_ENDPOINT_NAME", "")).strip()
        endpoint_url = (
            str(os.getenv("DGX_SPARK_SERVER_ENDPOINT_URL", "")).strip()
            or endpoint_name
        )
        self.endpoint_name = endpoint_url
        self.endpoint_label = (
            str(os.getenv("DGX_SPARK_SERVER_ENDPOINT_LABEL", "")).strip()
            or self.endpoint_name
            or "dgx-spark-server"
        )
        self.max_new_tokens = self._env_int("DGX_SPARK_SERVER_MAX_NEW_TOKENS", 1000)
        self.temperature = self._env_float("DGX_SPARK_SERVER_TEMPERATURE", 0.01)
        self.read_timeout = self._env_int("DGX_SPARK_SERVER_READ_TIMEOUT_SECONDS", 300)
        self.connect_timeout = self._env_int("DGX_SPARK_SERVER_CONNECT_TIMEOUT_SECONDS", 60)
        self.raw_log_path = (
            Path(__file__).resolve().parents[1] / "data" / "raw_llm_responses.txt"
        )
        self._log_lock = threading.Lock()

    @staticmethod
    def _env_int(name: str, default: int) -> int:
        try:
            return int(str(os.getenv(name, default)).strip())
        except Exception:
            return int(default)

    @staticmethod
    def _env_float(name: str, default: float) -> float:
        try:
            return float(str(os.getenv(name, default)).strip())
        except Exception:
            return float(default)

    def enabled(self) -> bool:
        return bool(self.endpoint_name)

    @staticmethod
    def _safe_score(src_dict: dict | None) -> float:
        value = (src_dict or {}).get("risk_score")
        try:
            return float(value) if value is not None else 0.0
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _normalize_score(value: str | int | float | None) -> float | None:
        if value is None:
            return None

        if isinstance(value, (int, float)):
            try:
                normalized = float(value)
            except (TypeError, ValueError):
                return None
        else:
            text = str(value).strip()
            if "/" in text:
                parts = [part.strip() for part in text.split("/", 1)]
                try:
                    numerator = float(parts[0])
                except ValueError:
                    return None
                denominator = 10.0
                if len(parts) > 1 and parts[1]:
                    try:
                        denominator = float(parts[1])
                    except ValueError:
                        denominator = 10.0
                if denominator == 0:
                    return None
                normalized = numerator if denominator == 10.0 else (numerator / denominator) * 10.0
            else:
                try:
                    normalized = float(text)
                except ValueError:
                    match = re.search(r"[-+]?[0-9]*\.?[0-9]+", text)
                    if not match:
                        return None
                    normalized = float(match.group(0))

        if not math.isfinite(normalized):
            return None
        return max(0.0, min(normalized, 10.0))

    def _build_asset_payload(self, record: dict) -> dict:
        tenable_data = record.get("tenable_raw", [])
        splunk_data = record.get("splunk_raw", [])
        
        if isinstance(tenable_data, str):
            try:
                tenable_data = json.loads(tenable_data)
            except Exception:
                tenable_data = []
        if isinstance(splunk_data, str):
            try:
                splunk_data = json.loads(splunk_data)
            except Exception:
                splunk_data = []
                
        payload = {
            "host_name": record.get("asset_name"),
            "sources": {
                "tenable": tenable_data,
                "splunk": splunk_data
            }
        }
        return payload

    @staticmethod
    def _build_analysis_prompt(payload: dict) -> str:
        return (
            f"Analyse the vulnerability data for asset '{payload['asset_id']}' "
            f"collected from four security tools:\n\n"
            f"{json.dumps(payload, indent=2)}\n\n"
            "Return ONLY the JSON object once. No markdown fences, no repetition, no extra text."
        )

    def log_raw_response(self, *, asset_id: str, raw_text: str, status: str = "OK") -> None:
        self.raw_log_path.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        separator = "=" * 80
        entry = (
            f"\n{separator}\n"
            f"ASSET       : {asset_id}\n"
            f"MODEL       : {self.endpoint_label}\n"
            f"ENDPOINT    : {self.endpoint_name}\n"
            f"TIMESTAMP   : {timestamp}\n"
            f"STATUS      : {status}\n"
            f"{'-' * 80}\n"
            f"{raw_text}\n"
            f"{separator}\n"
        )
        with self._log_lock:
            with self.raw_log_path.open("a", encoding="utf-8") as handle:
                handle.write(entry)

    @staticmethod
    def _priority_text(level: str) -> str:
        level = str(level or "N/A")
        return f"{PRIORITY_COLOR.get(level, '')}{level}{RESET}" if level in PRIORITY_COLOR else level

    @staticmethod
    def _wrap_text(text: str, width: int = 70, indent: str = "      ") -> str:
        text = str(text or "")
        words = text.split()
        if not words:
            return indent
        lines = []
        line = indent
        for word in words:
            candidate = f"{line} {word}" if line.strip() else f"{indent}{word}"
            if len(candidate) > width and line.strip():
                lines.append(line)
                line = f"{indent}{word}"
            else:
                line = candidate
        lines.append(line)
        return "\n".join(lines)

    def _print_result(self, *, asset_id: str, result: dict) -> None:
        overall_score = self._safe_score({"risk_score": result.get("overall_risk_score")})
        overall_priority = str(result.get("overall_priority_level") or "Low")
        print(f"\n  {BOLD}{'-' * 68}{RESET}")
        print(f"  {BOLD}ASSET    :{RESET} {CYAN}{asset_id}{RESET}")
        print(f"  {BOLD}MODEL    :{RESET} {CYAN}{self.endpoint_label}{RESET}")
        print(
            f"  {BOLD}OVERALL  :{RESET} Risk Score {BOLD}{overall_score}{RESET}   "
            f"Priority {self._priority_text(overall_priority)}"
        )
        print(f"  {'-' * 68}")

        for source in SOURCES:
            src_result = result.get(source) or {}
            if not src_result:
                continue
            score = self._safe_score(src_result)
            priority = str(src_result.get("priority_level") or "N/A")
            remediation = str(src_result.get("remediation") or "N/A")
            print(
                f"  {YELLOW}{source.upper():<10}{RESET}  "
                f"Score: {BOLD}{score:<5}{RESET}  "
                f"Priority: {self._priority_text(priority)}"
            )
            print(self._wrap_text(remediation, width=72, indent="    -> "))
            print()

        print(f"  {BOLD}AI SUMMARY{RESET}")
        print(self._wrap_text(str(result.get('ai_summary') or ""), width=72, indent="  "))

    def _print_asset_start(self, asset_id: str) -> None:
        width = 72
        print(f"\n\n{'#' * width}")
        print(f"  ASSET: {BOLD}{CYAN}{asset_id}{RESET}")
        print(f"{'#' * width}")

    def _print_query_start(self) -> None:
        print(f"\n  Querying {CYAN}{self.endpoint_label}{RESET}...", end="", flush=True)

    @staticmethod
    def _print_query_success() -> None:
        print(f"  {GREEN}OK{RESET}")

    @staticmethod
    def _print_query_error(label: str, message: str) -> None:
        print(f"  {RED}{label}{RESET}")
        if message:
            print(f"  {message}")

    def _invoke_endpoint(self, *, system_prompt: str, user_prompt: str, expect_json: bool) -> str:
        # payload = {
        #     "inputs": (
        #         f"<|system|>\n{system_prompt}\n"
        #         f"<|user|>\n{user_prompt}\n"
        #         "<|assistant|>"
        #     ),
        #     "parameters": {
        #         "max_new_tokens": self.max_new_tokens,
        #         "temperature": self.temperature,
        #         "do_sample": False,
        #         "return_full_text": False,
        #     },
        # }
        payload = {
        "model": "meta-llama/Llama-3.1-8B-Instruct",
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            }
        ],
        "max_tokens": 300,
        "temperature": 0.1
    }

        try:
            response = requests.post(
                self.endpoint_name,
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=(self.connect_timeout, self.read_timeout),
            )
            response.raise_for_status()
        except RequestException as exc:
            raise DGXSparkServerInvocationError(str(exc)) from exc

        raw = response.text

        try:
            parsed = response.json()
        except ValueError:
            parsed = None

        if parsed is None:
            return raw.strip()

        if isinstance(parsed, list) and parsed:
            first = parsed[0]
            if isinstance(first, dict) and "generated_text" in first:
                generated = first.get("generated_text", raw)
                return generated.strip() if isinstance(generated, str) else raw.strip()
            return json.dumps(parsed) if expect_json else raw.strip()

        if isinstance(parsed, dict):
            if "choices" in parsed and parsed["choices"]:
                choice = parsed["choices"][0]
                if isinstance(choice, dict):
                    if "message" in choice and isinstance(choice["message"], dict):
                        generated = choice["message"].get("content", raw)
                        return generated.strip() if isinstance(generated, str) else raw.strip()
                    generated = choice.get("text", raw)
                    return generated.strip() if isinstance(generated, str) else raw.strip()
            if "generated_text" in parsed:
                generated = parsed.get("generated_text", raw)
                return generated.strip() if isinstance(generated, str) else raw.strip()

        return json.dumps(parsed) if expect_json else raw.strip()

    def _extract_analysis_json(self, text: str) -> dict:
        text = re.sub(r"```(?:json)?\s*", "", text).strip()

        depth = 0
        in_object = False
        for index, char in enumerate(text):
            if char == "{":
                depth += 1
                in_object = True
            elif char == "}":
                depth -= 1
                if in_object and depth == 0:
                    text = text[: index + 1]
                    break
        text = text.strip()

        def derive_overall(result: dict) -> dict:
            # Preserve the model's output without synthesizing or defaulting values.
            # Coerce only per-source numeric risk_score values when present.
            for source in SOURCES:
                src = result.get(source)
                if isinstance(src, dict) and "risk_score" in src:
                    src["risk_score"] = self._normalize_score(src.get("risk_score"))
            # Normalize overall_risk_score to 0-10 and preserve None if invalid.
            if "overall_risk_score" in result and result["overall_risk_score"] is not None:
                result["overall_risk_score"] = self._normalize_score(result["overall_risk_score"])
            # Do not set or infer overall_priority_level or other fields; return as provided.
            return result

        array_start = text.find("[")
        object_start = text.find("{")

        if array_start != -1 and (object_start == -1 or array_start < object_start):
            array_end = text.rfind("]") + 1
            if array_end > 0:
                try:
                    items = json.loads(text[array_start:array_end])
                    if isinstance(items, list) and items:
                        first = items[0]
                        if isinstance(first, dict) and any(key in first for key in SOURCES):
                            return derive_overall(first)
                except (json.JSONDecodeError, IndexError, KeyError):
                    pass

        if object_start != -1:
            object_end = text.rfind("}") + 1
            if object_end > 0:
                try:
                    parsed = json.loads(text[object_start:object_end])
                    if isinstance(parsed, dict):
                        return derive_overall(parsed)
                except json.JSONDecodeError:
                    pass

        raise ValueError("No parseable JSON found in model output")

    def _normalize_analysis_result(self, *, record: dict, result: dict) -> dict:
        def get_src_score(src_key: str):
            src = result.get(src_key) or {}
            return self._normalize_score(src.get("risk_score"))

        def get_value(*keys: str):
            for key in keys:
                value = result.get(key)
                if value is not None:
                    return value
            return None

        risk_level = get_value("risk_level", "riskLevel", "risk level", "overall_priority_level", "overallPriorityLevel", "priority_level")
        asset_bucket = get_value("asset_bucket", "assetBucket", "asset bucket")
        overall_risk_score = self._normalize_score(get_value("overall_risk_score", "overallRiskScore", "risk_score"))
        overall_priority = get_value("overall_priority_level", "overallPriorityLevel", "priority_level")
        ai_summary = get_value("ai_summary", "summary", "aiSummary")

        if asset_bucket is None and isinstance(risk_level, str) and risk_level.strip():
            normalized_asset_bucket = f"{risk_level.strip().title()} Risk"
        elif asset_bucket is None and isinstance(overall_priority, str) and overall_priority.strip():
            normalized_asset_bucket = f"{overall_priority.strip().title()} Risk"
        else:
            normalized_asset_bucket = asset_bucket

        normalized = {
            "asset_name": str(record.get("asset_name") or record.get("asset_id") or "").strip(),
            "asset_id": str(record.get("asset_id") or "").strip(),
            "threat_status": overall_priority,
            "severity_validation": None,
            "priority": overall_priority,
            "asset_bucket": normalized_asset_bucket,
            "risk_level": risk_level,
            "risk_score": overall_risk_score,
            "overall_priority_level": overall_priority,
            "anomaly_score": get_src_score("splunk"),
            "ai_reason": ai_summary,
            "remediation": (result.get("tenable") or {}).get("remediation") or (result.get("splunk") or {}).get("remediation") or get_value("remediation"),
            "tenable_remediation": (result.get("tenable") or {}).get("remediation"),
            "splunk_remediation": (result.get("splunk") or {}).get("remediation"),
            "tenable_risk_score": get_src_score("tenable"),
            "tenable_priority_level": (result.get("tenable") or {}).get("priority_level"),
            "splunk_risk_score": get_src_score("splunk"),
            "splunk_priority_level": (result.get("splunk") or {}).get("priority_level"),
            "ai_analysis_source": "dgx_spark_server",
        }
        return normalized

    def generate_asset_analysis(self, *, asset_record: dict) -> dict:
        if not asset_record:
            raise ValueError("No asset data provided.")

        if not self.enabled():
            raise DGXSparkServerInvocationError(
                "Model endpoint is not configured. Set DGX_SPARK_SERVER_ENDPOINT_NAME or DGX_SPARK_SERVER_ENDPOINT_URL."
            )

        payload = self._build_asset_payload(asset_record)
        prompt = self._build_analysis_prompt(payload)
        asset_id = str(asset_record.get("asset_id") or asset_record.get("asset_name") or "").strip()
        self._print_asset_start(asset_id)
        self._print_query_start()
        raw_text = None
        try:
            raw_text = self._invoke_endpoint(
                system_prompt=ANALYSIS_SYSTEM_PROMPT,
                user_prompt=prompt,
                expect_json=True,
            )
            parsed = self._extract_analysis_json(raw_text)
            self.log_raw_response(asset_id=asset_id, raw_text=raw_text, status="OK")
            self._print_query_success()
            self._print_result(asset_id=asset_id, result=parsed)
        except DGXSparkServerInvocationError as exc:
            self.log_raw_response(
                asset_id=asset_id,
                raw_text=raw_text if raw_text is not None else "[No response captured]",
                status="dgx_ERROR",
            )
            self._print_query_error("dgx ERROR", str(exc))
            raise
        except (ValueError, json.JSONDecodeError) as exc:
            self.log_raw_response(
                asset_id=asset_id,
                raw_text=raw_text if raw_text is not None else "[No response captured]",
                status="PARSE_ERROR",
            )
            self._print_query_error("PARSE ERROR", str(exc))
            raise
        except Exception:
            self.log_raw_response(
                asset_id=asset_id,
                raw_text=raw_text if raw_text is not None else "[No response captured]",
                status="ERROR",
            )
            raise
        normalized = self._normalize_analysis_result(record=asset_record, result=parsed)
        return normalized

    def generate_dashboard_analysis(self, *, asset_records: list[dict]) -> dict:
        if not asset_records:
            return {"assets": [], "insights": {}}

        max_workers = min(4, len(asset_records))
        assets = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_record = {
                executor.submit(self.generate_asset_analysis, asset_record=record): record
                for record in asset_records
            }
            for future in as_completed(future_to_record):
                try:
                    asset_result = future.result()
                    assets.append(asset_result)
                except Exception as exc:
                    logging.exception("Asset analysis failed for a record during parallel processing")
        return {"assets": assets, "insights": {}}

    def generate_security_answer(
        self,
        *,
        question: str,
        context_text: str,
        history: list[dict] | None = None,
    ) -> str:
        if not self.enabled():
            return "Model endpoint is not configured. Set DGX_SPARK_SERVER_ENDPOINT_NAME or DGX_SPARK_SERVER_ENDPOINT_URL."

        if not is_security_question(question):
            return "Ask a cybersecurity-related question."

        transcript = []
        for item in (history or [])[-6:]:
            role = "Assistant" if item.get("role") in ("assistant", "model") else "User"
            text = str(item.get("text") or "").strip()
            if text:
                transcript.append(f"{role}: {text}")

        prior_history = "\n".join(transcript) if transcript else "No prior chat history."
        user_prompt = (
            f"Context:\n{context_text}\n\n"
            f"Conversation so far:\n{prior_history}\n\n"
            f"Question:\n{question}\n\n"
            "Answer as a cybersecurity assistant in plain text."
        )

        try:
            return self._invoke_endpoint(
                system_prompt=CHAT_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                expect_json=False,
            )
        except DGXSparkServerInvocationError as exc:
            return f"AI response unavailable: {exc}"
