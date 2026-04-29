import json
import time

from security_dashboard.data.datasets import (
    AI_ANALYSIS_COLUMNS,
    compute_asset_fingerprint,
    load_ai_analysis_cache,
    persist_ai_analysis_result,
)

BASE_SYSTEM_PROMPT = (
    "You are a cybersecurity risk analysis engine. "
    "Do not include Reasoning. Do not include <think> tags. "
    "Return ONLY valid JSON. No markdown. No explanation. "
    "Return exactly one JSON object with keys: "
    "asset_name, asset_id, threat_status, severity_validation, priority, "
    "asset_bucket, risk_level, risk_score, anomaly_score, ai_reason, remediation, "
    "tenable_remediation, defender_remediation, splunk_remediation, bigfix_remediation. "
    "Rules: "
    "risk_score and anomaly_score must be integers 0-100. "
    "risk_level must be one of High, Medium, Low and must match risk_score bands: "
    "High=75-100, Medium=45-74, Low=0-44. "
    "Use only provided input data; do not invent facts. "
    "If data is missing, keep conservative scoring and note uncertainty in ai_reason."
)

# Centralized field mapping
FIELD_MAP = {
    "asset_name": ["asset_name", "name", "hostname", "host_name"],
    "asset_id": ["asset_id", "id", "assetId"],
    "threat_status": ["threat_status", "status"],
    "severity_validation": ["severity_validation"],
    "priority": ["priority"],
    "asset_bucket": ["asset_bucket"],
    "risk_level": ["risk_level"],
    "risk_score": ["risk_score"],
    "anomaly_score": ["anomaly_score"],
    "ai_reason": ["ai_reason", "reason", "analysis"],
    "remediation": ["remediation", "recommendation"],
    "tenable_remediation": ["tenable_remediation"],
    "defender_remediation": ["defender_remediation"],
    "splunk_remediation": ["splunk_remediation"],
    "bigfix_remediation": ["bigfix_remediation"],
}


def _get_cached_source(cached: dict) -> str:
    source = str(cached.get("ai_analysis_source") or "").strip().lower()
    if source:
        return source
    return "unknown"


class SageMakerAnalysisMixin:

    @staticmethod
    def _cached_result_for_record(asset_record: dict) -> dict | None:
        cache = load_ai_analysis_cache()
        cached = cache.get(compute_asset_fingerprint(asset_record))
        if not isinstance(cached, dict):
            return None
        return {column: cached.get(column) for column in AI_ANALYSIS_COLUMNS}

    @staticmethod
    def _compact_asset_record(asset_record: dict) -> dict:
        keys = [
            "asset_name", "asset_id", "vuln_name", "vuln_severity",
            "vuln_description", "vuln_fix", "threat_alert",
            "threat_file_path", "threat_process", "threat_impact",
            "threat_fix", "anomaly_event", "anomaly_explanation",
            "source_anomaly_score", "patch_status", "patch_severity",
            "patch_recommendation", "issue_status",
        ]
        return {k: asset_record.get(k, "") for k in keys}

    def _generate_and_parse(self, system_instruction, user_prompt, tokens=1500):
        prompt = f"{system_instruction}\n\n{user_prompt}"
        response = self._invoke_endpoint(prompt, max_new_tokens=tokens, temperature=0.2)
        return self._parse_json_like(response)

    def _extract_fields(self, data: dict) -> dict:
        result = {}
        for key, aliases in FIELD_MAP.items():
            value = None
            for alias in aliases:
                if alias in data:
                    value = data[alias]
                    break
            result[key] = value
        return result

    def _normalize_scores(self, result: dict) -> dict:
        for field in ("risk_score", "anomaly_score"):
            try:
                result[field] = int(float(result[field]))
            except Exception:
                result[field] = None
        return result

    def _normalize_dashboard_row(self, result: dict, record: dict, source: str = "sagemaker") -> dict:
        normalized = self._normalize_scores(result.copy() if isinstance(result, dict) else {})
        normalized.update({
            "asset_name": str(normalized.get("asset_name") or record.get("asset_name") or "").strip(),
            "asset_id": str(normalized.get("asset_id") or record.get("asset_id") or "").strip(),
            "threat_status": str(normalized.get("threat_status") or "Unknown"),
            "severity_validation": str(normalized.get("severity_validation") or "Needs Review"),
            "priority": str(normalized.get("priority") or "Monitor"),
            "asset_bucket": str(normalized.get("asset_bucket") or "Low Risk"),
            "risk_level": str(normalized.get("risk_level") or "Unknown"),
            "ai_reason": str(normalized.get("ai_reason") or ""),
            "remediation": str(normalized.get("remediation") or ""),
            "tenable_remediation": str(normalized.get("tenable_remediation") or ""),
            "defender_remediation": str(normalized.get("defender_remediation") or ""),
            "splunk_remediation": str(normalized.get("splunk_remediation") or ""),
            "bigfix_remediation": str(normalized.get("bigfix_remediation") or ""),
            "ai_analysis_source": str(source or "sagemaker"),
        })
        return normalized

    def _normalize_cached_result(self, cached: dict, record: dict) -> dict:
        result = self._normalize_scores(cached.copy())
        result.update({
            "asset_name": str(result.get("asset_name") or record.get("asset_name") or "").strip(),
            "asset_id": str(result.get("asset_id") or record.get("asset_id") or "").strip(),
            "threat_status": str(result.get("threat_status") or "Unknown"),
            "severity_validation": str(result.get("severity_validation") or "Needs Review"),
            "priority": str(result.get("priority") or "Monitor"),
            "asset_bucket": str(result.get("asset_bucket") or "Low Risk"),
            "risk_level": str(result.get("risk_level") or "Unknown"),
            "ai_reason": str(result.get("ai_reason") or ""),
            "remediation": str(result.get("remediation") or ""),
            "tenable_remediation": str(result.get("tenable_remediation") or ""),
            "defender_remediation": str(result.get("defender_remediation") or ""),
            "splunk_remediation": str(result.get("splunk_remediation") or ""),
            "bigfix_remediation": str(result.get("bigfix_remediation") or ""),
            "ai_analysis_source": str(result.get("ai_analysis_source") or "cache"),
        })
        return result

    def generate_asset_analysis(self, *, asset_record: dict) -> dict:
        if not asset_record:
            raise ValueError("No asset data provided.")

        cached = self._cached_result_for_record(asset_record)
        if cached:
            print(
                "[sagemaker] cache hit "
                f"asset_id={asset_record.get('asset_id')} source={_get_cached_source(cached)}"
            )
            return self._normalize_cached_result(cached, asset_record)

        compact = self._compact_asset_record(asset_record)
        prompt = f"Analyze this asset:\n{json.dumps(compact, separators=(',', ':'))}"
        started = time.time()
        print(
            "[sagemaker] analyze start "
            f"asset_id={asset_record.get('asset_id')} asset_name={asset_record.get('asset_name')}"
        )

        try:
            data = self._generate_and_parse(BASE_SYSTEM_PROMPT, prompt)
        except Exception as e:
            raise ValueError(f"SageMaker analysis failed for asset {asset_record.get('asset_id')}: {e}") from e

        if not isinstance(data, dict):
            raise ValueError(f"SageMaker returned invalid payload type: {type(data)}")
        print(
            "[sagemaker] response received for asset_id="
            f"{data.get('asset_id') or asset_record.get('asset_id')}"
        )

        result = self._extract_fields(data)
        result = self._normalize_scores(result)
        result.update({
            "asset_name": str(result.get("asset_name") or compact["asset_name"]).strip(),
            "asset_id": str(result.get("asset_id") or compact["asset_id"]).strip(),
            "threat_status": str(result.get("threat_status") or "Unknown"),
            "severity_validation": str(result.get("severity_validation") or "Needs Review"),
            "priority": str(result.get("priority") or "Monitor"),
            "asset_bucket": str(result.get("asset_bucket") or "Low Risk"),
            "risk_level": str(result.get("risk_level") or "Unknown"),
            "ai_analysis_source": "sagemaker",
        })

        persist_ai_analysis_result(asset_record, result)
        print(
            "[sagemaker] analyze success "
            f"asset_id={result.get('asset_id')} elapsed={time.time() - started:.2f}s"
        )
        return result

    def generate_dashboard_analysis(self, *, asset_records: list[dict]) -> dict:
        if not asset_records:
            return {"assets": [], "insights": {}}

        all_results: list[dict] = []
        for record in asset_records:
            row_started = time.time()
            print(
                "[sagemaker] batch row start "
                f"asset_id={record.get('asset_id')} asset_name={record.get('asset_name')}"
            )
            raw_flag = record.get("ai_analysis_complete")
            if isinstance(raw_flag, str):
                analysis_complete = raw_flag.strip().lower() == "true"
            else:
                try:
                    analysis_complete = bool(raw_flag)
                except Exception:
                    analysis_complete = False

            cached = self._cached_result_for_record(record)
            if analysis_complete and cached:
                print(
                    "[sagemaker] batch row cache hit "
                    f"asset_id={record.get('asset_id')} source={_get_cached_source(cached)}"
                )
                all_results.append(self._normalize_cached_result(cached, record))
                continue

            compact = self._compact_asset_record(record)
            prompt = f"Analyze this asset:\n{json.dumps(compact, separators=(',', ':'))}"
            try:
                data = self._generate_and_parse(BASE_SYSTEM_PROMPT, prompt, tokens=1500)
            except Exception as e:
                print(
                    "[sagemaker] batch row error "
                    f"asset_id={record.get('asset_id')} elapsed={time.time() - row_started:.2f}s error={e}"
                )
                raise ValueError(f"SageMaker parse failure for asset {record.get('asset_id')}: {e}") from e

            if not isinstance(data, dict):
                raise ValueError(f"Unexpected SageMaker response format for asset {record.get('asset_id')}: {type(data)}")
            print(
                "[sagemaker] response received for asset_id="
                f"{data.get('asset_id') or record.get('asset_id')}"
            )

            result = self._extract_fields(data)
            normalized = self._normalize_dashboard_row(result, record, "sagemaker")
            all_results.append(normalized)
            persist_ai_analysis_result(record, normalized)
            print(
                "[sagemaker] batch row success "
                f"asset_id={normalized.get('asset_id')} elapsed={time.time() - row_started:.2f}s"
            )

        if not all_results:
            raise ValueError("No valid asset analysis returned.")

        return {"assets": all_results, "insights": {}}