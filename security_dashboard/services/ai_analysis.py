
import json

from security_dashboard.data.datasets import (
    AI_ANALYSIS_COLUMNS,
    compute_asset_fingerprint,
    load_ai_analysis_cache,
    persist_ai_analysis_result,
)
from security_dashboard.services.gemini_base import (
    GeminiRateLimitError,
    _TruncatedResponseError,
    get_gemini_pause_status,
    _is_truncated_json,
)

# Compact system prompt (token optimized)
BASE_SYSTEM_PROMPT = (
    "Return ONLY valid JSON. No extra text. "
    "Use only given data. "
    "Fields: asset_name, asset_id, threat_status, severity_validation, priority, "
    "asset_bucket, risk_level, risk_score, anomaly_score, ai_reason, remediation, "
    "tenable_remediation, defender_remediation, splunk_remediation, bigfix_remediation. "
    "Scores must be integers 0-100."
)

BATCH_SYSTEM_PROMPT = (
    BASE_SYSTEM_PROMPT
    + " For multi-asset input, return a JSON object with key 'assets' as an array."
    + " Return one analysis object per provided input asset."
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


def generate_local_asset_analysis(*, asset_record: dict) -> dict:
    """Deterministic local fallback when Gemini is unavailable or paused."""
    asset_record = asset_record or {}

    vuln_severity = str(asset_record.get("vuln_severity") or "").strip().lower()
    patch_status = str(asset_record.get("patch_status") or "").strip().lower()
    patch_severity = str(asset_record.get("patch_severity") or "").strip().lower()
    issue_status = str(asset_record.get("issue_status") or "Open").strip().lower()
    threat_alert = str(asset_record.get("threat_alert") or "").strip()
    threat_impact = str(asset_record.get("threat_impact") or "").strip()
    anomaly_event = str(asset_record.get("anomaly_event") or "").strip()
    anomaly_explanation = str(asset_record.get("anomaly_explanation") or "").strip()
    threat_blob = f"{threat_alert} {threat_impact}".lower()
    anomaly_blob = f"{anomaly_event} {anomaly_explanation}".lower()

    severity_score = {
        "critical": 92,
        "high": 78,
        "medium": 55,
        "low": 28,
    }.get(vuln_severity, 20)
    patch_score = {
        "critical": 18,
        "high": 12,
        "medium": 7,
        "low": 3,
    }.get(patch_severity, 0)
    if patch_status == "missing":
        patch_score += 10
    elif patch_status == "pending":
        patch_score += 5

    threat_score = 0
    if threat_alert:
        threat_score = 40
    if any(term in threat_blob for term in ("emotet", "trojan", "ransomware", "malware", "c2", "command-and-control")):
        threat_score = max(threat_score, 48)

    try:
        source_anomaly_score = int(float(asset_record.get("source_anomaly_score") or 0))
    except Exception:
        source_anomaly_score = 0
    source_anomaly_score = max(0, min(source_anomaly_score, 100))
    anomaly_bonus = 0
    if any(term in anomaly_blob for term in ("known command-and-control", "data exfiltration", "unusual outbound", "dns queries")):
        anomaly_bonus = 10
    anomaly_score = max(source_anomaly_score, min(100, source_anomaly_score + anomaly_bonus))

    issue_bonus = 6 if issue_status in {"open", "in progress"} else 0
    risk_score = min(
        100,
        int(round(severity_score * 0.45 + anomaly_score * 0.25 + threat_score * 0.20 + patch_score + issue_bonus)),
    )

    if risk_score >= 75:
        risk_level = "High"
        asset_bucket = "High Risk"
        priority = "Immediate"
    elif risk_score >= 45:
        risk_level = "Medium"
        asset_bucket = "Medium Risk"
        priority = "Planned"
    elif risk_score <= 15 and not threat_alert and patch_status not in {"missing", "pending"}:
        risk_level = "Low"
        asset_bucket = "All Good"
        priority = "Monitor"
    else:
        risk_level = "Low"
        asset_bucket = "Low Risk"
        priority = "Monitor"

    if threat_alert:
        threat_status = "True Positive" if threat_score >= 40 or anomaly_score >= 70 else "Needs Investigation"
    else:
        threat_status = "No Active Threat Observed"

    if vuln_severity in {"critical", "high"} and risk_level == "High":
        severity_validation = "Severity aligns with observed exposure"
    elif vuln_severity in {"critical", "high", "medium"}:
        severity_validation = "Severity partially supported by current signals"
    else:
        severity_validation = "Severity appears limited based on current signals"

    reasons = []
    if vuln_severity:
        reasons.append(f"{vuln_severity.title()} vulnerability exposure")
    if threat_alert:
        reasons.append(f"active alert: {threat_alert}")
    if source_anomaly_score:
        reasons.append(f"anomaly score {source_anomaly_score}/100")
    if patch_status in {"missing", "pending"}:
        reasons.append(f"patch status is {patch_status}")
    if not reasons:
        reasons.append("limited risk indicators in the current merged dataset")
    ai_reason = (
        "Local fallback assessment used because Gemini was unavailable. "
        + "; ".join(reasons[:4])
        + "."
    )

    remediation_parts = []
    for key in ("vuln_fix", "threat_fix", "patch_recommendation"):
        value = str(asset_record.get(key) or "").strip()
        if value and value not in remediation_parts:
            remediation_parts.append(value)
    if not remediation_parts:
        remediation_parts.append("Review the host, validate exposure, and apply standard hardening controls.")
    remediation = " ".join(remediation_parts[:3])

    return {
        "asset_name": str(asset_record.get("asset_name") or "").strip(),
        "asset_id": str(asset_record.get("asset_id") or "").strip(),
        "threat_status": threat_status,
        "severity_validation": severity_validation,
        "priority": priority,
        "asset_bucket": asset_bucket,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "anomaly_score": anomaly_score,
        "ai_reason": ai_reason,
        "remediation": remediation,
        "tenable_remediation": str(asset_record.get("vuln_fix") or remediation).strip(),
        "defender_remediation": str(asset_record.get("threat_fix") or remediation).strip(),
        "splunk_remediation": "Investigate suspicious log activity and validate whether containment is needed.",
        "bigfix_remediation": str(asset_record.get("patch_recommendation") or remediation).strip(),
        "ai_analysis_source": "local_fallback",
    }


class GeminiAnalysisMixin:
    @staticmethod
    def _cached_result_for_record(asset_record: dict) -> dict | None:
        """Return cached AI analysis for a source record when available."""
        cache = load_ai_analysis_cache()
        cached = cache.get(compute_asset_fingerprint(asset_record))
        if not isinstance(cached, dict):
            return None
        return {column: cached.get(column) for column in AI_ANALYSIS_COLUMNS}

    @staticmethod
    def _compact_asset_record(asset_record: dict) -> dict:
        """Reduce payload size before sending to Gemini."""
        keys = [
            "asset_name", "asset_id", "vuln_name", "vuln_severity",
            "vuln_description", "vuln_fix", "threat_alert",
            "threat_file_path", "threat_process", "threat_impact",
            "threat_fix", "anomaly_event", "anomaly_explanation",
            "source_anomaly_score", "patch_status", "patch_severity",
            "patch_recommendation", "issue_status",
        ]
        return {k: asset_record.get(k, "") for k in keys}

    # Unified Gemini call
    def _generate_and_parse(self, system_instruction, user_prompt, tokens=800):
        for budget in (tokens, 1500):
            payload = {
                "system_instruction": {"parts": [{"text": system_instruction}]},
                "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
                "generationConfig": {
                    "temperature": 0.0,
                    "maxOutputTokens": budget,
                    "responseMimeType": "application/json",
                },
            }

            for api_version in self._preferred_versions():
                for model_name in self._preferred_models():
                    try:
                        text, ok = self._attempt(
                            api_version=api_version,
                            model_name=model_name,
                            payload=payload,
                        )
                        if ok:
                            extracted = self._extract_json_payload(text)
                            if not _is_truncated_json(extracted):
                                return self._parse_json_like(text)
                    except GeminiRateLimitError:
                        raise
                    except _TruncatedResponseError:
                        continue
                    except ValueError:
                        continue

        raise ValueError("Gemini failed to return valid JSON response.")

    # Field extraction
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

    # Normalize scores
    def _normalize_scores(self, result: dict):
        for field in ("risk_score", "anomaly_score"):
            try:
                result[field] = int(float(result[field]))
            except Exception:
                result[field] = None
        return result

    @staticmethod
    def _normalize_dashboard_row(result: dict, source_record: dict, source: str) -> dict:
        normalized = {
            "asset_name": str(result.get("asset_name") or source_record.get("asset_name") or "").strip(),
            "asset_id": str(result.get("asset_id") or source_record.get("asset_id") or "").strip(),
            "threat_status": str(result.get("threat_status") or "Unknown"),
            "severity_validation": str(result.get("severity_validation") or "Needs Review"),
            "priority": str(result.get("priority") or "Monitor"),
            "asset_bucket": str(result.get("asset_bucket") or "Low Risk"),
            "ai_reason": str(result.get("ai_reason") or ""),
            "remediation": str(result.get("remediation") or ""),
            "tenable_remediation": str(result.get("tenable_remediation") or ""),
            "defender_remediation": str(result.get("defender_remediation") or ""),
            "splunk_remediation": str(result.get("splunk_remediation") or ""),
            "bigfix_remediation": str(result.get("bigfix_remediation") or ""),
            "ai_analysis_source": source,
            "anomaly_score": result.get("anomaly_score"),
            "risk_score": result.get("risk_score"),
            "risk_level": str(result.get("risk_level") or "Unknown"),
        }
        return normalized

    @staticmethod
    def _match_source_record(candidates: list[dict], result_row: dict) -> dict | None:
        result_asset_id = str(result_row.get("asset_id") or "").strip()
        result_asset_name = str(result_row.get("asset_name") or "").strip().lower()

        if result_asset_id:
            for candidate in candidates:
                if str(candidate.get("asset_id") or "").strip() == result_asset_id:
                    return candidate
        if result_asset_name:
            for candidate in candidates:
                if str(candidate.get("asset_name") or "").strip().lower() == result_asset_name:
                    return candidate
        return None

    # Single asset analysis
    def generate_asset_analysis(self, *, asset_record: dict) -> dict:
        if not asset_record:
            raise ValueError("No asset data provided.")

        cached = self._cached_result_for_record(asset_record)
        cached_source = str((cached or {}).get("ai_analysis_source") or "").strip().lower()
        if not cached_source:
            ai_reason_text = str((cached or {}).get("ai_reason") or "").strip().lower()
            if "local fallback assessment used" in ai_reason_text:
                cached_source = "local_fallback"
        can_retry_cached_fallback = (
            cached_source == "local_fallback"
            and self.enabled()
            and not get_gemini_pause_status().get("active")
        )
        if cached and not can_retry_cached_fallback:
            cached_result = self._normalize_scores(cached.copy())
            cached_result.update({
                "asset_name": str(cached_result.get("asset_name") or asset_record.get("asset_name") or "").strip(),
                "asset_id": str(cached_result.get("asset_id") or asset_record.get("asset_id") or "").strip(),
                "threat_status": str(cached_result.get("threat_status") or "Unknown"),
                "severity_validation": str(cached_result.get("severity_validation") or "Needs Review"),
                "priority": str(cached_result.get("priority") or "Monitor"),
                "asset_bucket": str(cached_result.get("asset_bucket") or "Low Risk"),
                "risk_level": str(cached_result.get("risk_level") or "Unknown"),
                "ai_analysis_source": str(cached_result.get("ai_analysis_source") or "cache"),
            })
            return cached_result

        compact = self._compact_asset_record(asset_record)

        prompt = f"Analyze this asset:\n{json.dumps(compact, separators=(',', ':'))}"

        try:
            data = self._generate_and_parse(BASE_SYSTEM_PROMPT, prompt)
        except ValueError:
            # Invalid/partial Gemini JSON should not block dashboard analysis.
            fallback = generate_local_asset_analysis(asset_record=asset_record)
            fallback["ai_analysis_source"] = "local_fallback"
            persist_ai_analysis_result(asset_record, fallback)
            return fallback

        if not isinstance(data, dict):
            fallback = generate_local_asset_analysis(asset_record=asset_record)
            fallback["ai_analysis_source"] = "local_fallback"
            persist_ai_analysis_result(asset_record, fallback)
            return fallback

        result = self._extract_fields(data)
        result = self._normalize_scores(result)

        # Defaults
        result.update({
            "asset_name": str(result.get("asset_name") or compact["asset_name"]).strip(),
            "asset_id": str(result.get("asset_id") or compact["asset_id"]).strip(),
            "threat_status": str(result.get("threat_status") or "Unknown"),
            "severity_validation": str(result.get("severity_validation") or "Needs Review"),
            "priority": str(result.get("priority") or "Monitor"),
            "asset_bucket": str(result.get("asset_bucket") or "Low Risk"),
            "risk_level": str(result.get("risk_level") or "Unknown"),
            "ai_analysis_source": "gemini",
        })

        # Service-level persistence keeps Gemini calls idempotent for repeated inputs.
        persist_ai_analysis_result(asset_record, result)
        return result

    # Dashboard analysis
    def generate_dashboard_analysis(self, *, asset_records: list[dict], batch_size: int = 3) -> dict:
        if not asset_records:
            return {"assets": [], "insights": {}}

        try:
            batch_size = int(batch_size)
        except Exception:
            batch_size = 3
        batch_size = max(1, batch_size)

        all_results: list[dict] = []
        pending_records: list[dict] = []

        cache = load_ai_analysis_cache()

        def cached_result_for_record(record: dict) -> dict | None:
            cached = cache.get(compute_asset_fingerprint(record))
            if not isinstance(cached, dict):
                return None
            return {column: cached.get(column) for column in AI_ANALYSIS_COLUMNS}

        for record in asset_records:
            cached = cached_result_for_record(record)
            if cached:
                cached_result = self._normalize_scores(cached.copy())
                all_results.append(
                    self._normalize_dashboard_row(
                        cached_result,
                        record,
                        str(cached_result.get("ai_analysis_source") or "cache"),
                    )
                )
            else:
                pending_records.append(record)

        compact_records = [self._compact_asset_record(r) for r in pending_records]

        # Chunking (prevents truncation)
        for i in range(0, len(compact_records), batch_size):
            chunk = compact_records[i:i + batch_size]
            chunk_source_records = pending_records[i:i + batch_size]

            prompt = f"Analyze these assets:\n{json.dumps(chunk)}"

            try:
                data = self._generate_and_parse(BATCH_SYSTEM_PROMPT, prompt, tokens=1200)
            except GeminiRateLimitError:
                raise
            except Exception:
                data = None

            if isinstance(data, dict):
                items = data.get("assets") or [data]
            else:
                items = []

            chunk_unmatched = list(chunk_source_records)

            for row in items:
                if not isinstance(row, dict):
                    continue

                result = self._extract_fields(row)
                result = self._normalize_scores(result)

                if not result.get("asset_name") and not result.get("asset_id"):
                    continue

                # Accept Gemini output only when it matches one of the current chunk rows.
                source_record = self._match_source_record(chunk_unmatched, result)
                if source_record:
                    normalized = self._normalize_dashboard_row(result, source_record, "gemini")
                    all_results.append(normalized)
                    persist_ai_analysis_result(source_record, normalized)
                    chunk_unmatched = [c for c in chunk_unmatched if c is not source_record]

            # If Gemini returned fewer rows than requested, complete remaining rows now
            # so one partial batch response does not leave rows stuck.
            for source_record in chunk_unmatched:
                fallback_row = generate_local_asset_analysis(asset_record=source_record)
                normalized_fallback = self._normalize_dashboard_row(
                    fallback_row,
                    source_record,
                    str(fallback_row.get("ai_analysis_source") or "local_fallback"),
                )
                persist_ai_analysis_result(source_record, normalized_fallback)
                all_results.append(normalized_fallback)

        if not all_results:
            raise ValueError("No valid asset analysis returned.")

        return {"assets": all_results, "insights": {}}
