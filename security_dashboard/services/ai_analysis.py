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

# Prompt tuned for deterministic JSON and stable scoring behavior.
BASE_SYSTEM_PROMPT = (
    "You are a cybersecurity risk analysis engine. "
    "Return ONLY valid JSON (no markdown, no code fences, no commentary). "
    "Return exactly one JSON object with keys: "
    "asset_name, asset_id, threat_status, severity_validation, priority, "
    "asset_bucket, risk_level, risk_score, anomaly_score, ai_reason, remediation, "
    "tenable_remediation, defender_remediation, splunk_remediation, bigfix_remediation. "
    "Rules: "
    "risk_score and anomaly_score must be integers 0-100. "
    "risk_level must be one of High, Medium, Low and must match risk_score bands: "
    "High=75-100, Medium=45-74, Low=0-44. "
    "priority must be one of Immediate, Planned, Monitor. "
    "asset_bucket must be one of High Risk, Medium Risk, Low Risk. "
    "Use only provided input data; do not invent facts. "
    "If data is missing, keep conservative scoring and note uncertainty in ai_reason. "
    "Remediation fields must be concise and actionable."
)

BATCH_SYSTEM_PROMPT = (
    "You are a cybersecurity risk analysis engine. "
    "Return ONLY valid JSON (no markdown, no code fences, no commentary). "
    "Return exactly this shape: {\"assets\": [...]}. "
    "For each input asset, return one output object in the same order as input. "
    "The assets array length MUST equal input length. "
    "Each asset object must include keys: "
    "asset_name, asset_id, threat_status, severity_validation, priority, "
    "asset_bucket, risk_level, risk_score, anomaly_score, ai_reason, remediation, "
    "tenable_remediation, defender_remediation, splunk_remediation, bigfix_remediation. "
    "Rules: "
    "risk_score and anomaly_score must be integers 0-100. "
    "risk_level must be one of High, Medium, Low and must match risk_score bands: "
    "High=75-100, Medium=45-74, Low=0-44. "
    "priority must be one of Immediate, Planned, Monitor. "
    "asset_bucket must be one of High Risk, Medium Risk, Low Risk. "
    "Use only provided input data; do not invent facts. "
    "If data is missing, still return a complete object with conservative scoring "
    "and note uncertainty in ai_reason. "
    "Never omit an asset."
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
    """
    Resolve the ai_analysis_source from a cached result dict.
    Mirrors the logic in datasets._resolve_cached_source so both
    files agree on what counts as a stale entry.
    """
    source = str(cached.get("ai_analysis_source") or "").strip().lower()
    if source:
        return source
    ai_reason_text = str(cached.get("ai_reason") or "").strip().lower()
    if "local fallback" in ai_reason_text:
        return "local_fallback"
    return "unknown"


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

    def _generate_and_parse(self, system_instruction, user_prompt, tokens=800):
        """
        Attempt Gemini call with two token budgets.
        Raises ValueError if all attempts fail or return invalid JSON.
        """
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
                        print(f"[gemini] trying {api_version}/{model_name} budget={budget}")
                        text, ok = self._attempt(
                            api_version=api_version,
                            model_name=model_name,
                            payload=payload,
                        )

                        if ok:
                            extracted = self._extract_json_payload(text)
                            if not _is_truncated_json(extracted):
                                parsed = self._parse_json_like(extracted)
                                print(f"[gemini] parsed ok from {model_name}")
                                return parsed
                            else:
                                print(f"[gemini] truncated json from {model_name}, trying next budget")

                    except GeminiRateLimitError:
                        print(f"[gemini] rate limit hit on {model_name}")
                        raise
                    except _TruncatedResponseError:
                        print(f"[gemini] truncated response from {model_name}, skipping")
                        continue
                    except ValueError as e:
                        print(f"[gemini] value error from {model_name}: {e}")
                        continue
                    except Exception as e:
                        print(f"[gemini] unexpected error from {model_name}: {type(e).__name__}: {e}")
                        continue

        raise ValueError("Gemini failed to return valid JSON after all attempts.")

    def _extract_fields(self, data: dict) -> dict:
        """Map raw Gemini response keys to canonical field names."""
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
        """Coerce risk_score and anomaly_score to integers."""
        for field in ("risk_score", "anomaly_score"):
            try:
                result[field] = int(float(result[field]))
            except Exception:
                result[field] = None
        return result

    def _normalize_dashboard_row(self, result: dict, record: dict, source: str = "gemini") -> dict:
        """Normalize dashboard analysis payload to the canonical cache/output shape."""
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
            "ai_analysis_source": str(source or "gemini"),
        })
        return normalized

    def _normalize_cached_result(self, cached: dict, record: dict) -> dict:
        """Apply defaults to a cached result dict."""
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

    # -------------------------------------------------------------------------
    # Single asset analysis
    # -------------------------------------------------------------------------

    def generate_asset_analysis(self, *, asset_record: dict) -> dict:
        if not asset_record:
            raise ValueError("No asset data provided.")

        cached = self._cached_result_for_record(asset_record)
        cached_source = _get_cached_source(cached or {})

        can_retry_cached_fallback = (
            cached_source == "unknown"
            and self.enabled()
            and not get_gemini_pause_status().get("active")
        )

        if cached and not can_retry_cached_fallback:
            return self._normalize_cached_result(cached, asset_record)

        compact = self._compact_asset_record(asset_record)
        prompt = f"Analyze this asset:\n{json.dumps(compact, separators=(',', ':'))}"

        try:
            data = self._generate_and_parse(BASE_SYSTEM_PROMPT, prompt)
        except (ValueError, GeminiRateLimitError) as e:
            raise ValueError(f"Gemini analysis failed for asset {asset_record.get('asset_id')}: {e}") from e

        if not isinstance(data, dict):
            raise ValueError(f"Gemini returned invalid payload type: {type(data)}")

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
            "ai_analysis_source": "gemini",
        })

        persist_ai_analysis_result(asset_record, result)
        return result

    # -------------------------------------------------------------------------
    # Dashboard (batch) analysis
    # -------------------------------------------------------------------------

    def generate_dashboard_analysis(self, *, asset_records: list[dict]) -> dict:
        """
        asset_records: list of dicts built from the merged DataFrame rows.
        Each dict must contain 'ai_analysis_complete' (bool) set by
        apply_cached_ai_analysis in datasets.py. When False the record is
        sent to Gemini regardless of what the cache contains.
        """
        if not asset_records:
            return {"assets": [], "insights": {}}

        all_results: list[dict] = []
        pending_records: list[dict] = []
        gemini_available = self.enabled() and not get_gemini_pause_status().get("active")

        cache = load_ai_analysis_cache()

        def cached_result_for_record(record: dict) -> dict | None:
            cached = cache.get(compute_asset_fingerprint(record))
            if not isinstance(cached, dict):
                return None
            return {column: cached.get(column) for column in AI_ANALYSIS_COLUMNS}

        for record in asset_records:
            # Normalise ai_analysis_complete across pandas bool, Python bool,
            # and string representations that may come from DataFrame serialization.
            raw_flag = record.get("ai_analysis_complete")
            if isinstance(raw_flag, str):
                analysis_complete = raw_flag.strip().lower() == "true"
            else:
                try:
                    analysis_complete = bool(raw_flag)
                except Exception:
                    analysis_complete = False

            if not analysis_complete:
                # datasets.py has already determined this record needs analysis.
                print(f"[dashboard] queuing {record.get('asset_id')} - ai_analysis_complete=False")
                pending_records.append(record)
                continue

            # Flag is True — try to serve from cache with a final safety check.
            cached = self._cached_result_for_record(record)
            if cached:
                cached_source = _get_cached_source(cached)
                if cached_source == "unknown" and gemini_available:
                    # Defensive: flag said complete but source is stale — re-queue.
                    print(
                        f"[dashboard] re-queuing {record.get('asset_id')} "
                        f"- flag=True but cached source is '{cached_source}'"
                    )
                    pending_records.append(record)
                else:
                    all_results.append(self._normalize_cached_result(cached, record))
            else:
                # Flag said complete but cache entry is gone — re-queue.
                print(f"[dashboard] queuing {record.get('asset_id')} - flag=True but no cache entry")
                pending_records.append(record)

        print(f"[dashboard] {len(all_results)} cached, {len(pending_records)} pending Gemini analysis")

        if not pending_records:
            return {"assets": all_results, "insights": {}}

        # Step 2: Build compact payloads
        compact_records = [self._compact_asset_record(r) for r in pending_records]
        chunk_size = 3
        total_chunks = (len(compact_records) + chunk_size - 1) // chunk_size

        # Step 3: Process chunks
        for chunk_index, i in enumerate(range(0, len(compact_records), chunk_size)):
            chunk_records = compact_records[i:i + chunk_size]
            source_records = pending_records[i:i + chunk_size]

            print(f"[dashboard] chunk {chunk_index + 1}/{total_chunks}: {len(chunk_records)} record(s)")

            prompt = f"Analyze these assets:\n{json.dumps(chunk_records)}"

            try:
                data = self._generate_and_parse(BATCH_SYSTEM_PROMPT, prompt, tokens=1200)
            except GeminiRateLimitError:
                raise
            except ValueError as e:
                raise ValueError(f"Gemini parse failure on chunk {chunk_index + 1}: {e}") from e
            except Exception as e:
                raise RuntimeError(
                    f"Gemini unexpected error on chunk {chunk_index + 1}: {type(e).__name__}: {e}"
                ) from e

            print(f"[dashboard] chunk {chunk_index + 1} returned data (type={type(data).__name__})")

            # Normalise Gemini response into a flat list
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = data.get("assets", [data])
            else:
                raise ValueError(f"Unexpected Gemini response format on chunk {chunk_index + 1}: {type(data)}")

            # Map Gemini items back to source records
            processed_ids: set[str] = set()

            for row in items:
                if not isinstance(row, dict):
                    continue

                result = self._extract_fields(row)
                result = self._normalize_scores(result)

                asset_id = str(result.get("asset_id") or "").strip().lower()
                asset_name = str(result.get("asset_name") or "").strip().lower()

                if not asset_id and not asset_name:
                    print(f"[dashboard] skipping row with no asset_id or asset_name: {row}")
                    continue

                # Match back to source record for persistence
                source_record = next(
                    (
                        r for r in source_records
                        if str(r.get("asset_id") or "").strip().lower() == asset_id
                    ),
                    None,
                ) or next(
                    (
                        r for r in source_records
                        if str(r.get("asset_name") or "").strip().lower() == asset_name
                    ),
                    None,
                )

                if source_record:
                    normalized = self._normalize_dashboard_row(result, source_record, "gemini")
                    all_results.append(normalized)
                    persist_ai_analysis_result(source_record, normalized)
                    processed_ids.add(
                        str(source_record.get("asset_id") or source_record.get("asset_name") or "").strip().lower()
                    )
                else:
                    print(f"[dashboard] could not match row back to source record: {asset_id or asset_name}")

            # Fallback for any source records Gemini silently omitted
            unmatched = [
                r for r in source_records
                if str(r.get("asset_id") or r.get("asset_name") or "").strip().lower()
                not in processed_ids
            ]
            if unmatched:
                raise ValueError(
                    f"Gemini omitted {len(unmatched)} record(s) in chunk {chunk_index + 1}; no fallback is allowed."
                )

        if not all_results:
            raise ValueError("No valid asset analysis returned.")

        print(f"[dashboard] complete: {len(all_results)} total results")
        return {"assets": all_results, "insights": {}}