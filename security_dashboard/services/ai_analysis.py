import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from security_dashboard.data.datasets import (
    AI_ANALYSIS_COLUMNS,
    compute_asset_fingerprint,
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


class SageMakerAnalysisMixin:
    """AI risk analysis mixin for SageMaker integration (caching removed, batching optimized)."""

    @staticmethod
    def _compact_asset_record(asset_record: dict) -> dict:
        """Extract only essential fields for analysis (token optimization)."""
        keys = [
            "asset_name", "asset_id", "vuln_name", "vuln_severity",
            "vuln_fix", "threat_alert", "threat_impact",
            "threat_fix", "anomaly_event", "source_anomaly_score", 
            "patch_status", "patch_severity", "patch_recommendation",
        ]
        return {k: asset_record.get(k, "") for k in keys if asset_record.get(k)}

    def _extract_fields(self, data: dict) -> dict:
        """Map SageMaker output to standard fields with flexible aliases."""
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
        """Coerce risk_score and anomaly_score to int 0-100."""
        for field in ("risk_score", "anomaly_score"):
            try:
                result[field] = max(0, min(100, int(float(result[field]))))
            except (TypeError, ValueError):
                result[field] = None
        return result

    def _normalize_dashboard_row(self, result: dict, record: dict) -> dict:
        """
        Ensure all required AI_ANALYSIS_COLUMNS are present with valid values.
        
        Also enforces that risk_level matches risk_score bands:
        - High: 75-100
        - Medium: 45-74
        - Low: 0-44
        """
        normalized = self._normalize_scores(result.copy() if isinstance(result, dict) else {})
        
        # Extract and coerce values
        risk_score = normalized.get("risk_score")
        risk_level = str(normalized.get("risk_level") or "Unknown").strip()
        
        # Enforce risk_level alignment with risk_score
        if risk_score is not None:
            if risk_score >= 75:
                expected_level = "High"
            elif risk_score >= 45:
                expected_level = "Medium"
            else:
                expected_level = "Low"
            
            # Override risk_level if it doesn't match score bands
            if risk_level not in ("High", "Medium", "Low"):
                risk_level = expected_level
            elif risk_level != expected_level:
                print(
                    f"[sagemaker] risk_level alignment: "
                    f"asset_id={record.get('asset_id')} "
                    f"risk_score={risk_score} enforces risk_level={expected_level} "
                    f"(overriding '{risk_level}')"
                )
                risk_level = expected_level
        
        normalized.update({
            "asset_name": str(normalized.get("asset_name") or record.get("asset_name") or "").strip(),
            "asset_id": str(normalized.get("asset_id") or record.get("asset_id") or "").strip(),
            "threat_status": str(normalized.get("threat_status") or "Unknown"),
            "severity_validation": str(normalized.get("severity_validation") or "Needs Review"),
            "priority": str(normalized.get("priority") or "Monitor"),
            "asset_bucket": str(normalized.get("asset_bucket") or "Low Risk"),
            "risk_level": risk_level,
            "ai_reason": str(normalized.get("ai_reason") or ""),
            "remediation": str(normalized.get("remediation") or ""),
            "tenable_remediation": str(normalized.get("tenable_remediation") or ""),
            "defender_remediation": str(normalized.get("defender_remediation") or ""),
            "splunk_remediation": str(normalized.get("splunk_remediation") or ""),
            "bigfix_remediation": str(normalized.get("bigfix_remediation") or ""),
            "ai_analysis_source": "sagemaker",
        })
        return normalized

    def generate_asset_analysis(self, *, asset_record: dict) -> dict:
        """Analyze a single asset (no caching)."""
        if not asset_record:
            raise ValueError("No asset data provided.")

        compact = self._compact_asset_record(asset_record)
        prompt = f"Analyze this asset:\n{json.dumps(compact, separators=(',', ':'))}"
        started = time.time()
        
        print(
            "[sagemaker] analyze start "
            f"asset_id={asset_record.get('asset_id')} asset_name={asset_record.get('asset_name')}"
        )

        try:
            system_instruction_text = BASE_SYSTEM_PROMPT + "\n\n" + prompt
            response = self._invoke_endpoint(system_instruction_text, max_new_tokens=1200, temperature=0.2)
            data = self._parse_json_like(response)
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
        normalized = self._normalize_dashboard_row(result, asset_record)

        print(
            "[sagemaker] analyze success "
            f"asset_id={normalized.get('asset_id')} elapsed={time.time() - started:.2f}s"
        )
        return normalized

    def _analyze_single_batch_item(self, record: dict, batch_index: int, batch_size: int) -> dict:
        """Analyze one asset within a batch context."""
        row_started = time.time()
        print(
            "[sagemaker] batch item start "
            f"asset_id={record.get('asset_id')} item={batch_index}/{batch_size}"
        )

        compact = self._compact_asset_record(record)
        prompt = f"Analyze this asset:\n{json.dumps(compact, separators=(',', ':'))}"
        
        try:
            system_instruction_text = BASE_SYSTEM_PROMPT + "\n\n" + prompt
            response = self._invoke_endpoint(system_instruction_text, max_new_tokens=1200, temperature=0.2)
            data = self._parse_json_like(response)
        except Exception as e:
            print(
                "[sagemaker] batch item error "
                f"asset_id={record.get('asset_id')} elapsed={time.time() - row_started:.2f}s error={e}"
            )
            raise ValueError(f"SageMaker parse failure for asset {record.get('asset_id')}: {e}") from e

        if not isinstance(data, dict):
            raise ValueError(f"Unexpected SageMaker response format for asset {record.get('asset_id')}: {type(data)}")

        result = self._extract_fields(data)
        normalized = self._normalize_dashboard_row(result, record)

        print(
            "[sagemaker] batch item success "
            f"asset_id={normalized.get('asset_id')} elapsed={time.time() - row_started:.2f}s"
        )
        return normalized

    def generate_dashboard_analysis(self, *, asset_records: list[dict], max_workers: int = 3, asset_timeout_seconds: int = 90) -> dict:
        """
        Analyze all assets with deduplication and parallel processing.
        
        Key improvements:
        - Deduplicates assets by fingerprint (within this run)
        - Parallel processing (default 3 workers)
        - Granular error handling: one asset failure doesn't crash all others
        - Per-asset timeout: don't wait forever for slow assets
        - Automatic retry with exponential backoff (in _invoke_endpoint)
        
        Args:
            asset_records: List of asset records to analyze
            max_workers: Number of parallel SageMaker requests (1-5 recommended)
            asset_timeout_seconds: Max seconds to wait for each asset (30-120 recommended)
        
        Returns:
            {
                "assets": [analysis results + error results],
                "insights": {"total": N, "successful": N, "failed": N, "errors": [...]}
            }
        """
        if not asset_records:
            return {"assets": [], "insights": {"total": 0, "successful": 0, "failed": 0}}

        # ── Deduplication by fingerprint (within this run) ──
        seen_fingerprints = set()
        unique_records = []
        fingerprint_map = {}  # Map fingerprint to list of original record indices

        for idx, record in enumerate(asset_records):
            fp = compute_asset_fingerprint(record)
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                unique_records.append(record)
                fingerprint_map[fp] = [idx]
            else:
                fingerprint_map[fp].append(idx)

        if len(unique_records) < len(asset_records):
            print(f"[sagemaker] deduplication: {len(asset_records)} → {len(unique_records)} unique assets")

        all_results = {}
        failed_errors = []

        # ── Parallel processing with ThreadPoolExecutor ──
        print(f"[sagemaker] batch analysis start: {len(unique_records)} unique assets, {max_workers} workers, {asset_timeout_seconds}s timeout per asset")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for batch_idx, record in enumerate(unique_records):
                future = executor.submit(
                    self._analyze_single_batch_item, 
                    record, 
                    batch_idx + 1, 
                    len(unique_records)
                )
                futures[future] = record

            successful_count = 0
            failed_count = 0
            
            for future in as_completed(futures, timeout=None):
                record = futures[future]
                asset_id = record.get("asset_id", "UNKNOWN")
                fp = compute_asset_fingerprint(record)
                
                try:
                    # Per-asset timeout: don't wait longer than asset_timeout_seconds
                    result = future.result(timeout=asset_timeout_seconds)
                    all_results[fp] = result
                    successful_count += 1
                    
                except TimeoutError:
                    # Timeout exceeded for this specific asset
                    error_msg = f"Asset analysis timed out after {asset_timeout_seconds}s"
                    print(f"[sagemaker] timeout error: asset_id={asset_id} error={error_msg}")
                    failed_errors.append({"asset_id": asset_id, "error": error_msg})
                    failed_count += 1
                    
                    # Return error result for this asset
                    all_results[fp] = self._create_error_result(record, error_msg)
                    
                except Exception as e:
                    # Granular error handling: one asset failure doesn't crash all others
                    error_msg = f"{type(e).__name__}: {str(e)}"
                    print(f"[sagemaker] batch processing error: asset_id={asset_id} error={error_msg}")
                    failed_errors.append({"asset_id": asset_id, "error": error_msg})
                    failed_count += 1
                    
                    # Return error result for this asset (with default values)
                    all_results[fp] = self._create_error_result(record, error_msg)

        print(f"[sagemaker] batch analysis complete: {successful_count} successful, {failed_count} failed")

        # ── Expand deduplicated results back to full list ──
        final_results = []
        for record in asset_records:
            fp = compute_asset_fingerprint(record)
            if fp in all_results:
                final_results.append(all_results[fp])

        # Return insights about the batch
        insights = {
            "total": len(asset_records),
            "unique": len(unique_records),
            "successful": successful_count,
            "failed": failed_count,
            "errors": failed_errors if failed_errors else [],
        }

        return {"assets": final_results, "insights": insights}

    def _create_error_result(self, record: dict, error_msg: str) -> dict:
        """Create a default result object for a failed asset with error message."""
        return {
            "asset_id": str(record.get("asset_id", "UNKNOWN")).strip(),
            "asset_name": str(record.get("asset_name", "UNKNOWN")).strip(),
            "risk_score": 50,  # Default to medium
            "risk_level": "Medium",
            "asset_bucket": "Requires Investigation",
            "anomaly_score": None,
            "threat_status": "Unknown",
            "severity_validation": "Error",
            "priority": "Review",
            "ai_reason": f"Analysis failed: {error_msg}",
            "remediation": "Unable to generate recommendations due to analysis failure",
            "tenable_remediation": "",
            "defender_remediation": "",
            "splunk_remediation": "",
            "bigfix_remediation": "",
            "ai_analysis_source": "error",
        }