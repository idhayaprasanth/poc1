import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from security_dashboard.data.datasets import (
    AI_ANALYSIS_COLUMNS,
    compute_asset_fingerprint,
)
from security_dashboard.services.structured_output_validator import StructuredOutputValidator
from security_dashboard.services.prompt_sanitizer import PromptSanitizer


logger = logging.getLogger(__name__)

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


class SageMakerAnalysisMixin:
    """
    AI risk analysis mixin for SageMaker integration.
    
    Uses StructuredOutputValidator to replace scattered parsing/normalization logic.
    Integrates PromptSanitizer for injection prevention.
    """
    
    def __init__(self, debug: bool = False):
        """Initialize with validator and sanitizer."""
        self._validator = StructuredOutputValidator(debug=debug)
        self._sanitizer = PromptSanitizer()
        self.debug = debug

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

    def generate_asset_analysis(self, *, asset_record: dict) -> dict:
        """Analyze a single asset."""
        if not asset_record:
            raise ValueError("No asset data provided.")

        compact = self._compact_asset_record(asset_record)
        
        # Sanitize asset data for JSON embedding (injection prevention)
        sanitized_compact = self._sanitizer.sanitize_asset_record(compact)
        
        prompt = f"Analyze this asset:\n{{data}}".replace(
            "{data}", 
            json.dumps(sanitized_compact, separators=(',', ':'))
        )
        started = time.time()
        
        print(
            "[sagemaker] analyze start "
            f"asset_id={asset_record.get('asset_id')} asset_name={asset_record.get('asset_name')}"
        )

        try:
            system_instruction_text = BASE_SYSTEM_PROMPT + "\n\n" + prompt
            response = self._invoke_endpoint(system_instruction_text, max_new_tokens=1200, temperature=0.2)
            
            # Use StructuredOutputValidator instead of old parsing methods
            validation_result = self.validate_asset_analysis_response(response)
            
            if not validation_result.is_valid:
                # Log per-field errors
                error_details = "; ".join([
                    f"{err.field}: {err.error_message}"
                    for err in validation_result.errors
                ])
                logger.warning(f"Validation errors for asset {asset_record.get('asset_id')}: {error_details}")
                raise ValueError(f"Response validation failed: {error_details}")
            
            result = validation_result.data.model_dump()
            
        except Exception as e:
            raise ValueError(f"SageMaker analysis failed for asset {asset_record.get('asset_id')}: {e}") from e

        print(
            "[sagemaker] analyze success "
            f"asset_id={result.get('asset_id')} elapsed={time.time() - started:.2f}s"
        )
        return result

    def _analyze_single_batch_item(self, record: dict, batch_index: int, batch_size: int) -> dict:
        """Analyze one asset within a batch context."""
        row_started = time.time()
        print(
            "[sagemaker] batch item start "
            f"asset_id={record.get('asset_id')} item={batch_index}/{batch_size}"
        )

        compact = self._compact_asset_record(record)
        
        # Sanitize asset data (injection prevention)
        sanitized_compact = self._sanitizer.sanitize_asset_record(compact)
        
        prompt = f"Analyze this asset:\n{{data}}".replace(
            "{data}",
            json.dumps(sanitized_compact, separators=(',', ':'))
        )
        
        try:
            system_instruction_text = BASE_SYSTEM_PROMPT + "\n\n" + prompt
            response = self._invoke_endpoint(system_instruction_text, max_new_tokens=1200, temperature=0.2)
            
            # Use validator instead of old _parse_json_like + _extract_fields + _normalize_*
            validation_result = self.validate_asset_analysis_response(response)
            
            if not validation_result.is_valid:
                # Log detailed error information
                error_details = "; ".join([
                    f"{err.field}: {err.error_message}"
                    for err in validation_result.errors
                ])
                logger.warning(f"Validation errors for asset {record.get('asset_id')}: {error_details}")
                raise ValueError(f"Response validation failed: {error_details}")
            
            result = validation_result.data.model_dump()
            
        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)}"
            print(
                "[sagemaker] batch item error "
                f"asset_id={record.get('asset_id')} elapsed={time.time() - row_started:.2f}s error={error_msg}"
            )
            raise ValueError(f"SageMaker analysis failed for asset {record.get('asset_id')}: {e}") from e

        print(
            "[sagemaker] batch item success "
            f"asset_id={result.get('asset_id')} elapsed={time.time() - row_started:.2f}s"
        )
        return result

    def generate_dashboard_analysis(
        self,
        *,
        asset_records: list[dict],
        max_workers: int = 3,
        asset_timeout_seconds: int = 90
    ) -> dict:
        """
        Analyze all assets with deduplication and parallel processing.
        
        Key features:
        - Deduplicates assets by fingerprint
        - Parallel processing with ThreadPoolExecutor
        - Granular error handling (one asset failure doesn't crash all)
        - Per-asset timeout
        - Automatic retry on transient errors (via _invoke_endpoint)
        - Per-field validation error logging
        
        Args:
            asset_records: List of asset records to analyze
            max_workers: Number of parallel SageMaker requests (1-5 recommended)
            asset_timeout_seconds: Max seconds per asset (30-120 recommended)
        
        Returns:
            {
                "assets": [analysis results],
                "insights": {
                    "total": N,
                    "unique": N,
                    "successful": N,
                    "failed": N,
                    "errors": [...]
                }
            }
        """
        if not asset_records:
            return {"assets": [], "insights": {"total": 0, "successful": 0, "failed": 0}}

        # Deduplication by fingerprint (within this run)
        seen_fingerprints = set()
        unique_records = []
        fingerprint_map = {}

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

        # Parallel processing
        print(
            f"[sagemaker] batch analysis start: {len(unique_records)} unique assets, "
            f"{max_workers} workers, {asset_timeout_seconds}s timeout per asset"
        )
        
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
                    # Per-asset timeout
                    result = future.result(timeout=asset_timeout_seconds)
                    all_results[fp] = result
                    successful_count += 1
                    
                except TimeoutError:
                    error_msg = f"Asset analysis timed out after {asset_timeout_seconds}s"
                    print(f"[sagemaker] timeout error: asset_id={asset_id}")
                    failed_errors.append({"asset_id": asset_id, "error": error_msg})
                    failed_count += 1
                    all_results[fp] = self._validator.create_error_result(asset_id, error_msg)
                    
                except Exception as e:
                    error_msg = f"{type(e).__name__}: {str(e)}"
                    print(f"[sagemaker] batch error: asset_id={asset_id} error={error_msg}")
                    failed_errors.append({"asset_id": asset_id, "error": error_msg})
                    failed_count += 1
                    all_results[fp] = self._validator.create_error_result(asset_id, error_msg)

        print(f"[sagemaker] batch analysis complete: {successful_count} successful, {failed_count} failed")

        # Expand deduplicated results back to full list
        final_results = []
        for record in asset_records:
            fp = compute_asset_fingerprint(record)
            if fp in all_results:
                final_results.append(all_results[fp])

        insights = {
            "total": len(asset_records),
            "unique": len(unique_records),
            "successful": successful_count,
            "failed": failed_count,
            "errors": failed_errors if failed_errors else [],
        }

        return {"assets": final_results, "insights": insights}