"""
Result envelope for row-isolated AI orchestration.

Ensures all AI analysis results (success and failure) conform to a consistent
JSON schema that the dashboard can reliably process.
"""

from typing import Any, Literal
import json

# Import schema from datasets to stay in sync
try:
    from security_dashboard.data.datasets import AI_ANALYSIS_COLUMNS
    SUCCESS_SCHEMA_KEYS = set(AI_ANALYSIS_COLUMNS)
except ImportError:
    # Fallback if import fails
    SUCCESS_SCHEMA_KEYS = {
        "asset_name", "asset_id", "threat_status", "severity_validation", "priority",
        "asset_bucket", "risk_level", "risk_score", "anomaly_score", "ai_reason",
        "remediation", "tenable_remediation", "defender_remediation", "splunk_remediation",
        "bigfix_remediation", "ai_analysis_source",
    }


class AnalysisResult:
    """
    Structured result envelope for a single asset analysis.
    
    Always returns a dict with the success schema keys, even on failure.
    Failed rows fill in error metadata while preserving schema shape.
    """

    @staticmethod
    def success(data: dict) -> dict:
        """
        Wrap a successful AI analysis result.
        
        Args:
            data: AI analysis output with success keys
        
        Returns:
            dict with all required keys, source="sagemaker"
        """
        result = {
            "asset_name": str(data.get("asset_name") or ""),
            "asset_id": str(data.get("asset_id") or ""),
            "threat_status": str(data.get("threat_status") or "Unknown"),
            "severity_validation": str(data.get("severity_validation") or "Needs Review"),
            "priority": str(data.get("priority") or "Monitor"),
            "asset_bucket": str(data.get("asset_bucket") or "Unknown"),
            "risk_level": str(data.get("risk_level") or "Unknown"),
            "risk_score": data.get("risk_score"),
            "anomaly_score": data.get("anomaly_score"),
            "ai_reason": str(data.get("ai_reason") or ""),
            "remediation": str(data.get("remediation") or ""),
            "tenable_remediation": str(data.get("tenable_remediation") or ""),
            "defender_remediation": str(data.get("defender_remediation") or ""),
            "splunk_remediation": str(data.get("splunk_remediation") or ""),
            "bigfix_remediation": str(data.get("bigfix_remediation") or ""),
            "ai_analysis_source": "sagemaker",
        }
        return result

    @staticmethod
    def failure(
        asset_name: str,
        asset_id: str,
        error_type: str,
        error_message: str,
        error_context: dict | None = None,
    ) -> dict:
        """
        Wrap a failed AI analysis result with consistent schema.
        
        All fields are filled with sensible defaults; error details go into
        ai_reason and remediation for dashboard visibility.
        
        Args:
            asset_name: Asset name or identifier
            asset_id: Asset ID
            error_type: Type of error (e.g., "parse_error", "token_overflow", "sagemaker_error")
            error_message: Human-readable error message
            error_context: Optional dict with error details (e.g., token_count, expected_budget)
        
        Returns:
            dict with all required keys, source="error"
        """
        # Construct error explanation
        reason_parts = [f"Analysis failed: {error_type}"]
        if error_context:
            if error_context.get("token_overflow"):
                reason_parts.append(
                    f"Token overflow: {error_context.get('token_count')} > "
                    f"{error_context.get('safe_budget')}"
                )
            if error_context.get("attempt"):
                reason_parts.append(f"Attempt {error_context.get('attempt')}")
        reason_parts.append(error_message)
        
        ai_reason = "; ".join(reason_parts)
        
        result = {
            "asset_name": str(asset_name or ""),
            "asset_id": str(asset_id or ""),
            "threat_status": "Error",
            "severity_validation": "Failed Analysis",
            "priority": "Review",
            "asset_bucket": "Analysis Failed",
            "risk_level": "Unknown",
            "risk_score": None,
            "anomaly_score": None,
            "ai_reason": ai_reason,
            "remediation": f"Manual review required. {error_type}: {error_message}",
            "tenable_remediation": "",
            "defender_remediation": "",
            "splunk_remediation": "",
            "bigfix_remediation": "",
            "ai_analysis_source": "error",
        }
        return result

    @staticmethod
    def validate_schema(result: dict) -> tuple[bool, str]:
        """
        Validate that a result dict conforms to the expected schema.
        
        Args:
            result: Result dict to validate
        
        Returns:
            (is_valid, error_message)
        """
        if not isinstance(result, dict):
            return False, f"Result must be dict, got {type(result)}"
        
        missing_keys = SUCCESS_SCHEMA_KEYS - set(result.keys())
        if missing_keys:
            return False, f"Missing required keys: {missing_keys}"
        
        # Check types for numeric fields
        for field in ("risk_score", "anomaly_score"):
            val = result.get(field)
            if val is not None and not isinstance(val, (int, float)):
                return False, f"{field} must be int/float or None, got {type(val)}"
        
        return True, ""

    @staticmethod
    def ensure_schema(result: dict) -> dict:
        """
        Ensure result conforms to schema, filling missing keys with sensible defaults.
        
        Args:
            result: Result dict (may be incomplete)
        
        Returns:
            Complete result dict with all required keys
        """
        output = {}
        for key in SUCCESS_SCHEMA_KEYS:
            if key in result:
                output[key] = result[key]
            else:
                # Provide sensible defaults
                if key in ("risk_score", "anomaly_score"):
                    output[key] = None
                elif key in ("ai_analysis_source",):
                    output[key] = result.get(key, "sagemaker")
                else:
                    output[key] = ""
        return output
