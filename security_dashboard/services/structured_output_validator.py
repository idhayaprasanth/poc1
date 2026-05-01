"""
StructuredOutputValidator: Replaces scattered parsing and normalization logic with centralized schema validation.

This module validates LLM responses against Pydantic schemas using outlines.
Replaces:
- _extract_fields() (FIELD_MAP-based field mapping)
- _normalize_scores() (score coercion and clamping)
- _normalize_dashboard_row() (risk_level alignment + field defaults)
- _parse_json_like() (regex-based JSON extraction)

New Features:
- Per-field validation errors with detailed messages
- Type coercion with clear error reporting
- Schema-driven validation (Pydantic models)
- Integration with outlines for schema generation
- Graceful error handling (returns ValidationResult with errors or data)
"""

import json
import logging
import re
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

from pydantic import ValidationError as PydanticValidationError

from security_dashboard.services.schemas import (
    AssetAnalysisOutput,
    ChatbotResponse,
    ValidationResult,
    ValidationError as ValidationErrorModel,
)

logger = logging.getLogger(__name__)


class StructuredOutputValidator:
    """Validates and normalizes LLM responses against Pydantic schemas."""
    
    # Mapping from old FIELD_MAP names to new schema field names
    # This allows responses using old field names to still work
    FIELD_ALIASES = {
        "risk_score": ["risk_score", "riskScore", "risk-score"],
        "risk_level": ["risk_level", "riskLevel", "risk-level", "risk_category"],
        "asset_name": ["asset_name", "assetName", "asset-name", "name", "hostname", "host_name"],
        "asset_id": ["asset_id", "assetId", "asset-id", "id", "asset_identifier"],
        "asset_bucket": ["asset_bucket", "assetBucket", "asset-bucket", "asset_category"],
        "anomaly_score": ["anomaly_score", "anomalyScore", "anomaly-score", "anomaly"],
        "threat_status": ["threat_status", "threatStatus", "threat-status", "threat"],
        "severity_validation": ["severity_validation", "severityValidation", "severity-validation"],
        "priority": ["priority", "remediation_priority", "priority_level"],
        "ai_reason": ["ai_reason", "reason", "justification", "analysis_reason"],
        "remediation": ["remediation", "recommendation", "remediation_steps"],
        "tenable_remediation": ["tenable_remediation", "tenableRemediation", "tenable-remediation"],
        "defender_remediation": ["defender_remediation", "defenderRemediation", "defender-remediation"],
        "splunk_remediation": ["splunk_remediation", "splunkRemediation", "splunk-remediation"],
        "bigfix_remediation": ["bigfix_remediation", "bigfixRemediation", "bigfix-remediation"],
        "ai_analysis_source": ["ai_analysis_source", "source", "model"],
    }
    
    def __init__(self, debug: bool = False):
        """
        Initialize validator.
        
        Args:
            debug: If True, log detailed debugging information
        """
        self.debug = debug
    
    def validate_asset_analysis(
        self,
        response_text: str,
        raw_response_dict: Optional[Dict[str, Any]] = None,
        include_raw_response: bool = False
    ) -> ValidationResult:
        """
        Validate an asset analysis response from LLM.
        
        Flow:
        1. Extract JSON from response text (if needed)
        2. Normalize field names using FIELD_ALIASES
        3. Validate against AssetAnalysisOutput schema
        4. Return ValidationResult with data or per-field errors
        
        Args:
            response_text: Raw LLM response text
            raw_response_dict: Pre-parsed response dict (skip extraction if provided)
            include_raw_response: Include raw response text in result
        
        Returns:
            ValidationResult with either valid AssetAnalysisOutput or detailed errors
        """
        try:
            # Step 1: Extract or parse JSON
            if raw_response_dict is not None:
                parsed_dict = raw_response_dict
                extraction_method = "provided_dict"
            else:
                parsed_dict, extraction_method = self._extract_json_from_text(response_text)
            
            if self.debug:
                logger.debug(f"Extracted JSON via {extraction_method}: {json.dumps(parsed_dict, default=str)}")
            
            # Step 2: Normalize field names (includes type coercion)
            normalized_dict = self._normalize_field_names(parsed_dict)
            
            if self.debug:
                logger.debug(f"After normalization: {json.dumps(normalized_dict, default=str)}")
                # Log specifically what priority became
                if 'priority' in normalized_dict:
                    logger.debug(f"Priority normalized to: {normalized_dict['priority']} (type: {type(normalized_dict['priority']).__name__})")
            
            # Step 3: Validate against schema
            validated_data = AssetAnalysisOutput(**normalized_dict)
            
            return ValidationResult(
                is_valid=True,
                data=validated_data,
                errors=None,
                raw_response=response_text if include_raw_response else None
            )
        
        except PydanticValidationError as e:
            # Extract per-field errors
            errors = self._extract_validation_errors(e, parsed_dict if 'parsed_dict' in locals() else {})
            
            if self.debug:
                logger.debug(f"Validation failed with {len(errors)} errors: {errors}")
            
            return ValidationResult(
                is_valid=False,
                data=None,
                errors=errors,
                raw_response=response_text if include_raw_response else None
            )
        
        except Exception as e:
            # Unexpected error (not Pydantic validation)
            logger.error(f"Unexpected error during validation: {type(e).__name__}: {e}")
            
            error = ValidationErrorModel(
                field="<root>",
                error_type="unexpected_error",
                error_message=str(e),
                received_value=str(response_text)[:100] if response_text else None,
                expected_constraint="Valid JSON object"
            )
            
            return ValidationResult(
                is_valid=False,
                data=None,
                errors=[error],
                raw_response=response_text if include_raw_response else None
            )
    
    def validate_chatbot_response(
        self,
        response_dict: Dict[str, Any],
        include_raw_response: bool = False
    ) -> ValidationResult:
        """
        Validate a chatbot response against ChatbotResponse schema.
        
        Args:
            response_dict: Parsed response dictionary
            include_raw_response: Include raw response in result
        
        Returns:
            ValidationResult with either valid ChatbotResponse or errors
        """
        try:
            validated_data = ChatbotResponse(**response_dict)
            
            return ValidationResult(
                is_valid=True,
                data=validated_data,
                errors=None,
                raw_response=json.dumps(response_dict) if include_raw_response else None
            )
        
        except PydanticValidationError as e:
            errors = self._extract_validation_errors(e, response_dict)
            
            return ValidationResult(
                is_valid=False,
                data=None,
                errors=errors,
                raw_response=json.dumps(response_dict) if include_raw_response else None
            )
    
    def _extract_json_from_text(self, text: str) -> Tuple[Dict[str, Any], str]:
        """
        Extract JSON object from LLM response text.
        
        Handles:
        - <think>...</think> tags (reasoning models)
        - Markdown code blocks (```json ...```)
        - Plain JSON objects
        - Escaped newlines and quotes
        
        Returns:
            (parsed_dict, extraction_method) where extraction_method indicates how JSON was found
        
        Raises:
            ValueError: If no valid JSON found or parsing failed
        """
        # Remove <think> tags (reasoning model output)
        text_cleaned = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
        
        # Try 1: Extract from markdown code block
        markdown_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text_cleaned)
        if markdown_match:
            json_str = markdown_match.group(1).strip()
            try:
                parsed = json.loads(json_str)
                return parsed, "markdown_block"
            except json.JSONDecodeError:
                pass
        
        # Try 2: Find first { and last }, clean, and parse
        first_brace = text_cleaned.find('{')
        last_brace = text_cleaned.rfind('}')
        
        if first_brace >= 0 and last_brace > first_brace:
            json_str = text_cleaned[first_brace:last_brace + 1]
            
            # Clean up common LLM output artifacts
            # Remove escaped newlines
            json_str = json_str.replace(r'\n', ' ')
            json_str = json_str.replace(r'\"', '"')
            
            try:
                parsed = json.loads(json_str)
                return parsed, "braces_extraction"
            except json.JSONDecodeError as e:
                if self.debug:
                    logger.debug(f"Failed to parse extracted JSON: {e}")
        
        # Try 3: Direct JSON parse (last resort)
        try:
            parsed = json.loads(text_cleaned)
            return parsed, "direct_parse"
        except json.JSONDecodeError as e:
            logger.error(f"Failed to extract JSON from response: {e}\nResponse text: {text[:200]}")
            raise ValueError(f"Could not extract valid JSON from response: {e}")
    
    def _normalize_field_names(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize field names from LLM output to schema field names using FIELD_ALIASES.
        
        Allows LLM to output field names in various formats (camelCase, kebab-case, etc.)
        and maps them to the canonical schema names.
        
        Also performs type coercion for numeric fields that may come as strings from LLM.
        Handles priority text level mappings (Critical -> 1, High -> 2, etc.).
        
        Returns:
            Dictionary with canonical field names and coerced types
        """
        normalized = {}
        used_aliases = set()
        
        # Integer fields that should be coerced from strings if needed
        INT_FIELDS = {"risk_score", "anomaly_score", "priority"}
        
        # Priority text-to-number mapping (if LLM returns "Critical" instead of 1)
        PRIORITY_LEVEL_MAP = {
            "critical": 1, "critical-priority": 1, "crit": 1,
            "high": 2, "high-priority": 2,
            "medium": 3, "medium-priority": 3, "med": 3,
            "low": 4, "low-priority": 4,
            "very low": 5, "very-low": 5, "minimal": 5,
        }
        
        # Map each FIELD_ALIAS to the first matching key found in data
        for canonical_name, aliases in self.FIELD_ALIASES.items():
            for alias in aliases:
                if alias in data and alias not in used_aliases:
                    value = data[alias]
                    
                    # Type coercion for integer fields
                    if canonical_name in INT_FIELDS and isinstance(value, str):
                        if canonical_name == "priority":
                            # Try to map priority text levels to numbers
                            priority_lower = str(value).lower().strip()
                            if priority_lower in PRIORITY_LEVEL_MAP:
                                value = PRIORITY_LEVEL_MAP[priority_lower]
                            else:
                                # Try to convert as numeric string
                                try:
                                    value = int(value)
                                except (ValueError, TypeError):
                                    if self.debug:
                                        logger.debug(f"Failed to coerce priority='{value}' (not in map, not numeric)")
                        else:
                            # For risk_score, anomaly_score: just convert numeric strings
                            try:
                                value = int(value)
                            except (ValueError, TypeError):
                                if self.debug:
                                    logger.debug(f"Failed to coerce {canonical_name}='{value}' to int")
                    
                    normalized[canonical_name] = value
                    used_aliases.add(alias)
                    break
            
            # If this field wasn't found, don't add it (let schema handle defaults)
        
        return normalized
    
    def _extract_validation_errors(
        self,
        pydantic_error: PydanticValidationError,
        input_data: Dict[str, Any]
    ) -> list[ValidationErrorModel]:
        """
        Convert Pydantic ValidationError to our ValidationErrorModel format.
        
        Provides more readable error messages for users and logging.
        """
        errors = []
        
        for error in pydantic_error.errors():
            field = ".".join(str(x) for x in error.get("loc", ["<root>"]))
            error_type = error.get("type", "unknown")
            message = error.get("msg", "Unknown validation error")
            input_value = error.get("input")
            ctx = error.get("ctx", {})
            
            # Build more readable messages for common errors
            readable_message = self._humanize_error_message(error_type, message, ctx)
            
            errors.append(
                ValidationErrorModel(
                    field=field,
                    error_type=error_type,
                    error_message=readable_message,
                    received_value=str(input_value)[:100] if input_value is not None else None,
                    expected_constraint=self._format_constraint(error_type, ctx)
                )
            )
        
        return errors
    
    def _humanize_error_message(self, error_type: str, message: str, ctx: Dict) -> str:
        """Convert Pydantic error messages to human-readable format."""
        humanized = {
            "greater_than_equal": f"Value must be >= {ctx.get('ge', 'N/A')}",
            "less_than_equal": f"Value must be <= {ctx.get('le', 'N/A')}",
            "enum": f"Value must be one of: {', '.join(str(v) for v in ctx.get('enum', []))}",
            "string_type": "Value must be a string",
            "integer_type": "Value must be an integer",
            "missing": "This field is required",
            "string_pattern": f"Value must match pattern: {ctx.get('pattern', 'N/A')}",
            "value_error": message,  # Use message as-is for value errors
        }
        return humanized.get(error_type, message)
    
    def _format_constraint(self, error_type: str, ctx: Dict) -> Optional[str]:
        """Format the constraint that was violated."""
        if error_type == "greater_than_equal":
            return f">= {ctx.get('ge')}"
        elif error_type == "less_than_equal":
            return f"<= {ctx.get('le')}"
        elif error_type == "enum":
            return f"One of: {ctx.get('enum')}"
        elif error_type == "string_pattern":
            return f"Pattern: {ctx.get('pattern')}"
        return None
    
    def create_error_result(self, asset_id: str, reason: str) -> Dict[str, Any]:
        """
        Create an error result for graceful handling of failed assets.
        
        This is used when validation fails but we still need to return something
        to the dashboard (instead of crashing the batch).
        
        Args:
            asset_id: The asset that failed
            reason: Why it failed
        
        Returns:
            Dictionary with default/conservative values (safe fallback)
        """
        return {
            "asset_id": asset_id,
            "asset_name": None,
            "risk_score": 50,  # Conservative middle ground
            "risk_level": "Medium",
            "anomaly_score": 0,
            "asset_bucket": None,
            "threat_status": "Unknown",
            "severity_validation": f"Analysis error: {reason}",
            "priority": 3,  # Medium priority
            "ai_reason": f"Failed to analyze: {reason}",
            "remediation": "Manual review required",
            "tenable_remediation": None,
            "defender_remediation": None,
            "splunk_remediation": None,
            "bigfix_remediation": None,
            "ai_analysis_source": "error",
        }
