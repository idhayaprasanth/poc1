"""
Pydantic schemas for structured LLM outputs.

Defines data contracts for all AI analysis and chatbot responses with built-in validation.
Replaces scattered normalization logic with centralized schema-driven validation.
"""

from enum import Enum
from typing import Optional, Literal
from pydantic import BaseModel, Field, field_validator, model_validator


class RiskLevel(str, Enum):
    """Risk level categories aligned with score bands."""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class ThreatStatus(str, Enum):
    """Threat categorization."""
    CRITICAL = "Critical"
    ACTIVE = "Active"
    POTENTIAL = "Potential"
    RESOLVED = "Resolved"
    UNKNOWN = "Unknown"


class AssetAnalysisOutput(BaseModel):
    """
    Structured output schema for asset risk analysis.
    
    Enforces:
    - risk_score and risk_level must align (75-100=High, 45-74=Medium, 0-44=Low)
    - All numeric scores must be integers in valid ranges
    - All required fields must be present (even if null)
    
    This schema replaces manual field extraction (FIELD_MAP) and scattered normalization logic.
    """
    
    # Core risk metrics
    risk_score: int = Field(
        ..., 
        ge=0, 
        le=100, 
        description="Overall risk score (0=Low risk, 100=Critical risk)"
    )
    risk_level: RiskLevel = Field(
        ..., 
        description="Risk category: High (75-100), Medium (45-74), Low (0-44)"
    )
    anomaly_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Anomaly detection score (0-100)"
    )
    
    # Asset identification
    asset_name: Optional[str] = Field(
        default=None,
        description="Friendly asset name/hostname"
    )
    asset_id: Optional[str] = Field(
        default=None,
        description="Unique asset identifier from source system"
    )
    asset_bucket: Optional[str] = Field(
        default=None,
        description="Asset classification bucket (e.g., 'Server', 'Workstation', 'Network')"
    )
    
    # Threat assessment
    threat_status: Optional[ThreatStatus] = Field(
        default=ThreatStatus.UNKNOWN,
        description="Current threat status"
    )
    severity_validation: Optional[str] = Field(
        default=None,
        description="Validation of severity rating from source systems"
    )
    priority: Optional[int] = Field(
        default=None,
        ge=1,
        le=5,
        description="Remediation priority (1=Critical, 5=Low)"
    )
    
    # Analysis & recommendations
    ai_reason: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Justification for risk assessment"
    )
    remediation: Optional[str] = Field(
        default=None,
        max_length=500,
        description="General remediation recommendation"
    )
    
    # Source-specific remediation
    tenable_remediation: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Tenable.io specific remediation steps"
    )
    defender_remediation: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Microsoft Defender specific remediation steps"
    )
    splunk_remediation: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Splunk-detected anomaly remediation"
    )
    bigfix_remediation: Optional[str] = Field(
        default=None,
        max_length=500,
        description="BigFix patch/compliance remediation"
    )
    
    # Metadata
    ai_analysis_source: Optional[str] = Field(
        default="sagemaker",
        description="AI model/endpoint used for analysis"
    )
    
    @field_validator('risk_score', 'anomaly_score', mode='before')
    @classmethod
    def coerce_numeric_scores(cls, v):
        """Coerce numeric scores to integers, handling string inputs."""
        if isinstance(v, str):
            try:
                v = int(float(v))
            except (ValueError, TypeError):
                raise ValueError(f"Cannot coerce to integer: {v}")
        elif isinstance(v, float):
            v = int(v)
        if not isinstance(v, int):
            raise ValueError(f"Score must be integer, got {type(v).__name__}: {v}")
        return v
    
    @model_validator(mode='after')
    def validate_risk_alignment(self):
        """Enforce risk_level matches risk_score band."""
        score = self.risk_score
        
        # Determine expected level from score
        if score >= 75:
            expected_level = RiskLevel.HIGH
        elif score >= 45:
            expected_level = RiskLevel.MEDIUM
        else:
            expected_level = RiskLevel.LOW
        
        # Override if misaligned (LLM sometimes outputs contradictory values)
        if self.risk_level != expected_level:
            self.risk_level = expected_level
        
        return self


class ChatbotResponse(BaseModel):
    """
    Structured output schema for security chatbot responses.
    
    Enforces proper message formatting and confidence scoring.
    """
    
    message: str = Field(
        ...,
        max_length=2000,
        description="Chatbot response message"
    )
    is_security_related: bool = Field(
        default=True,
        description="Whether the question was security-related"
    )
    confidence: int = Field(
        default=50,
        ge=0,
        le=100,
        description="Confidence in response accuracy (0-100)"
    )
    source: Optional[str] = Field(
        default="sagemaker",
        description="AI model used for response"
    )
    
    @field_validator('confidence', mode='before')
    @classmethod
    def coerce_confidence(cls, v):
        """Coerce confidence to integer 0-100."""
        if isinstance(v, str):
            try:
                v = int(float(v))
            except (ValueError, TypeError):
                return 50  # Default on parse error
        elif isinstance(v, float):
            v = int(v)
        
        # Clamp to range
        if isinstance(v, int):
            return max(0, min(100, v))
        return 50


class ValidationError(BaseModel):
    """
    Per-field validation error details for debugging and logging.
    """
    
    field: str = Field(..., description="Field name that failed validation")
    error_type: str = Field(
        ...,
        description="Error category: 'type_error', 'value_error', 'constraint_error', 'alignment_error'"
    )
    error_message: str = Field(..., description="Human-readable error message")
    received_value: Optional[str] = Field(default=None, description="Value that failed validation")
    expected_constraint: Optional[str] = Field(default=None, description="Constraint that was violated")
    

class ValidationResult(BaseModel):
    """
    Result of schema validation: success with data, or failure with detailed errors.
    """
    
    is_valid: bool = Field(..., description="Whether validation succeeded")
    data: Optional[AssetAnalysisOutput] = Field(
        default=None,
        description="Validated data (present only if is_valid=True)"
    )
    errors: Optional[list[ValidationError]] = Field(
        default=None,
        description="Validation errors (present only if is_valid=False)"
    )
    raw_response: Optional[str] = Field(
        default=None,
        description="Original LLM response text (for debugging)"
    )
