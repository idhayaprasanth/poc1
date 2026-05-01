"""
Prompt Template System: Replaces hardcoded BASE_SYSTEM_PROMPT with versioned, reusable templates.

Features:
- Template versioning (e.g., "1.0", "1.1") for A/B testing and rollback
- Safe placeholder rendering with PromptSanitizer
- Schema association (each template knows what schema it produces)
- Easy prompt maintenance and updates without code changes
"""

from enum import Enum
from typing import Optional, Dict, Any
from abc import ABC, abstractmethod
import json

from pydantic import BaseModel
from security_dashboard.services.prompt_sanitizer import PromptSanitizer
from security_dashboard.services.schemas import AssetAnalysisOutput, ChatbotResponse


class TemplateVersion(str, Enum):
    """Supported template versions."""
    V1_0 = "1.0"
    V1_1 = "1.1"  # Can add new versions as prompts are improved


class PromptTemplate(ABC):
    """
    Abstract base class for prompt templates.
    
    Subclasses define:
    - Template text with placeholders
    - Expected output schema
    - Versioning
    """
    
    def __init__(
        self,
        template: str,
        version: str,
        schema: Optional[BaseModel] = None,
        debug: bool = False
    ):
        """
        Initialize template.
        
        Args:
            template: Template string with {placeholder} format
            version: Version identifier (e.g., "1.0")
            schema: Pydantic model for validation of output (if applicable)
            debug: Enable debug logging
        """
        self.template = template
        self.version = version
        self.schema = schema
        self.debug = debug
        self._sanitizer = PromptSanitizer()
    
    @abstractmethod
    def get_required_placeholders(self) -> list[str]:
        """Return list of required placeholders for this template."""
        pass
    
    def render(self, **kwargs) -> str:
        """
        Render template with provided values.
        
        Uses PromptSanitizer to safely render without injection risks.
        
        Args:
            **kwargs: Placeholder values (e.g., system_instruction="...", asset_data="...")
        
        Returns:
            Rendered prompt string
        
        Raises:
            ValueError: If required placeholders missing
        """
        required = self.get_required_placeholders()
        
        # Check all required placeholders are provided
        missing = [p for p in required if p not in kwargs]
        if missing:
            raise ValueError(f"Missing required placeholders: {missing}")
        
        # Sanitize and render
        return self._sanitizer.render_prompt(self.template, **kwargs)
    
    def with_version(self, new_version: str) -> 'PromptTemplate':
        """Create a new template instance with a different version."""
        return self.__class__(
            template=self.template,
            version=new_version,
            schema=self.schema,
            debug=self.debug
        )


class AssetAnalysisTemplate(PromptTemplate):
    """
    Template for asset security risk analysis.
    
    Produces: AssetAnalysisOutput schema
    Version: 1.0 (baseline), 1.1 (improved)
    """
    
    # Version 1.0: Baseline comprehensive analysis template
    TEMPLATE_V1_0 = (
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
        "If data is missing, keep conservative scoring and note uncertainty in ai_reason.\n\n"
        "{asset_data}"
    )
    
    # Version 1.1: Enhanced template with explicit examples (more reliable LLM output)
    TEMPLATE_V1_1 = (
        "You are a cybersecurity risk analysis engine. "
        "RESPOND WITH ONLY A JSON OBJECT. NO TEXT BEFORE OR AFTER JSON. "
        "DO NOT WRITE 'Here is', 'My analysis', OR ANY PREAMBLE. "
        "START IMMEDIATELY WITH { AND END WITH }}.\n\n"
        "RULES:\n"
        "- risk_score: NUMBER 0-100 (e.g. 75)\n"
        "- anomaly_score: NUMBER 0-100\n"
        "- priority: NUMBER 1-5 only (1=Critical, 2=High, 3=Medium, 4=Low, 5=Very Low)\n"
        "- risk_level: 'High'|'Medium'|'Low' matching risk_score (75+=High, 45-74=Medium, 0-44=Low)\n"
        "- threat_status: 'Active'|'Potential'|'Resolved'|'Unknown'\n"
        "- Use ONLY provided data. No invented facts. If missing: conservative scoring + uncertainty in ai_reason.\n\n"
        "OUTPUT EXACTLY THIS FORMAT (NO TEXT BEFORE {{ OR AFTER }}):\n"
        '{{"asset_name":"server-prod","asset_id":"asset-001","risk_score":78,"anomaly_score":35,'
        '"priority":1,"risk_level":"High","threat_status":"Active","asset_bucket":"Production",'
        '"severity_validation":"Confirmed","ai_reason":"Critical vuln","remediation":"Apply patch",'
        '"tenable_remediation":"","defender_remediation":"","splunk_remediation":"","bigfix_remediation":"",'
        '"ai_analysis_source":"sagemaker"}}\n\n'
        "ASSET DATA:\n"
        "{asset_data}"
    )
    
    VERSIONS = {
        "1.0": TEMPLATE_V1_0,
        "1.1": TEMPLATE_V1_1,
    }
    
    def __init__(self, version: str = "1.0", debug: bool = False):
        """
        Initialize asset analysis template.
        
        Args:
            version: Template version ("1.0" or "1.1")
            debug: Enable debug logging
        
        Raises:
            ValueError: If version not supported
        """
        if version not in self.VERSIONS:
            raise ValueError(f"Unsupported template version: {version}. Supported: {list(self.VERSIONS.keys())}")
        
        template_text = self.VERSIONS[version]
        super().__init__(
            template=template_text,
            version=version,
            schema=AssetAnalysisOutput,
            debug=debug
        )
    
    def get_required_placeholders(self) -> list[str]:
        """Asset analysis requires asset_data placeholder."""
        return ["asset_data"]


class ChatbotTemplate(PromptTemplate):
    """
    Template for security chatbot responses.
    
    Produces: ChatbotResponse schema (or plain text)
    Version: 1.0 (baseline)
    """
    
    TEMPLATE_V1_0 = (
        "You are a cybersecurity assistant. "
        "Answer only security-related questions. "
        "Use provided context. Be concise and actionable. "
        "Do not invent data.\n\n"
        "Conversation history:\n{history}\n\n"
        "Context:\n{context}\n\n"
        "Question:\n{question}"
    )
    
    VERSIONS = {
        "1.0": TEMPLATE_V1_0,
    }
    
    def __init__(self, version: str = "1.0", debug: bool = False):
        """
        Initialize chatbot template.
        
        Args:
            version: Template version (currently "1.0")
            debug: Enable debug logging
        """
        if version not in self.VERSIONS:
            raise ValueError(f"Unsupported template version: {version}")
        
        template_text = self.VERSIONS[version]
        super().__init__(
            template=template_text,
            version=version,
            schema=ChatbotResponse,
            debug=debug
        )
    
    def get_required_placeholders(self) -> list[str]:
        """Chatbot requires these placeholders."""
        return ["history", "context", "question"]


class PromptTemplateRegistry:
    """
    Registry for managing prompt templates across the application.
    
    Allows:
    - Registering/retrieving templates by name + version
    - Swapping template versions via configuration
    - Tracking template changes over time
    """
    
    def __init__(self):
        """Initialize registry."""
        self._templates: Dict[str, Dict[str, PromptTemplate]] = {}
        
        # Register default templates
        self.register("asset_analysis", AssetAnalysisTemplate(version="1.0"))
        self.register("asset_analysis", AssetAnalysisTemplate(version="1.1"))
        self.register("chatbot", ChatbotTemplate(version="1.0"))
    
    def register(self, name: str, template: PromptTemplate) -> None:
        """
        Register a template.
        
        Args:
            name: Template name (e.g., "asset_analysis")
            template: PromptTemplate instance
        """
        if name not in self._templates:
            self._templates[name] = {}
        
        self._templates[name][template.version] = template
    
    def get(self, name: str, version: Optional[str] = None) -> PromptTemplate:
        """
        Retrieve a template by name and version.
        
        Args:
            name: Template name
            version: Version (defaults to latest if not specified)
        
        Returns:
            PromptTemplate instance
        
        Raises:
            ValueError: If template not found
        """
        if name not in self._templates:
            raise ValueError(f"Template '{name}' not registered")
        
        versions = self._templates[name]
        
        if version is None:
            # Return latest version (last registered)
            version = max(versions.keys())
        
        if version not in versions:
            raise ValueError(f"Template '{name}' version '{version}' not found")
        
        return versions[version]
    
    def list_versions(self, name: str) -> list[str]:
        """List all available versions for a template."""
        if name not in self._templates:
            return []
        return sorted(self._templates[name].keys())
    
    def get_all_versions(self, name: str) -> Dict[str, PromptTemplate]:
        """Get all versions of a template."""
        return self._templates.get(name, {})


# Global registry instance
_registry = PromptTemplateRegistry()


def get_template(name: str, version: Optional[str] = None) -> PromptTemplate:
    """
    Global convenience function to get a template.
    
    Args:
        name: Template name
        version: Version (defaults to latest)
    
    Returns:
        PromptTemplate instance
    """
    return _registry.get(name, version)


def register_template(name: str, template: PromptTemplate) -> None:
    """Register a template globally."""
    _registry.register(name, template)
