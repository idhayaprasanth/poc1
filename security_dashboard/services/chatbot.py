"""SageMaker-powered security chatbot helpers."""

import logging

from security_dashboard.services.prompt_templates import get_template
from security_dashboard.config import get_chatbot_prompt_template_version

logger = logging.getLogger(__name__)

# 🔹 Faster lookup (tuple + lowercase once)
SECURITY_KEYWORDS = tuple(k.lower() for k in [
    "security", "cyber", "cybersecurity", "infosec", "vulnerability", "vuln",
    "cve", "risk", "threat", "incident", "malware", "ransomware", "phishing",
    "exploit", "patch", "edr", "siem", "soc", "ids", "ips", "waf", "firewall",
    "splunk", "tenable", "defender", "bigfix", "ioc", "attack", "breach",
    "mitre", "tactic", "remediation", "remediate", "severity", "critical",
    "high", "medium", "low", "asset", "hostname", "server", "virus",
    "antivirus", "secure", "protect", "endpoint", "windows defender",
])


def is_security_question(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return any(k in lowered for k in SECURITY_KEYWORDS)


def _fallback_security_answer(question: str, context_text: str) -> str:
    q = (question or "").lower()

    if not q:
        return "Please ask a cybersecurity-related question."

    if any(x in q for x in ("high risk", "critical", "top risk")):
        return "Focus on high-risk assets and active threats first."

    if any(x in q for x in ("remediation", "fix", "mitigate")):
        return (
            "1) Isolate affected systems\n"
            "2) Patch vulnerabilities\n"
            "3) Remove threats\n"
            "4) Harden configs\n"
            "5) Monitor via SIEM/EDR"
        )

    if "patch" in q:
        return "Prioritize assets with missing patches, especially Critical/High severity."

    return f"AI response unavailable. Context:\n{context_text}"


class SageMakerChatbotMixin:
    """Chatbot mixin with structured response validation."""
    
    def __init__(self, *args, **kwargs):
        """Initialize the mixin while preserving cooperative multiple inheritance."""
        super().__init__(*args, **kwargs)

    def generate_security_answer(
        self,
        *,
        question: str,
        context_text: str,
        history: list[dict] | None = None,
    ) -> str:
        """
        Generate a security-focused chatbot response.
        
        Falls back gracefully if LLM is unavailable or question is not security-related.
        """
        if not self.enabled():
            return "SageMaker endpoint is not configured. Set SAGEMAKER_ENDPOINT_NAME."

        if not is_security_question(question):
            return "Ask a cybersecurity-related question."

        chat_history = []
        for item in (history or [])[-6:]:
            role = item.get("role", "user")
            text = item.get("text", "")
            if text:
                chat_history.append(f"{role}: {text}")
        
        history_text = "\n".join(chat_history)
        
        # Get template version from config and render with chat context
        template_version = get_chatbot_prompt_template_version()
        template = get_template("chatbot", template_version)
        rendered_prompt = template.render(
            history=history_text,
            context=context_text,
            question=question
        )

        try:
            response_text = self.generate_text(rendered_prompt, "")
            
            # Optionally validate as structured response
            # For now, return raw text (simple chatbot mode)
            # To validate: parse as JSON + validate using _validator.validate_chatbot_response()
            
            if response_text:
                return response_text.strip()
        except Exception as e:
            logger.error(f"Chatbot generation failed: {e}")
            return _fallback_security_answer(question, context_text)

        return "AI response unavailable. Please try again."