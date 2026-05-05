"""Public LLM client facade for dashboard services.

NOTE: This module provides the SageMakerClient interface for backward compatibility.
The current implementation uses Ollama instead of AWS SageMaker.
For Ollama-specific features, use OllamaClient directly.
"""

from security_dashboard.services.ai_analysis import SageMakerAnalysisMixin
from security_dashboard.services.chatbot import SageMakerChatbotMixin, is_security_question
from security_dashboard.services.ollama_client import OllamaClient


# Alias for backward compatibility: SageMakerClient now uses Ollama implementation
class SageMakerClient(OllamaClient):
    """
    LLM client facade combining AI analysis and chatbot mixins with Ollama backend.
    
    This class maintains the SageMakerClient interface for backward compatibility
    while using Ollama as the underlying LLM provider.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


__all__ = ["SageMakerClient", "is_security_question"]
