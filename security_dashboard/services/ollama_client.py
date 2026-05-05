"""Public Ollama client facade for dashboard services."""

from security_dashboard.services.ai_analysis import SageMakerAnalysisMixin
from security_dashboard.services.chatbot import SageMakerChatbotMixin, is_security_question
from security_dashboard.services.ollama_base import OllamaBaseClient


class OllamaClient(SageMakerAnalysisMixin, SageMakerChatbotMixin, OllamaBaseClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


__all__ = ["OllamaClient", "is_security_question"]
