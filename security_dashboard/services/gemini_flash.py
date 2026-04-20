"""Compatibility facade for the refactored Gemini services."""

from security_dashboard.services.ai_analysis import GeminiAnalysisMixin
from security_dashboard.services.chatbot import GeminiChatbotMixin, is_security_question
from security_dashboard.services.gemini_base import GeminiBaseClient, GeminiRateLimitError, get_gemini_pause_status


class GeminiFlashClient(GeminiAnalysisMixin, GeminiChatbotMixin, GeminiBaseClient):
    """Public Gemini client that keeps the old import path stable."""


__all__ = [
    "GeminiFlashClient",
    "GeminiRateLimitError",
    "get_gemini_pause_status",
    "is_security_question",
]
