"""Public SageMaker client facade for dashboard services."""

from security_dashboard.services.ai_analysis import SageMakerAnalysisMixin
from security_dashboard.services.chatbot import SageMakerChatbotMixin, is_security_question
from security_dashboard.services.sagemaker_base import SageMakerBaseClient


class SageMakerClient(SageMakerAnalysisMixin, SageMakerChatbotMixin, SageMakerBaseClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


__all__ = ["SageMakerClient", "is_security_question"]
