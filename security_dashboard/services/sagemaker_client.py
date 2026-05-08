"""Public SageMaker client facade for dashboard services."""

from security_dashboard.services.ai_analysis import SageMakerAnalysisMixin
from security_dashboard.services.chatbot import SageMakerChatbotMixin, is_security_question
from security_dashboard.services.sagemaker_base import SageMakerBaseClient
from security_dashboard.services.result_envelope import AnalysisResult


class SageMakerClient(SageMakerAnalysisMixin, SageMakerChatbotMixin, SageMakerBaseClient):
    """
    Public facade combining all SageMaker-related functionality:
    - AI analysis (row-isolated, batched, cached)
    - Chatbot (security Q&A)
    - Base client (token counting, endpoint invocation)
    - Result envelope (structured success/failure responses)
    """
    
    def validate_result_schema(self, result: dict) -> tuple[bool, str]:
        """
        Validate that a result conforms to the expected AI analysis schema.
        
        Args:
            result: Result dict to validate
        
        Returns:
            (is_valid, error_message)
        """
        return AnalysisResult.validate_schema(result)


__all__ = ["SageMakerClient", "is_security_question"]
