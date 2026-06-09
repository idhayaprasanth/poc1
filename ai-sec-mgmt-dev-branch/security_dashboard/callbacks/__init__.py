"""Dash callback registration for the security dashboard."""

from .analysis import register_analysis_callbacks
from .assets import register_asset_callbacks
from .kpis import register_kpi_callbacks
from .chat import register_chat_callbacks
from .onboarding import register_onboarding_callbacks

def register_callbacks(app, ai_analysis_batch_size: int) -> None:
    """Register all modular callbacks for the application."""
    register_onboarding_callbacks(app)
    register_analysis_callbacks(app, ai_analysis_batch_size)
    register_kpi_callbacks(app)
    register_asset_callbacks(app)
    register_chat_callbacks(app)
