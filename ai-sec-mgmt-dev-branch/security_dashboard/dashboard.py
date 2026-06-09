"""
Unified Security Risk Dashboard - Python Dash Application
Merges data from Tenable.io, Microsoft Defender, and Splunk.
"""

import logging

from dash import Dash

from security_dashboard.analysis import build_initial_analysis_status_payload
from security_dashboard.callbacks import register_callbacks
from security_dashboard.config import get_ai_analysis_batch_size, load_env_file
from security_dashboard.data.datasets import empty_dashboard_dataframe
from security_dashboard.layout import create_layout

load_env_file()
AI_ANALYSIS_BATCH_SIZE = get_ai_analysis_batch_size()

logger = logging.getLogger(__name__)
df_base = empty_dashboard_dataframe()

app = Dash(
    __name__,
    suppress_callback_exceptions=True,
    update_title=None,
    external_stylesheets=[
        "https://fonts.googleapis.com/css2?family=Source+Sans+3:ital,wght@0,400;0,600;0,700;1,400&display=swap",
    ],
)
app.title = "Unified Security Risk Dashboard"
app.layout = create_layout(
    df_base,
    analysis_status_initial=build_initial_analysis_status_payload(df_base),
)
register_callbacks(app, AI_ANALYSIS_BATCH_SIZE)

server = app.server

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8050)
