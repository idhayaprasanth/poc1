"""
Unified Security Risk Dashboard - Python Dash Application
Merges data from Tenable.io, Microsoft Defender, and Splunk.
"""

import logging

from dash import Dash

from security_dashboard.analysis import build_initial_analysis_status_payload
from security_dashboard.callbacks import register_callbacks
from security_dashboard.config import get_ai_analysis_batch_size, load_env_file
from security_dashboard.data.datasets import build_merged_dataset
from security_dashboard.layout import create_layout

import threading
from datetime import datetime
from security_dashboard.callbacks.shared import analysis_background_state
from security_dashboard.analysis import run_analysis_worker_thread
from security_dashboard.filters import analysis_pending_mask

load_env_file()
AI_ANALYSIS_BATCH_SIZE = get_ai_analysis_batch_size()

logger = logging.getLogger(__name__)

def run_startup_analysis():
    df = build_merged_dataset()
    pending = analysis_pending_mask(df)
    if pending.any():
        logger.info(f"Startup: Found {int(pending.sum())} asset(s) needing analysis. Running analysis immediately in the background...")
        request_id = "startup_" + datetime.now().isoformat()
        initial_status = {
            "state": "running",
            "message": f"Startup: Running AI analysis for {int(pending.sum())} pending row(s)...",
        }
        analysis_background_state.start_analysis(
            request_id,
            df.to_json(date_format="iso", orient="split"),
            initial_status,
        )
        thread = threading.Thread(
            target=run_analysis_worker_thread,
            args=(request_id, df, AI_ANALYSIS_BATCH_SIZE, analysis_background_state),
            daemon=True
        )
        analysis_background_state.set_thread(thread)
        thread.start()
    else:
        logger.info("Startup: All assets are up to date. No analysis needed.")

run_startup_analysis()

app = Dash(
    __name__,
    suppress_callback_exceptions=True,
    update_title=None,
    external_stylesheets=[
        "https://fonts.googleapis.com/css2?family=Source+Sans+3:ital,wght@0,400;0,600;0,700;1,400&display=swap",
    ],
)
app.title = "Unified Security Risk Dashboard"

def get_layout():
    df = build_merged_dataset()
    running, _, _, status = analysis_background_state.get_state()
    if running:
        initial_status = status
    else:
        initial_status = build_initial_analysis_status_payload(df)
    return create_layout(df, analysis_status_initial=initial_status)

app.layout = get_layout
register_callbacks(app, AI_ANALYSIS_BATCH_SIZE)

server = app.server

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8050)
