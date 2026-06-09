import io
import logging
import threading
from datetime import datetime
import pandas as pd
from dash import html, Input, Output, State, no_update

from security_dashboard.analysis import run_dataset_analysis_worker_thread
from security_dashboard.theme import COLORS
from security_dashboard.data.datasets import (
    empty_dashboard_dataframe,
    raw_records_from_json,
)
from security_dashboard.services.dgx_spark_server_client import DGXSparkServerClient
from .shared import analysis_background_state

logger = logging.getLogger(__name__)

def register_analysis_callbacks(app, ai_analysis_batch_size: int) -> None:
    @app.callback(
        Output("analysis-request-store", "data"),
        Output("analysis-status-store", "data", allow_duplicate=True),
        Output("onboarding-step-store", "data", allow_duplicate=True),
        Input("start-analysis-btn", "n_clicks"),
        State("tenable-raw-store", "data"),
        State("splunk-raw-store", "data"),
        State("analysis-request-store", "data"),
        prevent_initial_call=True,
    )
    def queue_dashboard_analysis(start_clicks, tenable_json, splunk_json, current_request):
        triggered = getattr(__import__("dash").ctx, "triggered_id", None)
        if triggered != "start-analysis-btn" or not start_clicks:
            return no_update, no_update, no_update
        if current_request:
            return no_update, no_update, no_update

        tenable_records = raw_records_from_json(tenable_json)
        splunk_records = raw_records_from_json(splunk_json)
        if not tenable_records or not splunk_records:
            return no_update, {
                "state": "error",
                "message": "Upload and insert both Tenable and Splunk CSV data before starting analysis.",
            }, no_update

        client = DGXSparkServerClient()
        if not client.enabled():
            return no_update, {
                "state": "error",
                "message": "DGX Spark Server endpoint is not configured. Set DGX_SPARK_SERVER_ENDPOINT_NAME before running AI analysis.",
            }, no_update

        total_rows = len(tenable_records) + len(splunk_records)
        message = f"Queued AI correlation for {total_rows} uploaded row(s)."
        return (
            {"requested_at": datetime.now().isoformat(), "source_row_count": total_rows},
            {"state": "running", "message": message},
            "analyzing",
        )

    @app.callback(
        Output("merged-data-store", "data", allow_duplicate=True),
        Output("analysis-status-store", "data", allow_duplicate=True),
        Output("analysis-request-store", "data", allow_duplicate=True),
        Input("analysis-request-store", "data"),
        State("tenable-raw-store", "data"),
        State("splunk-raw-store", "data"),
        prevent_initial_call=True,
    )
    def run_dashboard_analysis(analysis_request, tenable_json, splunk_json):
        if not analysis_request:
            return no_update, no_update, no_update

        running, _, _, _ = analysis_background_state.get_state()
        if running:
            return no_update, {
                "state": "running",
                "message": "AI analysis is already running. Progress updates will appear shortly.",
            }, no_update

        client = DGXSparkServerClient()
        if not client.enabled():
            return (
                no_update,
                {
                    "state": "error",
                    "message": "DGX Spark Server endpoint is not configured. AI analysis is required before assets can be displayed.",
                },
                None,
            )

        tenable_records = raw_records_from_json(tenable_json)
        splunk_records = raw_records_from_json(splunk_json)
        if not tenable_records or not splunk_records:
            return (
                empty_dashboard_dataframe().to_json(date_format="iso", orient="split"),
                {"state": "error", "message": "Both uploaded datasets are required before analysis can run."},
                None,
            )

        request_id = str(analysis_request.get("requested_at") or datetime.now().isoformat())
        initial_status = {
            "state": "running",
            "message": "Running AI correlation across uploaded Tenable and Splunk datasets...",
        }
        analysis_background_state.start_analysis(
            request_id,
            empty_dashboard_dataframe().to_json(date_format="iso", orient="split"),
            initial_status,
        )

        thread = threading.Thread(
            target=run_dataset_analysis_worker_thread,
            args=(request_id, tenable_records, splunk_records, analysis_background_state),
            daemon=True
        )
        analysis_background_state.set_thread(thread)
        thread.start()

        return no_update, initial_status, no_update

    @app.callback(
        Output("merged-data-store", "data", allow_duplicate=True),
        Output("analysis-status-store", "data", allow_duplicate=True),
        Output("analysis-request-store", "data", allow_duplicate=True),
        Output("onboarding-step-store", "data", allow_duplicate=True),
        Input("analysis-poll-interval", "n_intervals"),
        State("analysis-request-store", "data"),
        State("merged-data-store", "data"),
        prevent_initial_call="initial_duplicate",
    )
    def poll_analysis_progress(n_intervals, analysis_request, current_json):
        if not analysis_request:
            return no_update, no_update, no_update

        request_id = str((analysis_request or {}).get("requested_at") or "")
        running, state_request_id, df_json, status = analysis_background_state.get_state()
        if state_request_id != request_id:
            return no_update, no_update, no_update

        status = status or {
            "state": "running",
            "message": "AI analysis is running...",
        }

        if df_json is None:
            return no_update, status, no_update

        if running:
            if df_json != current_json:
                return df_json, status, no_update, "dashboard"
            return no_update, status, no_update, no_update

        analysis_background_state.clear_finished_request()
        if df_json == current_json:
            return no_update, status, None, "dashboard"
        return df_json, status, None, "dashboard"

    @app.callback(
        Output("analysis-status-banner", "children"),
        Input("analysis-status-store", "data"),
    )
    def render_analysis_status(status):
        status = status or {}
        state = status.get("state", "pending")
        message = status.get("message", "")

        if not message:
            return ""

        color_map = {
            "pending": (COLORS["text_muted"], COLORS["card"]),
            "running": (COLORS["primary_dark"], COLORS["primary_light"]),
            "complete": (COLORS["low"], COLORS["low_bg"]),
            "warning": (COLORS["medium"], COLORS["medium_bg"]),
            "error": (COLORS["high"], COLORS["high_bg"]),
        }
        text_color, background = color_map.get(state, (COLORS["text_muted"], COLORS["card"]))

        return html.Div(
            message,
            style={
                "padding": "14px 16px",
                "borderRadius": "4px",
                "background": background,
                "borderLeft": f"4px solid {text_color}",
                "borderTop": f"1px solid {COLORS['border']}",
                "borderRight": f"1px solid {COLORS['border']}",
                "borderBottom": f"1px solid {COLORS['border']}",
                "color": text_color,
                "fontSize": "15px",
                "fontWeight": "600",
            },
        )

    @app.callback(
        Output("analysis-request-store", "data", allow_duplicate=True),
        Output("analysis-status-store", "data", allow_duplicate=True),
        Output("onboarding-step-store", "data", allow_duplicate=True),
        Input("rerun-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def trigger_rerun(n_clicks):
        if not n_clicks:
            return no_update, no_update, no_update
        return (
            {"requested_at": datetime.now().isoformat(), "rerun": True},
            {"state": "running", "message": "Queued AI rerun for uploaded datasets."},
            "analyzing",
        )

    @app.callback(
        Output("rerun-btn", "disabled"),
        Output("rerun-btn", "style"),
        Input("analysis-status-store", "data"),
    )
    def update_rerun_button(status):
        status = status or {}
        is_running = status.get("state") == "running"
        style = {
            "background": COLORS["border"] if is_running else COLORS["primary"],
            "color": COLORS["text_muted"] if is_running else "white",
            "border": "none",
            "borderRadius": "4px",
            "padding": "10px 20px",
            "cursor": "not-allowed" if is_running else "pointer",
            "fontSize": "15px",
            "fontWeight": "700",
            "fontFamily": "inherit",
        }
        return is_running, style
