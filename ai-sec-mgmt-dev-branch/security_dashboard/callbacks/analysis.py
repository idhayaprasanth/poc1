import io
import logging
import threading
from datetime import datetime
import pandas as pd
from dash import html, Input, Output, State, no_update

from security_dashboard.analysis import run_analysis_worker_thread
from security_dashboard.theme import COLORS
from security_dashboard.filters import analysis_pending_mask, analysis_error_mask
from security_dashboard.data.datasets import ensure_ai_analysis_columns
from security_dashboard.services.dgx_spark_server_client import DGXSparkServerClient
from .shared import analysis_background_state

logger = logging.getLogger(__name__)

def register_analysis_callbacks(app, ai_analysis_batch_size: int) -> None:
    @app.callback(
        Output("analysis-request-store", "data"),
        Output("analysis-status-store", "data", allow_duplicate=True),
        Input("merged-data-store", "data"),
        Input("analysis-request-store", "data"),
        prevent_initial_call="initial_duplicate",
    )
    def queue_dashboard_analysis(json_data, current_request):
        df = ensure_ai_analysis_columns(pd.read_json(io.StringIO(json_data), orient="split"))
        client = DGXSparkServerClient()
        pending = analysis_pending_mask(df)
        failed_count = int(analysis_error_mask(df).sum())
        if pending.any() and not client.enabled():
            return no_update, {
                "state": "error",
                "message": "DGX Spark Server endpoint is not configured. Set DGX_SPARK_SERVER_ENDPOINT_NAME before running AI analysis.",
            }
        if not pending.any():
            if failed_count:
                return no_update, {"state": "warning", "message": f"{failed_count} row(s) failed AI analysis and were skipped. Check the terminal logs."}
            return no_update, {"state": "complete", "message": "AI analysis is up to date."}
        if current_request:
            return no_update, no_update

        pending_assets = df.loc[pending, "asset_name"].fillna(df.loc[pending, "asset_id"]).tolist()
        if len(pending_assets) > 1:
            message = (
                f"Running AI analysis in batches of {ai_analysis_batch_size} row(s). "
                f"{len(pending_assets)} row(s) pending."
            )
        else:
            message = f"Running AI analysis for {pending_assets[0]}..."
        return (
            {"requested_at": datetime.now().isoformat(), "pending_count": int(pending.sum())},
            {"state": "running", "message": message},
        )

    @app.callback(
        Output("merged-data-store", "data", allow_duplicate=True),
        Output("analysis-status-store", "data", allow_duplicate=True),
        Output("analysis-request-store", "data", allow_duplicate=True),
        Input("analysis-request-store", "data"),
        State("merged-data-store", "data"),
        prevent_initial_call=True,
    )
    def run_dashboard_analysis(analysis_request, json_data):
        if not analysis_request:
            return no_update, no_update, no_update

        running, _, _, _ = analysis_background_state.get_state()
        if running:
            return no_update, {
                "state": "running",
                "message": "AI analysis is already running. Progress updates will appear shortly.",
            }, no_update

        df = ensure_ai_analysis_columns(pd.read_json(io.StringIO(json_data), orient="split"))
        pending = analysis_pending_mask(df)
        if not pending.any():
            failed_count = int(analysis_error_mask(df).sum())
            if failed_count:
                return no_update, {
                    "state": "warning",
                    "message": f"{failed_count} row(s) failed AI analysis and were skipped. Check the terminal logs.",
                }, None
            return no_update, {"state": "complete", "message": "AI analysis is up to date."}, None

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

        request_id = str(analysis_request.get("requested_at") or datetime.now().isoformat())
        initial_status = {
            "state": "running",
            "message": (
                f"Running AI analysis in batches of {ai_analysis_batch_size} row(s). "
                f"{int(pending.sum())} row(s) pending."
            ),
        }
        analysis_background_state.start_analysis(
            request_id,
            df.to_json(date_format="iso", orient="split"),
            initial_status,
        )

        thread = threading.Thread(
            target=run_analysis_worker_thread,
            args=(request_id, df, ai_analysis_batch_size, analysis_background_state),
            daemon=True
        )
        analysis_background_state.set_thread(thread)
        thread.start()

        return no_update, initial_status, no_update

    @app.callback(
        Output("merged-data-store", "data", allow_duplicate=True),
        Output("analysis-status-store", "data", allow_duplicate=True),
        Output("analysis-request-store", "data", allow_duplicate=True),
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
                return df_json, status, no_update
            return no_update, status, no_update

        analysis_background_state.clear_finished_request()
        if df_json == current_json:
            return no_update, status, None
        return df_json, status, None

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
