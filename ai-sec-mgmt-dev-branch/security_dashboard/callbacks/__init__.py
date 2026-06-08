"""Dash callback registration for the security dashboard."""

import io
import logging
import threading
from datetime import datetime

import pandas as pd
from dash import html, dcc, Input, Output, State, no_update, ctx

from security_dashboard.analysis import AnalysisBackgroundState, run_analysis_worker_thread
from security_dashboard.components import build_asset_section, get_asset_table_configs, kpi_card
from security_dashboard.detail_panel import DetailPanelRenderer
from security_dashboard.filters import (
    analysis_completion_mask,
    analysis_error_mask,
    analysis_pending_mask,
    assign_asset_sections,
    prepare_filtered_assets,
)
from security_dashboard.theme import COLORS, KPI_ICON_SVGS, svg_icon
from security_dashboard.data.datasets import ensure_ai_analysis_columns
from security_dashboard.services.dgx_spark_server_client import DGXSparkServerClient

logger = logging.getLogger(__name__)
ASSET_TABLE_CONFIGS = get_asset_table_configs()
TABLE_ID_MAP = {config["id"]: config for config in ASSET_TABLE_CONFIGS}
analysis_background_state = AnalysisBackgroundState()


def register_callbacks(app, ai_analysis_batch_size: int) -> None:
    # Issue status update
    @app.callback(
        Output("merged-data-store", "data", allow_duplicate=True),
        Input("issue-status-save", "n_clicks"),
        State("issue-status-dropdown", "value"),
        State("selected-asset-store", "data"),
        State("merged-data-store", "data"),
        prevent_initial_call=True,
    )
    def update_issue_status(issue_status_save, issue_status_value, selected_asset, json_data):
        if issue_status_value not in ["Open", "In Progress", "Resolved"]:
            return no_update
        asset_id = (selected_asset or {}).get("asset_id")
        if not asset_id:
            return no_update

        df = pd.read_json(io.StringIO(json_data), orient="split")
        if "asset_id" not in df.columns:
            return no_update

        existing = df.loc[df["asset_id"] == asset_id, "issue_status"]
        if len(existing) and existing.iloc[0] == issue_status_value:
            return no_update

        df.loc[df["asset_id"] == asset_id, "issue_status"] = issue_status_value
        return df.to_json(date_format="iso", orient="split")


    @app.callback(
        Output("selected-asset-store", "data"),
        Input("asset-table-critical", "selected_rows"),
        Input("asset-table-high", "selected_rows"),
        Input("asset-table-medium", "selected_rows"),
        State("asset-table-critical", "data"),
        State("asset-table-high", "data"),
        State("asset-table-medium", "data"),
        prevent_initial_call=True,
    )
    def sync_selected_asset(critical_rows, high_rows, medium_rows, critical_data, high_data, medium_data):
        triggered_table = ctx.triggered_id
        if triggered_table not in TABLE_ID_MAP:
            return None

        selections = {
            "asset-table-critical": (critical_rows, critical_data),
            "asset-table-high": (high_rows, high_data),
            "asset-table-medium": (medium_rows, medium_data),
        }

        selected_rows, table_data = selections.get(triggered_table, (None, None))
        if not selected_rows or not table_data:
            return None

        selected_idx = selected_rows[0]
        if selected_idx >= len(table_data):
            return None

        row = table_data[selected_idx] or {}
        asset_id = row.get("asset_id")
        if not asset_id:
            return None

        return {
            "asset_id": asset_id,
            "asset_name": row.get("asset_name"),
            "table_id": triggered_table,
        }


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

        thread = threading.Thread(target=run_analysis_worker_thread, args=(request_id, df, ai_analysis_batch_size, analysis_background_state), daemon=True)
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

        # Analysis finished; clear the request marker after delivering final state.
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


    # KPI cards
    @app.callback(Output("kpi-cards", "children"), Input("merged-data-store", "data"))
    def update_kpis(json_data):
        df = ensure_ai_analysis_columns(pd.read_json(io.StringIO(json_data), orient="split"))
        total_assets = len(df)
        complete_mask = analysis_completion_mask(df)
        if not complete_mask.any():
            return [
                kpi_card("Total Assets", total_assets, COLORS["primary"], svg_icon(KPI_ICON_SVGS["assets"], COLORS["primary"], size=22)),
                kpi_card("Critical Risk", "Pending", COLORS["high"], svg_icon(KPI_ICON_SVGS["high"], COLORS["high"], size=22)),
                kpi_card("High Risk", "Pending", COLORS["high"], svg_icon(KPI_ICON_SVGS["high"], COLORS["high"], size=22)),
                kpi_card("Medium Risk", "Pending", COLORS["medium"], svg_icon(KPI_ICON_SVGS["medium"], COLORS["medium"], size=22)),
                kpi_card("Low Risk", "Pending", COLORS["low"], svg_icon(KPI_ICON_SVGS["low"], COLORS["low"], size=22)),
            ]
        df = df.loc[complete_mask].copy()
        critical = len(df[df["risk_level"] == "Critical"])
        high = len(df[df["risk_level"] == "High"])
        med = len(df[df["risk_level"] == "Medium"])
        low = len(df[df["risk_level"] == "Low"])
        return [
            kpi_card("Total Assets", total_assets, COLORS["primary"], svg_icon(KPI_ICON_SVGS["assets"], COLORS["primary"], size=22)),
            kpi_card("Critical Risk", critical, COLORS["high"], svg_icon(KPI_ICON_SVGS["high"], COLORS["high"], size=22)),
            kpi_card("High Risk", high, COLORS["high"], svg_icon(KPI_ICON_SVGS["high"], COLORS["high"], size=22)),
            kpi_card("Medium Risk", med, COLORS["medium"], svg_icon(KPI_ICON_SVGS["medium"], COLORS["medium"], size=22)),
            kpi_card("Low Risk", low, COLORS["low"], svg_icon(KPI_ICON_SVGS["low"], COLORS["low"], size=22)),
        ]


    # SLA / aging tracker
    @app.callback(Output("sla-panel", "children"), Input("merged-data-store", "data"))
    def update_sla_panel(json_data):
        df = ensure_ai_analysis_columns(pd.read_json(io.StringIO(json_data), orient="split"))
        complete_mask = analysis_completion_mask(df)
        pending_count = int(analysis_pending_mask(df).sum())
        failed_count = int(analysis_error_mask(df).sum())
        if not complete_mask.any():
            return html.Div(
                "SLA tracking will appear after at least one asset completes AI analysis.",
                style={"fontSize": "15px", "color": COLORS["text_muted"], "lineHeight": "1.5"},
            )
        df = df.loc[complete_mask].copy()
        today = pd.Timestamp.now().normalize()

        first_seen = pd.to_datetime(df.get("scan_date"), errors="coerce")
        first_seen = first_seen.fillna(today)
        age_days = (today - first_seen).dt.days.clip(lower=0)

        status = df.get("issue_status", pd.Series(["Open"] * len(df))).fillna("Open")
        risk = df.get("risk_level", pd.Series(["Low"] * len(df))).fillna("Low")

        sla_days = risk.map({"Critical": 1, "High": 3, "Medium": 7})
        breached = sla_days.notna() & status.isin(["Open", "In Progress"]) & (age_days > sla_days)

        breached_count = int(breached.sum())
        open_count = int(status.eq("Open").sum())
        in_progress_count = int(status.eq("In Progress").sum())

        rows = df.copy()
        rows["age_days"] = age_days
        rows["sla_days"] = sla_days
        rows["sla_breached"] = breached

        top = rows[rows["sla_breached"]].sort_values(["risk_score", "age_days"], ascending=[False, False]).head(8)
        top_lines = []
        for _, r in top.iterrows():
            top_lines.append(
                f"{r.get('asset_id','')} {r.get('asset_name','')}: {r.get('risk_level','')} age={int(r.get('age_days',0))}d (sla {int(r.get('sla_days',0))}d)"
            )

        def stat_box(label, value, color, bg):
            return html.Div(style={
                "flex": "1",
                "minWidth": "160px",
                "border": f"1px solid {COLORS['border']}",
                "borderRadius": "4px",
                "padding": "16px",
                "background": bg,
                "boxShadow": "0 1px 4px rgba(27,27,27,0.04)",
            }, children=[
                html.Div(
                    label,
                    style={
                        "fontSize": "13px",
                        "fontWeight": "700",
                        "color": COLORS["text_muted"],
                        "textTransform": "uppercase",
                        "letterSpacing": "0.05em",
                    },
                ),
                html.Div(str(value), style={"fontSize": "28px", "fontWeight": "700", "color": color, "marginTop": "8px", "lineHeight": "1.1"}),
            ])

        breached_list = html.Div(
            ("; ".join(top_lines)) if top_lines else "No SLA breaches detected.",
            style={
                "marginTop": "12px",
                "fontSize": "15px",
                "color": COLORS["text"],
                "background": COLORS["high_bg"] if top_lines else COLORS["primary_lighter"],
                "border": f"1px solid {COLORS['border']}",
                "borderRadius": "4px",
                "padding": "14px 16px",
                "lineHeight": "1.55",
            },
        )

        children = [
            html.Div(style={"display": "flex", "gap": "12px", "flexWrap": "wrap"}, children=[
                stat_box("Open", open_count, COLORS["high"] if open_count else COLORS["low"], COLORS["card"]),
                stat_box("In Progress", in_progress_count, COLORS["medium"] if in_progress_count else COLORS["low"], COLORS["card"]),
                stat_box("SLA Breached", breached_count, COLORS["high"] if breached_count else COLORS["low"], COLORS["high_bg"] if breached_count else COLORS["low_bg"]),
            ]),
            breached_list,
        ]
        if pending_count or failed_count:
            children.append(
                html.Div(
                    f"SLA metrics include {len(df)} analyzed row(s). Pending={pending_count}, failed={failed_count}.",
                    style={
                        "marginTop": "12px",
                        "fontSize": "14px",
                        "color": COLORS["text_muted"],
                        "lineHeight": "1.45",
                    },
                )
            )
        return html.Div(children)
    # Filtered tables
    @app.callback(
        Output("asset-table-container", "children"),
        Input("merged-data-store", "data"),
        Input("search-input", "value"),
        Input("risk-filter", "value"),
        Input("sort-order", "value"),
        Input("date-range", "start_date"),
        Input("date-range", "end_date"),
    )
    def update_table(json_data, search, risk_f, sort, date_from, date_to):
        df = ensure_ai_analysis_columns(pd.read_json(io.StringIO(json_data), orient="split"))
        df = prepare_filtered_assets(df, search, risk_f, sort, date_from, date_to)
        df = assign_asset_sections(df)

        # If some rows are marked complete but still have no asset_section mapping,
        # attempt a defensive fallback: map them from `risk_level` synonyms so they
        # appear in the risk tables immediately.
        try:
            complete_mask = analysis_completion_mask(df)
            unmapped_mask = df["asset_section"].isna() & complete_mask & ~analysis_error_mask(df)
            if unmapped_mask.any():
                # derive from risk_level with normalized mapping
                rl = (
                    df.loc[unmapped_mask, "risk_level"]
                    .fillna("")
                    .astype(str)
                    .str.strip()
                    .str.lower()
                )
                rl = rl.str.replace(r"^priority[:\s]+", "", regex=True).str.replace(r"\s*risk\s*$", "", regex=True).str.strip()
                fallback_map = {"critical": "critical", "high": "high", "medium": "medium", "med": "medium", "low": "low", "info": "low", "informational": "low"}
                reassigned = 0
                for idx, val in rl.items():
                    section = fallback_map.get(val)
                    if section:
                        df.at[idx, "asset_section"] = section
                        reassigned += 1
                if reassigned:
                    logger.info("Reassigned %s previously-unmapped completed row(s) to sections via risk_level fallback.", reassigned)
        except Exception:
            logger.debug("Failed to apply fallback mapping for unmapped completed rows.")
        failed_mask = analysis_error_mask(df)
        pending_analysis_mask = analysis_pending_mask(df)
        pending_count = int(pending_analysis_mask.sum())
        failed_count = int(failed_mask.sum())

        children = []
        if pending_count:
            children.append(
                html.Div(
                    f"AI analysis running... {pending_count} row(s) still pending. Completed rows are shown below as they finish.",
                    style={
                        "padding": "14px 16px",
                        "borderRadius": "4px",
                        "background": COLORS["primary_lighter"],
                        "borderLeft": f"4px solid {COLORS['primary']}",
                        "borderTop": f"1px solid {COLORS['border']}",
                        "borderRight": f"1px solid {COLORS['border']}",
                        "borderBottom": f"1px solid {COLORS['border']}",
                        "color": COLORS["primary_dark"],
                        "fontSize": "15px",
                        "fontWeight": "700",
                    },
                )
            )
        if failed_count:
            children.append(
                html.Div(
                    f"{failed_count} row(s) have AI analysis errors and are listed below. Retry analysis when ready. Check the terminal output for the full error.",
                    style={
                        "padding": "14px 16px",
                        "borderRadius": "4px",
                        "background": COLORS["medium_bg"],
                        "borderLeft": f"4px solid {COLORS['medium']}",
                        "borderTop": f"1px solid {COLORS['border']}",
                        "borderRight": f"1px solid {COLORS['border']}",
                        "borderBottom": f"1px solid {COLORS['border']}",
                        "color": COLORS["medium"],
                        "fontSize": "15px",
                        "fontWeight": "700",
                    },
                )
            )
        sections = []
        if failed_count:
            error_config = {
                "id": "asset-table-errors",
                "title": "Analysis Errors",
                "section": "errors",
                "accent": COLORS["medium"],
                "background": COLORS["medium_bg"],
                "empty": "No analysis errors match the current filters.",
            }
            sections.append(build_asset_section(error_config, df[failed_mask].copy()))

        for config in ASSET_TABLE_CONFIGS:
            section_df = df[(df["asset_section"] == config["section"]) & (~pending_analysis_mask)].copy()
            sections.append(build_asset_section(config, section_df))

        children.append(html.Div(style={"display": "grid", "gap": "24px"}, children=sections))
        return html.Div(style={"display": "grid", "gap": "20px"}, children=children)


    # Detail panel
    @app.callback(
        Output("detail-overlay", "style"),
        Output("detail-body", "children"),
        Output("detail-asset-name", "children"),
        Output("detail-asset-id", "children"),
        Output("detail-scan-date", "children"),
        Output("issue-status-dropdown", "value"),
        Input("selected-asset-store", "data"),
        Input("detail-backdrop", "n_clicks"),
        Input("detail-close-btn", "n_clicks"),
        Input("merged-data-store", "data"),
        prevent_initial_call=True,
    )
    def show_detail(selected_asset, backdrop_click, close_click, json_data):
        if ctx.triggered_id in ["detail-backdrop", "detail-close-btn"] or not selected_asset:
            return {"display": "none"}, [], "", "", "", "Open"

        df = pd.read_json(io.StringIO(json_data), orient="split")
        selected_asset_id = selected_asset.get("asset_id")
        if not selected_asset_id or "asset_id" not in df.columns or not (df["asset_id"] == selected_asset_id).any():
            return {"display": "none"}, [], "", "", "", "Open"

        row = df[df["asset_id"] == selected_asset_id].iloc[0]
        renderer = DetailPanelRenderer()
        children, asset_name, asset_id, scan_date, issue_status = renderer.render_detail_panel(row)
        return {"display": "block"}, children, asset_name, asset_id, scan_date, issue_status


    @app.callback(
        Output("asset-table-critical", "selected_rows"),
        Output("asset-table-high", "selected_rows"),
        Output("asset-table-medium", "selected_rows"),
        Output("selected-asset-store", "data", allow_duplicate=True),
        Input("detail-backdrop", "n_clicks"),
        Input("detail-close-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def clear_detail_selection(backdrop_clicks, close_clicks):
        return [], [], [], None


    # Export CSV
    @app.callback(
        Output("download-csv", "data"),
        Input("export-btn", "n_clicks"),
        State("merged-data-store", "data"),
        prevent_initial_call=True,
    )
    def export_csv(n, json_data):
        df = pd.read_json(io.StringIO(json_data), orient="split")
        return dcc.send_data_frame(df.to_csv, f"security-report-{datetime.now().strftime('%Y-%m-%d')}.csv", index=False)


    # Chat toggle
    @app.callback(
        Output("chat-window", "style"),
        Input("chat-fab", "n_clicks"),
        Input("chat-close", "n_clicks"),
        State("chat-window", "style"),
        prevent_initial_call=True,
    )
    def toggle_chat(fab_clicks, close_clicks, current):
        if not isinstance(current, dict):
            current = {"display": "none"}
        if ctx.triggered_id == "chat-close":
            return {"display": "none"}
        if current.get("display") == "none":
            return {"display": "block"}
        return {"display": "none"}


    # Chat responses
    @app.callback(
        Output("chat-messages", "children"),
        Output("chat-input", "value"),
        Output("chat-history-store", "data"),
        Input("chat-send", "n_clicks"),
        State("chat-input", "value"),
        State("chat-messages", "children"),
        State("chat-history-store", "data"),
        State("merged-data-store", "data"),
        prevent_initial_call=True,
    )
    def chat_respond(n, user_msg, current_msgs, history, json_data):
        if not user_msg or not user_msg.strip():
            return no_update, no_update, no_update

        df = ensure_ai_analysis_columns(pd.read_json(io.StringIO(json_data), orient="split"))
        current_msgs = current_msgs or []
        history = history or []
        complete_mask = analysis_completion_mask(df)
        pending_count = int(analysis_pending_mask(df).sum())
        failed_count = int(analysis_error_mask(df).sum())

        if not complete_mask.any():
            user_bubble = html.Div(user_msg, style={
                "background": COLORS["primary"], "color": "white", "padding": "12px 14px",
                "borderRadius": "4px", "fontSize": "15px", "alignSelf": "flex-end", "maxWidth": "85%"
            })
            bot_bubble = html.Div("AI dashboard analysis has not completed for any assets yet. Please try again after the first asset finishes.", style={
                "background": COLORS["primary_light"], "padding": "12px 14px",
                "borderRadius": "4px", "fontSize": "15px",
                "color": COLORS["text"], "maxWidth": "85%", "border": f"1px solid {COLORS['border']}",
            })
            return current_msgs + [user_bubble, bot_bubble], "", history

        df = df.loc[complete_mask].copy()
        c = int((df.get("risk_level") == "Critical").sum()) if "risk_level" in df.columns else 0
        h = int((df.get("risk_level") == "High").sum()) if "risk_level" in df.columns else 0
        m = int((df.get("risk_level") == "Medium").sum()) if "risk_level" in df.columns else 0
        lo = int((df.get("risk_level") == "Low").sum()) if "risk_level" in df.columns else 0

        top = df.nlargest(5, "risk_score") if "risk_score" in df.columns and not df.empty else df.head(5)
        lines = []
        for _, r in top.iterrows():
            lines.append(
                f"- {r.get('asset_id','')} {r.get('asset_name','')}: {r.get('risk_score','—')}/10 "
                f"({r.get('risk_level','—')}), issue={r.get('issue_status','—')}, patch={r.get('patch_status','—')}, "
                f"vuln={r.get('vuln_severity','—')} {r.get('vuln_name','—')}, threat={r.get('threat_alert','—')}"
            )

        context_text = (
            f"Summary: analyzed_assets={len(df)}, critical={c}, high={h}, medium={m}, low={lo}. "
            f"Pending assets excluded={pending_count}; failed analysis rows excluded={failed_count}.\n"
            f"Top assets by risk_score:\n" + "\n".join(lines)
        )

        client = DGXSparkServerClient()
        response = client.generate_security_answer(question=user_msg.strip(), context_text=context_text, history=history)

        user_bubble = html.Div(user_msg, style={
            "background": COLORS["primary"], "color": "white", "padding": "12px 14px",
            "borderRadius": "4px", "fontSize": "15px", "alignSelf": "flex-end", "maxWidth": "85%"
        })
        bot_bubble = html.Div(response, style={
            "background": COLORS["primary_light"], "padding": "12px 14px",
            "borderRadius": "4px", "fontSize": "15px",
            "color": COLORS["text"], "maxWidth": "85%", "border": f"1px solid {COLORS['border']}",
        })

        new_history = (history + [{"role": "user", "text": user_msg.strip()}, {"role": "assistant", "text": response}])[-20:]
        return current_msgs + [user_bubble, bot_bubble], "", new_history
