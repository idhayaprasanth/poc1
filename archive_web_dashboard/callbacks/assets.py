import io
import logging
from datetime import datetime
import pandas as pd
from dash import html, dcc, Input, Output, State, no_update, ctx, dash_table

from security_dashboard.components import build_asset_section
from security_dashboard.detail_panel import DetailPanelRenderer
from security_dashboard.filters import (
    analysis_completion_mask,
    analysis_error_mask,
    analysis_pending_mask,
    assign_asset_sections,
    prepare_filtered_assets,
)
from security_dashboard.theme import COLORS
from security_dashboard.data.datasets import ensure_ai_analysis_columns
from .shared import ASSET_TABLE_CONFIGS, TABLE_ID_MAP

logger = logging.getLogger(__name__)

def register_asset_callbacks(app) -> None:
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

        try:
            complete_mask = analysis_completion_mask(df)
            unmapped_mask = df["asset_section"].isna() & complete_mask & ~analysis_error_mask(df)
            if unmapped_mask.any():
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
                    logger.info("Reassigned %s unmapped completed rows.", reassigned)
        except Exception:
            logger.debug("Failed to apply fallback mapping.")

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

    @app.callback(
        Output("detail-overlay", "style"),
        Output("detail-body", "children"),
        Output("detail-asset-name", "children"),
        Output("detail-asset-id", "children"),
        Output("detail-ip-address", "children"),
        Output("detail-facing", "children"),
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
            return {"display": "none"}, [], "", "", "", "", "", "Open"

        df = pd.read_json(io.StringIO(json_data), orient="split")
        selected_asset_id = selected_asset.get("asset_id")
        if not selected_asset_id or "asset_id" not in df.columns or not (df["asset_id"] == selected_asset_id).any():
            return {"display": "none"}, [], "", "", "", "", "", "Open"

        row = df[df["asset_id"] == selected_asset_id].iloc[0]
        renderer = DetailPanelRenderer()
        children, asset_name, asset_id, ip_address, facing, scan_date, issue_status = renderer.render_detail_panel(row)
        ip_display = f"IP Address: {ip_address}"
        facing_display = f"Facing: {facing}"
        return {"display": "block"}, children, asset_name, asset_id, ip_display, facing_display, scan_date, issue_status

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

    @app.callback(
        Output("download-csv", "data"),
        Input("export-btn", "n_clicks"),
        State("merged-data-store", "data"),
        prevent_initial_call=True,
    )
    def export_csv(n, json_data):
        df = pd.read_json(io.StringIO(json_data), orient="split")
        from security_dashboard.data.datasets import AI_ANALYSIS_COLUMNS
        rename_map = {col: f"ai_{col}" for col in AI_ANALYSIS_COLUMNS if col in df.columns and not col.startswith("ai_")}
        if rename_map:
            df = df.rename(columns=rename_map)
        return dcc.send_data_frame(df.to_csv, f"security-report-{datetime.now().strftime('%Y-%m-%d')}.csv", index=False)

    @app.callback(
        Output("download-raw-tenable", "data"),
        Input("download-tenable-raw-btn", "n_clicks"),
        State("selected-asset-store", "data"),
        State("merged-data-store", "data"),
        prevent_initial_call=True,
    )
    def download_tenable_raw(n_clicks, selected_asset, json_data):
        if not n_clicks or not selected_asset or not json_data:
            return no_update
        df = pd.read_json(io.StringIO(json_data), orient="split")
        asset_id = selected_asset.get("asset_id")
        if not asset_id or "asset_id" not in df.columns or not (df["asset_id"] == asset_id).any():
            return no_update
        row = df[df["asset_id"] == asset_id].iloc[0]
        asset_name = row.get("asset_name", asset_id)
        
        import json
        raw_data = row.get("tenable_raw", [])
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                raw_data = []
        if not raw_data:
            return no_update
        
        raw_df = pd.DataFrame(raw_data)
        return dcc.send_data_frame(raw_df.to_csv, f"tenable-raw-{asset_name}.csv", index=False)

    @app.callback(
        Output("download-raw-splunk", "data"),
        Input("download-splunk-raw-btn", "n_clicks"),
        State("selected-asset-store", "data"),
        State("merged-data-store", "data"),
        prevent_initial_call=True,
    )
    def download_splunk_raw(n_clicks, selected_asset, json_data):
        if not n_clicks or not selected_asset or not json_data:
            return no_update
        df = pd.read_json(io.StringIO(json_data), orient="split")
        asset_id = selected_asset.get("asset_id")
        if not asset_id or "asset_id" not in df.columns or not (df["asset_id"] == asset_id).any():
            return no_update
        row = df[df["asset_id"] == asset_id].iloc[0]
        asset_name = row.get("asset_name", asset_id)
        
        import json
        raw_data = row.get("splunk_raw", [])
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                raw_data = []
        if not raw_data:
            return no_update
        
        raw_df = pd.DataFrame(raw_data)
        return dcc.send_data_frame(raw_df.to_csv, f"splunk-raw-{asset_name}.csv", index=False)
