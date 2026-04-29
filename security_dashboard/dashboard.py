"""
Unified Security Risk Dashboard — Python Dash Application
Merges data from Tenable.io, Microsoft Defender, Splunk, and IBM BigFix.
"""

import io
import base64
import logging
from datetime import datetime

import pandas as pd
from dash import Dash, html, dcc, dash_table, Input, Output, State, callback, no_update, ctx

from security_dashboard.config import get_ai_analysis_batch_size, load_env_file
from security_dashboard.data.datasets import (
    AI_ANALYSIS_COLUMNS,
    build_merged_dataset,
    coerce_ai_analysis_complete_series,
    ensure_ai_analysis_columns,
    persist_ai_analysis_result,
)
from security_dashboard.layout import create_layout
from security_dashboard.services.sagemaker_client import SageMakerClient

load_env_file()
AI_ANALYSIS_BATCH_SIZE = get_ai_analysis_batch_size()

# ── Build merged data ──
df_base = build_merged_dataset()
logger = logging.getLogger(__name__)

# ── USWDS 3–aligned palette (light theme; designsystem.digital.gov tokens) ──
COLORS = {
    "bg": "#f0f0f0",
    "card": "#ffffff",
    "border": "#dfe1e2",
    "primary": "#005ea2",
    "primary_dark": "#1a4480",
    "primary_light": "#d9e8f6",
    "primary_lighter": "#e7f6f8",
    "text": "#1b1b1b",
    "text_muted": "#565c65",
    "high": "#b50909",
    "high_bg": "#f4e3db",
    "medium": "#c05600",
    "medium_bg": "#faf3d1",
    "low": "#008817",
    "low_bg": "#ecf3ec",
    "info_bg": "#e7f6f8",
    "focus": "#2491ff",
}

primary_color = COLORS["primary"]
close_svg_str = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6L6 18"/><path d="M6 6l12 12"/></svg>'
close_svg_str = close_svg_str.replace('stroke="currentColor"', f'stroke="{primary_color}"')
close_encoded = base64.b64encode(close_svg_str.encode('utf-8')).decode('utf-8')
close_svg = html.Img(src=f"data:image/svg+xml;base64,{close_encoded}", style={"width": "20px", "height": "20px"})

app = Dash(
    __name__,
    suppress_callback_exceptions=True,
    external_stylesheets=[
        "https://fonts.googleapis.com/css2?family=Source+Sans+3:ital,wght@0,400;0,600;0,700;1,400&display=swap",
    ],
)
app.title = "Unified Security Risk Dashboard"

# ── Styles (USWDS-style cards: crisp border, minimal shadow) ──
card_style = {
    "background": COLORS["card"],
    "borderRadius": "4px",
    "padding": "24px",
    "border": f"1px solid {COLORS['border']}",
    "boxShadow": "0 2px 8px rgba(27, 27, 27, 0.06)",
}

def svg_icon(svg_str, stroke_color, size=20):
    svg_str = svg_str.replace('stroke="currentColor"', f'stroke="{stroke_color}"')
    encoded = base64.b64encode(svg_str.encode("utf-8")).decode("utf-8")
    return html.Img(
        src=f"data:image/svg+xml;base64,{encoded}",
        style={"width": f"{size}px", "height": f"{size}px", "display": "block"},
    )


KPI_ICON_SVGS = {
    "assets": '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>',
    "high": '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l7 3v6c0 5-3 9-7 11-4-2-7-6-7-11V5l7-3z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>',
    "medium": '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/></svg>',
    "low": '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="M22 4L12 14.01l-3-3"/></svg>',
}


def kpi_card(title, value, color, icon_element):
    return html.Div([
        html.Div(style={"display": "flex", "alignItems": "center", "justifyContent": "space-between", "gap": "14px"}, children=[
            html.Div(children=[
                html.Div(
                    title,
                    style={
                        "fontSize": "13px",
                        "fontWeight": "700",
                        "color": COLORS["text_muted"],
                        "textTransform": "uppercase",
                        "letterSpacing": "0.06em",
                    },
                ),
                html.Div(str(value), style={"fontSize": "32px", "fontWeight": "700", "color": COLORS["text"], "marginTop": "8px", "lineHeight": "1.1"}),
            ]),
            html.Div(style={
                "width": "48px", "height": "48px", "borderRadius": "4px",
                "display": "flex", "alignItems": "center", "justifyContent": "center",
                "background": color + "22",
                "border": f"1px solid {COLORS['border']}",
            }, children=[icon_element]),
        ]),
    ], style={**card_style, "flex": "1", "minWidth": "200px"})


def risk_badge(level):
    c = COLORS.get(level.lower(), COLORS["text_muted"])
    bg = COLORS.get(f"{level.lower()}_bg", COLORS["bg"])
    return html.Span(level, style={
        "background": bg, "color": c, "padding": "4px 10px",
        "borderRadius": "2px", "fontSize": "12px", "fontWeight": "700",
        "border": f"1px solid {COLORS['border']}",
    })

def patch_color(status):
    return COLORS["high"] if status == "Missing" else COLORS["medium"] if status == "Pending" else COLORS["low"]


ASSET_TABLE_CONFIGS = [
    {
        "id": "asset-table-high",
        "title": "High Risk Assets",
        "section": "high",
        "accent": COLORS["high"],
        "background": COLORS["high_bg"],
        "empty": "No high risk assets match the current filters.",
    },
    {
        "id": "asset-table-medium",
        "title": "Medium Risk Assets",
        "section": "medium",
        "accent": COLORS["medium"],
        "background": COLORS["medium_bg"],
        "empty": "No medium risk assets match the current filters.",
    },
    {
        "id": "asset-table-low",
        "title": "Low Risk Assets",
        "section": "low",
        "accent": COLORS["low"],
        "background": COLORS["low_bg"],
        "empty": "No low risk assets match the current filters.",
    },
]

TABLE_ID_MAP = {config["id"]: config for config in ASSET_TABLE_CONFIGS}
TABLE_IDS = [config["id"] for config in ASSET_TABLE_CONFIGS]


def analysis_is_complete(df):
    return not bool(analysis_pending_mask(ensure_ai_analysis_columns(df)).any())


def analysis_completion_mask(df):
    if "ai_analysis_complete" not in df.columns:
        return pd.Series([False] * len(df), index=df.index, dtype=bool)
    return coerce_ai_analysis_complete_series(df["ai_analysis_complete"])


def analysis_error_mask(df):
    if "ai_analysis_error" not in df.columns:
        return pd.Series([False] * len(df), index=df.index, dtype=bool)
    errors = df["ai_analysis_error"].astype("object")
    return errors.notna() & errors.astype(str).str.strip().ne("")


def analysis_pending_mask(df):
    return ~analysis_completion_mask(df) & ~analysis_error_mask(df)


def prepare_filtered_assets(df, search, risk_f, sort, date_from, date_to):
    df = df.copy()

    if search:
        q = search.lower().strip()
        if q:
            asset_name_series = df.get("asset_name", pd.Series(index=df.index, dtype=str)).fillna("").astype(str)
            asset_id_series = df.get("asset_id", pd.Series(index=df.index, dtype=str)).fillna("").astype(str)
            df = df[asset_name_series.str.lower().str.contains(q) | asset_id_series.str.lower().str.contains(q)]
    if risk_f and risk_f != "All":
        complete_mask = analysis_completion_mask(df)
        risk_matches = df.get("risk_level", pd.Series(index=df.index, dtype="object")).eq(risk_f)
        df = df[(~complete_mask) | risk_matches]
    if date_from:
        df = df[df["scan_date"] >= date_from]
    if date_to:
        df = df[df["scan_date"] <= date_to]
    if sort == "high-low":
        df = df.sort_values("risk_score", ascending=False, na_position="last")
    elif sort == "low-high":
        df = df.sort_values("risk_score", ascending=True, na_position="last")

    return df


def assign_asset_sections(df):
    df = df.copy()
    complete_mask = analysis_completion_mask(df)
    pending_analysis_mask = analysis_pending_mask(df)
    asset_bucket = (
        df.get("asset_bucket", pd.Series(index=df.index, dtype="object"))
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
    )
    risk_level = (
        df.get("risk_level", pd.Series(index=df.index, dtype="object"))
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
    )
    bucket_map = {
        "high risk": "high",
        "high": "high",
        "medium risk": "medium",
        "medium": "medium",
        "low risk": "low",
        "low": "low",
    }
    risk_map = {
        "high": "high",
        "medium": "medium",
        "low": "low",
    }
    mapped_from_bucket = asset_bucket.map(bucket_map)
    mapped_from_risk = risk_level.map(risk_map)
    df["asset_section"] = mapped_from_bucket.fillna(mapped_from_risk)

    # Ensure analyzed rows are always visible in a risk section.
    risk_scores = pd.to_numeric(df.get("risk_score", pd.Series(index=df.index, dtype="object")), errors="coerce")
    fallback_from_score = pd.Series(index=df.index, dtype="object")
    fallback_from_score.loc[risk_scores >= 75] = "high"
    fallback_from_score.loc[(risk_scores >= 45) & (risk_scores < 75)] = "medium"
    fallback_from_score.loc[risk_scores < 45] = "low"
    # Rows not waiting for AI (complete, or failed with error) get a risk bucket for main tables.
    not_waiting = ~pending_analysis_mask
    df.loc[not_waiting, "asset_section"] = (
        df.loc[not_waiting, "asset_section"].fillna(fallback_from_score.loc[not_waiting])
    )
    # Rows waiting for AI remain unmapped and are not shown in risk tables yet.
    df.loc[pending_analysis_mask, "asset_section"] = pd.NA

    # Debug visibility issues: analyzed rows that did not map to a visible section.
    unmapped_complete = complete_mask & df["asset_section"].isna()
    if bool(unmapped_complete.any()):
        sample = df.loc[unmapped_complete, ["asset_id", "asset_name", "asset_bucket", "risk_level"]].head(5)
        logger.warning(
            "Found %s analyzed row(s) with no asset_section mapping. Sample: %s",
            int(unmapped_complete.sum()),
            sample.to_dict("records"),
        )

    return df


def build_asset_table(table_id, df):
    cols_display = [
        "asset_id", "asset_name", "vuln_name", "vuln_severity", "threat_alert",
        "patch_status", "anomaly_score", "risk_score", "risk_level", "issue_status",
    ]
    has_ai = bool(analysis_completion_mask(df).any())
    if has_ai:
        cols_display += ["threat_status", "severity_validation", "priority", "remediation"]

    col_names = {
        "asset_id": "Asset ID", "asset_name": "Hostname", "vuln_name": "Vulnerability",
        "vuln_severity": "Severity", "threat_alert": "Threat", "patch_status": "Patch",
        "anomaly_score": "Anomaly", "risk_score": "Risk Score", "risk_level": "Level", "issue_status": "Issue Status",
        "threat_status": "Threat Status", "severity_validation": "Severity Check", "priority": "Priority", "remediation": "Remediation",
    }

    existing_cols = [c for c in cols_display if c in df.columns]
    table_frame = df[existing_cols].astype("object")
    table_data = table_frame.where(pd.notna(table_frame), "-").to_dict("records")

    return dash_table.DataTable(
        id=table_id,
        columns=[{"name": col_names.get(c, c), "id": c} for c in existing_cols],
        data=table_data,
        row_selectable="single",
        style_table={"overflowX": "auto"},
        style_header={
            "backgroundColor": COLORS["bg"],
            "fontWeight": "700",
            "fontSize": "12px",
            "textTransform": "uppercase",
            "letterSpacing": "0.04em",
            "color": COLORS["text_muted"],
            "border": "none",
            "borderBottom": f"2px solid {COLORS['border']}",
            "padding": "14px 16px",
        },
        style_cell={
            "fontSize": "15px",
            "padding": "12px 16px",
            "border": "none",
            "borderBottom": f"1px solid {COLORS['border']}",
            "textAlign": "left",
            "maxWidth": "180px",
            "overflow": "hidden",
            "textOverflow": "ellipsis",
            "fontFamily": '"Source Sans 3", "Source Sans Pro", sans-serif',
        },
        style_data_conditional=[
            {"if": {"filter_query": '{Severity} = "Immediate"', "column_id": "priority"}, "color": COLORS["high"], "fontWeight": "600"},
            {"if": {"filter_query": '{risk_level} = "High"', "column_id": "risk_level"}, "color": COLORS["high"], "fontWeight": "700"},
            {"if": {"filter_query": '{risk_level} = "Medium"', "column_id": "risk_level"}, "color": COLORS["medium"], "fontWeight": "700"},
            {"if": {"filter_query": '{risk_level} = "Low"', "column_id": "risk_level"}, "color": COLORS["low"], "fontWeight": "700"},
            {"if": {"filter_query": '{issue_status} = "Open"', "column_id": "issue_status"}, "color": COLORS["high"], "fontWeight": "600"},
            {"if": {"filter_query": '{issue_status} = "In Progress"', "column_id": "issue_status"}, "color": COLORS["medium"], "fontWeight": "600"},
            {"if": {"filter_query": '{issue_status} = "Resolved"', "column_id": "issue_status"}, "color": COLORS["low"], "fontWeight": "600"},
            {"if": {"filter_query": '{patch_status} = "Missing"', "column_id": "patch_status"}, "color": COLORS["high"], "fontWeight": "600"},
            {"if": {"filter_query": '{patch_status} = "Pending"', "column_id": "patch_status"}, "color": COLORS["medium"], "fontWeight": "600"},
            {"if": {"filter_query": '{threat_status} = "True Positive"', "column_id": "threat_status"}, "color": COLORS["high"], "fontWeight": "600"},
            {"if": {"filter_query": '{priority} = "Immediate"', "column_id": "priority"}, "color": COLORS["high"], "fontWeight": "600"},
            {"if": {"state": "selected"}, "backgroundColor": COLORS["primary_light"], "border": "none"},
        ],
        style_as_list_view=True,
    )


def build_asset_section(config, df):
    count = len(df)
    table = build_asset_table(config["id"], df)
    body_children = []
    if df.empty:
        body_children.append(
            html.Div(
                config["empty"],
                style={
                    "marginBottom": "12px",
                    "padding": "14px 16px",
                    "border": f"1px dashed {COLORS['border']}",
                    "borderRadius": "4px",
                    "color": COLORS["text_muted"],
                    "fontSize": "15px",
                    "background": COLORS["bg"],
                },
            )
        )
    body_children.append(table)

    return html.Div(
        style={**card_style, "padding": "0", "overflow": "hidden"},
        children=[
            html.Div(
                style={
                    "display": "flex",
                    "justifyContent": "space-between",
                    "alignItems": "center",
                    "gap": "12px",
                    "padding": "16px 20px",
                    "background": config["background"],
                    "borderBottom": f"1px solid {COLORS['border']}",
                },
                children=[
                    html.Div(
                        [
                            html.H3(
                                config["title"],
                                style={
                                    "margin": 0,
                                    "fontSize": "17px",
                                    "fontWeight": "700",
                                    "color": COLORS["text"],
                                    "lineHeight": "1.3",
                                },
                            ),
                            html.Div(
                                f"{count} assets",
                                style={"marginTop": "6px", "fontSize": "13px", "color": COLORS["text_muted"]},
                            ),
                        ]
                    ),
                    html.Div(
                        str(count),
                        style={
                            "minWidth": "40px",
                            "height": "40px",
                            "borderRadius": "4px",
                            "display": "flex",
                            "alignItems": "center",
                            "justifyContent": "center",
                            "fontWeight": "700",
                            "fontSize": "14px",
                            "color": config["accent"],
                            "background": COLORS["card"],
                            "border": f"2px solid {config['accent']}",
                        },
                    ),
                ],
            ),
            html.Div(style={"padding": "0 16px 16px"}, children=body_children),
        ],
    )


def build_initial_analysis_status_payload():
    """Match hydrate_dashboard_data status logic so the banner is correct on first paint."""
    df = ensure_ai_analysis_columns(df_base.copy())
    pending_count = int(analysis_pending_mask(df).sum())
    failed_count = int(analysis_error_mask(df).sum())
    if pending_count:
        return {
            "state": "running",
            "message": f"Running AI analysis for {pending_count} pending row(s)...",
        }
    if failed_count:
        return {
            "state": "warning",
            "message": f"{failed_count} row(s) previously failed AI analysis. Check the terminal logs.",
        }
    return {"state": "complete", "message": "AI analysis is up to date."}


app.layout = create_layout(df_base, analysis_status_initial=build_initial_analysis_status_payload())


# ── Callbacks ──

# Issue status update
@callback(
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


@callback(
    Output("selected-asset-store", "data"),
    Input("asset-table-high", "selected_rows"),
    Input("asset-table-medium", "selected_rows"),
    Input("asset-table-low", "selected_rows"),
    State("asset-table-high", "data"),
    State("asset-table-medium", "data"),
    State("asset-table-low", "data"),
    prevent_initial_call=True,
)
def sync_selected_asset(high_rows, medium_rows, low_rows, high_data, medium_data, low_data):
    triggered_table = ctx.triggered_id
    if triggered_table not in TABLE_ID_MAP:
        return None

    selections = {
        "asset-table-high": (high_rows, high_data),
        "asset-table-medium": (medium_rows, medium_data),
        "asset-table-low": (low_rows, low_data),
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


@callback(
    Output("analysis-request-store", "data"),
    Output("analysis-status-store", "data", allow_duplicate=True),
    Input("merged-data-store", "data"),
    Input("analysis-request-store", "data"),
    prevent_initial_call="initial_duplicate",
)
def queue_dashboard_analysis(json_data, current_request):
    df = ensure_ai_analysis_columns(pd.read_json(io.StringIO(json_data), orient="split"))
    pending = analysis_pending_mask(df)
    failed_count = int(analysis_error_mask(df).sum())
    if not pending.any():
        if failed_count:
            return no_update, {"state": "warning", "message": f"{failed_count} row(s) failed AI analysis and were skipped. Check the terminal logs."}
        return no_update, {"state": "complete", "message": "AI analysis is up to date."}
    if current_request:
        return no_update, no_update

    pending_assets = df.loc[pending, "asset_name"].fillna(df.loc[pending, "asset_id"]).tolist()
    if len(pending_assets) > 1:
        message = (
            f"Running AI analysis in batches of {AI_ANALYSIS_BATCH_SIZE} row(s). "
            f"{len(pending_assets)} row(s) pending."
        )
    else:
        message = f"Running AI analysis for {pending_assets[0]}..."
    return (
        {"requested_at": datetime.now().isoformat(), "pending_count": int(pending.sum())},
        {"state": "running", "message": message},
    )


@callback(
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

    df = ensure_ai_analysis_columns(pd.read_json(io.StringIO(json_data), orient="split"))
    pending = analysis_pending_mask(df)
    print(f"[dashboard] analysis run started pending_rows={int(pending.sum())}")
    if not pending.any():
        failed_count = int(analysis_error_mask(df).sum())
        if failed_count:
            return no_update, {"state": "warning", "message": f"{failed_count} row(s) failed AI analysis and were skipped. Check the terminal logs."}, None
        return no_update, {"state": "complete", "message": "AI analysis is up to date."}, None

    client = SageMakerClient()
    if not client.enabled():
        return (
            no_update,
            {
                "state": "error",
                "message": "SageMaker endpoint is not configured. Set SAGEMAKER_ENDPOINT_NAME.",
            },
            None,
        )

    # Process every pending row in this callback. Dash cannot reliably chain multiple
    # analysis cycles via Stores alone; looping here matches user expectation (all rows).
    batch_number = 0
    max_batches = max(64, len(df) // max(AI_ANALYSIS_BATCH_SIZE, 1) + 10)

    while analysis_pending_mask(df).any():
        pending = analysis_pending_mask(df)
        batch_number += 1
        print(
            "[dashboard] batch begin "
            f"batch={batch_number} remaining_rows={int(pending.sum())} batch_size={AI_ANALYSIS_BATCH_SIZE}"
        )
        if batch_number > max_batches:
            logger.error("AI analysis stopped after %s batch(es); possible loop guard.", max_batches)
            print(f"[dashboard] safety stop triggered at batch={batch_number} max_batches={max_batches}")
            break

        batch_indices = list(df.index[pending][:AI_ANALYSIS_BATCH_SIZE])
        batch_records = [df.loc[idx].to_dict() for idx in batch_indices]
        batch_assets = [
            str(record.get("asset_name") or record.get("asset_id") or f"row {idx + 1}")
            for idx, record in zip(batch_indices, batch_records)
        ]
        logger.info(
            "Starting AI analysis batch %s for %s row(s): %s",
            batch_number,
            len(batch_indices),
            ", ".join(batch_assets),
        )
        print(
            "[dashboard] sending batch "
            f"batch={batch_number} rows={len(batch_indices)} assets={', '.join(batch_assets)}"
        )

        try:
            batch_result = client.generate_dashboard_analysis(asset_records=batch_records)
        except Exception as exc:
            logger.exception("AI analysis batch failed")
            print(f"[dashboard] batch error batch={batch_number} error={type(exc).__name__}: {exc}")
            for idx in batch_indices:
                df.at[idx, "ai_analysis_error"] = str(exc)
            remaining_pending = analysis_pending_mask(df)
            remaining_count = int(remaining_pending.sum())
            print(
                "[dashboard] batch error status "
                f"batch={batch_number} remaining_rows={remaining_count}"
            )
            if not remaining_count:
                failed_count = int(analysis_error_mask(df).sum())
                return (
                    df.to_json(date_format="iso", orient="split"),
                    {
                        "state": "warning",
                        "message": (
                            f"AI analysis failed for the final batch of {len(batch_indices)} row(s). "
                            f"No more pending rows remain. {failed_count} row(s) failed in total. Check the terminal logs."
                        ),
                    },
                    None,
                )
            continue

        assets = (batch_result or {}).get("assets", []) if isinstance(batch_result, dict) else []

        index_to_record = {idx: record for idx, record in zip(batch_indices, batch_records)}
        unresolved_indices = set(batch_indices)
        id_to_indices = {}
        name_to_indices = {}
        for idx, record in index_to_record.items():
            asset_id = str(record.get("asset_id") or "").strip()
            asset_name = str(record.get("asset_name") or "").strip()
            if asset_id:
                id_to_indices.setdefault(asset_id, []).append(idx)
            if asset_name:
                name_to_indices.setdefault(asset_name, []).append(idx)

        completed_assets = []
        for ai_row in assets:
            if not isinstance(ai_row, dict):
                continue

            matched_idx = None
            ai_asset_id = str(ai_row.get("asset_id") or "").strip()
            ai_asset_name = str(ai_row.get("asset_name") or "").strip()

            if ai_asset_id and id_to_indices.get(ai_asset_id):
                matched_idx = id_to_indices[ai_asset_id].pop(0)
            elif ai_asset_name and name_to_indices.get(ai_asset_name):
                matched_idx = name_to_indices[ai_asset_name].pop(0)

            if matched_idx is None or matched_idx not in unresolved_indices:
                continue

            for col in AI_ANALYSIS_COLUMNS:
                value = ai_row.get(col)
                if col in ("risk_score", "anomaly_score"):
                    try:
                        value = int(float(value))
                    except Exception:
                        value = pd.NA
                df.at[matched_idx, col] = value

            df.at[matched_idx, "ai_analysis_complete"] = True
            df.at[matched_idx, "ai_analysis_error"] = pd.NA
            persist_ai_analysis_result(index_to_record[matched_idx], ai_row)

            asset_label = str(
                index_to_record[matched_idx].get("asset_name")
                or index_to_record[matched_idx].get("asset_id")
                or f"row {matched_idx + 1}"
            )
            completed_assets.append(asset_label)
            unresolved_indices.remove(matched_idx)

        for idx in unresolved_indices:
            df.at[idx, "ai_analysis_error"] = "No valid AI analysis returned for this row in the current batch."
            unresolved_record = index_to_record.get(idx, {})
            print(
                "[dashboard] unresolved row "
                f"batch={batch_number} asset_id={unresolved_record.get('asset_id')} asset_name={unresolved_record.get('asset_name')}"
            )

        logger.info(
            "Completed AI analysis batch %s. Success=%s, Failed=%s",
            batch_number,
            len(completed_assets),
            len(unresolved_indices),
        )
        remaining_after_batch = int(analysis_pending_mask(df).sum())
        print(
            "[dashboard] batch complete "
            f"batch={batch_number} success={len(completed_assets)} failed={len(unresolved_indices)} "
            f"remaining_rows={remaining_after_batch}"
        )

    if analysis_pending_mask(df).any():
        pending_left = int(analysis_pending_mask(df).sum())
        logger.warning("AI analysis stopped with %s row(s) still pending (safety limit).", pending_left)
        print(f"[dashboard] analysis stopped with pending_rows={pending_left}")
        return (
            df.to_json(date_format="iso", orient="split"),
            {
                "state": "warning",
                "message": (
                    f"AI analysis stopped after {batch_number} batch(es) with {pending_left} row(s) still pending. "
                    "Try again or check the terminal logs."
                ),
            },
            None,
        )
    failed_count = int(analysis_error_mask(df).sum())
    if failed_count:
        print(f"[dashboard] analysis completed with failures failed_rows={failed_count}")
        status = {
            "state": "warning",
            "message": (
                f"AI analysis completed for all remaining rows. {failed_count} row(s) failed and were skipped. "
                "Check the terminal logs."
            ),
        }
    else:
        print("[dashboard] analysis completed successfully with no failed rows")
        status = {"state": "complete", "message": "AI analysis completed for all assets."}

    return df.to_json(date_format="iso", orient="split"), status, None


@callback(
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
@callback(Output("kpi-cards", "children"), Input("merged-data-store", "data"))
def update_kpis(json_data):
    df = ensure_ai_analysis_columns(pd.read_json(io.StringIO(json_data), orient="split"))
    total_assets = len(df)
    complete_mask = analysis_completion_mask(df)
    if not complete_mask.any():
        return [
            kpi_card("Total Assets", total_assets, COLORS["primary"], svg_icon(KPI_ICON_SVGS["assets"], COLORS["primary"], size=22)),
            kpi_card("High Risk", "Pending", COLORS["high"], svg_icon(KPI_ICON_SVGS["high"], COLORS["high"], size=22)),
            kpi_card("Medium Risk", "Pending", COLORS["medium"], svg_icon(KPI_ICON_SVGS["medium"], COLORS["medium"], size=22)),
            kpi_card("Low Risk", "Pending", COLORS["low"], svg_icon(KPI_ICON_SVGS["low"], COLORS["low"], size=22)),
        ]
    df = df.loc[complete_mask].copy()
    high = len(df[df["risk_level"] == "High"])
    med = len(df[df["risk_level"] == "Medium"])
    low = len(df[df["risk_level"] == "Low"])
    return [
        kpi_card("Total Assets", total_assets, COLORS["primary"], svg_icon(KPI_ICON_SVGS["assets"], COLORS["primary"], size=22)),
        kpi_card("High Risk", high, COLORS["high"], svg_icon(KPI_ICON_SVGS["high"], COLORS["high"], size=22)),
        kpi_card("Medium Risk", med, COLORS["medium"], svg_icon(KPI_ICON_SVGS["medium"], COLORS["medium"], size=22)),
        kpi_card("Low Risk", low, COLORS["low"], svg_icon(KPI_ICON_SVGS["low"], COLORS["low"], size=22)),
    ]


# SLA / aging tracker
@callback(Output("sla-panel", "children"), Input("merged-data-store", "data"))
def update_sla_panel(json_data):
    df = pd.read_json(io.StringIO(json_data), orient="split")
    if not analysis_is_complete(df):
        return html.Div(
            "SLA tracking will appear after AI analysis completes for all assets.",
            style={"fontSize": "15px", "color": COLORS["text_muted"], "lineHeight": "1.5"},
        )
    today = pd.Timestamp.now().normalize()

    first_seen = pd.to_datetime(df.get("scan_date"), errors="coerce")
    first_seen = first_seen.fillna(today)
    age_days = (today - first_seen).dt.days.clip(lower=0)

    status = df.get("issue_status", pd.Series(["Open"] * len(df))).fillna("Open")
    risk = df.get("risk_level", pd.Series(["Low"] * len(df))).fillna("Low")

    sla_days = risk.map({"High": 3, "Medium": 7})
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

    return html.Div([
        html.Div(style={"display": "flex", "gap": "12px", "flexWrap": "wrap"}, children=[
            stat_box("Open", open_count, COLORS["high"] if open_count else COLORS["low"], COLORS["card"]),
            stat_box("In Progress", in_progress_count, COLORS["medium"] if in_progress_count else COLORS["low"], COLORS["card"]),
            stat_box("SLA Breached", breached_count, COLORS["high"] if breached_count else COLORS["low"], COLORS["high_bg"] if breached_count else COLORS["low_bg"]),
        ]),
        breached_list,
    ])
# Filtered tables
@callback(
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
    failed_mask = analysis_error_mask(df)
    pending_analysis_mask = analysis_pending_mask(df)
    pending_count = int(pending_analysis_mask.sum())
    failed_count = int(failed_mask.sum())

    children = []
    if pending_count:
        return html.Div(
            "AI analysis running...",
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
    if failed_count:
        children.append(
            html.Div(
                f"{failed_count} row(s) have AI analysis errors (listed in the risk tables below). Retry analysis when ready. Check the terminal output for the full error.",
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
    for config in ASSET_TABLE_CONFIGS:
        section_df = df[(df["asset_section"] == config["section"]) & (~pending_analysis_mask)].copy()
        sections.append(build_asset_section(config, section_df))
    children.append(html.Div(style={"display": "grid", "gap": "24px"}, children=sections))
    return html.Div(style={"display": "grid", "gap": "20px"}, children=children)


# Detail panel
@callback(
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

    primary_color = COLORS["primary"]

    bug_svg_str = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20v-9"/><path d="M14 7a4 4 0 0 1 4 4v3a6 6 0 0 1-12 0v-3a4 4 0 0 1 4-4z"/><path d="M14.12 3.88 16 2"/><path d="M21 21a4 4 0 0 0-3.81-4"/><path d="M21 5a4 4 0 0 1-3.55 3.97"/><path d="M22 13h-4"/><path d="M3 21a4 4 0 0 1 3.81-4"/><path d="M3 5a4 4 0 0 0 3.55 3.97"/><path d="M6 13H2"/><path d="m8 2 1.88 1.88"/><path d="M9 7.13V6a3 3 0 1 1 6 0v1.13"/></svg>'
    bug_svg_str = bug_svg_str.replace('stroke="currentColor"', f'stroke="{primary_color}"')
    bug_encoded = base64.b64encode(bug_svg_str.encode('utf-8')).decode('utf-8')
    bug_svg = html.Img(src=f"data:image/svg+xml;base64,{bug_encoded}", style={"width": "16px", "height": "16px", "display": "inline-flex", "alignItems": "center", "justifyContent": "center"})

    shield_svg_str = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'
    shield_svg_str = shield_svg_str.replace('stroke="currentColor"', f'stroke="{primary_color}"')
    shield_encoded = base64.b64encode(shield_svg_str.encode('utf-8')).decode('utf-8')
    shield_svg = html.Img(src=f"data:image/svg+xml;base64,{shield_encoded}", style={"width": "16px", "height": "16px", "display": "inline-flex", "alignItems": "center", "justifyContent": "center"})

    chart_svg_str = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" x2="12" y1="20" y2="10"/><line x1="18" x2="18" y1="20" y2="4"/><line x1="6" x2="6" y1="20" y2="16"/></svg>'
    chart_svg_str = chart_svg_str.replace('stroke="currentColor"', f'stroke="{primary_color}"')
    chart_encoded = base64.b64encode(chart_svg_str.encode('utf-8')).decode('utf-8')
    chart_svg = html.Img(src=f"data:image/svg+xml;base64,{chart_encoded}", style={"width": "16px", "height": "16px", "display": "inline-flex", "alignItems": "center", "justifyContent": "center"})

    disk_svg_str = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" x2="2" y1="12" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" x2="6.01" y1="16" y2="16"/><line x1="10" x2="10.01" y1="16" y2="16"/></svg>'
    disk_svg_str = disk_svg_str.replace('stroke="currentColor"', f'stroke="{primary_color}"')
    disk_encoded = base64.b64encode(disk_svg_str.encode('utf-8')).decode('utf-8')
    disk_svg = html.Img(src=f"data:image/svg+xml;base64,{disk_encoded}", style={"width": "16px", "height": "16px", "display": "inline-flex", "alignItems": "center", "justifyContent": "center"})

    brain_svg_str = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44 2.5 2.5 0 0 1-4.96-.44V8.5A2.5 2.5 0 0 1 4.5 6a2.5 2.5 0 0 1 2.5 2.5V6A2.5 2.5 0 0 1 9.5 3.5a2.5 2.5 0 0 1 2.5 2.5v.5A2.5 2.5 0 0 1 9.5 8.5a2.5 2.5 0 0 1 2.5-2.5V6a2.5 2.5 0 0 1 2.5 2.5v11.5a2.5 2.5 0 0 1-4.96.44 2.5 2.5 0 0 1-4.96-.44V8.5A2.5 2.5 0 0 1 9.5 6a2.5 2.5 0 0 1 2.5 2.5"/></svg>'
    brain_svg_str = brain_svg_str.replace('stroke="currentColor"', f'stroke="{primary_color}"')
    brain_encoded = base64.b64encode(brain_svg_str.encode('utf-8')).decode('utf-8')
    brain_svg = html.Img(src=f"data:image/svg+xml;base64,{brain_encoded}", style={"width": "16px", "height": "16px", "display": "inline-flex", "alignItems": "center", "justifyContent": "center"})

    section_icons = {
        "Vulnerability (Tenable.io)": bug_svg,
        "Threat (Microsoft Defender)": shield_svg,
        "Logs & Anomaly (Splunk)": chart_svg,
        "Patch Status (IBM BigFix)": disk_svg,
        "AI Analysis": brain_svg,
    }

    def field_row(label, value, highlight=False):
        font_size = "14px" if label == "Score" else "15px"
        return html.Div(style={"display": "flex", "gap": "8px", "alignItems": "flex-start"}, children=[
            html.Span(f"{label}:", style={"fontSize": font_size, "color": COLORS["text_muted"], "minWidth": "80px", "fontWeight": "600"}),
            html.Span(str(value), style={"fontSize": font_size, "color": COLORS["high"] if highlight else COLORS["text"], "fontWeight": "600" if highlight else "500", "lineHeight": "1.4"}),
        ])

    def section(title, fields):
        icon = section_icons.get(title, "")
        icon_element = icon
        return html.Div(style={"marginBottom": "20px"}, children=[
            html.Div(style={"display": "flex", "alignItems": "center", "gap": "8px", "marginBottom": "10px"}, children=[
                icon_element,
                html.Span(title, style={"fontSize": "14px", "fontWeight": "700", "color": COLORS["text"]}),
            ]),
            html.Div(style={"marginLeft": "24px", "display": "flex", "flexDirection": "column", "gap": "6px"}, children=[
                field_row(k, v, highlight=(k == "Severity" or k in ["Alert", "Status"] or (k == "Score" and isinstance(v, (int, float)) and v > 70))) for k, v in fields.items()
            ])
        ])

    risk_value = row.get("risk_score", None)
    risk_value = None if pd.isna(risk_value) else risk_value
    risk_level_value = row.get("risk_level", "")
    risk_level_value = "" if pd.isna(risk_level_value) else risk_level_value

    risk_color = COLORS["high"] if risk_level_value == "High" else COLORS["medium"] if risk_level_value == "Medium" else COLORS["low"]
    scan_date_value = pd.to_datetime(row.get("scan_date"), errors="coerce")
    scan_date_text = scan_date_value.strftime("%Y-%m-%d") if not pd.isna(scan_date_value) else "—"

    risk_styles = {
        "High": {"bg": COLORS["high_bg"], "border": COLORS["high"], "text": COLORS["high"], "badgeBg": COLORS["high"], "badgeText": "white"},
        "Medium": {"bg": COLORS["medium_bg"], "border": COLORS["medium"], "text": COLORS["medium"], "badgeBg": COLORS["medium"], "badgeText": "white"},
        "Low": {"bg": COLORS["low_bg"], "border": COLORS["low"], "text": COLORS["low"], "badgeBg": COLORS["low"], "badgeText": "white"},
    }
    risk_style = risk_styles.get(risk_level_value or "Low", risk_styles["Low"])
    risk_score_text = "—" if risk_value is None else f"{int(risk_value)}/100"
    risk_level_text = "Risk Pending" if not risk_level_value else f"{risk_level_value} Risk"

    children = [
        html.Div(style={"background": risk_style["bg"], "borderLeft": f"4px solid {risk_style['border']}", "borderTop": f"1px solid {COLORS['border']}", "borderRight": f"1px solid {COLORS['border']}", "borderBottom": f"1px solid {COLORS['border']}", "borderRadius": "4px", "padding": "20px", "marginBottom": "20px", "display": "flex", "justifyContent": "space-between", "alignItems": "center", "gap": "12px"}, children=[
            html.Div(children=[
                html.Span("Risk Score", style={"display": "block", "fontSize": "13px", "fontWeight": "700", "color": COLORS["text_muted"], "textTransform": "uppercase", "letterSpacing": "0.05em"}),
                html.Span(risk_score_text, style={"fontSize": "32px", "fontWeight": "700", "color": risk_style["text"], "lineHeight": "1.1"}),
            ]),
            html.Span(risk_level_text, style={"padding": "8px 14px", "borderRadius": "4px", "fontSize": "13px", "fontWeight": "700", "background": risk_style["badgeBg"], "color": risk_style["badgeText"]}),
        ]),
        section("Vulnerability (Tenable.io)", {
            "Name": row.get("vuln_name", "—"),
            "Severity": row.get("vuln_severity", "—"),
            "Description": row.get("vuln_description", "—"),
            "Fix": row.get("vuln_fix", "—"),
        }),
        section("Threat (Microsoft Defender)", {
            "Alert": row.get("threat_alert", "—"),
            "File Path": row.get("threat_file_path", "—"),
            "Process": row.get("threat_process", "—"),
            "Impact": row.get("threat_impact", "—"),
            "Fix": row.get("threat_fix", "—"),
        }),
        section("Logs & Anomaly (Splunk)", {
            "Event": row.get("anomaly_event", "—"),
            "Score": row.get("source_anomaly_score", "—"),
            "Details": row.get("anomaly_explanation", "—"),
        }),
        section("Patch Status (IBM BigFix)", {
            "Status": row.get("patch_status", "—"),
            "Severity": row.get("patch_severity", "—"),
            "Action": row.get("patch_recommendation", "—"),
            "Issue Status": row.get("issue_status", "—"),
        }),
    ]

    if pd.notna(row.get("threat_status")):
        children.append(section("AI Analysis", {
            "Source": row.get("ai_analysis_source", "—"),
            "Threat Decision": row.get("threat_status", "—"),
            "Severity Check": row.get("severity_validation", "—"),
            "Priority": row.get("priority", "—"),
            "AI Anomaly Score": row.get("anomaly_score", "—"),
            "Reason": row.get("ai_reason", "—"),
            "Overall Remediation": row.get("remediation", "—"),
            "Tenable Remediation": row.get("tenable_remediation", "—"),
            "Defender Remediation": row.get("defender_remediation", "—"),
            "Splunk Remediation": row.get("splunk_remediation", "—"),
            "BigFix Remediation": row.get("bigfix_remediation", "—"),
        }))

    issue_status = row.get("issue_status", "Open")
    if issue_status not in ["Open", "In Progress", "Resolved"]:
        issue_status = "Open"

    return (
        {"display": "block"},
        children,
        row.get("asset_name", ""),
        row.get("asset_id", ""),
        f"Last scan date: {scan_date_text}",
        issue_status,
    )


@callback(
    Output("asset-table-high", "selected_rows"),
    Output("asset-table-medium", "selected_rows"),
    Output("asset-table-low", "selected_rows"),
    Output("selected-asset-store", "data", allow_duplicate=True),
    Input("detail-backdrop", "n_clicks"),
    Input("detail-close-btn", "n_clicks"),
    prevent_initial_call=True,
)
def clear_detail_selection(backdrop_clicks, close_clicks):
    return [], [], [], None


# Export CSV
@callback(
    Output("download-csv", "data"),
    Input("export-btn", "n_clicks"),
    State("merged-data-store", "data"),
    prevent_initial_call=True,
)
def export_csv(n, json_data):
    df = pd.read_json(io.StringIO(json_data), orient="split")
    return dcc.send_data_frame(df.to_csv, f"security-report-{datetime.now().strftime('%Y-%m-%d')}.csv", index=False)


# Chat toggle
@callback(
    Output("chat-window", "style"),
    Input("chat-fab", "n_clicks"),
    Input("chat-close", "n_clicks"),
    State("chat-window", "style"),
    prevent_initial_call=True,
)
def toggle_chat(fab_clicks, close_clicks, current):
    from dash import ctx
    if not isinstance(current, dict):
        current = {"display": "none"}
    if ctx.triggered_id == "chat-close":
        return {"display": "none"}
    if current.get("display") == "none":
        return {"display": "block"}
    return {"display": "none"}


# Chat responses
@callback(
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

    df = pd.read_json(io.StringIO(json_data), orient="split")
    current_msgs = current_msgs or []
    history = history or []

    if not analysis_is_complete(df):
        user_bubble = html.Div(user_msg, style={
            "background": COLORS["primary"], "color": "white", "padding": "12px 14px",
            "borderRadius": "4px", "fontSize": "15px", "alignSelf": "flex-end", "maxWidth": "85%"
        })
        bot_bubble = html.Div("AI dashboard analysis is still running. Please try again after it finishes.", style={
            "background": COLORS["primary_light"], "padding": "12px 14px",
            "borderRadius": "4px", "fontSize": "15px",
            "color": COLORS["text"], "maxWidth": "85%", "border": f"1px solid {COLORS['border']}",
        })
        return current_msgs + [user_bubble, bot_bubble], "", history

    h = int((df.get("risk_level") == "High").sum()) if "risk_level" in df.columns else 0
    m = int((df.get("risk_level") == "Medium").sum()) if "risk_level" in df.columns else 0
    lo = int((df.get("risk_level") == "Low").sum()) if "risk_level" in df.columns else 0

    top = df.nlargest(5, "risk_score") if "risk_score" in df.columns and not df.empty else df.head(5)
    lines = []
    for _, r in top.iterrows():
        lines.append(
            f"- {r.get('asset_id','')} {r.get('asset_name','')}: {r.get('risk_score','—')}/100 "
            f"({r.get('risk_level','—')}), issue={r.get('issue_status','—')}, patch={r.get('patch_status','—')}, "
            f"vuln={r.get('vuln_severity','—')} {r.get('vuln_name','—')}, threat={r.get('threat_alert','—')}"
        )

    context_text = (
        f"Summary: total_assets={len(df)}, high={h}, medium={m}, low={lo}.\n"
        f"Top assets by risk_score:\n" + "\n".join(lines)
    )

    client = SageMakerClient()
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
