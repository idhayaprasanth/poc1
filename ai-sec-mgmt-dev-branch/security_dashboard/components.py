"""
Reusable UI components for the security dashboard.
Builds KPI cards, risk badges, asset tables, and section containers.
"""

from dash import html, dash_table
import pandas as pd

from security_dashboard.theme import COLORS, CARD_STYLE, svg_icon, KPI_ICON_SVGS
from security_dashboard.filters import analysis_completion_mask


def kpi_card(title: str, value, color: str, icon_element) -> html.Div:
    """
    Build a KPI card with title, large value, and icon.
    
    Args:
        title: KPI label (e.g., "Total Assets")
        value: Numeric or string value to display
        color: Hex color for icon background tint
        icon_element: Dash component (usually html.Img) for icon
    
    Returns:
        Div component with card styling
    """
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
    ], style={**CARD_STYLE, "flex": "1", "minWidth": "200px"})


def risk_badge(level: str) -> html.Span:
    """
    Build a styled risk level badge.
    
    Args:
        level: Risk level string ("Critical", "High", "Medium", "Low")
    
    Returns:
        Span component with risk-appropriate colors
    """
    c = COLORS.get(level.lower(), COLORS["text_muted"])
    bg = COLORS.get(f"{level.lower()}_bg", COLORS["bg"])
    return html.Span(level, style={
        "background": bg, "color": c, "padding": "4px 10px",
        "borderRadius": "2px", "fontSize": "12px", "fontWeight": "700",
        "border": f"1px solid {COLORS['border']}",
    })


def patch_color(status: str) -> str:
    """
    Map patch status string to risk color.
    
    Args:
        status: Patch status ("Missing", "Pending", or other)
    
    Returns:
        Hex color code
    """
    return COLORS["high"] if status == "Missing" else COLORS["medium"] if status == "Pending" else COLORS["low"]


def get_asset_table_configs() -> list:
    """
    Get configuration dicts for asset risk level tables.
    
    Returns:
        List of config dicts with id, title, section, colors, and empty message
    """
    return [
        {
            "id": "asset-table-critical",
            "title": "Critical Risk Assets",
            "section": "critical",
            "accent": COLORS["high"],
            "background": COLORS["high_bg"],
            "empty": "No critical risk assets match the current filters.",
        },
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
    ]


def build_asset_table(table_id: str, df: pd.DataFrame) -> dash_table.DataTable:
    """
    Build a styled Dash DataTable for assets with risk-aware conditional formatting.
    
    Args:
        table_id: Unique ID for the table component
        df: Asset dataframe with vulnerability/threat/patch columns
    
    Returns:
        Dash DataTable component
    """
    cols_display = [
        "asset_id", "asset_name", "vuln_name", "threat_alert",
        "patch_status", "anomaly_score", "risk_score", "risk_level", "issue_status",
    ]

    col_names = {
        "asset_id": "Asset ID", "asset_name": "Hostname", "vuln_name": "Vulnerability",
        "threat_alert": "Threat", "patch_status": "Patch",
        "anomaly_score": "Anomaly", "risk_score": "Risk Score", "risk_level": "Level", "issue_status": "Issue Status",
    }

    # Filter to existing columns only
    existing_cols = [c for c in cols_display if c in df.columns]
    df = df.copy()

    # Sort by risk score descending
    if "risk_score" in df.columns:
        df["_risk_sort"] = pd.to_numeric(df["risk_score"], errors="coerce")
        df = df.sort_values("_risk_sort", ascending=False, na_position="last")
        df = df.drop(columns=["_risk_sort"])

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
            {"if": {"filter_query": '{risk_level} = "Critical"', "column_id": "risk_level"}, "color": COLORS["high"], "fontWeight": "700"},
            {"if": {"filter_query": '{risk_level} = "High"', "column_id": "risk_level"}, "color": COLORS["high"], "fontWeight": "700"},
            {"if": {"filter_query": '{risk_level} = "Medium"', "column_id": "risk_level"}, "color": COLORS["medium"], "fontWeight": "700"},
            {"if": {"filter_query": '{risk_level} = "Low"', "column_id": "risk_level"}, "color": COLORS["low"], "fontWeight": "700"},
            {"if": {"filter_query": '{issue_status} = "Open"', "column_id": "issue_status"}, "color": COLORS["high"], "fontWeight": "600"},
            {"if": {"filter_query": '{issue_status} = "In Progress"', "column_id": "issue_status"}, "color": COLORS["medium"], "fontWeight": "600"},
            {"if": {"filter_query": '{issue_status} = "Resolved"', "column_id": "issue_status"}, "color": COLORS["low"], "fontWeight": "600"},
            {"if": {"filter_query": '{patch_status} = "Missing"', "column_id": "patch_status"}, "color": COLORS["high"], "fontWeight": "600"},
            {"if": {"filter_query": '{patch_status} = "Pending"', "column_id": "patch_status"}, "color": COLORS["medium"], "fontWeight": "600"},
            {"if": {"state": "selected"}, "backgroundColor": COLORS["primary_light"], "border": "none"},
        ],
        style_as_list_view=True,
    )


def build_asset_section(config: dict, df: pd.DataFrame) -> html.Div:
    """
    Build a styled section container with table for one risk level.
    
    Args:
        config: Config dict with id, title, section, colors, empty message
        df: Asset dataframe filtered to this risk level
    
    Returns:
        Div component with header, count badge, and DataTable
    """
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
        style={**CARD_STYLE, "padding": "0", "overflow": "hidden"},
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
