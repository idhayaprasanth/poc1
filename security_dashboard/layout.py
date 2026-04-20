"""Dash layout for the security dashboard."""

from dash import dcc, html


def create_layout(df_base):
    from security_dashboard.dashboard import COLORS, card_style, close_svg

    return html.Div(
        style={
            "background": COLORS["bg"],
            "minHeight": "100vh",
            "fontFamily": "'Public Sans', -apple-system, sans-serif",
        },
        children=[
            dcc.Store(id="merged-data-store", data=df_base.to_json(date_format="iso", orient="split")),
            dcc.Store(id="analysis-request-store", data=None),
            dcc.Store(id="analysis-status-store", data={"state": "pending", "message": ""}),
            dcc.Store(id="selected-asset-store", data=None),
            dcc.Store(id="chat-history-store", data=[]),
            dcc.Interval(id="analysis-bootstrap", interval=100, n_intervals=0, max_intervals=1),
            html.Header(
                style={
                    "background": COLORS["card"],
                    "borderBottom": f"1px solid {COLORS['border']}",
                    "padding": "16px 32px",
                    "display": "flex",
                    "alignItems": "center",
                },
                children=[
                    html.Div(
                        style={"display": "flex", "alignItems": "center", "gap": "12px"},
                        children=[
                            html.Div(
                                "🛡️",
                                style={
                                    "fontSize": "22px",
                                    "width": "40px",
                                    "height": "40px",
                                    "borderRadius": "10px",
                                    "background": COLORS["primary"],
                                    "color": "white",
                                    "display": "flex",
                                    "alignItems": "center",
                                    "justifyContent": "center",
                                },
                            ),
                            html.Div(
                                [
                                    html.H1(
                                        "Unified Security Risk Dashboard",
                                        style={
                                            "fontSize": "18px",
                                            "fontWeight": "700",
                                            "margin": 0,
                                            "color": COLORS["text"],
                                        },
                                    ),
                                    html.P(
                                        "AI-driven threat analysis and prioritization",
                                        style={
                                            "fontSize": "12px",
                                            "color": COLORS["text_muted"],
                                            "margin": 0,
                                        },
                                    ),
                                ]
                            ),
                        ],
                    ),
                ],
            ),
            html.Main(
                style={"maxWidth": "1440px", "margin": "0 auto", "padding": "24px 32px"},
                children=[
                    html.Div(
                        id="kpi-cards",
                        style={"display": "flex", "gap": "16px", "marginBottom": "24px", "flexWrap": "wrap"},
                    ),
                    html.Div(id="analysis-status-banner", style={"marginBottom": "16px"}),
                    html.Div(
                        style={**card_style, "marginBottom": "24px"},
                        children=[
                            html.Div(
                                style={
                                    "display": "flex",
                                    "alignItems": "center",
                                    "justifyContent": "space-between",
                                    "marginBottom": "16px",
                                },
                                children=[
                                    html.H2(
                                        "Asset Risk Inventory",
                                        style={"fontSize": "16px", "fontWeight": "700", "margin": 0},
                                    ),
                                    html.Div(
                                        style={"display": "flex", "gap": "8px"},
                                        children=[
                                            html.Button(
                                                "📥 Export CSV",
                                                id="export-btn",
                                                style={
                                                    "background": COLORS["card"],
                                                    "border": f"1px solid {COLORS['border']}",
                                                    "borderRadius": "8px",
                                                    "padding": "8px 16px",
                                                    "cursor": "pointer",
                                                    "fontSize": "13px",
                                                },
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                            html.Div(
                                style={
                                    "display": "flex",
                                    "gap": "12px",
                                    "flexWrap": "wrap",
                                    "alignItems": "center",
                                },
                                children=[
                                    dcc.Input(
                                        id="search-input",
                                        type="text",
                                        placeholder="Search by hostname or ID...",
                                        style={
                                            "width": "240px",
                                            "height": "36px",
                                            "border": f"1px solid {COLORS['border']}",
                                            "borderRadius": "8px",
                                            "padding": "0 12px",
                                            "fontSize": "13px",
                                        },
                                    ),
                                    dcc.Dropdown(
                                        id="risk-filter",
                                        options=[
                                            {"label": "All Levels", "value": "All"},
                                            {"label": "High Risk", "value": "High"},
                                            {"label": "Medium Risk", "value": "Medium"},
                                            {"label": "Low Risk", "value": "Low"},
                                        ],
                                        value="All",
                                        clearable=False,
                                        style={"width": "160px", "fontSize": "13px"},
                                    ),
                                    dcc.Dropdown(
                                        id="sort-order",
                                        options=[
                                            {"label": "Default Order", "value": "default"},
                                            {"label": "Risk: High → Low", "value": "high-low"},
                                            {"label": "Risk: Low → High", "value": "low-high"},
                                        ],
                                        value="default",
                                        clearable=False,
                                        style={"width": "180px", "fontSize": "13px"},
                                    ),
                                    dcc.DatePickerRange(
                                        id="date-range",
                                        start_date_placeholder_text="From",
                                        end_date_placeholder_text="To",
                                        display_format="YYYY-MM-DD",
                                        style={
                                            "height": "36px",
                                            "border": f"1px solid {COLORS['border']}",
                                            "borderRadius": "8px",
                                            "padding": "0 8px",
                                            "fontSize": "13px",
                                        },
                                    ),
                                ],
                            ),
                        ],
                    ),
                    html.Div(id="asset-table-container", style=card_style),
                    html.Div(
                        style={**card_style, "marginTop": "24px"},
                        children=[
                            html.Div(
                                style={
                                    "display": "flex",
                                    "alignItems": "center",
                                    "justifyContent": "space-between",
                                    "marginBottom": "8px",
                                },
                                children=[
                                    html.H2(
                                        "SLA / Aging Tracker",
                                        style={"fontSize": "14px", "fontWeight": "700", "margin": 0},
                                    ),
                                    html.Span(
                                        "High: 3 days, Medium: 7 days",
                                        style={"fontSize": "12px", "color": COLORS["text_muted"]},
                                    ),
                                ],
                            ),
                            html.Div(id="sla-panel"),
                        ],
                    ),
                    html.Div(
                        id="detail-overlay",
                        style={"display": "none"},
                        children=[
                            html.Div(
                                id="detail-backdrop",
                                style={
                                    "position": "fixed",
                                    "top": 0,
                                    "left": 0,
                                    "right": 0,
                                    "bottom": 0,
                                    "background": "rgba(0,0,0,0.3)",
                                    "zIndex": 40,
                                },
                            ),
                            html.Div(
                                id="detail-panel",
                                style={
                                    "position": "fixed",
                                    "top": 0,
                                    "right": 0,
                                    "bottom": 0,
                                    "width": "100%",
                                    "maxWidth": "480px",
                                    "height": "100%",
                                    "background": COLORS["card"],
                                    "borderLeft": f"1px solid {COLORS['border']}",
                                    "boxShadow": "-10px 0 40px rgba(0,0,0,0.12)",
                                    "zIndex": 50,
                                    "overflowY": "auto",
                                    "transition": "transform 0.35s cubic-bezier(0.22, 1, 0.36, 1)",
                                    "transform": "translateX(0)",
                                    "padding": "10px 20px 20px 20px",
                                },
                                children=[
                                    html.Button(
                                        close_svg,
                                        id="detail-close-btn",
                                        n_clicks=0,
                                        style={
                                            "position": "absolute",
                                            "top": "10px",
                                            "right": "10px",
                                            "background": "transparent",
                                            "border": "none",
                                            "cursor": "pointer",
                                            "padding": "5px",
                                            "zIndex": 52,
                                        },
                                    ),
                                    html.Div(
                                        id="detail-panel-content",
                                        style={"padding": "12px 0 24px 0"},
                                        children=[
                                            html.Div(
                                                id="detail-header",
                                                style={
                                                    "display": "flex",
                                                    "position": "sticky",
                                                    "top": 0,
                                                    "zIndex": 51,
                                                    "background": COLORS["card"],
                                                    "borderBottom": f"1px solid {COLORS['border']}",
                                                    "padding": "20px 20px 16px",
                                                    "flexDirection": "column",
                                                    "gap": "6px",
                                                },
                                                children=[
                                                    html.Div(
                                                        style={
                                                            "display": "flex",
                                                            "justifyContent": "space-between",
                                                            "alignItems": "center",
                                                            "gap": "12px",
                                                        },
                                                        children=[
                                                            html.Div(
                                                                children=[
                                                                    html.H2(
                                                                        id="detail-asset-name",
                                                                        children="",
                                                                        style={
                                                                            "fontSize": "17px",
                                                                            "fontWeight": "800",
                                                                            "margin": 0,
                                                                            "color": COLORS["text"],
                                                                        },
                                                                    ),
                                                                    html.Span(
                                                                        id="detail-asset-id",
                                                                        children="",
                                                                        style={
                                                                            "fontSize": "11px",
                                                                            "fontFamily": "monospace",
                                                                            "color": COLORS["text_muted"],
                                                                            "display": "block",
                                                                            "marginTop": "4px",
                                                                        },
                                                                    ),
                                                                ]
                                                            ),
                                                            html.Div(
                                                                style={
                                                                    "display": "flex",
                                                                    "flexDirection": "column",
                                                                    "alignItems": "flex-end",
                                                                    "gap": "6px",
                                                                },
                                                                children=[
                                                                    html.Span(
                                                                        "Issue Status",
                                                                        style={
                                                                            "fontSize": "11px",
                                                                            "color": COLORS["text_muted"],
                                                                            "fontWeight": "600",
                                                                        },
                                                                    ),
                                                                    dcc.Dropdown(
                                                                        id="issue-status-dropdown",
                                                                        options=[
                                                                            {"label": "Open", "value": "Open"},
                                                                            {"label": "In Progress", "value": "In Progress"},
                                                                            {"label": "Resolved", "value": "Resolved"},
                                                                        ],
                                                                        value="Open",
                                                                        clearable=False,
                                                                        searchable=False,
                                                                        style={"width": "150px", "fontSize": "12px"},
                                                                    ),
                                                                    html.Button(
                                                                        "Update",
                                                                        id="issue-status-save",
                                                                        n_clicks=0,
                                                                        style={
                                                                            "background": COLORS["card"],
                                                                            "border": f"1px solid {COLORS['border']}",
                                                                            "borderRadius": "8px",
                                                                            "padding": "6px 12px",
                                                                            "cursor": "pointer",
                                                                            "fontSize": "12px",
                                                                            "fontWeight": "600",
                                                                            "color": COLORS["text_muted"],
                                                                            "marginTop": "6px",
                                                                            "width": "150px",
                                                                        },
                                                                    ),
                                                                ],
                                                            ),
                                                        ],
                                                    ),
                                                    html.Span(
                                                        id="detail-scan-date",
                                                        children="",
                                                        style={"fontSize": "11px", "color": COLORS["text_muted"]},
                                                    ),
                                                ],
                                            ),
                                            html.Div(
                                                id="detail-divider",
                                                style={
                                                    "height": "1px",
                                                    "backgroundColor": COLORS["border"],
                                                    "margin": "0 0 20px",
                                                },
                                            ),
                                            html.Div(id="detail-body"),
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    ),
                    dcc.Download(id="download-csv"),
                ],
            ),
            html.Div(
                id="chat-fab",
                n_clicks=0,
                children="🤖",
                style={
                    "position": "fixed",
                    "bottom": "44px",
                    "right": "34px",
                    "width": "56px",
                    "height": "56px",
                    "borderRadius": "50%",
                    "background": COLORS["primary"],
                    "color": "white",
                    "display": "flex",
                    "alignItems": "center",
                    "justifyContent": "center",
                    "fontSize": "24px",
                    "cursor": "pointer",
                    "boxShadow": "0 4px 16px rgba(0,0,0,0.2)",
                    "zIndex": 1001,
                },
            ),
            html.Div(
                id="chat-window",
                style={"display": "none"},
                children=[
                    html.Div(
                        style={
                            "position": "fixed",
                            "bottom": "90px",
                            "right": "24px",
                            "width": "380px",
                            "height": "480px",
                            "background": COLORS["card"],
                            "borderRadius": "16px",
                            "border": f"1px solid {COLORS['border']}",
                            "boxShadow": "0 8px 32px rgba(0,0,0,0.15)",
                            "zIndex": 1002,
                            "display": "flex",
                            "flexDirection": "column",
                            "overflow": "hidden",
                        },
                        children=[
                            html.Div(
                                style={
                                    "background": COLORS["primary"],
                                    "color": "white",
                                    "padding": "16px",
                                    "display": "flex",
                                    "alignItems": "center",
                                    "justifyContent": "space-between",
                                },
                                children=[
                                    html.Span(
                                        "🤖 AI Security Assistant",
                                        style={"fontWeight": "600", "fontSize": "14px"},
                                    ),
                                    html.Button(
                                        "✕",
                                        id="chat-close",
                                        n_clicks=0,
                                        style={
                                            "background": "transparent",
                                            "border": "none",
                                            "color": "white",
                                            "fontSize": "18px",
                                            "cursor": "pointer",
                                        },
                                    ),
                                ],
                            ),
                            html.Div(
                                id="chat-messages",
                                style={
                                    "flex": "1",
                                    "overflowY": "auto",
                                    "padding": "16px",
                                    "display": "flex",
                                    "flexDirection": "column",
                                    "gap": "8px",
                                },
                                children=[
                                    html.Div(
                                        "Hello! I'm your AI Security Assistant. Ask me about high-risk assets, remediation steps, or threat status.",
                                        style={
                                            "background": COLORS["primary_light"],
                                            "padding": "10px 14px",
                                            "borderRadius": "12px 12px 12px 4px",
                                            "fontSize": "13px",
                                            "color": COLORS["text"],
                                            "maxWidth": "85%",
                                        },
                                    )
                                ],
                            ),
                            html.Div(
                                style={
                                    "padding": "12px",
                                    "borderTop": f"1px solid {COLORS['border']}",
                                    "display": "flex",
                                    "gap": "8px",
                                },
                                children=[
                                    dcc.Input(
                                        id="chat-input",
                                        type="text",
                                        placeholder="Ask about security risks...",
                                        style={
                                            "flex": "1",
                                            "height": "36px",
                                            "border": f"1px solid {COLORS['border']}",
                                            "borderRadius": "8px",
                                            "padding": "0 12px",
                                            "fontSize": "13px",
                                        },
                                        debounce=False,
                                    ),
                                    html.Button(
                                        "Send",
                                        id="chat-send",
                                        n_clicks=0,
                                        style={
                                            "background": COLORS["primary"],
                                            "color": "white",
                                            "border": "none",
                                            "borderRadius": "8px",
                                            "padding": "0 16px",
                                            "cursor": "pointer",
                                            "fontSize": "13px",
                                            "fontWeight": "600",
                                        },
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            ),
        ],
    )
