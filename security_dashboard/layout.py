"""Dash layout for the security dashboard."""

from dash import dcc, html


def create_layout(df_base, analysis_status_initial=None):
    from security_dashboard.dashboard import COLORS, card_style, close_svg

    if analysis_status_initial is None:
        analysis_status_initial = {"state": "pending", "message": ""}

    return html.Div(
        className="dash-uswds",
        style={
            "background": COLORS["bg"],
            "minHeight": "100vh",
            "fontFamily": '"Source Sans 3", "Source Sans Pro", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
        },
        children=[
            dcc.Store(id="merged-data-store", data=df_base.to_json(date_format="iso", orient="split")),
            dcc.Store(id="analysis-request-store", data=None),
            dcc.Store(id="analysis-status-store", data=analysis_status_initial),
            dcc.Store(id="selected-asset-store", data=None),
            dcc.Store(id="chat-history-store", data=[]),
            html.Header(
                style={
                    "background": COLORS["card"],
                    "borderTop": f"4px solid {COLORS['primary']}",
                    "borderBottom": f"1px solid {COLORS['border']}",
                    "boxShadow": "0 2px 8px rgba(27, 27, 27, 0.06)",
                },
                children=[
                    html.Div(
                        style={
                            "maxWidth": "87.5rem",
                            "margin": "0 auto",
                            "padding": "20px 24px",
                            "display": "flex",
                            "alignItems": "center",
                            "justifyContent": "space-between",
                            "flexWrap": "wrap",
                            "gap": "16px",
                        },
                        children=[
                    html.Div(
                        style={"display": "flex", "alignItems": "center", "gap": "20px", "flex": "1", "minWidth": "280px"},
                        children=[
                            html.Img(
                                src=(
                                    "https://th.bing.com/th/id/OIP.Dl6ZSeYEI2zcqRpiPU04OwAAAA"
                                    "?w=400&h=170&c=7&o=7&dpr=1.5&pid=1.7&rm=3"
                                ),
                                alt="FUTREND Technology",
                                style={
                                    "height": "56px",
                                    "width": "auto",
                                    "maxWidth": "min(100%, 420px)",
                                    "objectFit": "contain",
                                    "objectPosition": "left center",
                                    "display": "block",
                                },
                            ),
                            html.Div(
                                [
                                    html.P(
                                        "Federal design system · light theme",
                                        style={
                                            "fontSize": "11px",
                                            "fontWeight": "700",
                                            "textTransform": "uppercase",
                                            "letterSpacing": "0.08em",
                                            "color": COLORS["primary"],
                                            "margin": "0 0 6px 0",
                                        },
                                    ),
                                    html.H1(
                                        "Unified Security Risk Dashboard",
                                        style={
                                            "fontSize": "22px",
                                            "fontWeight": "700",
                                            "lineHeight": "1.25",
                                            "margin": 0,
                                            "color": COLORS["text"],
                                        },
                                    ),
                                    html.P(
                                        "AI-driven threat analysis and prioritization across Tenable, Defender, Splunk, and BigFix",
                                        style={
                                            "fontSize": "15px",
                                            "color": COLORS["text_muted"],
                                            "margin": "8px 0 0 0",
                                            "maxWidth": "36rem",
                                            "lineHeight": "1.45",
                                        },
                                    ),
                                ]
                            ),
                        ],
                    ),
                    html.Span(
                        "USWDS-aligned",
                        style={
                            "fontSize": "12px",
                            "fontWeight": "700",
                            "color": COLORS["text_muted"],
                            "border": f"1px solid {COLORS['border']}",
                            "padding": "6px 12px",
                            "borderRadius": "4px",
                            "background": COLORS["bg"],
                            "whiteSpace": "nowrap",
                        },
                    ),
                        ],
                    ),
                ],
            ),
            html.Main(
                className="dash-uswds-main",
                style={"maxWidth": "87.5rem", "margin": "0 auto", "padding": "24px 24px 48px"},
                children=[
                    html.Div(
                        id="kpi-cards",
                        style={"display": "flex", "gap": "20px", "marginBottom": "28px", "flexWrap": "wrap"},
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
                                    "marginBottom": "20px",
                                    "flexWrap": "wrap",
                                    "gap": "12px",
                                },
                                children=[
                                    html.H2(
                                        "Asset Risk Inventory",
                                        style={
                                            "fontSize": "20px",
                                            "fontWeight": "700",
                                            "margin": 0,
                                            "color": COLORS["text"],
                                            "lineHeight": "1.3",
                                        },
                                    ),
                                    html.Div(
                                        style={"display": "flex", "gap": "8px"},
                                        children=[
                                            html.Button(
                                                "Export CSV",
                                                id="export-btn",
                                                style={
                                                    "background": COLORS["card"],
                                                    "color": COLORS["primary"],
                                                    "border": f"2px solid {COLORS['primary']}",
                                                    "borderRadius": "4px",
                                                    "padding": "10px 20px",
                                                    "cursor": "pointer",
                                                    "fontSize": "15px",
                                                    "fontWeight": "700",
                                                    "fontFamily": "inherit",
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
                                        className="dash-uswds",
                                        style={
                                            "width": "260px",
                                            "height": "40px",
                                            "border": f"1px solid {COLORS['border']}",
                                            "borderRadius": "4px",
                                            "padding": "0 12px",
                                            "fontSize": "15px",
                                            "fontFamily": "inherit",
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
                                        style={"width": "170px", "fontSize": "15px"},
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
                                        style={"width": "200px", "fontSize": "15px"},
                                    ),
                                    dcc.DatePickerRange(
                                        id="date-range",
                                        start_date_placeholder_text="From",
                                        end_date_placeholder_text="To",
                                        display_format="YYYY-MM-DD",
                                        style={
                                            "height": "40px",
                                            "border": f"1px solid {COLORS['border']}",
                                            "borderRadius": "4px",
                                            "padding": "0 8px",
                                            "fontSize": "15px",
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
                                        style={"fontSize": "17px", "fontWeight": "700", "margin": 0, "color": COLORS["text"]},
                                    ),
                                    html.Span(
                                        "Targets: High 3 days · Medium 7 days",
                                        style={"fontSize": "13px", "color": COLORS["text_muted"], "fontWeight": "600"},
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
                                    "borderLeft": f"4px solid {COLORS['primary']}",
                                    "boxShadow": "-8px 0 32px rgba(27,27,27,0.12)",
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
                                                                        "Save status",
                                                                        id="issue-status-save",
                                                                        n_clicks=0,
                                                                        style={
                                                                            "background": COLORS["primary"],
                                                                            "border": "none",
                                                                            "borderRadius": "4px",
                                                                            "padding": "10px 12px",
                                                                            "cursor": "pointer",
                                                                            "fontSize": "15px",
                                                                            "fontWeight": "700",
                                                                            "color": "#ffffff",
                                                                            "marginTop": "8px",
                                                                            "width": "150px",
                                                                            "fontFamily": "inherit",
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
                children="💬",
                title="Open AI assistant",
                style={
                    "position": "fixed",
                    "bottom": "40px",
                    "right": "28px",
                    "width": "56px",
                    "height": "56px",
                    "borderRadius": "4px",
                    "background": COLORS["primary"],
                    "color": "white",
                    "display": "flex",
                    "alignItems": "center",
                    "justifyContent": "center",
                    "fontSize": "22px",
                    "cursor": "pointer",
                    "boxShadow": "0 4px 12px rgba(0, 94, 162, 0.35)",
                    "zIndex": 1001,
                    "border": f"2px solid {COLORS['primary_dark']}",
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
                            "height": "500px",
                            "background": COLORS["card"],
                            "borderRadius": "4px",
                            "border": f"1px solid {COLORS['border']}",
                            "boxShadow": "0 8px 24px rgba(27,27,27,0.12)",
                            "zIndex": 1002,
                            "display": "flex",
                            "flexDirection": "column",
                            "overflow": "hidden",
                        },
                        children=[
                            html.Div(
                                style={
                                    "background": COLORS["primary_dark"],
                                    "color": "white",
                                    "padding": "14px 16px",
                                    "display": "flex",
                                    "alignItems": "center",
                                    "justifyContent": "space-between",
                                    "borderBottom": f"1px solid rgba(255,255,255,0.2)",
                                },
                                children=[
                                    html.Span(
                                        "AI Security Assistant",
                                        style={"fontWeight": "700", "fontSize": "16px", "letterSpacing": "0.02em"},
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
                                            "padding": "12px 14px",
                                            "borderRadius": "4px",
                                            "fontSize": "15px",
                                            "color": COLORS["text"],
                                            "maxWidth": "85%",
                                            "border": f"1px solid {COLORS['border']}",
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
                                            "height": "40px",
                                            "border": f"1px solid {COLORS['border']}",
                                            "borderRadius": "4px",
                                            "padding": "0 12px",
                                            "fontSize": "15px",
                                            "fontFamily": "inherit",
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
                                            "borderRadius": "4px",
                                            "padding": "0 18px",
                                            "cursor": "pointer",
                                            "fontSize": "15px",
                                            "fontWeight": "700",
                                            "fontFamily": "inherit",
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
