import io

import pandas as pd
from dash import Input, Output, State, html, no_update

from security_dashboard.data.datasets import parse_uploaded_csv
from security_dashboard.layout import _upload_panel, build_raw_preview_table
from security_dashboard.theme import CARD_STYLE, COLORS


def _status(message: str, state: str = "info"):
    color_map = {
        "info": (COLORS["primary_dark"], COLORS["primary_lighter"]),
        "success": (COLORS["low"], COLORS["low_bg"]),
        "error": (COLORS["high"], COLORS["high_bg"]),
    }
    color, background = color_map.get(state, color_map["info"])
    return html.Div(
        message,
        style={
            "padding": "12px 14px",
            "borderRadius": "4px",
            "background": background,
            "border": f"1px solid {COLORS['border']}",
            "borderLeft": f"4px solid {color}",
            "color": color,
            "fontSize": "15px",
            "fontWeight": "600",
        },
    )


def _read_raw_json(raw_json: str | None) -> pd.DataFrame:
    if not raw_json:
        return pd.DataFrame()
    return pd.read_json(io.StringIO(raw_json), orient="split")


def register_onboarding_callbacks(app) -> None:
    @app.callback(
        Output("onboarding-container", "children"),
        Output("dashboard-content", "style"),
        Input("onboarding-step-store", "data"),
        Input("analysis-status-store", "data"),
        State("tenable-raw-store", "data"),
        State("splunk-raw-store", "data"),
    )
    def render_onboarding(step, analysis_status, tenable_json, splunk_json):
        step = step or "tenable_upload"
        analysis_status = analysis_status or {}

        if step in ("dashboard", "analyzing"):
            return "", {"display": "block"}

        if step == "splunk_upload":
            tenable_rows = len(_read_raw_json(tenable_json))
            return html.Div(
                [
                    _status(f"Tenable data inserted: {tenable_rows} row(s).", "success"),
                    _upload_panel("Splunk", "splunk-upload", "splunk-preview", "splunk-insert-btn", "splunk-upload-status"),
                ]
            ), {"display": "none"}

        if step == "ready_to_analyze":
            tenable_rows = len(_read_raw_json(tenable_json))
            splunk_rows = len(_read_raw_json(splunk_json))
            return html.Div(
                style={**CARD_STYLE, "marginBottom": "24px"},
                children=[
                    html.Div(
                        style={
                            "display": "flex",
                            "justifyContent": "space-between",
                            "alignItems": "center",
                            "marginBottom": "16px",
                        },
                        children=[
                            html.H2(
                                "Ready for AI Analysis",
                                style={"fontSize": "20px", "fontWeight": "700", "margin": 0, "color": COLORS["text"]},
                            ),
                            html.Button(
                                "Start Analysis",
                                id="start-analysis-btn",
                                n_clicks=0,
                                style={
                                    "background": COLORS["primary"],
                                    "color": "white",
                                    "border": "none",
                                    "borderRadius": "4px",
                                    "padding": "10px 20px",
                                    "cursor": "pointer",
                                    "fontSize": "15px",
                                    "fontWeight": "700",
                                    "fontFamily": "inherit",
                                },
                            ),
                        ]
                    ),
                    _status(f"Inserted {tenable_rows} Tenable row(s) and {splunk_rows} Splunk row(s).", "success"),
                ],
            ), {"display": "none"}

        return _upload_panel("Tenable", "tenable-upload", "tenable-preview", "tenable-insert-btn", "tenable-upload-status"), {"display": "none"}

    def _parse_upload(contents, filename):
        if not contents:
            return no_update, "", "", {"display": "none"}
        try:
            df = parse_uploaded_csv(contents, filename)
        except ValueError as exc:
            return None, _status(str(exc), "error"), "", {"display": "none"}
        if df.empty:
            return None, _status("The uploaded CSV parsed successfully but contains no rows.", "error"), "", {"display": "none"}
        preview = build_raw_preview_table(f"preview-{filename or 'csv'}", df)
        return (
            df.to_json(date_format="iso", orient="split"),
            _status(f"Parsed {len(df)} row(s) and {len(df.columns)} column(s).", "success"),
            preview,
            {
                "background": COLORS["primary"],
                "color": "white",
                "border": "none",
                "borderRadius": "4px",
                "padding": "10px 20px",
                "cursor": "pointer",
                "fontSize": "15px",
                "fontWeight": "700",
                "fontFamily": "inherit",
                "display": "block",
            },
        )

    @app.callback(
        Output("tenable-raw-store", "data", allow_duplicate=True),
        Output("tenable-upload-status", "children"),
        Output("tenable-preview", "children"),
        Output("tenable-insert-btn", "style"),
        Input("tenable-upload", "contents"),
        State("tenable-upload", "filename"),
        prevent_initial_call=True,
    )
    def parse_tenable_upload(contents, filename):
        return _parse_upload(contents, filename)

    @app.callback(
        Output("splunk-raw-store", "data", allow_duplicate=True),
        Output("splunk-upload-status", "children"),
        Output("splunk-preview", "children"),
        Output("splunk-insert-btn", "style"),
        Input("splunk-upload", "contents"),
        State("splunk-upload", "filename"),
        prevent_initial_call=True,
    )
    def parse_splunk_upload(contents, filename):
        return _parse_upload(contents, filename)

    @app.callback(
        Output("onboarding-step-store", "data", allow_duplicate=True),
        Input("tenable-insert-btn", "n_clicks"),
        State("tenable-raw-store", "data"),
        prevent_initial_call=True,
    )
    def insert_tenable(n_clicks, raw_json):
        if not n_clicks or not raw_json:
            return no_update
        return "splunk_upload"

    @app.callback(
        Output("onboarding-step-store", "data", allow_duplicate=True),
        Input("splunk-insert-btn", "n_clicks"),
        State("splunk-raw-store", "data"),
        prevent_initial_call=True,
    )
    def insert_splunk(n_clicks, raw_json):
        if not n_clicks or not raw_json:
            return no_update
        return "ready_to_analyze"
