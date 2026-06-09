"""
Asset detail panel rendering for the security dashboard modal.
Formats and displays detailed vulnerability, threat, and remediation information.
"""

import pandas as pd
from dash import html

from security_dashboard.theme import COLORS


class DetailPanelRenderer:
    """Renders asset detail information with source-specific sections."""

    def __init__(self, colors_dict: dict = None, primary_color: str = None):
        """
        Initialize detail panel renderer with color scheme.
        
        Args:
            colors_dict: Color palette dict (defaults to COLORS)
            primary_color: Primary UI color for icons (defaults to COLORS["primary"])
        """
        self.colors = colors_dict or COLORS
        self.primary_color = primary_color or COLORS["primary"]

    def render_detail_panel(self, row: pd.Series) -> tuple:
        """
        Render complete detail panel for an asset row.
        
        Args:
            row: Pandas Series with asset data
        
        Returns:
            Tuple of (children_list, asset_name, asset_id, scan_date_text, issue_status)
        """
        # Extract and normalize core fields
        risk_value = row.get("risk_score", None)
        risk_value = None if pd.isna(risk_value) else risk_value

        risk_level_value = row.get("risk_level", "")
        risk_level_value = "" if pd.isna(risk_level_value) else risk_level_value

        scan_date_value = pd.to_datetime(row.get("scan_date"), errors="coerce")
        scan_date_text = scan_date_value.strftime("%Y-%m-%d") if not pd.isna(scan_date_value) else "—"

        # Risk styling
        risk_styles = {
            "Critical": {"bg": self.colors["high_bg"], "border": self.colors["high"], "text": self.colors["high"], "badgeBg": self.colors["high"], "badgeText": "white"},
            "High": {"bg": self.colors["high_bg"], "border": self.colors["high"], "text": self.colors["high"], "badgeBg": self.colors["high"], "badgeText": "white"},
            "Medium": {"bg": self.colors["medium_bg"], "border": self.colors["medium"], "text": self.colors["medium"], "badgeBg": self.colors["medium"], "badgeText": "white"},
            "Low": {"bg": self.colors["low_bg"], "border": self.colors["low"], "text": self.colors["low"], "badgeBg": self.colors["low"], "badgeText": "white"},
        }
        risk_style = risk_styles.get(risk_level_value or "Low", risk_styles["Low"])

        risk_score_text = "—" if risk_value is None else f"{float(risk_value):.1f}/10"
        risk_level_text = "Risk Pending" if not risk_level_value else f"{risk_level_value} Risk"

        # Build sections
        children = [self._render_risk_header(risk_score_text, risk_level_text, risk_style)]
        
        if pd.notna(row.get("ai_reason")):
            children.append(self._section("AI Summary", {"Summary": row.get("ai_reason", "—")}))

        children.extend(self._render_source_sections(row))

        # Issue status
        issue_status = row.get("issue_status", "Open")
        if issue_status not in ["Open", "In Progress", "Resolved"]:
            issue_status = "Open"

        return (
            children,
            row.get("asset_name", ""),
            row.get("asset_id", ""),
            f"Last scan date: {scan_date_text}",
            issue_status,
        )

    def _render_risk_header(self, score_text: str, level_text: str, risk_style: dict) -> html.Div:
        """Render risk score header banner."""
        return html.Div(
            style={
                "background": risk_style["bg"],
                "borderLeft": f"4px solid {risk_style['border']}",
                "borderTop": f"1px solid {self.colors['border']}",
                "borderRight": f"1px solid {self.colors['border']}",
                "borderBottom": f"1px solid {self.colors['border']}",
                "borderRadius": "4px",
                "padding": "20px",
                "marginBottom": "20px",
                "display": "flex",
                "justifyContent": "space-between",
                "alignItems": "center",
                "gap": "12px",
            },
            children=[
                html.Div(children=[
                    html.Span("AI Overall", style={
                        "display": "block",
                        "fontSize": "13px",
                        "fontWeight": "700",
                        "color": self.colors["text_muted"],
                        "textTransform": "uppercase",
                        "letterSpacing": "0.05em",
                    }),
                    html.Span(score_text, style={
                        "fontSize": "32px",
                        "fontWeight": "700",
                        "color": risk_style["text"],
                        "lineHeight": "1.1",
                    }),
                ]),
                html.Span(level_text, style={
                    "padding": "8px 14px",
                    "borderRadius": "4px",
                    "fontSize": "13px",
                    "fontWeight": "700",
                    "background": risk_style["badgeBg"],
                    "color": risk_style["badgeText"],
                }),
            ],
        )

    def _render_source_sections(self, row: pd.Series) -> list:
        """Render sections for Tenable and Splunk raw data."""
        import json
        def score_text(value):
            return f"{float(value):.1f}/10" if pd.notna(value) else "—"

        tenable_raw = row.get("tenable_raw", [])
        if isinstance(tenable_raw, str):
            try:
                tenable_raw = json.loads(tenable_raw)
            except Exception:
                tenable_raw = []

        splunk_raw = row.get("splunk_raw", [])
        if isinstance(splunk_raw, str):
            try:
                splunk_raw = json.loads(splunk_raw)
            except Exception:
                splunk_raw = []

        tenable_records = []
        for idx, r in enumerate(tenable_raw):
            fields = []
            for k, v in r.items():
                if pd.notna(v) and str(v).strip() != "":
                    fields.append(html.Div([
                        html.Span(f"{k}: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                        html.Span(str(v))
                    ], style={"fontSize": "13px", "marginBottom": "2px"}))
            tenable_records.append(html.Div(fields, style={
                "padding": "10px", "border": f"1px solid {self.colors['border']}",
                "borderRadius": "4px", "marginBottom": "8px", "background": self.colors["bg"]
            }))

        splunk_records = []
        for idx, r in enumerate(splunk_raw):
            fields = []
            for k, v in r.items():
                if pd.notna(v) and str(v).strip() != "":
                    fields.append(html.Div([
                        html.Span(f"{k}: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                        html.Span(str(v))
                    ], style={"fontSize": "13px", "marginBottom": "2px"}))
            splunk_records.append(html.Div(fields, style={
                "padding": "10px", "border": f"1px solid {self.colors['border']}",
                "borderRadius": "4px", "marginBottom": "8px", "background": self.colors["bg"]
            }))

        return [
            html.Div(style={"marginBottom": "20px"}, children=[
                html.Span("Vulnerability (Tenable.io)", style={"fontSize": "14px", "fontWeight": "700", "color": self.colors["text"], "display": "block", "marginBottom": "8px"}),
                html.Div([
                    html.Div([
                        html.Span("Model Risk Score: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                        html.Span(score_text(row.get("tenable_risk_score")))
                    ], style={"fontSize": "13px", "marginBottom": "4px"}),
                    html.Div([
                        html.Span("Model Priority: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                        html.Span(row.get("tenable_priority_level", "—"))
                    ], style={"fontSize": "13px", "marginBottom": "4px"}),
                    html.Div([
                        html.Span("Model Remediation: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                        html.Span(row.get("tenable_remediation", "—"))
                    ], style={"fontSize": "13px", "marginBottom": "12px"}),
                ], style={"marginLeft": "12px"}),
                html.Div(tenable_records if tenable_records else "No Tenable records found for this host.", style={"marginLeft": "12px"})
            ]),
            html.Div(style={"marginBottom": "20px"}, children=[
                html.Span("Logs & Anomaly (Splunk)", style={"fontSize": "14px", "fontWeight": "700", "color": self.colors["text"], "display": "block", "marginBottom": "8px"}),
                html.Div([
                    html.Div([
                        html.Span("Model Risk Score: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                        html.Span(score_text(row.get("splunk_risk_score")))
                    ], style={"fontSize": "13px", "marginBottom": "4px"}),
                    html.Div([
                        html.Span("Model Priority: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                        html.Span(row.get("splunk_priority_level", "—"))
                    ], style={"fontSize": "13px", "marginBottom": "4px"}),
                    html.Div([
                        html.Span("Model Remediation: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                        html.Span(row.get("splunk_remediation", "—"))
                    ], style={"fontSize": "13px", "marginBottom": "12px"}),
                ], style={"marginLeft": "12px"}),
                html.Div(splunk_records if splunk_records else "No Splunk logs found for this host.", style={"marginLeft": "12px"})
            ])
        ]

    def _section(self, title: str, fields: dict) -> html.Div:
        """
        Render a detail section with title and fields.
        
        Args:
            title: Section title
            fields: Dict of label -> value pairs
        
        Returns:
            Div component
        """
        return html.Div(style={"marginBottom": "20px"}, children=[
            html.Div(style={
                "display": "flex",
                "alignItems": "center",
                "gap": "8px",
                "marginBottom": "10px",
            }, children=[
                html.Span(title, style={
                    "fontSize": "14px",
                    "fontWeight": "700",
                    "color": self.colors["text"],
                }),
            ]),
            html.Div(style={
                "marginLeft": "24px",
                "display": "flex",
                "flexDirection": "column",
                "gap": "6px",
            }, children=[
                self._field_row(k, v) for k, v in fields.items()
            ]),
        ])

    def _field_row(self, label: str, value) -> html.Div:
        """
        Render a single field row with label and value.
        
        Args:
            label: Field label
            value: Field value
        
        Returns:
            Div component
        """
        font_size = "14px" if label == "Score" else "15px"
        highlight = (label == "Severity" or label in ["Alert", "Status"] or
                    (label == "Score" and isinstance(value, (int, float)) and value > 70))

        return html.Div(style={
            "display": "flex",
            "gap": "8px",
            "alignItems": "flex-start",
        }, children=[
            html.Span(f"{label}:", style={
                "fontSize": font_size,
                "color": self.colors["text_muted"],
                "minWidth": "80px",
                "fontWeight": "600",
            }),
            html.Span(str(value), style={
                "fontSize": font_size,
                "color": self.colors["high"] if highlight else self.colors["text"],
                "fontWeight": "600" if highlight else "500",
                "lineHeight": "1.4",
            }),
        ])
