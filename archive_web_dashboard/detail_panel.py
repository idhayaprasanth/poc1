"""
Asset detail panel rendering for the security dashboard modal.
Formats and displays detailed vulnerability, threat, and remediation information.
"""

import json
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
            Tuple of (children_list, asset_name, asset_id, ip_address, facing, scan_date_text, issue_status)
        """
        # Extract and normalize core fields
        risk_value = row.get("risk_score", None)
        risk_value = None if pd.isna(risk_value) else risk_value

        risk_level_value = row.get("risk_level", "")
        risk_level_value = "" if pd.isna(risk_level_value) else risk_level_value

        scan_date_value = pd.to_datetime(row.get("scan_date"), errors="coerce")
        scan_date_text = scan_date_value.strftime("%Y-%m-%d") if not pd.isna(scan_date_value) else "—"
        ip_address_text = "—" if pd.isna(row.get("ip_address")) else str(row.get("ip_address")).strip() or "—"
        facing_text = "—" if pd.isna(row.get("facing")) else str(row.get("facing")).strip() or "—"

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
        
        ai_reason = row.get("ai_reason")
        if ai_reason is not None and not pd.isna(ai_reason) and str(ai_reason).strip():
            from dash import dcc
            children.append(
                html.Div(
                    style={"marginBottom": "24px"},
                    children=[
                        html.Span("AI Summary", style={
                            "fontSize": "15px",
                            "fontWeight": "700",
                            "color": self.colors["text"],
                            "display": "block",
                            "marginBottom": "12px"
                        }),
                        html.Div(
                            dcc.Markdown(
                                str(ai_reason),
                                style={
                                    "fontSize": "14px",
                                    "lineHeight": "1.6",
                                    "color": self.colors["text"],
                                    "padding": "16px",
                                    "background": self.colors["bg"],
                                    "border": f"1px solid {self.colors['border']}",
                                    "borderRadius": "4px",
                                }
                            ),
                            style={"marginLeft": "0"}
                        )
                    ]
                )
            )

        children.extend(self._render_source_sections(row))

        # Issue status
        issue_status = row.get("issue_status", "Open")
        if issue_status not in ["Open", "In Progress", "Resolved"]:
            issue_status = "Open"

        return (
            children,
            row.get("asset_name", ""),
            row.get("asset_id", ""),
            ip_address_text,
            facing_text,
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
                    html.Span("Overall Risk Score", style={
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
        def score_text(value):
            return f"{float(value):.1f}/10" if pd.notna(value) else "—"

        def display_text(value):
            if value is None or value is pd.NA:
                return "—"
            if pd.isna(value):
                return "—"
            text = str(value).strip()
            return text if text else "—"

        def raw_has_data(value) -> bool:
            if value is None or value is pd.NA:
                return False
            try:
                if pd.isna(value):
                    return False
            except Exception:
                pass
            if isinstance(value, list):
                return len(value) > 0
            if isinstance(value, dict):
                return len(value) > 0
            text = str(value).strip()
            if not text or text.lower() in {"nan", "nat", "none", "null", "[]", "{}"}:
                return False
            try:
                parsed = json.loads(text) if text.startswith("[") or text.startswith("{") else None
            except Exception:
                parsed = None
            if parsed is not None:
                if isinstance(parsed, list):
                    return len(parsed) > 0
                if isinstance(parsed, dict):
                    return len(parsed) > 0
                return bool(parsed)
            return True

        def parse_raw_records(value) -> list[dict]:
            if value is None or value is pd.NA:
                return []
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                return [value]
            if pd.isna(value):
                return []
            text = str(value).strip()
            if not text:
                return []
            try:
                parsed = json.loads(text)
            except Exception:
                return []
            if isinstance(parsed, list):
                return [item for item in parsed if isinstance(item, dict)]
            if isinstance(parsed, dict):
                return [parsed]
            return []

        def normalize_level(value) -> str | None:
            if value is None or value is pd.NA:
                return None
            try:
                if pd.isna(value):
                    return None
            except Exception:
                pass
            if isinstance(value, (int, float)):
                numeric = float(value)
                if numeric >= 4:
                    return "Critical"
                if numeric >= 3:
                    return "High"
                if numeric >= 2:
                    return "Medium"
                return "Low"
            text = str(value).strip().lower()
            if not text:
                return None
            if "critical" in text:
                return "Critical"
            if "high" in text:
                return "High"
            if "medium" in text or "moderate" in text:
                return "Medium"
            if "low" in text or "informational" in text or text == "info":
                return "Low"
            if text.isdigit():
                return normalize_level(float(text))
            return None

        def count_levels(raw_value) -> dict[str, int]:
            counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for record in parse_raw_records(raw_value):
                level = None
                for key in ("severity", "Severity", "priority_level", "Priority Level", "priority", "Priority", "risk_level", "Risk Level", "severity_id", "Severity_ID", "Level"):
                    if key in record:
                        level = normalize_level(record.get(key))
                        if level:
                            break
                if not level and any(key.lower() == "level" for key in record.keys()):
                    level = normalize_level(next(record.get(key) for key in record.keys() if key.lower() == "level"))
                if level in counts:
                    counts[level] += 1
            return counts

        def count_summary(counts: dict[str, int]) -> str:
            parts = []
            for label in ("Critical", "High", "Medium", "Low"):
                count = int(counts.get(label, 0) or 0)
                if count:
                    noun = "issue" if count == 1 else "issues"
                    parts.append(f"{count} {label.lower()} {noun} found")
            return ", ".join(parts) if parts else "No severity labels found"

        tenable_counts = count_levels(row.get("tenable_raw"))
        splunk_counts = count_levels(row.get("splunk_raw"))

        tenable_has_data = raw_has_data(row.get("tenable_raw"))
        splunk_has_data = raw_has_data(row.get("splunk_raw"))

        sections: list = []

        if not tenable_has_data and not splunk_has_data:
            sections.append(
                html.Div(
                    "No Tenable or Splunk data available for this asset.",
                    style={
                        "padding": "14px 16px",
                        "border": f"1px dashed {self.colors['border']}",
                        "borderRadius": "4px",
                        "background": self.colors["bg"],
                        "color": self.colors["text_muted"],
                        "fontSize": "14px",
                        "fontWeight": "600",
                        "marginBottom": "20px",
                    },
                )
            )
            return sections

        if tenable_has_data:
            tenable_body = [
                html.Div(
                    count_summary(tenable_counts),
                    style={
                        "padding": "12px 14px",
                        "borderRadius": "4px",
                        "background": self.colors["bg"],
                        "border": f"1px solid {self.colors['border']}",
                        "color": self.colors["text_muted"],
                        "fontSize": "14px",
                        "fontWeight": "600",
                    },
                ),
                html.Div([
                    html.Span("Model Risk Score: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                    html.Span(score_text(row.get("tenable_risk_score")))
                ], style={"fontSize": "14px"}),
                html.Div([
                    html.Span("Model Priority: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                    html.Span(display_text(row.get("tenable_priority_level")))
                ], style={"fontSize": "14px"}),
                html.Div([
                    html.Span("Model Remediation: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                    html.Span(display_text(row.get("tenable_remediation")))
                ], style={"fontSize": "14px"}),
                html.Div([
                    html.Span("Vulnerabilities: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                    html.Span(display_text(row.get("tenable_vulnerabilities")))
                ], style={"fontSize": "14px"}),
            ]
        else:
            tenable_body = [
                html.Div(
                    "No data available",
                    style={
                        "padding": "14px 16px",
                        "border": f"1px dashed {self.colors['border']}",
                        "borderRadius": "4px",
                        "background": self.colors["bg"],
                        "color": self.colors["text_muted"],
                        "fontSize": "14px",
                        "fontWeight": "600",
                    },
                )
            ]

        sections.append(
            html.Div(style={"marginBottom": "24px"}, children=[
                html.Span("Vulnerability (Tenable.io)", style={
                    "fontSize": "15px", "fontWeight": "700", "color": self.colors["text"], "display": "block", "marginBottom": "12px"
                }),
                html.Div(
                    style={
                        "padding": "16px", "border": f"1px solid {self.colors['border']}",
                        "borderRadius": "4px", "background": self.colors["bg"],
                        "display": "flex", "flexDirection": "column", "gap": "8px"
                    },
                    children=tenable_body,
                )
            ])
        )

        if splunk_has_data:
            splunk_body = [
                html.Div(
                    count_summary(splunk_counts),
                    style={
                        "padding": "12px 14px",
                        "borderRadius": "4px",
                        "background": self.colors["bg"],
                        "border": f"1px solid {self.colors['border']}",
                        "color": self.colors["text_muted"],
                        "fontSize": "14px",
                        "fontWeight": "600",
                    },
                ),
                html.Div([
                    html.Span("Model Priority: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                    html.Span(display_text(row.get("splunk_priority_level")))
                ], style={"fontSize": "14px"}),
                html.Div([
                    html.Span("Model Remediation: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                    html.Span(display_text(row.get("splunk_remediation")))
                ], style={"fontSize": "14px"}),
                html.Div([
                    html.Span("Log Type: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                    html.Span(display_text(row.get("splunk_log_type")))
                ], style={"fontSize": "14px"}),
                html.Div([
                    html.Span("Is Vulnerable: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                    html.Span("Yes" if row.get("splunk_is_vulnerable") is True else "No" if row.get("splunk_is_vulnerable") is False else display_text(row.get("splunk_is_vulnerable")))
                ], style={"fontSize": "14px"}),
                html.Div([
                    html.Span("Evidence for Tenable: ", style={"fontWeight": "600", "color": self.colors["text_muted"]}),
                    html.Span(display_text(row.get("splunk_evidence_for_tenable")))
                ], style={"fontSize": "14px"}),
            ]
        else:
            splunk_body = [
                html.Div(
                    "Logs not found",
                    style={
                        "padding": "14px 16px",
                        "border": f"1px dashed {self.colors['border']}",
                        "borderRadius": "4px",
                        "background": self.colors["bg"],
                        "color": self.colors["text_muted"],
                        "fontSize": "14px",
                        "fontWeight": "600",
                    },
                )
            ]

        sections.append(
            html.Div(style={"marginBottom": "24px"}, children=[
                html.Span("Logs & Anomaly (Splunk)", style={
                    "fontSize": "15px", "fontWeight": "700", "color": self.colors["text"], "display": "block", "marginBottom": "12px"
                }),
                html.Div(
                    style={
                        "padding": "16px", "border": f"1px solid {self.colors['border']}",
                        "borderRadius": "4px", "background": self.colors["bg"],
                        "display": "flex", "flexDirection": "column", "gap": "8px"
                    },
                    children=splunk_body,
                )
            ])
        )

        sections.append(
            html.Div(
                style={
                    "display": "flex",
                    "gap": "12px",
                    "marginTop": "24px",
                    "marginBottom": "24px",
                    "justifyContent": "flex-start",
                },
                children=[
                    html.Button(
                        "Download CSV - Tenable",
                        id="download-tenable-raw-btn",
                        n_clicks=0,
                        style={
                            "background": self.colors["primary"],
                            "color": "white",
                            "border": "none",
                            "borderRadius": "4px",
                            "padding": "12px 18px",
                            "cursor": "pointer",
                            "fontSize": "14px",
                            "fontWeight": "700",
                            "fontFamily": "inherit",
                        }
                    ) if tenable_has_data else html.Div(),
                    html.Button(
                        "Download CSV - Splunk",
                        id="download-splunk-raw-btn",
                        n_clicks=0,
                        style={
                            "background": self.colors["primary"],
                            "color": "white",
                            "border": "none",
                            "borderRadius": "4px",
                            "padding": "12px 18px",
                            "cursor": "pointer",
                            "fontSize": "14px",
                            "fontWeight": "700",
                            "fontFamily": "inherit",
                        }
                    ) if splunk_has_data else html.Div(),
                ]
            )
        )

        return sections

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
