import io
import pandas as pd
from dash import html, Input, Output

from security_dashboard.components import kpi_card
from security_dashboard.filters import analysis_completion_mask, analysis_pending_mask, analysis_error_mask
from security_dashboard.theme import COLORS, KPI_ICON_SVGS, svg_icon
from security_dashboard.data.datasets import ensure_ai_analysis_columns

def register_kpi_callbacks(app) -> None:
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
