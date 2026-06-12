import io
import pandas as pd
from dash import html, Input, Output, State, no_update, ctx

from security_dashboard.filters import analysis_completion_mask, analysis_pending_mask, analysis_error_mask
from security_dashboard.theme import COLORS
from security_dashboard.data.datasets import ensure_ai_analysis_columns
from security_dashboard.services.dgx_spark_server_client import DGXSparkServerClient

def register_chat_callbacks(app) -> None:
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
                f"({r.get('risk_level','—')}), status={r.get('issue_status','—')}, "
                f"remediation={r.get('remediation','—')}"
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
