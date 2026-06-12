import io
import unittest
from unittest.mock import patch

import pandas as pd

from security_dashboard.analysis import AnalysisBackgroundState, run_analysis_worker_thread
from security_dashboard.data.datasets import ensure_ai_analysis_columns
from security_dashboard.filters import analysis_completion_mask, analysis_error_mask, analysis_pending_mask, assign_asset_sections


class RecordingState(AnalysisBackgroundState):
    def __init__(self):
        super().__init__()
        self.updates = []

    def update_progress(self, df_json: str, status: dict) -> None:
        super().update_progress(df_json, status)
        snapshot = pd.read_json(io.StringIO(df_json), orient="split")
        self.updates.append((snapshot, status))


class FakeDGXClient:
    def generate_asset_analysis(self, asset_record):
        asset_id = asset_record.get("asset_id")
        if asset_id == "A-1":
            return {
                "asset_id": "A-1",
                "asset_name": "host-1",
                "risk_score": 9.5,
                "risk_level": "Critical",
                "asset_bucket": "Critical Risk",
                "anomaly_score": 8.0,
                "priority": "Immediate",
                "remediation": "Patch immediately.",
            }
        elif asset_id == "A-2":
            return {
                "asset_id": "A-2",
                "asset_name": "host-2",
                "risk_score": 7.2,
                "risk_level": "High",
                "asset_bucket": "High Risk",
                "anomaly_score": 5.0,
                "priority": "High",
                "remediation": "Patch soon.",
            }
        else:
            raise Exception("No valid AI analysis returned for this row")


class ProgressiveAnalysisTests(unittest.TestCase):
    def test_worker_publishes_after_each_completed_asset(self):
        df = ensure_ai_analysis_columns(
            pd.DataFrame(
                [
                    {"asset_id": "A-1", "asset_name": "host-1"},
                    {"asset_id": "A-2", "asset_name": "host-2"},
                    {"asset_id": "A-3", "asset_name": "host-3"},
                ]
            )
        )
        state = RecordingState()
        state.start_analysis("request-1", df.to_json(date_format="iso", orient="split"), {"state": "running", "message": "Starting"})

        with patch("security_dashboard.analysis.DGXSparkServerClient", return_value=FakeDGXClient()):
            run_analysis_worker_thread("request-1", df, batch_size=3, state=state)

        completed_counts = [int(analysis_completion_mask(snapshot).sum()) for snapshot, _ in state.updates]
        self.assertIn(1, completed_counts)
        self.assertIn(2, completed_counts)
        self.assertEqual(2, int(analysis_completion_mask(df).sum()))
        self.assertEqual(1, int(analysis_error_mask(df).sum()))
        self.assertFalse(state.running)
        self.assertEqual("request-1", state.request_id)
        self.assertTrue(any("Analyzed 1 of 3 row(s)" in status["message"] for _, status in state.updates))

    def test_section_assignment_keeps_critical_rows_visible(self):
        df = ensure_ai_analysis_columns(
            pd.DataFrame(
                [
                    {
                        "asset_id": "A-1",
                        "asset_name": "host-1",
                        "risk_level": "Critical",
                        "asset_bucket": pd.NA,
                        "ai_analysis_complete": True,
                    },
                    {
                        "asset_id": "A-2",
                        "asset_name": "host-2",
                        "risk_level": pd.NA,
                        "asset_bucket": pd.NA,
                        "ai_analysis_complete": False,
                    },
                ]
            )
        )

        assigned = assign_asset_sections(df)

        self.assertEqual("critical", assigned.loc[0, "asset_section"])
        self.assertTrue(pd.isna(assigned.loc[1, "asset_section"]))
        self.assertEqual(1, int(analysis_pending_mask(assigned).sum()))

    def test_risk_score_rounding_and_columns_in_table(self):
        from security_dashboard.components import build_asset_table
        df = pd.DataFrame([
            {
                "asset_id": "ASSET-001",
                "asset_name": "host-001",
                "vuln_name": "Exposure",
                "threat_alert": "Alert",
                "patch_status": "Missing",
                "anomaly_score": 9.733244,
                "risk_score": 9.733244,
                "risk_level": "Critical",
                "issue_status": "Open",
            }
        ])
        table = build_asset_table("test-table", df)
        col_ids = [c["id"] for c in table.columns]
        self.assertNotIn("patch_status", col_ids)
        self.assertNotIn("anomaly_score", col_ids)
        self.assertIn("risk_score", col_ids)
        row_data = table.data[0]
        self.assertEqual(row_data["risk_score"], 9.7)

    def test_csv_export_ai_prefixing(self):
        from security_dashboard.data.datasets import AI_ANALYSIS_COLUMNS
        df = pd.DataFrame([
            {
                "asset_id": "ASSET-001",
                "risk_score": 9.733244,
                "remediation": "Update package",
                "ai_reason": "Summary text",
            }
        ])
        rename_map = {col: f"ai_{col}" for col in AI_ANALYSIS_COLUMNS if col in df.columns and not col.startswith("ai_")}
        df_renamed = df.rename(columns=rename_map)
        
        self.assertIn("ai_risk_score", df_renamed.columns)
        self.assertIn("ai_remediation", df_renamed.columns)
        self.assertIn("ai_reason", df_renamed.columns)
        self.assertNotIn("risk_score", df_renamed.columns)
        self.assertNotIn("remediation", df_renamed.columns)


if __name__ == "__main__":
    unittest.main()
