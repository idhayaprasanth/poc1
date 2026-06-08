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
    def generate_dashboard_analysis(self, asset_records):
        return {
            "assets": [
                {
                    "asset_id": asset_records[0]["asset_id"],
                    "asset_name": asset_records[0]["asset_name"],
                    "risk_score": 9.5,
                    "risk_level": "Critical",
                    "asset_bucket": "Critical Risk",
                    "anomaly_score": 8.0,
                    "priority": "Immediate",
                    "remediation": "Patch immediately.",
                },
                {
                    "asset_id": asset_records[1]["asset_id"],
                    "asset_name": asset_records[1]["asset_name"],
                    "risk_score": 7.2,
                    "risk_level": "High",
                    "asset_bucket": "High Risk",
                    "anomaly_score": 5.0,
                    "priority": "High",
                    "remediation": "Patch soon.",
                },
            ]
        }


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


if __name__ == "__main__":
    unittest.main()
