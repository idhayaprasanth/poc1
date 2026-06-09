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


class MockApp:
    def __init__(self):
        self.callbacks = {}

    def callback(self, *args, **kwargs):
        def decorator(func):
            self.callbacks[func.__name__] = func
            return func
        return decorator


class OnboardingAndDatasetAnalysisTests(unittest.TestCase):
    def test_csv_parsing_valid(self):
        import base64
        from security_dashboard.data.datasets import parse_uploaded_csv
        valid_csv = "col1,col2\nval1,val2\n"
        contents = "data:text/csv;base64," + base64.b64encode(valid_csv.encode()).decode()
        df = parse_uploaded_csv(contents, "tenable.csv")
        self.assertEqual(list(df.columns), ["col1", "col2"])
        self.assertEqual(len(df), 1)

    def test_csv_parsing_malformed(self):
        from security_dashboard.data.datasets import parse_uploaded_csv
        with self.assertRaises(ValueError):
            parse_uploaded_csv("invalid_base64_data", "tenable.csv")
        with self.assertRaises(ValueError):
            parse_uploaded_csv("data:text/csv;base64,invalid!!!", "tenable.csv")

    def test_onboarding_transitions(self):
        from security_dashboard.callbacks.onboarding import register_onboarding_callbacks
        
        app = MockApp()
        register_onboarding_callbacks(app)
        
        render_onboarding = app.callbacks["render_onboarding"]
        insert_tenable = app.callbacks["insert_tenable"]
        insert_splunk = app.callbacks["insert_splunk"]

        # Initial transition: tenable_upload
        res, style = render_onboarding(None, None, None, None)
        self.assertEqual(style, {"display": "none"})
        self.assertIn("Tenable", str(res))

        # Insert Tenable: advances to splunk_upload
        tenable_json = '{"columns":["col"],"index":[0],"data":[["val"]]}'
        step = insert_tenable(1, tenable_json)
        self.assertEqual(step, "splunk_upload")

        # Step splunk_upload: shows splunk upload panel
        res, style = render_onboarding("splunk_upload", None, tenable_json, None)
        self.assertEqual(style, {"display": "none"})
        self.assertIn("Splunk", str(res))

        # Insert Splunk: advances to ready_to_analyze
        splunk_json = '{"columns":["col"],"index":[0],"data":[["val"]]}'
        step = insert_splunk(1, splunk_json)
        self.assertEqual(step, "ready_to_analyze")

        # Step ready_to_analyze: shows start analysis button
        res, style = render_onboarding("ready_to_analyze", None, tenable_json, splunk_json)
        self.assertEqual(style, {"display": "none"})
        self.assertIn("Start Analysis", str(res))

    def test_parse_upload_style(self):
        import base64
        from security_dashboard.callbacks.onboarding import register_onboarding_callbacks
        
        app = MockApp()
        register_onboarding_callbacks(app)
        parse_tenable_upload = app.callbacks["parse_tenable_upload"]

        # Parse None: button should be hidden
        res_data, res_status, res_preview, res_style = parse_tenable_upload(None, None)
        self.assertEqual(res_style, {"display": "none"})

        # Parse Valid CSV: button should be visible (display: block)
        valid_csv = "col1,col2\nval1,val2\n"
        contents = "data:text/csv;base64," + base64.b64encode(valid_csv.encode()).decode()
        res_data, res_status, res_preview, res_style = parse_tenable_upload(contents, "tenable.csv")
        self.assertEqual(res_style["display"], "block")

        # Parse Malformed CSV: button should be hidden
        res_data, res_status, res_preview, res_style = parse_tenable_upload("invalid_csv", "tenable.csv")
        self.assertEqual(res_style, {"display": "none"})

    def test_dataset_level_analysis(self):
        from security_dashboard.analysis import run_dataset_analysis_worker_thread, AnalysisBackgroundState
        
        class FakeDGXClientDataset:
            def generate_uploaded_dataset_analysis(self, tenable_records, splunk_records):
                return {
                    "assets": [
                        {
                            "asset_id": "ASSET-001",
                            "asset_name": "host-001",
                            "risk_score": 8.5,
                            "risk_level": "High",
                            "ai_reason": "High risk detected",
                            "remediation": "Update OS",
                        }
                    ]
                }

        state = AnalysisBackgroundState()
        
        with patch("security_dashboard.analysis.DGXSparkServerClient", return_value=FakeDGXClientDataset()):
            run_dataset_analysis_worker_thread(
                "req-1",
                [{"id": 1}],
                [{"id": 2}],
                state
            )
        
        running, req_id, df_json, status = state.get_state()
        self.assertFalse(running)
        self.assertEqual(req_id, "req-1")
        self.assertEqual(status["state"], "complete")
        
        df = pd.read_json(io.StringIO(df_json), orient="split")
        self.assertEqual(len(df), 1)
        self.assertEqual(df.loc[0, "asset_id"], "ASSET-001")
        self.assertEqual(df.loc[0, "risk_score"], 8.5)
        self.assertEqual(df.loc[0, "risk_level"], "High")

    def test_regression_empty_dashboard_kpis(self):
        from security_dashboard.callbacks.kpis import register_kpi_callbacks
        from security_dashboard.data.datasets import empty_dashboard_dataframe
        
        app = MockApp()
        register_kpi_callbacks(app)
        update_kpis = app.callbacks["update_kpis"]
        
        empty_json = empty_dashboard_dataframe().to_json(date_format="iso", orient="split")
        kpis = update_kpis(empty_json)
        self.assertEqual(len(kpis), 5)
        total_assets_kpi = kpis[0]
        self.assertIn("Total Assets", str(total_assets_kpi))

    def test_regression_empty_dashboard_table(self):
        from security_dashboard.callbacks.assets import register_asset_callbacks
        from security_dashboard.data.datasets import empty_dashboard_dataframe
        
        app = MockApp()
        register_asset_callbacks(app)
        update_table = app.callbacks["update_table"]
        
        empty_json = empty_dashboard_dataframe().to_json(date_format="iso", orient="split")
        table_container = update_table(empty_json, None, "All", "default", None, None)
        self.assertIn("No analyzed assets returned", str(table_container))


if __name__ == "__main__":
    unittest.main()
