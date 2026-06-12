"""
AI analysis orchestration and background worker thread management.
Handles batching, LLM communication, and progress tracking.
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd

from security_dashboard.data.datasets import AI_ANALYSIS_COLUMNS, ensure_ai_analysis_columns, persist_ai_analysis_result
from security_dashboard.filters import analysis_pending_mask, analysis_error_mask, analysis_completion_mask
from security_dashboard.services.dgx_spark_server_client import DGXSparkServerClient

logger = logging.getLogger(__name__)


class AnalysisBackgroundState:
    """Thread-safe container for background analysis state and progress tracking."""

    def __init__(self):
        self.thread = None
        self.running = False
        self.request_id = None
        self.df_json = None
        self.status = None
        self.lock = threading.Lock()

    def start_analysis(self, request_id: str, df_json: str, status: dict) -> None:
        """Atomically set analysis as running with initial state."""
        with self.lock:
            self.running = True
            self.request_id = request_id
            self.df_json = df_json
            self.status = status

    def set_thread(self, thread: threading.Thread) -> None:
        """Atomically store the worker thread handle."""
        with self.lock:
            self.thread = thread

    def clear_finished_request(self) -> None:
        """Clear final state after the Dash polling callback has consumed it."""
        with self.lock:
            self.thread = None
            self.request_id = None
            self.status = None
            self.df_json = None

    def update_progress(self, df_json: str, status: dict) -> None:
        """Atomically update progress during analysis."""
        with self.lock:
            self.df_json = df_json
            self.status = status

    def finish_analysis(self, df_json: str, status: dict) -> None:
        """Atomically mark analysis as complete."""
        with self.lock:
            self.running = False
            self.thread = None
            self.df_json = df_json
            self.status = status

    def __getitem__(self, key: str):
        return getattr(self, key)

    def __setitem__(self, key: str, value) -> None:
        setattr(self, key, value)

    def get_state(self) -> tuple:
        """
        Atomically retrieve current analysis state.
        
        Returns:
            Tuple (is_running, request_id, df_json, status)
        """
        with self.lock:
            return self.running, self.request_id, self.df_json, self.status

    def reset(self) -> None:
        """Reset analysis state to initial idle state."""
        with self.lock:
            self.thread = None
            self.running = False
            self.request_id = None
            self.df_json = None
            self.status = None


def build_initial_analysis_status_payload(df_base: pd.DataFrame) -> dict:
    """
    Build initial analysis status message shown on dashboard load.
    Checks if analysis is pending, has errors, or is complete.
    
    Args:
        df_base: Base dataset
    
    Returns:
        Status dict with state and message keys
    """
    df = ensure_ai_analysis_columns(df_base.copy())
    pending_count = int(analysis_pending_mask(df).sum())
    failed_count = int(analysis_error_mask(df).sum())
    client = DGXSparkServerClient()

    if pending_count and not client.enabled():
        return {
            "state": "error",
            "message": "DGX Spark Server endpoint is not configured. Set DGX_SPARK_SERVER_ENDPOINT_URL before running AI analysis.",
        }
    if pending_count:
        return {
            "state": "running",
            "message": f"Running AI analysis for {pending_count} pending row(s)...",
        }
    if failed_count:
        return {
            "state": "warning",
            "message": f"{failed_count} row(s) previously failed AI analysis. Check the terminal logs.",
        }
    return {"state": "complete", "message": "AI analysis is up to date."}


def run_analysis_worker_thread(
    request_id: str,
    df: pd.DataFrame,
    batch_size: int,
    state: AnalysisBackgroundState,
) -> None:
    """
    Background worker thread that batches rows and calls LLM for analysis in parallel.
    Updates shared state with progress and results progressively after each row finishes.
    
    Args:
        request_id: Unique ID for this analysis request
        df: Asset dataframe with rows to analyze
        batch_size: Number of rows per LLM batch
        state: Shared AnalysisBackgroundState object
    """
    client = DGXSparkServerClient()
    total_rows = len(df)
    total_completed = 0
    total_failed = 0
    batch_number = 0
    max_batches = max(64, len(df) // max(batch_size, 1) + 10)

    while analysis_pending_mask(df).any():
        pending = analysis_pending_mask(df)
        batch_indices = list(df.index[pending][:batch_size])
        if not batch_indices:
            break

        batch_number += 1
        if batch_number > max_batches:
            logger.error("AI analysis stopped after %s batch(es); possible loop guard.", max_batches)
            break

        # Prepare batch records
        batch_records = [df.loc[idx].to_dict() for idx in batch_indices]
        batch_assets = [
            str(record.get("asset_name") or record.get("asset_id") or f"row {idx + 1}")
            for idx, record in zip(batch_indices, batch_records)
        ]

        logger.info(
            "Starting AI analysis batch %s for %s row(s) in parallel: %s",
            batch_number,
            len(batch_indices),
            ", ".join(batch_assets),
        )

        max_workers = min(4, len(batch_indices))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_idx = {
                executor.submit(client.generate_asset_analysis, asset_record=df.loc[idx].to_dict()): idx
                for idx in batch_indices
            }

            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                asset_label = str(df.loc[idx].get("asset_name") or df.loc[idx].get("asset_id") or f"row {idx + 1}")
                try:
                    ai_row = future.result()
                    if not isinstance(ai_row, dict):
                        raise ValueError("No valid AI analysis returned for this row.")

                    # Update dataframe with LLM analysis results
                    for col in AI_ANALYSIS_COLUMNS:
                        value = ai_row.get(col)
                        if col in ("risk_score", "anomaly_score"):
                            try:
                                value = float(value)
                            except Exception:
                                value = pd.NA
                        df.at[idx, col] = value

                    df.at[idx, "ai_analysis_complete"] = True
                    df.at[idx, "ai_analysis_error"] = pd.NA
                    total_completed += 1
                    logger.info("AI analysis completed successfully for %s", asset_label)
                    try:
                        persist_ai_analysis_result(df.loc[idx], ai_row)
                    except Exception as cache_exc:
                        logger.error("Failed to persist analysis result to cache: %s", cache_exc)
                except Exception as exc:
                    logger.exception("AI analysis failed for asset %s", asset_label)
                    df.at[idx, "ai_analysis_error"] = str(exc)
                    total_failed += 1

                # Update progress in state immediately after each row completes
                pending_left = int(analysis_pending_mask(df).sum())
                state.update_progress(
                    df.to_json(date_format="iso", orient="split"),
                    {
                        "state": "running",
                        "message": (
                            f"Analyzed {total_completed} of {total_rows} row(s). "
                            f"{pending_left} row(s) remaining."
                        ),
                    },
                )

        logger.info(
            "Completed AI analysis batch %s. Success=%s, Failed=%s.",
            batch_number,
            total_completed,
            total_failed,
        )

    # Final status
    pending_left = int(analysis_pending_mask(df).sum())
    failed_count = int(analysis_error_mask(df).sum())

    if pending_left:
        status = {
            "state": "warning",
            "message": (
                f"AI analysis stopped with {pending_left} row(s) still pending. "
                f"Completed={total_completed}, Failed={total_failed}. Check the terminal logs."
            ),
        }
    elif failed_count:
        status = {
            "state": "warning",
            "message": (
                f"AI analysis completed for all remaining rows. {failed_count} row(s) failed and were skipped. "
                "Check the terminal logs."
            ),
        }
    else:
        status = {"state": "complete", "message": "AI analysis completed for all assets."}

    state.finish_analysis(
        df.to_json(date_format="iso", orient="split"),
        status,
    )

    # Log final summary
    try:
        completed_rows = df[analysis_completion_mask(df)].head(10)[["asset_id", "asset_name", "risk_score", "risk_level", "asset_bucket"]]
        logger.info("AI analysis finished. Completed rows sample: %s", completed_rows.to_dict("records"))
    except Exception:
        logger.debug("Unable to log completed rows sample after analysis.")
