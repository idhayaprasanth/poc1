"""CSV-backed security datasets and merged dataset builder."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

import pandas as pd


DATA_DIR = Path(__file__).resolve().parent
SEED_DIR = DATA_DIR / "seed_data"
CACHE_FILE = DATA_DIR / "ai_analysis_cache.json"

DATASET_FILES = {
    "tenable": SEED_DIR / "tenable.csv",
    "defender": SEED_DIR / "defender.csv",
    "splunk": SEED_DIR / "splunk.csv",
    "bigfix": SEED_DIR / "bigfix.csv",
}

DATASET_COLUMN_ALIASES = {
    "tenable": {
        "Asset ID": "asset_id",
        "Name": "vuln_name",
        "Severity": "vuln_severity",
        "Solution": "vuln_fix",
        "State": "issue_status",
        "Last Seen": "scan_date",
    },
    "defender": {
        "Asset ID": "asset_id",
        "Title": "threat_alert",
        "Severity": "threat_impact",
        "Remediation": "threat_fix",
        "Status": "issue_status",
        "Last Seen": "scan_date",
    },
    "splunk": {
        "Asset ID": "asset_id",
        "Rule Name": "anomaly_event",
        "Risk Score": "source_anomaly_score",
        "Recommendation": "anomaly_explanation",
        "Status": "issue_status",
        "Last Seen": "scan_date",
    },
    "bigfix": {
        "Asset ID": "asset_id",
        "Status": "patch_status",
        "Severity": "patch_severity",
        "Action": "patch_recommendation",
        "Last Seen": "scan_date",
    },
}

DATASET_OUTPUT_COLUMNS = {
    "tenable": [
        "asset_name",
        "asset_id",
        "vuln_name",
        "vuln_severity",
        "vuln_description",
        "vuln_fix",
        "issue_status",
        "scan_date",
    ],
    "defender": [
        "asset_name",
        "asset_id",
        "threat_alert",
        "threat_file_path",
        "threat_process",
        "threat_impact",
        "threat_fix",
    ],
    "splunk": [
        "asset_name",
        "asset_id",
        "anomaly_event",
        "source_anomaly_score",
        "anomaly_explanation",
    ],
    "bigfix": [
        "asset_name",
        "asset_id",
        "patch_status",
        "patch_severity",
        "patch_recommendation",
    ],
}

AI_ANALYSIS_COLUMNS = [
    "risk_score",
    "risk_level",
    "asset_bucket",
    "anomaly_score",
    "threat_status",
    "severity_validation",
    "priority",
    "ai_reason",
    "remediation",
    "tenable_remediation",
    "defender_remediation",
    "splunk_remediation",
    "bigfix_remediation",
    "ai_analysis_source",
]

FLOAT_AI_ANALYSIS_COLUMNS = {"risk_score", "anomaly_score"}

SOURCE_FINGERPRINT_COLUMNS = [
    "asset_name",
    "vuln_name",
    "vuln_severity",
    "vuln_description",
    "vuln_fix",
    "threat_alert",
    "threat_file_path",
    "threat_process",
    "threat_impact",
    "threat_fix",
    "anomaly_event",
    "anomaly_explanation",
    "source_anomaly_score",
    "patch_status",
    "patch_severity",
    "patch_recommendation",
    "scan_date",
]


def _json_safe_value(value):
    if pd.isna(value):
        return None
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    return value


def compute_asset_fingerprint(row: dict | pd.Series) -> str:
    row_dict = row.to_dict() if isinstance(row, pd.Series) else dict(row)
    payload = {
        column: _json_safe_value(row_dict.get(column))
        for column in SOURCE_FINGERPRINT_COLUMNS
    }
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def ensure_ai_analysis_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for column in AI_ANALYSIS_COLUMNS:
        if column in FLOAT_AI_ANALYSIS_COLUMNS:
            if column in df.columns:
                df[column] = pd.to_numeric(df[column], errors="coerce").astype("Float64")
            else:
                df[column] = pd.Series([pd.NA] * len(df), dtype="Float64")
        else:
            if column in df.columns:
                df[column] = df[column].where(pd.notna(df[column]), pd.NA).astype("object")
            else:
                df[column] = pd.Series([pd.NA] * len(df), dtype="object")
    if "ai_analysis_complete" not in df.columns:
        df["ai_analysis_complete"] = False
    else:
        df["ai_analysis_complete"] = df["ai_analysis_complete"].fillna(False).astype(bool)
    if "ai_analysis_error" not in df.columns:
        df["ai_analysis_error"] = pd.Series([pd.NA] * len(df), dtype="object")
    else:
        df["ai_analysis_error"] = df["ai_analysis_error"].where(pd.notna(df["ai_analysis_error"]), pd.NA).astype("object")
    return df


def load_ai_analysis_cache() -> dict[str, dict]:
    if not CACHE_FILE.exists():
        return {}
    try:
        cache = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return cache if isinstance(cache, dict) else {}


def save_ai_analysis_cache(cache: dict[str, dict]) -> None:
    CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=True, indent=2), encoding="utf-8")


def persist_ai_analysis_result(row: dict | pd.Series, analysis_result: dict) -> None:
    fingerprint = compute_asset_fingerprint(row)
    cache = load_ai_analysis_cache()
    cache[fingerprint] = {
        column: analysis_result.get(column)
        for column in AI_ANALYSIS_COLUMNS
    }
    save_ai_analysis_cache(cache)


def apply_cached_ai_analysis(df: pd.DataFrame) -> pd.DataFrame:
    df = ensure_ai_analysis_columns(df)
    cache = load_ai_analysis_cache()
    if not cache:
        return df

    for idx, row in df.iterrows():
        cached = cache.get(compute_asset_fingerprint(row))
        if not cached:
            continue
        for column in AI_ANALYSIS_COLUMNS:
            df.at[idx, column] = cached.get(column, pd.NA)
        cached_source = str(cached.get("ai_analysis_source") or "").strip().lower()
        if not cached_source:
            # Backward compatibility: infer fallback source from legacy ai_reason text.
            ai_reason = str(cached.get("ai_reason") or "").strip().lower()
            if "local fallback assessment used" in ai_reason:
                cached_source = "local_fallback"
                df.at[idx, "ai_analysis_source"] = "local_fallback"
        gemini_key_available = bool((os.getenv("GEMINI_API_KEY") or "").strip())
        should_retry_with_gemini = cached_source == "local_fallback" and gemini_key_available
        df.at[idx, "ai_analysis_complete"] = not should_retry_with_gemini
        df.at[idx, "ai_analysis_error"] = pd.NA
    return df


def _read_dataset(name: str) -> pd.DataFrame:
    path = DATASET_FILES[name]
    if not path.exists():
        raise FileNotFoundError(f"Missing dataset CSV for {name}: {path}")
    df = pd.read_csv(path)

    alias_map = DATASET_COLUMN_ALIASES.get(name, {})
    if alias_map:
        df = df.rename(columns=alias_map)

    # Generic header normalization as a fallback for spacing/casing differences.
    df = df.rename(
        columns={
            column: re.sub(r"[^a-z0-9]+", "_", str(column).strip().lower()).strip("_")
            for column in df.columns
        }
    )

    if "asset_id" not in df.columns:
        df["asset_id"] = pd.Series([pd.NA] * len(df), dtype="object")

    if "asset_name" not in df.columns:
        df["asset_name"] = df["asset_id"].astype("object")

    for column in DATASET_OUTPUT_COLUMNS.get(name, []):
        if column not in df.columns:
            df[column] = pd.Series([pd.NA] * len(df), dtype="object")

    selected_columns = DATASET_OUTPUT_COLUMNS.get(name, list(df.columns))
    return df[selected_columns].copy()


def build_merged_dataset() -> pd.DataFrame:
    """Merge all four data sources by asset_name and prepare blank AI-owned fields."""
    tenable_data = _read_dataset("tenable")
    defender_data = _read_dataset("defender")
    splunk_data = _read_dataset("splunk")
    bigfix_data = _read_dataset("bigfix")

    # Keep a single canonical asset_id from the primary dataset to avoid merge suffix conflicts.
    defender_data = defender_data.drop(columns=["asset_id"], errors="ignore")
    splunk_data = splunk_data.drop(columns=["asset_id"], errors="ignore")
    bigfix_data = bigfix_data.drop(columns=["asset_id"], errors="ignore")

    df = tenable_data.merge(defender_data, on="asset_name", how="outer")
    df = df.merge(splunk_data, on="asset_name", how="outer")
    df = df.merge(bigfix_data, on="asset_name", how="outer")

    if "source_anomaly_score" in df.columns:
        df["source_anomaly_score"] = pd.to_numeric(df["source_anomaly_score"], errors="coerce").astype("Float64")
    else:
        df["source_anomaly_score"] = pd.Series([pd.NA] * len(df), dtype="Float64")

    # AI-owned fields start empty and must be filled by the model, not local code.
    df = ensure_ai_analysis_columns(df)

    # Source-owned field
    df["issue_status"] = "Open"

    df["scan_date"] = pd.to_datetime(df["scan_date"], errors="coerce")

    df = df.reset_index(drop=True)
    generated_ids = [f"ASSET-{str(i + 1).zfill(3)}" for i in range(len(df))]
    if "asset_id" in df.columns:
        asset_id_series = df["asset_id"].astype("object").where(df["asset_id"].notna(), pd.NA)
        df["asset_id"] = [
            str(asset_id_series.iloc[i]).strip() if pd.notna(asset_id_series.iloc[i]) and str(asset_id_series.iloc[i]).strip() else generated_ids[i]
            for i in range(len(df))
        ]
        reordered = ["asset_id"] + [column for column in df.columns if column != "asset_id"]
        df = df[reordered]
    else:
        df.insert(0, "asset_id", generated_ids)

    return apply_cached_ai_analysis(df)
