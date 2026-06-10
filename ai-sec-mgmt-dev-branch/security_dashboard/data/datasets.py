"""CSV-backed security datasets and merged dataset builder."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pandas as pd


DATA_DIR = Path(__file__).resolve().parent
SEED_DIR = DATA_DIR / "seed_data"
CACHE_FILE = DATA_DIR / "ai_analysis_cache.json"

DATASET_FILES = {
    "tenable": SEED_DIR / "tenable",
    "splunk": SEED_DIR / "splunk",
}

AI_ANALYSIS_COLUMNS = [
    "risk_score",
    "risk_level",
    "asset_bucket",
    "overall_priority_level",
    "anomaly_score",
    "threat_status",
    "severity_validation",
    "priority",
    "ai_reason",
    "remediation",
    "tenable_remediation",
    "splunk_remediation",
    "tenable_risk_score",
    "tenable_priority_level",
    "splunk_risk_score",
    "splunk_priority_level",
    "ai_analysis_source",
    "tenable_vulnerabilities",
    "splunk_log_type",
    "splunk_is_vulnerable",
    "splunk_evidence_for_tenable",
]

FLOAT_AI_ANALYSIS_COLUMNS = {
    "risk_score",
    "anomaly_score",
    "tenable_risk_score",
    "splunk_risk_score",
}

SOURCE_FINGERPRINT_COLUMNS = [
    "asset_name",
    "tenable_raw",
    "splunk_raw",
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


def coerce_ai_analysis_complete_series(series: pd.Series) -> pd.Series:
    """
    Normalize ai_analysis_complete after JSON round-trips via Dash Stores.
    Plain .astype(bool) mis-treats string \"false\" as True (non-empty string).
    """

    def to_bool(v):
        if isinstance(v, str):
            return v.strip().lower() in ("true", "1", "yes")
        if pd.isna(v):
            return False
        if isinstance(v, bool):
            return v
        try:
            return bool(int(v))
        except (TypeError, ValueError):
            return bool(v)

    return series.map(to_bool).astype(bool)


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
        df["ai_analysis_complete"] = coerce_ai_analysis_complete_series(df["ai_analysis_complete"])
    if "ai_analysis_error" not in df.columns:
        df["ai_analysis_error"] = pd.Series([pd.NA] * len(df), dtype="object")
    else:
        df["ai_analysis_error"] = df["ai_analysis_error"].where(pd.notna(df["ai_analysis_error"]), pd.NA).astype("object")
    return df


import threading
CACHE_LOCK = threading.Lock()


def load_ai_analysis_cache() -> dict[str, dict]:
    with CACHE_LOCK:
        if not CACHE_FILE.exists():
            return {}
        try:
            cache = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
        return cache if isinstance(cache, dict) else {}


def save_ai_analysis_cache(cache: dict[str, dict]) -> None:
    with CACHE_LOCK:
        CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=True, indent=2), encoding="utf-8")


def persist_ai_analysis_result(row: dict | pd.Series, analysis_result: dict) -> None:
    fingerprint = compute_asset_fingerprint(row)
    cache = load_ai_analysis_cache()
    cache[fingerprint] = {
        column: analysis_result.get(column)
        for column in AI_ANALYSIS_COLUMNS
    }
    save_ai_analysis_cache(cache)


def _resolve_cached_source(cached: dict) -> str:
    source = str(cached.get("ai_analysis_source") or "").strip().lower()
    if source:
        return source
    ai_reason = str(cached.get("ai_reason") or "").strip().lower()
    if "local fallback" in ai_reason:
        return "local_fallback"
    return "unknown"


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

        cached_source = _resolve_cached_source(cached)

        if cached_source:
            df.at[idx, "ai_analysis_source"] = cached_source

        df.at[idx, "ai_analysis_complete"] = True
        df.at[idx, "ai_analysis_error"] = pd.NA

        print(
            f"[cache] {row.get('asset_name') or row.get('asset_id')} source={cached_source!r} "
            "needs_retry=False "
            "complete=True"
        )

    return df


def clear_ai_analysis_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Start each dashboard run with fresh AI-owned fields so analysis always re-runs."""
    df = ensure_ai_analysis_columns(df)
    for column in AI_ANALYSIS_COLUMNS:
        if column in FLOAT_AI_ANALYSIS_COLUMNS:
            df[column] = pd.Series([pd.NA] * len(df), dtype="Float64")
        else:
            df[column] = pd.Series([pd.NA] * len(df), dtype="object")
    df["ai_analysis_complete"] = False
    df["ai_analysis_error"] = pd.Series([pd.NA] * len(df), dtype="object")
    return df


def extract_host(dns_name) -> str | None:
    if pd.isna(dns_name) or not isinstance(dns_name, str):
        return None
    dns_name = dns_name.strip()
    if not dns_name:
        return None
    return dns_name.split(".")[0].lower()


def extract_splunk_host(row: dict | pd.Series) -> str | None:
    row_dict = row.to_dict() if isinstance(row, pd.Series) else dict(row)
    for col in ["host", "Computer", "ComputerName", "Caller_Computer_Name", "Caller_Machine_Name", "Client_Machine_Name", "dvc_nt_host"]:
        val = row_dict.get(col)
        if pd.notna(val) and isinstance(val, str) and val.strip():
            parts = val.strip().split(".")
            if parts:
                return parts[0].lower()
    return None


def get_latest_date(rows: list[dict]) -> pd.Timestamp:
    dates = []
    for r in rows:
        for col in ["SystemTime", "_time", "Last Seen", "scan_date"]:
            val = r.get(col)
            if pd.notna(val) and val != "":
                try:
                    dt = pd.to_datetime(val, utc=True).tz_localize(None)
                    dates.append(dt)
                except Exception:
                    pass
    if dates:
        return max(dates)
    return pd.Timestamp.now().normalize()


def load_dynamic_datasets():
    tenable_dfs = []
    splunk_dfs = []
    
    tenable_dir = SEED_DIR / "tenable"
    splunk_dir = SEED_DIR / "splunk"
    
    tenable_dir.mkdir(parents=True, exist_ok=True)
    splunk_dir.mkdir(parents=True, exist_ok=True)
    
    all_csvs = list(tenable_dir.glob("*.csv")) + list(splunk_dir.glob("*.csv"))
    
    for path in all_csvs:
        try:
            df = pd.read_csv(path)
            # Detect type by looking at columns
            cols = [str(c).lower().strip() for c in df.columns]
            if any(c in cols for c in ["dns name", "dns_name", "plugin", "plugin name"]):
                tenable_dfs.append((path, df))
            elif any(c in cols for c in ["eventcode", "eventid", "accessmask", "sourcetype", "splunk_server"]):
                splunk_dfs.append((path, df))
            else:
                # Fallback to directory name
                if "tenable" in path.parts:
                    tenable_dfs.append((path, df))
                elif "splunk" in path.parts:
                    splunk_dfs.append((path, df))
        except Exception as e:
            print(f"Error reading {path}: {e}")
            
    return tenable_dfs, splunk_dfs


def sanitize_and_compact_record(record: dict) -> dict:
    import math
    cleaned = {}
    for k, v in record.items():
        if pd.notna(v) and v is not None:
            if isinstance(v, float):
                if math.isnan(v) or math.isinf(v):
                    continue
            val_str = str(v).strip()
            if val_str != "" and val_str.lower() != "nan" and val_str.lower() != "nat":
                cleaned[k] = v
    return cleaned


def deduplicate_records(records: list[dict], keys_to_compare: list[str]) -> list[dict]:
    seen = set()
    unique_records = []
    for r in records:
        sig = tuple(str(r.get(k, "")).strip().lower() for k in keys_to_compare)
        if all(val == "" for val in sig):
            sig = tuple(str(v).strip().lower() for k, v in r.items() if k.lower() not in ("_time", "systemtime", "time", "date", "eventrecordid", "recordnumber"))
        if sig not in seen:
            seen.add(sig)
            unique_records.append(r)
    return unique_records


def build_merged_dataset() -> pd.DataFrame:
    """Load Tenable and Splunk raw CSV data, group by hostname, and merge."""
    tenable_dfs, splunk_dfs = load_dynamic_datasets()
    
    tenable_by_host = {}
    for path, df in tenable_dfs:
        df_clean = df.copy()
        df_clean.columns = [str(c).strip() for c in df_clean.columns]
        dns_col = next((c for c in df_clean.columns if c.lower().replace("_", " ") in ["dns name", "dns_name"]), None)
        
        for _, row in df_clean.iterrows():
            dns_val = row.get(dns_col) if dns_col else None
            host = extract_host(dns_val)
            if not host:
                for fallback in ["NetBIOS Name", "IP Address", "host", "Computer", "ComputerName"]:
                    fb_val = row.get(fallback)
                    if pd.notna(fb_val):
                        host = str(fb_val).strip().split(".")[0].lower()
                        break
            if host:
                if host not in tenable_by_host:
                    tenable_by_host[host] = []
                tenable_by_host[host].append(sanitize_and_compact_record(row.to_dict()))

    splunk_by_host = {}
    for path, df in splunk_dfs:
        df_clean = df.copy()
        df_clean.columns = [str(c).strip() for c in df_clean.columns]
        
        for _, row in df_clean.iterrows():
            host = extract_splunk_host(row)
            if host:
                if host not in splunk_by_host:
                    splunk_by_host[host] = []
                splunk_by_host[host].append(sanitize_and_compact_record(row.to_dict()))

    all_hosts = set(tenable_by_host.keys()).union(set(splunk_by_host.keys()))
    
    records = []
    for idx, host in enumerate(sorted(all_hosts)):
        t_rows = tenable_by_host.get(host, [])
        s_rows = splunk_by_host.get(host, [])
        
        # De-duplicate logs to reduce prompt size and avoid context window limitations
        t_rows = deduplicate_records(t_rows, ["Plugin", "Plugin Name", "Severity", "Port"])
        s_rows = deduplicate_records(s_rows, ["EventID", "EventCode", "CommandLine", "Message", "signature"])
        
        # Limit to top 25 records each to be safe
        t_rows = t_rows[:25]
        s_rows = s_rows[:25]
        
        scan_date = get_latest_date(t_rows + s_rows)
        
        records.append({
            "asset_id": f"ASSET-{str(idx + 1).zfill(3)}",
            "asset_name": host,
            "tenable_raw": json.dumps(t_rows),
            "splunk_raw": json.dumps(s_rows),
            "scan_date": scan_date,
            "issue_status": "Open"
        })

    if not records:
        df = pd.DataFrame(columns=["asset_id", "asset_name", "tenable_raw", "splunk_raw", "scan_date", "issue_status"])
    else:
        df = pd.DataFrame(records)

    df["scan_date"] = pd.to_datetime(df["scan_date"], errors="coerce")
    
    df = ensure_ai_analysis_columns(df)
    df = apply_cached_ai_analysis(df)
    
    return df
