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

FINDINGS_MAX = 8

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
    "ai_analysis_detail_json",
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


def parse_raw_json_list(value) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []
    return []


def compute_asset_facts(tenable_rows: list, splunk_rows: list) -> dict:
    """Derive deterministic counts, ports, CVEs, and telemetry from full source rows."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    ports: set[int] = set()
    cve_candidates: list[dict] = []
    tenable_findings: list[dict] = []
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    for row in tenable_rows:
        sev_raw = str(row.get("Severity", "") or "").strip().lower()
        if sev_raw in counts:
            counts[sev_raw] += 1

        port_val = row.get("Port")
        if port_val is not None and str(port_val).strip().lower() not in ("", "0", "nan"):
            try:
                port_int = int(float(str(port_val).strip()))
                if port_int > 0:
                    ports.add(port_int)
            except (TypeError, ValueError):
                pass

        plugin_name = str(row.get("Plugin Name", "") or row.get("Plugin", "") or "").strip()
        sev_label = str(row.get("Severity", "Medium") or "Medium").strip().title()
        if sev_label not in ("Critical", "High", "Medium", "Low"):
            sev_label = "Medium"

        if plugin_name:
            tenable_findings.append(
                {"source": "tenable", "title": plugin_name[:120], "severity": sev_label}
            )

        vpr_float = None
        vpr_val = row.get("VPR")
        if vpr_val is not None and str(vpr_val).strip().lower() not in ("", "nan"):
            try:
                vpr_float = float(vpr_val)
            except (TypeError, ValueError):
                pass

        cve_match = re.search(r"CVE-\d{4}-\d+", plugin_name, re.IGNORECASE)
        if cve_match:
            cve_candidates.append(
                {
                    "cve": cve_match.group(0).upper(),
                    "title": plugin_name[:120],
                    "vpr": vpr_float,
                    "severity": sev_label,
                }
            )

    cve_candidates.sort(
        key=lambda item: (
            item.get("vpr") or 0.0,
            severity_rank.get(str(item.get("severity", "")).lower(), 0),
        ),
        reverse=True,
    )
    top_cves: list[dict] = []
    seen_cve: set[str] = set()
    for item in cve_candidates:
        key = item.get("cve") or item.get("title")
        if not key or key in seen_cve:
            continue
        seen_cve.add(key)
        top_cves.append(item)
        if len(top_cves) >= 3:
            break

    tenable_findings.sort(
        key=lambda item: severity_rank.get(str(item.get("severity", "")).lower(), 0),
        reverse=True,
    )

    return {
        "vulnerability_counts": counts,
        "total_findings_tenable": len(tenable_rows),
        "total_splunk_events": len(splunk_rows),
        "open_ports": sorted(ports),
        "top_cves": top_cves,
        "tenable_findings_seed": tenable_findings[:FINDINGS_MAX],
    }


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
            df = pd.read_csv(path, low_memory=False)
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


def filter_splunk_columns(record: dict) -> dict:
    """
    Filter Splunk record to keep only relevant security columns.
    Removes XML data, empty columns, and redundant metadata to reduce token usage.
    """
    # Columns to keep for AI analysis
    keep_patterns = [
        # Identity
        "computer", "computername", "host", "ipaddress", "ip",
        # Events
        "eventcode", "eventid", "signature",
        # Process
        "processname", "commandline", "parentprocessname", "newprocessname",
        "process_name", "process_command", "parent_process",
        # User/Account
        "user", "username", "subjectusername", "targetusername",
        "account_name", "caller_user", "subject",
        # Security
        "message", "result", "status", "severity", "action",
        "logontype", "substatus",
        # Time
        "_time", "systemtime",
        # File/Object
        "filename", "objectname", "file_name", "file_path",
    ]
    
    # Columns to explicitly exclude
    exclude_patterns = [
        "_xml", "xml", "props_xml", "data_xml", "rendering",
        "recordnumber", "qualifiers", "keywords", "opcode",
        "tag::", "ta_windows_", "splunk_server", "index",
        "linecount", "punct", "_raw"
    ]
    
    filtered = {}
    for k, v in record.items():
        if pd.notna(v) and v is not None:
            key_lower = k.lower()
            
            # Skip if explicitly excluded
            if any(excl in key_lower for excl in exclude_patterns):
                continue
            
            # Keep if matches keep pattern
            if any(pattern in key_lower for pattern in keep_patterns):
                val_str = str(v).strip()
                if val_str and val_str.lower() not in ("nan", "nat", ""):
                    filtered[k] = v
    
    return filtered


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


def get_asset_ip(t_rows: list[dict], s_rows: list[dict]) -> str:
    # Try to find IP in tenable rows first
    for r in t_rows:
        for key in ["IP Address", "ip_address", "ip", "IPAddress", "IP"]:
            val = r.get(key)
            if pd.notna(val) and str(val).strip():
                return str(val).strip()
    # Try splunk rows
    for r in s_rows:
        for key in ["ip", "ip_address", "ipAddress", "IPAddress", "IP", "dest_ip", "src_ip", "host_ip"]:
            val = r.get(key)
            if pd.notna(val) and str(val).strip():
                return str(val).strip()
    return "—"


def get_ip_facing(ip_str: str) -> str:
    import ipaddress
    if not ip_str or ip_str == "—":
        return "Internal" # default fallback
    try:
        clean_ip = ip_str.split(":")[0].strip()
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return "Internal"
        else:
            return "External"
    except Exception:
        # Fallback patterns if ipaddress parsing fails
        clean_ip = ip_str.split(":")[0].strip()
        if any(clean_ip.startswith(prefix) for prefix in ["10.", "192.168.", "127.", "169.254."]):
            return "Internal"
        if clean_ip.startswith("172."):
            try:
                parts = clean_ip.split(".")
                if len(parts) >= 2 and 16 <= int(parts[1]) <= 31:
                    return "Internal"
            except Exception:
                pass
        return "External"


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
                # Apply both filtering and sanitization
                record = filter_splunk_columns(sanitize_and_compact_record(row.to_dict()))
                if record:  # Only add if there's useful data after filtering
                    splunk_by_host[host].append(record)

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
        ip_addr = get_asset_ip(t_rows, s_rows)
        facing = get_ip_facing(ip_addr)
        
        records.append({
            "asset_id": f"ASSET-{str(idx + 1).zfill(3)}",
            "asset_name": host,
            "ip_address": ip_addr,
            "facing": facing,
            "tenable_raw": json.dumps(t_rows),
            "splunk_raw": json.dumps(s_rows),
            "scan_date": scan_date,
            "issue_status": "Open"
        })

    if not records:
        df = pd.DataFrame(columns=["asset_id", "asset_name", "ip_address", "facing", "tenable_raw", "splunk_raw", "scan_date", "issue_status"])
    else:
        df = pd.DataFrame(records)

    df["scan_date"] = pd.to_datetime(df["scan_date"], errors="coerce")
    
    df = ensure_ai_analysis_columns(df)
    df = apply_cached_ai_analysis(df)
    
    return df
