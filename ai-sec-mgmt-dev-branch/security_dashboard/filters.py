"""
Data filtering and masking utilities for the security dashboard.
Handles risk level normalization, asset filtering, and analysis state tracking.
"""

import logging
import pandas as pd

from security_dashboard.data.datasets import coerce_ai_analysis_complete_series, ensure_ai_analysis_columns

logger = logging.getLogger(__name__)


def analysis_is_complete(df: pd.DataFrame) -> bool:
    """Check if all rows have completed AI analysis."""
    return not bool(analysis_pending_mask(ensure_ai_analysis_columns(df)).any())


def analysis_completion_mask(df: pd.DataFrame) -> pd.Series:
    """Return boolean series indicating rows with completed AI analysis."""
    if "ai_analysis_complete" not in df.columns:
        return pd.Series([False] * len(df), index=df.index, dtype=bool)
    return coerce_ai_analysis_complete_series(df["ai_analysis_complete"])


def analysis_error_mask(df: pd.DataFrame) -> pd.Series:
    """Return boolean series indicating rows with AI analysis errors."""
    if "ai_analysis_error" not in df.columns:
        return pd.Series([False] * len(df), index=df.index, dtype=bool)
    errors = df["ai_analysis_error"].astype("object")
    return errors.notna() & errors.astype(str).str.strip().ne("")


def analysis_pending_mask(df: pd.DataFrame) -> pd.Series:
    """Return boolean series indicating rows pending AI analysis."""
    return ~analysis_completion_mask(df) & ~analysis_error_mask(df)


def prepare_filtered_assets(
    df: pd.DataFrame,
    search: str = None,
    risk_f: str = None,
    sort: str = None,
    date_from: str = None,
    date_to: str = None,
) -> pd.DataFrame:
    """
    Apply user-driven filters to asset dataframe.
    
    Args:
        df: Asset dataframe
        search: Search query for asset_name or asset_id
        risk_f: Risk level filter ("High", "Medium", "Low", or "All")
        sort: Sort order ("high-low" or "low-high" by risk_score)
        date_from: Start date filter (ISO format)
        date_to: End date filter (ISO format)
    
    Returns:
        Filtered dataframe
    """
    df = df.copy()

    # Search filter: asset name or ID
    if search:
        q = search.lower().strip()
        if q:
            asset_name_series = df.get("asset_name", pd.Series(index=df.index, dtype=str)).fillna("").astype(str)
            asset_id_series = df.get("asset_id", pd.Series(index=df.index, dtype=str)).fillna("").astype(str)
            df = df[asset_name_series.str.lower().str.contains(q) | asset_id_series.str.lower().str.contains(q)]

    # Risk level filter: only show completed rows matching filter, or all pending rows
    if risk_f and risk_f != "All":
        complete_mask = analysis_completion_mask(df)
        risk_matches = df.get("risk_level", pd.Series(index=df.index, dtype="object")).eq(risk_f)
        df = df[(~complete_mask) | risk_matches]

    # Date range filter
    if date_from:
        df = df[df["scan_date"] >= date_from]
    if date_to:
        df = df[df["scan_date"] <= date_to]

    # Sort by risk score
    if sort == "high-low":
        df = df.sort_values("risk_score", ascending=False, na_position="last")
    elif sort == "low-high":
        df = df.sort_values("risk_score", ascending=True, na_position="last")

    return df


def assign_asset_sections(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize risk_level and asset_bucket into canonical asset sections.
    Maps various risk level variations to ["critical", "high", "medium", "low"].
    
    Rows pending analysis remain unmapped (asset_section = NA).
    
    Args:
        df: Asset dataframe with risk_level and asset_bucket columns
    
    Returns:
        DataFrame with added 'asset_section' column
    """
    df = df.copy()
    complete_mask = analysis_completion_mask(df)
    pending_analysis_mask_vals = analysis_pending_mask(df)

    # Normalize risk_level and asset_bucket to lowercase
    asset_bucket = (
        df.get("asset_bucket", pd.Series(index=df.index, dtype="object"))
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
    )
    risk_level = (
        df.get("risk_level", pd.Series(index=df.index, dtype="object"))
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
    )

    # Mapping tables for risk level synonyms
    bucket_map = {
        "critical risk": "critical",
        "critical": "critical",
        "high risk": "high",
        "high": "high",
        "medium risk": "medium",
        "medium": "medium",
        "low risk": "low",
        "low": "low",
    }

    risk_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "med": "medium",
        "low": "low",
        "informational": "low",
        "info": "low",
    }

    # Clean up variations like "Critical Risk" or "Priority Critical"
    cleaned_bucket = asset_bucket.str.replace(r"\s*risk\s*$", "", regex=True).str.strip()
    cleaned_risk = (
        risk_level
        .str.replace(r"^priority[:\s]+", "", regex=True)
        .str.replace(r"\s*risk\s*$", "", regex=True)
        .str.strip()
    )

    # Map to canonical sections, prefer bucket mapping, fallback to risk_level mapping
    mapped_from_bucket = cleaned_bucket.map(bucket_map)
    mapped_from_risk = cleaned_risk.map(risk_map)
    combined = mapped_from_bucket.where(mapped_from_bucket.notna(), mapped_from_risk)
    combined = combined.where(combined.isin(["critical", "high", "medium", "low"]), pd.NA)
    df["asset_section"] = combined

    # Rows waiting for AI remain unmapped
    df.loc[pending_analysis_mask_vals, "asset_section"] = pd.NA

    # Debug logging
    try:
        mapped_counts = df.loc[complete_mask, "asset_section"].value_counts(dropna=False).to_dict()
        logger.info("Asset section counts for completed rows: %s", mapped_counts)
        unmapped_sample = df.loc[complete_mask & df["asset_section"].isna(), ["asset_id", "asset_name", "asset_bucket", "risk_level"]].head(5)
        if not unmapped_sample.empty:
            logger.info("Sample unmapped completed rows: %s", unmapped_sample.to_dict("records"))
    except Exception:
        logger.debug("Unable to compute mapped counts for assign_asset_sections.")

    # Warn about unmapped completed rows
    unmapped_complete = complete_mask & df["asset_section"].isna()
    if bool(unmapped_complete.any()):
        sample = df.loc[unmapped_complete, ["asset_id", "asset_name", "asset_bucket", "risk_level"]].head(5)
        logger.warning(
            "Found %s analyzed row(s) with no asset_section mapping. Sample: %s",
            int(unmapped_complete.sum()),
            sample.to_dict("records"),
        )

    return df
