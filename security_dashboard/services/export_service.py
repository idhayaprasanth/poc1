"""Export service for security analysis data (CSV, Excel)."""

import io
from datetime import datetime
from typing import Dict, Optional

import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils.dataframe import dataframe_to_rows

from security_dashboard.config import get_ollama_model, get_analysis_prompt_template_version
from security_dashboard.data.datasets import AI_ANALYSIS_COLUMNS


class ExportService:
    """Service for exporting analysis data in various formats."""

    @staticmethod
    def generate_filename(format: str = "csv", model: str = None) -> str:
        """
        Generate timestamp and model-based filename.
        
        Format: security-analysis-{model}-{date}.{ext}
        Example: security-analysis-neural-chat-2024-05-05.csv
        
        Args:
            format: Export format ('csv' or 'excel')
            model: LLM model name (auto-loaded from config if None)
        
        Returns:
            Filename string
        """
        if model is None:
            model = get_ollama_model()
        
        # Sanitize model name for filename (replace spaces/special chars)
        model_safe = model.lower().replace(" ", "-").replace("/", "-")
        
        # ISO date format (YYYY-MM-DD)
        date_str = datetime.now().strftime("%Y-%m-%d")
        ext = "xlsx" if format.lower() in ("excel", "xlsx") else "csv"
        
        return f"security-analysis-{model_safe}-{date_str}.{ext}"

    @staticmethod
    def to_csv(df: pd.DataFrame, model: str = None) -> bytes:
        """
        Export dataframe to CSV format.
        
        Args:
            df: DataFrame with AI_ANALYSIS_COLUMNS
            model: LLM model name for filename (auto-loaded if None)
        
        Returns:
            CSV bytes
        """
        # Ensure only AI_ANALYSIS_COLUMNS are present (filter if needed)
        export_columns = [col for col in AI_ANALYSIS_COLUMNS if col in df.columns]
        if not export_columns:
            export_columns = list(df.columns)
        export_df = df[export_columns]
        
        # Convert to CSV bytes
        csv_buffer = io.StringIO()
        export_df.to_csv(csv_buffer, index=False)
        return csv_buffer.getvalue().encode('utf-8')

    @staticmethod
    def to_excel(
        df: pd.DataFrame,
        asset_counts: dict = None,
        model: str = None,
        template_version: str = None
    ) -> bytes:
        """
        Export dataframe to Excel format with multiple sheets.
        
        Sheets:
        - Data: The analyzed assets
        - Summary: High/Medium/Low count breakdown
        - Metadata: Export details (timestamp, model, template version)
        
        Args:
            df: DataFrame with AI_ANALYSIS_COLUMNS
            asset_counts: Dict with {high: int, medium: int, low: int} counts
            model: LLM model name (auto-loaded if None)
            template_version: Prompt template version (auto-loaded if None)
        
        Returns:
            Excel bytes
        """
        if model is None:
            model = get_ollama_model()
        
        if template_version is None:
            template_version = get_analysis_prompt_template_version()
        
        if asset_counts is None:
            asset_counts = {"high": 0, "medium": 0, "low": 0}
        
        # Create workbook
        wb = Workbook()
        wb.remove(wb.active)  # Remove default sheet
        
        # ── Sheet 1: Data ──
        data_sheet = wb.create_sheet("Data")
        export_columns = [col for col in AI_ANALYSIS_COLUMNS if col in df.columns]
        if not export_columns:
            export_columns = list(df.columns)
        export_df = df[export_columns].copy()
        
        # Replace NaN/NA with None for Excel compatibility
        export_df = export_df.where(pd.notna(export_df), None)
        
        for r_idx, row in enumerate(dataframe_to_rows(export_df, index=False, header=True), 1):
            for c_idx, value in enumerate(row, 1):
                # Convert remaining NaN/NA values to None
                if pd.isna(value):
                    value = None
                cell = data_sheet.cell(row=r_idx, column=c_idx, value=value)
                # Header formatting
                if r_idx == 1:
                    cell.font = Font(bold=True, color="FFFFFF")
                    cell.fill = PatternFill(start_color="005EA2", end_color="005EA2", fill_type="solid")
                    cell.alignment = Alignment(horizontal="center", vertical="center")
        
        # Auto-fit columns
        for column in data_sheet.columns:
            max_length = 0
            column_letter = column[0].column_letter
            for cell in column:
                try:
                    if len(str(cell.value or "")) > max_length:
                        max_length = len(str(cell.value or ""))
                except:
                    pass
            adjusted_width = min(max_length + 2, 50)  # Cap at 50
            data_sheet.column_dimensions[column_letter].width = adjusted_width
        
        # ── Sheet 2: Summary ──
        summary_sheet = wb.create_sheet("Summary")
        summary_data = [
            ["Risk Level", "Count"],
            ["High", asset_counts.get("high", 0)],
            ["Medium", asset_counts.get("medium", 0)],
            ["Low", asset_counts.get("low", 0)],
            ["Total", sum(asset_counts.values())],
        ]
        
        for r_idx, row in enumerate(summary_data, 1):
            for c_idx, value in enumerate(row, 1):
                cell = summary_sheet.cell(row=r_idx, column=c_idx, value=value)
                if r_idx == 1:
                    cell.font = Font(bold=True, color="FFFFFF")
                    cell.fill = PatternFill(start_color="005EA2", end_color="005EA2", fill_type="solid")
                    cell.alignment = Alignment(horizontal="center", vertical="center")
        
        summary_sheet.column_dimensions["A"].width = 15
        summary_sheet.column_dimensions["B"].width = 10
        
        # ── Sheet 3: Metadata ──
        metadata_sheet = wb.create_sheet("Metadata")
        metadata = [
            ["Export Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["LLM Model", model],
            ["Template Version", template_version],
            ["Row Count", len(export_df)],
            ["Column Count", len(export_columns)],
        ]
        
        for r_idx, row in enumerate(metadata, 1):
            for c_idx, value in enumerate(row, 1):
                cell = metadata_sheet.cell(row=r_idx, column=c_idx, value=value)
                if c_idx == 1:
                    cell.font = Font(bold=True)
        
        metadata_sheet.column_dimensions["A"].width = 20
        metadata_sheet.column_dimensions["B"].width = 30
        
        # Save to bytes
        excel_buffer = io.BytesIO()
        wb.save(excel_buffer)
        excel_buffer.seek(0)
        return excel_buffer.getvalue()

    @staticmethod
    def filter_by_scope(
        df: pd.DataFrame,
        scope: str = "all",
        selected_rows: Dict = None
    ) -> pd.DataFrame:
        """
        Filter DataFrame by export scope.
        
        Args:
            df: Full dataset
            scope: 'all' (full dataset), 'selected' (checked rows)
            selected_rows: Dict mapping table_id to list of selected row indices
        
        Returns:
            Filtered DataFrame
        """
        if scope == "all":
            return df.copy()
        
        elif scope == "selected" and selected_rows:
            # Combine selected rows from all three risk tables
            selected_indices = set()
            for table_id, (indices, data) in selected_rows.items():
                if indices:
                    selected_indices.update(indices)
            
            if selected_indices:
                return df.iloc[list(selected_indices)].copy()
            else:
                return df.copy()  # Fallback: no selection = all
        
        # Default: return full dataset
        return df.copy()

    @staticmethod
    def build_asset_counts(df: pd.DataFrame) -> dict:
        """
        Build asset counts by risk level.
        
        Args:
            df: DataFrame with 'risk_level' column
        
        Returns:
            Dict with {high: int, medium: int, low: int}
        """
        if "risk_level" not in df.columns:
            return {"high": 0, "medium": 0, "low": 0}
        
        counts = df["risk_level"].value_counts().to_dict()
        return {
            "high": counts.get("High", 0),
            "medium": counts.get("Medium", 0),
            "low": counts.get("Low", 0),
        }
