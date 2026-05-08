"""
Unit tests for row-isolated AI orchestration with context window management.

Tests cover:
- Token counting accuracy
- Context budget validation
- Row-isolated analysis (success and failure)
- Structured error envelopes
- Back-to-back row independence
- Adaptive chunking
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock

from security_dashboard.services.sagemaker_base import (
    SageMakerBaseClient,
    CONTEXT_WINDOW_TOKENS,
    OUTPUT_RESERVE_TOKENS,
    SAFE_INPUT_BUDGET,
)
from security_dashboard.services.result_envelope import AnalysisResult
from security_dashboard.services.ai_analysis import SageMakerAnalysisMixin


class TestTokenCounting:
    """Tests for tiktoken integration and token counting."""

    def test_count_tokens_basic(self):
        """Test basic token counting with sample text."""
        client = SageMakerBaseClient()
        
        # Short text
        text = "Hello world"
        count = client.count_tokens(text)
        assert isinstance(count, int)
        assert count > 0
        
        # Medium text
        text = "This is a longer text that should have more tokens than the short text above."
        count_long = client.count_tokens(text)
        assert count_long > count

    def test_context_budget_check(self):
        """Test context budget validation."""
        client = SageMakerBaseClient()
        
        # Small prompt should fit
        small_prompt = "Analyze this: {asset_id: 1}"
        budget = client.check_context_budget(small_prompt)
        assert budget["fits"] is True
        assert budget["token_count"] > 0
        assert budget["budget_remaining"] > 0
        assert budget["safe_budget"] == SAFE_INPUT_BUDGET
        
        # Verify budget math
        assert budget["token_count"] + budget["budget_remaining"] <= SAFE_INPUT_BUDGET

    def test_context_budget_overflow(self):
        """Test detection of token budget overflow."""
        client = SageMakerBaseClient()
        
        # Create a prompt that definitely exceeds budget
        # (naive estimate: 1 token per 4 chars, so need > SAFE_INPUT_BUDGET * 4 chars)
        huge_prompt = "x" * (SAFE_INPUT_BUDGET * 5 + 1000)
        budget = client.check_context_budget(huge_prompt)
        assert budget["fits"] is False


class TestAnalysisResultEnvelope:
    """Tests for structured success and failure result envelopes."""

    def test_success_envelope(self):
        """Test wrapping a successful analysis result."""
        data = {
            "asset_name": "test-server",
            "asset_id": "asset-123",
            "risk_score": 75,
            "risk_level": "High",
            "threat_status": "Active",
            "ai_reason": "Multiple vulnerabilities detected",
        }
        
        result = AnalysisResult.success(data)
        
        # Verify all required keys are present
        assert "asset_name" in result
        assert "asset_id" in result
        assert "risk_score" in result
        assert "risk_level" in result
        assert "ai_analysis_source" in result
        assert result["ai_analysis_source"] == "sagemaker"
        
        # Verify values are preserved
        assert result["asset_name"] == "test-server"
        assert result["risk_score"] == 75

    def test_failure_envelope(self):
        """Test wrapping a failed analysis result."""
        result = AnalysisResult.failure(
            asset_name="test-server",
            asset_id="asset-123",
            error_type="sagemaker_error",
            error_message="Failed to generate response",
        )
        
        # Verify all required keys are present
        assert "asset_name" in result
        assert "asset_id" in result
        assert "risk_score" in result
        assert "risk_level" in result
        assert "ai_analysis_source" in result
        assert result["ai_analysis_source"] == "error"
        
        # Verify error information is captured
        assert "Error" in result["threat_status"]
        assert "Analysis failed" in result["ai_reason"]
        
        # Verify graceful defaults
        assert result["asset_name"] == "test-server"
        assert result["asset_id"] == "asset-123"
        assert result["risk_score"] is None

    def test_failure_envelope_with_context(self):
        """Test failure envelope with error context."""
        error_context = {
            "token_overflow": True,
            "token_count": 35000,
            "safe_budget": 30800,
        }
        
        result = AnalysisResult.failure(
            asset_name="test-server",
            asset_id="asset-123",
            error_type="token_overflow",
            error_message="Prompt exceeds token budget",
            error_context=error_context,
        )
        
        # Verify error context is captured in reason
        assert "token_overflow" in result["ai_reason"].lower()
        assert "35000" in result["ai_reason"]

    def test_schema_validation(self):
        """Test schema validation for result envelopes."""
        valid_result = AnalysisResult.success({
            "asset_name": "server",
            "asset_id": "123",
            "risk_score": 50,
        })
        
        is_valid, error = AnalysisResult.validate_schema(valid_result)
        assert is_valid is True
        assert error == ""

    def test_schema_validation_missing_keys(self):
        """Test schema validation detects missing keys."""
        incomplete_result = {"asset_name": "server"}
        
        is_valid, error = AnalysisResult.validate_schema(incomplete_result)
        assert is_valid is False
        assert "Missing required keys" in error

    def test_schema_ensure(self):
        """Test schema ensure fills missing keys with defaults."""
        partial_result = {
            "asset_name": "server",
            "asset_id": "123",
            "risk_score": 75,
        }
        
        complete = AnalysisResult.ensure_schema(partial_result)
        
        # Verify all keys are present
        assert len(complete) >= 14
        assert "threat_status" in complete
        assert "ai_reason" in complete
        
        # Verify provided values are preserved
        assert complete["asset_name"] == "server"
        assert complete["risk_score"] == 75


class TestRowIsolatedOrchestration:
    """Tests for row-isolated analysis with context isolation."""

    @patch.object(SageMakerBaseClient, '_invoke_endpoint')
    def test_row_isolated_success(self, mock_invoke):
        """Test successful row-isolated analysis."""
        # Mock SageMaker response
        mock_invoke.return_value = {
            "generated_text": json.dumps({
                "asset_name": "test-server",
                "asset_id": "asset-123",
                "risk_score": 65,
                "risk_level": "Medium",
                "threat_status": "Monitoring",
                "severity_validation": "Valid",
                "priority": "High",
                "ai_reason": "Some vulnerabilities detected",
                "remediation": "Apply patches",
                "tenable_remediation": "Update",
                "defender_remediation": "Scan",
                "splunk_remediation": "Monitor",
                "bigfix_remediation": "Patch",
            })
        }
        
        # Create a mixin instance (normally mixed into SageMakerClient)
        client = SageMakerBaseClient()
        mixin = SageMakerAnalysisMixin()
        
        # Monkey-patch the mixin to use our base client's _invoke_endpoint
        mixin._invoke_endpoint = client._invoke_endpoint
        
        asset_record = {
            "asset_name": "test-server",
            "asset_id": "asset-123",
            "vuln_name": "CVE-2023-1234",
            "vuln_severity": "High",
            "threat_alert": "Suspicious activity",
        }
        
        result = mixin.analyze_row_isolated(
            asset_record=asset_record,
            row_index=0,
            total_rows=10,
        )
        
        # Verify result structure
        assert result is not None
        assert "asset_name" in result
        assert "risk_score" in result
        assert result["asset_id"] == "asset-123"

    def test_row_isolated_no_data(self):
        """Test row-isolated analysis with no asset data."""
        mixin = SageMakerAnalysisMixin()
        
        result = mixin.analyze_row_isolated(
            asset_record={},
            row_index=0,
            total_rows=1,
        )
        
        # Should return structured error
        assert result is not None
        assert "ai_analysis_source" in result
        assert result["ai_analysis_source"] == "error"

    def test_row_isolation_no_state_carryover(self):
        """Test that consecutive rows don't share context."""
        mixin = SageMakerAnalysisMixin()
        
        record1 = {
            "asset_name": "server1",
            "asset_id": "asset-1",
            "vuln_name": "Vuln1",
        }
        
        record2 = {
            "asset_name": "server2",
            "asset_id": "asset-2",
            "vuln_name": "Vuln2",
        }
        
        # Both records should compact independently
        compact1 = mixin._compact_asset_record(record1)
        compact2 = mixin._compact_asset_record(record2)
        
        # Verify no cross-contamination
        assert compact1.get("asset_name") != record2.get("asset_name")
        assert compact2.get("asset_name") != record1.get("asset_name")


class TestAdaptiveChunking:
    """Tests for adaptive chunking of large records."""

    def test_chunk_splitting(self):
        """Test record is split into focused chunks."""
        mixin = SageMakerAnalysisMixin()
        
        record = {
            "asset_name": "server",
            "asset_id": "123",
            "vuln_name": "CVE-2023-1234",
            "vuln_severity": "High",
            "threat_alert": "Suspicious",
            "threat_impact": "High",
            "anomaly_event": "Unusual traffic",
            "patch_status": "Pending",
        }
        
        chunks = mixin._split_asset_for_chunking(record)
        
        # Should create multiple chunks
        assert len(chunks) >= 3
        
        # Each chunk should have a focus marker
        focuses = [c.get("_chunk_focus") for c in chunks]
        assert "vulnerability" in focuses
        assert "threat" in focuses or "anomaly" in focuses

    def test_chunk_merge(self):
        """Test merging chunk results back together."""
        mixin = SageMakerAnalysisMixin()
        
        chunk_results = [
            {
                "_chunk_focus": "vulnerability",
                "risk_score": 70,
                "ai_reason": "Vulnerabilities found",
                "tenable_remediation": "Update patches",
            },
            {
                "_chunk_focus": "threat",
                "risk_score": 60,
                "ai_reason": "Threats detected",
                "defender_remediation": "Scan system",
            },
        ]
        
        merged = mixin._merge_chunk_results(chunk_results)
        
        # Should take highest risk score
        assert merged["risk_score"] == 70
        
        # Should combine reasons
        assert "Vulnerabilities" in merged["ai_reason"]
        assert "Threats" in merged["ai_reason"]
        
        # Should combine remediation
        assert "Update patches" in merged.get("tenable_remediation", "")
        assert "Scan system" in merged.get("defender_remediation", "")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
