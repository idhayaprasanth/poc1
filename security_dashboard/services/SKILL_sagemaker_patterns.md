# Skill: SageMaker Integration Patterns

**Use this skill when**: Adding new SageMaker features, modifying risk analysis logic, debugging endpoint calls, implementing new AI analysis types, or extending the chatbot.

## Mixin-Based Architecture

POC1 uses a **mixin pattern** to compose SageMaker functionality:

```python
class SageMakerClient(
    SageMakerAnalysisMixin,      # Risk analysis + caching
    SageMakerChatbotMixin,        # Security Q&A
    SageMakerBaseClient           # AWS API wrapper
):
    pass
```

### When to Add a New Feature

**DO**: Create a new mixin in `services/sagemaker_*.py`
```python
# Example: services/sagemaker_compliance.py
class SageMakerComplianceMixin:
    def generate_compliance_report(self, asset_data):
        """Generates compliance scoring for an asset."""
        # Implementation
```

**DON'T**: Add logic directly to `dashboard.py` or modify `sagemaker_client.py`

## SageMaker Invocation Pattern

All AI calls go through `SageMakerBaseClient._invoke_endpoint()`:

```python
def _invoke_endpoint(self, system_prompt: str, user_message: str) -> str:
    """Low-level SageMaker API call."""
    # 1. Check if SAGEMAKER_ENDPOINT_NAME is set
    # 2. Format payload: {"inputs": [{"role": "system", "content": ...}]}
    # 3. Call boto3 client.invoke_endpoint()
    # 4. Log request/response to sagemaker_api_debug.jsonl
    # 5. Extract and return response text
```

### High-Level Pattern (Analysis)

```python
def generate_asset_analysis(self, asset_record: dict) -> dict:
    """Orchestrate full analysis flow."""
    # 1. Compute fingerprint: SHA256(17 key fields)
    fingerprint = compute_asset_fingerprint(asset_record)
    
    # 2. Check cache first
    cached = self._cached_result_for_record(fingerprint)
    if cached:
        return cached  # Mark source="cache"
    
    # 3. Invoke SageMaker
    raw_response = self._generate_and_parse(
        system_prompt=BASE_SYSTEM_PROMPT,
        user_message=json.dumps(asset_record)
    )
    
    # 4. Normalize scores (int 0-100)
    normalized = self._normalize_scores(raw_response)
    
    # 5. Persist to cache
    persist_ai_analysis_result(fingerprint, normalized)
    
    return normalized  # Mark source="sagemaker"
```

## System Prompts (Critical)

### BASE_SYSTEM_PROMPT (Analysis)

**Location**: `ai_analysis.py`

**Key Requirements**:
- Enforce JSON-only output (no reasoning, no markdown)
- Specify exactly 14 required fields (all must be present)
- Define risk_level bands: High (75-100), Medium (45-74), Low (0-44)
- Enforce conservative scoring when data is incomplete

**Template**:
```
You are a cybersecurity expert. Analyze the provided asset data and return ONLY valid JSON 
(no markdown, no reasoning). Include these 14 fields:
- risk_score (int 0-100)
- risk_level (str: "High" | "Medium" | "Low")
- ... [12 more fields]

Risk level alignment:
- 75-100 → High
- 45-74 → Medium
- 0-44 → Low

If data is incomplete, use conservative (lower) scores.
```

**When modifying**: 
- Test that endpoint returns valid JSON
- Verify all 14 fields appear in response
- Check risk_score/risk_level alignment via `_normalize_dashboard_row()`

## Response Parsing

### Pattern: Robust JSON Extraction

```python
def _parse_json_like(self, text: str) -> dict:
    """Extract JSON from LLM response (may contain markdown, reasoning)."""
    # 1. Try direct JSON parse
    # 2. If fails, search for json block: ```json...```
    # 3. If fails, search for {...]
    # 4. Raise error if nothing found
```

### Pattern: Field Mapping with Aliases

```python
FIELD_MAP = {
    "asset_name": ["asset_name", "name", "hostname"],
    "risk_score": ["risk_score", "score"],
    # ... flexible field aliases for robustness
}

def _extract_fields(self, json_obj: dict) -> dict:
    """Map SageMaker output to standard AI_ANALYSIS_COLUMNS."""
    result = {}
    for target_field, aliases in FIELD_MAP.items():
        for alias in aliases:
            if alias in json_obj:
                result[target_field] = json_obj[alias]
                break
    return result
```

## Normalization Pattern

### Numeric Normalization (FLOAT_AI_ANALYSIS_COLUMNS)

```python
def _normalize_scores(self, analysis: dict) -> dict:
    """Coerce risk_score, anomaly_score to int 0-100."""
    for field in ["risk_score", "anomaly_score"]:
        value = analysis.get(field)
        if value is not None:
            # Convert float → int, clamp 0-100
            analysis[field] = max(0, min(100, int(float(value))))
    return analysis
```

### Risk Level Alignment

```python
def _normalize_dashboard_row(self, row: dict) -> dict:
    """Ensure risk_score and risk_level match bands."""
    risk_score = row.get("risk_score")
    
    if risk_score is None:
        risk_level = "Unknown"
    elif risk_score >= 75:
        risk_level = "High"
    elif risk_score >= 45:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    row["risk_level"] = risk_level
    return row
```

## Batch Processing Pattern

**Batch Size Control**: `AI_ANALYSIS_BATCH_SIZE` in `.env` (1-5, default 1)

```python
# In dashboard.py
AI_ANALYSIS_BATCH_SIZE = config.get_ai_analysis_batch_size()

# For each batch:
for i in range(0, len(assets), AI_ANALYSIS_BATCH_SIZE):
    batch = assets[i:i+AI_ANALYSIS_BATCH_SIZE]
    for asset in batch:
        result = sagemaker_client.generate_asset_analysis(asset)
```

## Debugging SageMaker Calls

### Debug Log Location
`security_dashboard/data/sagemaker_api_debug.jsonl`

**Each entry contains**:
- request payload (system_prompt, user_message, model params)
- response body (raw LLM output)
- timestamp
- endpoint name

**To inspect**:
```bash
# View last 10 calls
tail -10 security_dashboard/data/sagemaker_api_debug.jsonl | jq .

# Count cache hits vs API calls
grep '"source":"cache"' security_dashboard/data/ai_analysis_cache.json | wc -l
```

### Common Issues

| Issue | Debug Step |
|---|---|
| Non-JSON response | Check debug log for response body; verify endpoint model supports structured output |
| Missing fields in output | Check FIELD_MAP aliases; verify BASE_SYSTEM_PROMPT lists all 14 fields |
| risk_score/risk_level mismatch | Run `_normalize_dashboard_row()` manually on response; verify bands |
| Endpoint not found | Check `config.get_ai_analysis_batch_size()`; verify `.env` SAGEMAKER_ENDPOINT_NAME |
| Slow analysis | Check batch size; reduce from 5 to 1; monitor boto3 credentials |

## Testing Pattern

When adding a new SageMaker feature:

```python
# 1. Create a test mixin
def test_new_analysis():
    client = SageMakerClient()
    
    # 2. Test with mock data
    test_asset = {"asset_id": "test-1", "vuln_name": "CVE-2024-001"}
    
    # 3. Verify JSON response
    result = client.generate_new_analysis(test_asset)
    assert isinstance(result, dict)
    
    # 4. Verify required fields present
    for field in REQUIRED_FIELDS:
        assert field in result
    
    # 5. Verify normalization
    assert 0 <= result["score"] <= 100
```

## References

- `services/sagemaker_base.py`: Low-level API wrapper
- `services/ai_analysis.py`: Risk analysis mixin (reference implementation)
- `services/chatbot.py`: Chatbot mixin (simpler example)
- [AWS SageMaker Runtime API](https://docs.aws.amazon.com/sagemaker/latest/dg/runtime-invoke-endpoint.html)
