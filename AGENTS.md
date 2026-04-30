# AI Coding Agent Instructions for POC1

This file helps AI coding agents quickly understand the project structure, conventions, and workflow.

## Quick Start Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run the dashboard (dev mode on port 8050)
python app.py

# Clear AI analysis cache (if results are stale)
rm security_dashboard/data/ai_analysis_cache.json
```

## Project Overview

**POC1** is an AI-powered cybersecurity monitoring dashboard built with **Dash** (Plotly). It aggregates security data from four platforms (Tenable, Defender, Splunk, BigFix) into a unified asset inventory, then uses **AWS SageMaker** to generate risk scores, threat analysis, and remediation recommendations.

See [poc1-architecture.md](/memories/repo/poc1-architecture.md) for complete architecture details.

## Key Architecture Patterns

### 1. **Data Pipeline** (Critical for modifications)

The flow is: CSV sources → Pandas merge → Fingerprinting → SageMaker AI → Cache → Dash UI

- **Fingerprinting**: Each asset is hashed (17 columns) to create a cache key. Same asset data = cache hit (no SageMaker call).
- **Cache Strategy**: Persistent in `security_dashboard/data/ai_analysis_cache.json`. Delete this file to force re-analysis.
- **Normalization**: All risk scores MUST be int 0-100. Risk level bands: High (75-100), Medium (45-74), Low (0-44).

### 2. **Service Layer Design**

Services are mixins + facade pattern:
- `SageMakerBaseClient`: Low-level AWS SageMaker API wrapper
- `SageMakerAnalysisMixin`: Risk analysis and cache logic
- `SageMakerChatbotMixin`: Security Q&A
- `SageMakerClient`: Public facade combining all mixins

When adding new SageMaker features, follow this pattern. Don't add logic directly to dashboard.py.

### 3. **Dash Callback Pattern**

Use explicit `@callback(Input(...), Output(...), State(...))`. Avoid chaining callbacks. Use `ctx.triggered_id` for multi-button handling and `no_update` for conditional returns.

### 4. **Column Management**

Three critical column lists in `security_dashboard/data/datasets.py`:
- `AI_ANALYSIS_COLUMNS`: 14 output fields from SageMaker (must all be present, even if null)
- `SOURCE_FINGERPRINT_COLUMNS`: 17 fields used for cache key generation
- `FLOAT_AI_ANALYSIS_COLUMNS`: {risk_score, anomaly_score} — must be coerced to int 0-100

When adding new fields, update these lists and the fingerprint columns if they affect caching.

## Project Structure & File Responsibilities

| File | Purpose | When to Edit |
|---|---|---|
| `app.py` | Entry point; starts Dash server | Only for port/host changes |
| `security_dashboard/config.py` | .env loading; configuration | Adding new config values |
| `security_dashboard/datasets.py` | CSV loading, merging, fingerprinting | Changing data sources or schema |
| `security_dashboard/services/sagemaker_base.py` | AWS SageMaker API wrapper | Modifying SageMaker invocation logic |
| `security_dashboard/services/ai_analysis.py` | Risk analysis, caching, parsing | Changing risk scoring or cache behavior |
| `security_dashboard/services/chatbot.py` | Security Q&A | Modifying chatbot behavior |
| `security_dashboard/services/sagemaker_client.py` | Public facade | Don't edit; add mixins in sagemaker_*.py instead |
| `security_dashboard/dashboard.py` | Dash UI and callbacks | Adding UI elements or interactivity |
| `security_dashboard/layout.py` | UI component library | Creating reusable UI components |
| `security_dashboard/assets/dashboard_theme.css` | USWDS 3.0 styling | Customizing colors/fonts |

## Critical Conventions

### Environment Setup

Required `.env` file (not in repo):
```env
SAGEMAKER_ENDPOINT_NAME=huggingface-text2text-flan-t5-xl-2024-01-15-12-34-56
AWS_REGION=us-east-1
AI_ANALYSIS_BATCH_SIZE=1
```

### AI Output Format

The SageMaker system prompt (`BASE_SYSTEM_PROMPT` in `ai_analysis.py`) enforces:
- **JSON-only output** (no reasoning, no markdown)
- **Exact 14 required fields** (see `AI_ANALYSIS_COLUMNS`)
- **Conservative scoring** (avoid inflating risk when data is incomplete)
- **Risk level alignment**: risk_score and risk_level MUST match bands

When modifying prompts or response parsing, verify JSON is valid and all 14 fields present.

### Fingerprinting & Cache Validation

When adding new columns to the dataset:
1. Update `SOURCE_FINGERPRINT_COLUMNS` if the new column should affect cache key
2. Test cache behavior: Run analysis twice with same data; second run should hit cache
3. Delete `ai_analysis_cache.json` if results seem stale

### Code Style

- Type hints used in config.py and datasets.py
- Docstrings in service classes
- Constants in UPPERCASE
- Private methods prefixed with `_`

## Common Pitfalls & Solutions

| Issue | Root Cause | Fix |
|---|---|---|
| SageMaker returns non-JSON | LLM ignoring system prompt | Check endpoint model; verify BASE_SYSTEM_PROMPT enforcement in `_generate_and_parse()` |
| risk_score/risk_level mismatch | Normalization logic skipped | Ensure `_normalize_scores()` and `_normalize_dashboard_row()` are called |
| Cache never updates | Fingerprint logic broken or file locked | Delete cache, verify SOURCE_FINGERPRINT_COLUMNS, check file permissions |
| Chatbot unavailable | SAGEMAKER_ENDPOINT_NAME not set | Verify .env file exists; check `config.get_ai_analysis_batch_size()` |
| Dash callbacks timeout | Batch size too large or SageMaker slow | Reduce `AI_ANALYSIS_BATCH_SIZE` in .env; check boto3 credentials |
| CSV merge produces empty DataFrame | asset_id mismatch across sources | Print asset_id values in each CSV; verify merge logic in `build_merged_dataset()` |
| UI styling broken | CSS not loaded from assets | Verify `security_dashboard/assets/` path and stylesheet reference in dashboard.py |

## Data Contracts (API Boundaries)

### AI_ANALYSIS_COLUMNS (14 fields in final output)
```python
risk_score, risk_level, asset_bucket, anomaly_score, threat_status, 
severity_validation, priority, ai_reason, remediation, 
tenable_remediation, defender_remediation, splunk_remediation, 
bigfix_remediation, ai_analysis_source
```

### Multi-Source Column Aliases

Each CSV has columns renamed during load:
- **Tenable**: `Asset ID` → `asset_id`, `Name` → `vuln_name`, `Severity` → `vuln_severity`, etc.
- **Defender**: `Asset ID` → `asset_id`, `Title` → `threat_alert`, etc.
- **Splunk**: `Asset ID` → `asset_id`, `Rule Name` → `anomaly_event`, etc.
- **BigFix**: `Asset ID` → `asset_id`, `Status` → `patch_status`, etc.

All sources merged on `asset_id` (left/outer join). See `DATASET_COLUMN_ALIASES` in datasets.py.

### Risk Level Bands (MUST Align)
```
risk_score 75-100   → risk_level = "High"
risk_score 45-74    → risk_level = "Medium"
risk_score 0-44     → risk_level = "Low"
```

## Debugging Tips

- **Check SageMaker calls**: See `security_dashboard/data/sagemaker_api_debug.jsonl` for request/response logs
- **Monitor cache hits**: Logs show `[sagemaker] cache hit asset_id=... source=cache`
- **Enable debug mode**: Already enabled in app.py (debug=True); Dash will reload on file changes
- **Inspect parsed JSON**: Add print statements to `_parse_json_like()` and `_extract_fields()` if parsing fails

## Performance Considerations

- **Batch Size**: `AI_ANALYSIS_BATCH_SIZE` (1-5, default 1). Larger batch = faster but higher latency per call.
- **Cache Strategy**: Fingerprint-based (not time-based). Monitor hit rates in debug logs.
- **Dataset Size**: Tested up to 1000 assets per source. Merge is O(n log n).

## References

- [Dash Documentation](https://dash.plotly.com/)
- [USWDS 3.0 Design System](https://designsystem.digital.gov/)
- [AWS SageMaker Runtime](https://docs.aws.amazon.com/sagemaker/latest/dg/runtime-invoke-endpoint.html)
- [Tenable.io API](https://developer.tenable.com/)
- [Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)
- [Splunk API](https://docs.splunk.com/)
- [IBM BigFix](https://www.ibm.com/products/bigfix)

