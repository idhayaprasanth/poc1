# AI Coding Agent Instructions for POC1

This file helps AI coding agents quickly understand the project structure, conventions, and workflow.

## Quick Start Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Start Ollama (if not already running)
ollama serve

# In another terminal, pull the model
ollama pull neural-chat

# Run the dashboard (dev mode on port 8050)
python app.py

# Clear AI analysis cache (if results are stale)
rm security_dashboard/data/ai_analysis_cache.json
```

## Project Overview

**POC1** is an AI-powered cybersecurity monitoring dashboard built with **Dash** (Plotly). It aggregates security data from four platforms (Tenable, Defender, Splunk, BigFix) into a unified asset inventory, then uses **Ollama** (local LLM) to generate risk scores, threat analysis, and remediation recommendations.

See [poc1-architecture.md](/memories/repo/poc1-architecture.md) for complete architecture details.

## Key Architecture Patterns

### 1. **Data Pipeline** (Critical for modifications)

The flow is: CSV sources → Pandas merge → Fingerprinting → Ollama AI → Cache → Dash UI

- **Fingerprinting**: Each asset is hashed (17 columns) to create a cache key. Same asset data = cache hit (no Ollama call).
- **Cache Strategy**: Persistent in `security_dashboard/data/ai_analysis_cache.json`. Delete this file to force re-analysis with Ollama.
- **Normalization**: All risk scores MUST be int 0-100. Risk level bands: High (75-100), Medium (45-74), Low (0-44).

### 2. **Service Layer Design**

Services are mixins + facade pattern:
- `OllamaBaseClient`: Low-level Ollama HTTP wrapper (`/api/generate` endpoint)
- `SageMakerAnalysisMixin`: Risk analysis and cache logic (provider-agnostic)
- `SageMakerChatbotMixin`: Security Q&A (provider-agnostic)
- `OllamaClient`: Public facade combining all mixins with Ollama backend
- `SageMakerClient`: Alias for backward compatibility (maps to OllamaClient)

When adding new LLM features, follow this pattern. Don't add logic directly to dashboard.py.

### 3. **Dash Callback Pattern**

Use explicit `@callback(Input(...), Output(...), State(...))`. Avoid chaining callbacks. Use `ctx.triggered_id` for multi-button handling and `no_update` for conditional returns.

### 4. **Column Management**

Three critical column lists in `security_dashboard/data/datasets.py`:
- `AI_ANALYSIS_COLUMNS`: 14 output fields from Ollama (must all be present, even if null)
- `SOURCE_FINGERPRINT_COLUMNS`: 17 fields used for cache key generation
- `FLOAT_AI_ANALYSIS_COLUMNS`: {risk_score, anomaly_score} — must be coerced to int 0-100

When adding new fields, update these lists and the fingerprint columns if they affect caching.

## Project Structure & File Responsibilities

| File | Purpose | When to Edit |
|---|---|---|
| `app.py` | Entry point; starts Dash server | Only for port/host changes |
| `security_dashboard/config.py` | .env loading; configuration | Adding new config values |
| `security_dashboard/datasets.py` | CSV loading, merging, fingerprinting | Changing data sources or schema |
| `security_dashboard/services/ollama_base.py` | Ollama HTTP API wrapper | Modifying Ollama invocation logic |
| `security_dashboard/services/ollama_client.py` | Ollama facade | Public LLM client interface |
| `security_dashboard/services/ai_analysis.py` | Risk analysis, caching, parsing | Changing risk scoring or cache behavior |
| `security_dashboard/services/chatbot.py` | Security Q&A | Modifying chatbot behavior |
| `security_dashboard/services/sagemaker_client.py` | Backward-compatible alias | Don't edit; use OllamaClient for new code |
| `security_dashboard/dashboard.py` | Dash UI and callbacks | Adding UI elements or interactivity |
| `security_dashboard/layout.py` | UI component library | Creating reusable UI components |
| `security_dashboard/assets/dashboard_theme.css` | USWDS 3.0 styling | Customizing colors/fonts |

## Critical Conventions

### Environment Setup

Required `.env` file (not in repo):
```env
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=neural-chat
AI_ANALYSIS_BATCH_SIZE=1
```

**Ollama Model Options**:
- `neural-chat` (7B, recommended): Good for instruction following and security analysis
- `mistral` (7B): Higher quality, slower
- `llama2` (7B/13B): Larger but more capable

To use a different model:
```bash
ollama pull mistral
export OLLAMA_MODEL=mistral
python app.py
```

### AI Output Format

The Ollama system prompt (via `prompt_templates.py`) enforces:
- **JSON-only output** (no reasoning, no markdown, no preamble)
- **Exact 14 required fields** (see `AI_ANALYSIS_COLUMNS`)
- **Conservative scoring** (avoid inflating risk when data is incomplete)
- **Risk level alignment**: risk_score and risk_level MUST match bands

When modifying prompts or response parsing, verify JSON is valid and all 14 fields present.
Note: Ollama response format is `{"response": "...json output...", "done": true}`

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
| Ollama returns non-JSON | Model ignoring system prompt | Verify Ollama model supports JSON output; check `neural-chat` or `mistral`; review template in `prompt_templates.py` |
| Ollama connection refused | Ollama not running or wrong URL | Run `ollama serve` first; verify `OLLAMA_BASE_URL` in .env (default: http://localhost:11434) |
| risk_score/risk_level mismatch | Normalization logic skipped | Ensure `_normalize_scores()` and `_normalize_dashboard_row()` are called |
| Cache never updates | Fingerprint logic broken or file locked | Delete cache, verify SOURCE_FINGERPRINT_COLUMNS, check file permissions |
| Chatbot unavailable | OLLAMA_MODEL not set | Verify .env file exists; ensure model is pulled (`ollama pull neural-chat`) |
| Dash callbacks timeout | Batch size too large or Ollama overloaded | Reduce `AI_ANALYSIS_BATCH_SIZE` in .env; consider using smaller model |
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

- **Check Ollama calls**: See `security_dashboard/data/sagemaker_api_debug.jsonl` for request/response logs (same format, provider=ollama)
- **Monitor cache hits**: Logs show `[ollama] cache hit asset_id=... source=cache`
- **Test Ollama directly**: `curl http://localhost:11434/api/generate -d '{"model":"neural-chat","prompt":"test","stream":false}'`
- **Enable debug mode**: Already enabled in app.py (debug=True); Dash will reload on file changes
- **Inspect parsed JSON**: Add print statements to `_parse_json_like()` and `_extract_fields()` if parsing fails
- **Check Ollama logs**: Monitor Ollama process output for model loading errors or memory issues

## Performance Considerations

- **Batch Size**: `AI_ANALYSIS_BATCH_SIZE` (1-5, default 1). Larger batch = faster but higher latency per call.
- **Cache Strategy**: Fingerprint-based (not time-based). Monitor hit rates in debug logs.
- **Dataset Size**: Tested up to 1000 assets per source. Merge is O(n log n).

## References

- [Dash Documentation](https://dash.plotly.com/)
- [USWDS 3.0 Design System](https://designsystem.digital.gov/)
- [Ollama Documentation](https://ollama.ai/)
- [Ollama API Reference](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [Tenable.io API](https://developer.tenable.com/)
- [Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)
- [Splunk API](https://docs.splunk.com/)
- [IBM BigFix](https://www.ibm.com/products/bigfix)

