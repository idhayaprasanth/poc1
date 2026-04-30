# Skill: Fingerprinting & Cache Strategy

**Use this skill when**: Adding new data columns, debugging cache misses, optimizing analysis performance, or validating cache behavior.

## Fingerprinting Concept

**Goal**: Detect when asset data hasn't changed → reuse cached AI analysis → skip expensive SageMaker calls

### How It Works

```
Asset Record → Select 17 Key Fields → JSON Serialize → SHA256 Hash → Cache Lookup
                                                           ↓
                                        If hash matches existing: HIT
                                        If hash is new: MISS → SageMaker call
```

## The 17 Fingerprint Columns

**Location**: `SOURCE_FINGERPRINT_COLUMNS` in `datasets.py`

```python
SOURCE_FINGERPRINT_COLUMNS = [
    "asset_name",              # Core asset identifier
    "vuln_name",               # Tenable: vulnerability name
    "vuln_severity",           # Tenable: severity
    "vuln_description",        # Tenable: description
    "vuln_fix",                # Tenable: remediation
    "threat_alert",            # Defender: threat name
    "threat_file_path",        # Defender: affected file
    "threat_process",          # Defender: process info
    "threat_impact",           # Defender: impact description
    "threat_fix",              # Defender: remediation
    "anomaly_event",           # Splunk: event name
    "anomaly_explanation",     # Splunk: explanation
    "source_anomaly_score",    # Splunk: anomaly score
    "patch_status",            # BigFix: patch state
    "patch_severity",          # BigFix: severity
    "patch_recommendation",    # BigFix: recommendation
    "scan_date",               # Metadata: when data was collected
]
```

### Why These 17?

- **Excludes AI output**: risk_score, risk_level, remediation, etc. (these are generated, not input)
- **Includes all source data**: Covers Tenable, Defender, Splunk, BigFix fields
- **Includes temporal marker**: scan_date ensures new scans invalidate cache

## Fingerprinting Implementation

### Computing a Fingerprint

```python
def compute_asset_fingerprint(asset_record: dict) -> str:
    """Create SHA256 hash of asset's key fields."""
    # 1. Extract only fingerprint columns
    fingerprint_dict = {
        col: asset_record.get(col, "")
        for col in SOURCE_FINGERPRINT_COLUMNS
    }
    
    # 2. Serialize to JSON (order matters!)
    json_str = json.dumps(fingerprint_dict, sort_keys=True, default=str)
    
    # 3. Hash it
    return hashlib.sha256(json_str.encode()).hexdigest()
```

### Why JSON Serialization Order Matters

```python
# These produce DIFFERENT hashes (different JSON):
{"a": 1, "b": 2}  # No order enforcement
{"b": 2, "a": 1}  # Different key order

# Solution: Use sort_keys=True
json.dumps(data, sort_keys=True)  # Always produces consistent JSON
```

## Cache Storage

**Location**: `security_dashboard/data/ai_analysis_cache.json`

**Structure**:
```json
{
  "3f7a9c2d1e...": {
    "asset_id": "asset-001",
    "asset_name": "server-prod-01",
    "risk_score": 78,
    "risk_level": "High",
    "threat_status": "Active",
    "ai_analysis_source": "cache",
    "cached_at": "2024-01-15T10:30:00Z"
  },
  "8b2c5e9f1a...": {
    "asset_id": "asset-002",
    ...
  }
}
```

### Cache Lookup

```python
def _cached_result_for_record(self, fingerprint: str) -> dict | None:
    """Retrieve cached analysis by fingerprint."""
    cache = load_ai_analysis_cache()
    
    if fingerprint in cache:
        result = cache[fingerprint]
        result["ai_analysis_source"] = "cache"
        return result
    
    return None
```

### Cache Persistence

```python
def persist_ai_analysis_result(fingerprint: str, result: dict) -> None:
    """Save analysis result to cache."""
    cache = load_ai_analysis_cache()
    cache[fingerprint] = result
    
    with open("security_dashboard/data/ai_analysis_cache.json", "w") as f:
        json.dump(cache, f, indent=2)
```

## When to Update Fingerprint Columns

### Scenario 1: Adding a New Source Field

**Example**: Defender starts providing `threat_registry_key`

**Action**:
1. Add to CSV column aliases (`DATASET_COLUMN_ALIASES`)
2. Add to fingerprint columns if it affects risk scoring
3. Delete `ai_analysis_cache.json` (all fingerprints now invalid)
4. Test: Run twice, verify 2nd run shows cache hit

```python
# In datasets.py
SOURCE_FINGERPRINT_COLUMNS = [
    # ... existing 17 ...
    "threat_registry_key",  # NEW
]
```

### Scenario 2: Ignoring a Field for Cache

**Example**: `scan_date` changes frequently but shouldn't invalidate cache

**Action**:
1. Remove from `SOURCE_FINGERPRINT_COLUMNS`
2. Delete cache
3. Test: Run with different `scan_date`, verify same fingerprint

```python
# OLD (fingerprint changes on every scan)
SOURCE_FINGERPRINT_COLUMNS = [
    ..., "scan_date"
]

# NEW (fingerprint stable across scans)
SOURCE_FINGERPRINT_COLUMNS = [
    ...  # scan_date removed
]
```

## Cache Validation

### Manual Cache Inspection

```bash
# Count cached entries
cat security_dashboard/data/ai_analysis_cache.json | jq '. | length'

# Check a specific fingerprint
cat security_dashboard/data/ai_analysis_cache.json | jq '.["3f7a9c2d1e..."]'

# List all asset_ids in cache
cat security_dashboard/data/ai_analysis_cache.json | jq 'to_entries[] | .value.asset_id' | sort -u
```

### Testing Cache Behavior

```python
def test_fingerprinting():
    """Verify cache hits work correctly."""
    # 1. Create test asset
    asset1 = {
        "asset_name": "server-01",
        "vuln_name": "CVE-2024-001",
        "vuln_severity": "High",
        # ... all 17 fingerprint columns
    }
    
    # 2. First analysis (should hit SageMaker)
    result1 = client.generate_asset_analysis(asset1)
    assert result1["ai_analysis_source"] == "sagemaker"
    
    # 3. Same asset again (should hit cache)
    result2 = client.generate_asset_analysis(asset1)
    assert result2["ai_analysis_source"] == "cache"
    
    # 4. Modify non-fingerprint field (should still cache)
    asset1["non_fingerprint_field"] = "new_value"
    result3 = client.generate_asset_analysis(asset1)
    assert result3["ai_analysis_source"] == "cache"
    
    # 5. Modify fingerprint field (should hit SageMaker)
    asset1["vuln_severity"] = "Medium"
    result4 = client.generate_asset_analysis(asset1)
    assert result4["ai_analysis_source"] == "sagemaker"
```

## Cache Invalidation Scenarios

### Scenario 1: Update Fingerprint Columns

```bash
# Before: SOURCE_FINGERPRINT_COLUMNS had 17 fields
# After: Added new field (18 fields)

# Action: Delete cache (all hashes now invalid)
rm security_dashboard/data/ai_analysis_cache.json

# Result: First analysis on each asset will recompute
```

### Scenario 2: Clear Stale Cache

```bash
# If you suspect cache has old data:
rm security_dashboard/data/ai_analysis_cache.json

# Or programmatically:
import os
if os.path.exists("security_dashboard/data/ai_analysis_cache.json"):
    os.remove("security_dashboard/data/ai_analysis_cache.json")
```

### Scenario 3: Selective Cache Clearing

```python
def clear_cache_for_asset(asset_id: str) -> None:
    """Remove only entries for a specific asset."""
    cache = load_ai_analysis_cache()
    
    # Remove fingerprints where asset_id matches
    cache_entries_to_delete = [
        fp for fp, result in cache.items()
        if result.get("asset_id") == asset_id
    ]
    
    for fp in cache_entries_to_delete:
        del cache[fp]
    
    persist_ai_analysis_cache(cache)
```

## Performance Impact

### Cache Hit Rate Estimation

```
Given:
- 1000 assets in dataset
- Fingerprint collision = 0% (SHA256 is cryptographically secure)
- First run: 1000 SageMaker calls (~2-5 sec each = 2000-5000 sec total)
- Subsequent runs: 1000 cache hits = ~100 msec total

Optimization: ~20-50x speedup on unchanged data
```

### Monitoring Cache Effectiveness

```python
def analyze_cache_stats():
    """Report cache hit rate."""
    cache = load_ai_analysis_cache()
    
    total_entries = len(cache)
    hit_entries = sum(1 for result in cache.values() 
                     if result.get("ai_analysis_source") == "cache")
    
    print(f"Cache entries: {total_entries}")
    print(f"Cache hits: {hit_entries}")
    print(f"Hit rate: {hit_entries / total_entries * 100:.1f}%")
```

## Debugging Cache Issues

| Issue | Diagnosis | Fix |
|---|---|---|
| Cache never hits | Fingerprint logic broken | Verify `compute_asset_fingerprint()` produces same hash for identical data; check `sort_keys=True` in JSON serialization |
| Cache grows infinitely | Fingerprints keep changing | Check if `SOURCE_FINGERPRINT_COLUMNS` includes non-deterministic fields (timestamps without normalization) |
| Cache returns wrong data | Multiple fingerprints collide | Extremely unlikely with SHA256; check if asset_id field is included in fingerprint |
| Cache file corrupted | JSON parse error | Manually inspect file; delete and regenerate |
| File permission denied | Cache locked during write | Ensure no other process writing; use file locking if concurrent access |

## Best Practices

1. **Include all source fields**: If a field affects risk scoring, add to fingerprint
2. **Exclude all AI outputs**: Don't include generated fields (risk_score, remediation, etc.)
3. **Include temporal markers**: Include scan_date or last_modified to catch updates
4. **Use sort_keys=True**: Ensures consistent JSON serialization
5. **Document fingerprint changes**: Update this skill when SOURCE_FINGERPRINT_COLUMNS changes
6. **Test cache behavior**: Always verify 2nd analysis hits cache
7. **Monitor cache file size**: If >100MB, consider archiving old entries

## References

- `datasets.py`: `compute_asset_fingerprint()`, `load_ai_analysis_cache()`, `persist_ai_analysis_result()`
- `ai_analysis.py`: `generate_asset_analysis()`, `_cached_result_for_record()`
- [SHA256 Collision Probability](https://en.wikipedia.org/wiki/Birthday_attack): ~2^128 for practical purposes (negligible)
