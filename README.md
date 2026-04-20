# Unified Security Risk Dashboard (Dash)

A single-page cybersecurity dashboard built with Python + Dash. It merges multiple mock data sources (vuln/threat/logs/patch) into one asset inventory, computes a risk score, and provides analyst-friendly views (KPIs, table, detail panel, trend, daily change summary, SLA aging, AI insights, and an AI chat window).

## Quick Start

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Configure Gemini (optional):

- Copy `.env.example` -> `.env`
- Set `GEMINI_API_KEY="..."` (model can stay `auto`)

3. Run:

```bash
python app.py
```

Then open `http://127.0.0.1:8050`.

## Project Structure

```
.
├─ app.py                      # Entry point (loads .env, runs Dash app)
├─ .env                        # Local secrets (ignored by git)
├─ requirements.txt            # Python dependencies
├─ security_dashboard/
│  ├─ app.py                   # Dash layout + callbacks (main app)
│  ├─ config.py                # Minimal .env loader
│  ├─ data/
│  │  ├─ datasets.py           # Mock datasets + build_merged_dataset()
│  │  └─ __init__.py
│  ├─ services/
│  │  ├─ gemini_flash.py       # Gemini client + security gating + fallback
│  │  └─ __init__.py
│  └─ __init__.py
└─ .gitignore
```

## Data Flow (High Level)

The app revolves around `merged-data-store` (JSON-serialized DataFrame). Most UI components react to it.

```mermaid
flowchart TD
  A[datasets.build_merged_dataset()] --> B[merged-data-store]
  B --> C[KPIs]
  B --> D[Trend Chart]
  B --> E[Asset Table]
  E --> F[Detail Panel]
  B --> G[SLA / Aging Tracker]
  B --> H[AI Insights]
  B --> I[AI Chat Context]
  J[Refresh Button] --> K[previous-merged-data-store]
  B --> L[What Changed Today]
  K --> L
  I --> M[Gemini Client]
  M --> N[Chat Response]
```

## Key Screens / Components

- **KPI cards**: Counts of Total/High/Medium/Low risk.
- **Asset table**: Sort/filter/search; select a row to open the detail panel.
- **Detail panel**: Drill-down sections; Issue Status can be set to `Open / In Progress / Resolved`.
- **Risk Trend**: Avg risk score per scan date.
- **What Changed Today**: Compares the latest snapshot vs the previous snapshot.
  - Click **Refresh** once to capture the previous snapshot.
- **SLA / Aging Tracker**:
  - Age is derived from `scan_date`
  - SLA defaults: High=3 days, Medium=7 days
  - Flags breached items where status is Open/In Progress.
- **AI Insights**: Local heuristic insights (works even when Gemini quota is unavailable).
- **AI Chat**: Uses Gemini when available; falls back locally when quota/model is unavailable.

## Environment Variables

- `GEMINI_API_KEY`: Enables Gemini calls.
- `GEMINI_MODEL`: `auto` recommended.
- `GEMINI_API_VERSION`: Defaults to `v1beta`.

## Notes

- If Gemini returns `429` quota errors, the app automatically backs off and uses the built-in fallback so the dashboard stays usable.

