# Vulnerability Risk Intelligence Dashboard - TUI Edition

A terminal-based user interface (TUI) for analyzing security vulnerabilities by correlating Tenable vulnerability scans with Splunk security logs using AI-powered analysis.

## Overview

This dashboard replaces the previous web-based interface with a lightweight, high-performance terminal UI that provides:

- **Real-time AI Analysis**: Watch as each asset is analyzed with immediate updates
- **Live Data Reload**: Press F5 to reload CSV data without restarting
- **Filtered Splunk Data**: Optimized column filtering reduces AI token usage
- **Interactive Navigation**: Keyboard-driven interface for fast workflow
- **Asset Risk Scoring**: AI-generated risk scores, levels, and remediation recommendations

## Features

### Core Functionality

- ✅ **Asset Correlation**: Automatically groups Tenable and Splunk data by hostname
- ✅ **AI-Powered Analysis**: Integrates with DGX Spark Server (Llama 3.1) for vulnerability analysis
- ✅ **Real-time Updates**: Asset rows update instantly as AI analysis completes
- ✅ **Progress Tracking**: Visual progress bar and counters during analysis
- ✅ **Intelligent Caching**: Results are cached to avoid re-analyzing unchanged assets
- ✅ **Column Filtering**: Removes unnecessary Splunk columns (XML, metadata) before AI analysis
- ✅ **Risk Levels**: Critical, High, Medium, Low classifications with color coding
- ✅ **Detail Panel**: Scrollable detailed view of each asset's analysis
- ✅ **Filter Tabs**: Quick filtering by risk level or pending status

### Data Optimization

The TUI dashboard implements intelligent Splunk column filtering to reduce token usage:

**Columns Kept:**
- Identity: Computer, host, IpAddress
- Events: EventCode, EventID, signature
- Process: ProcessName, CommandLine, ParentProcessName
- User: User, UserName, SubjectUserName
- Security: Message, Result, Status
- Time: _time, SystemTime

**Columns Removed:**
- XML data fields
- Empty columns
- Redundant metadata
- Tag fields
- Splunk internal fields

This reduces the average AI analysis payload by ~70%, improving speed and reducing costs.

## Installation

### Prerequisites

- Python 3.8 or higher
- Windows Terminal (recommended) or any terminal with curses support

### Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `pandas` - Data manipulation
- `requests` - HTTP client for AI endpoint
- `windows-curses` - Terminal UI support (Windows only)

### Configuration

Set your AI endpoint URL as an environment variable:

```bash
# Windows (PowerShell)
$env:DGX_SPARK_SERVER_ENDPOINT_URL="http://your-endpoint-url"

# Linux/Mac
export DGX_SPARK_SERVER_ENDPOINT_URL="http://your-endpoint-url"
```

Optional configuration:
```bash
$env:DGX_SPARK_SERVER_MAX_NEW_TOKENS="1000"
$env:DGX_SPARK_SERVER_TEMPERATURE="0.01"
$env:DGX_SPARK_SERVER_READ_TIMEOUT_SECONDS="300"
```

## Usage

### Quick Start

```bash
# Recommended: Use the launcher script
python run_tui.py

# Or run directly
python tui_dashboard.py
```

### Adding Data

1. Place Tenable CSV files in: `security_dashboard/data/seed_data/tenable/`
2. Place Splunk CSV files in: `security_dashboard/data/seed_data/splunk/`
3. Press **F5** in the TUI to reload data (or restart the dashboard)

The dashboard automatically detects and loads all CSV files from these directories.

### Keyboard Controls

| Key | Action |
|-----|--------|
| `R` | Run AI analysis for pending assets |
| `F5` | Reload data from CSV files |
| `↑` `↓` | Navigate asset list |
| `←` `→` | Switch filter tabs |
| `TAB` | Toggle focus between list and detail panel |
| `PgUp` `PgDn` | Page through assets |
| `Home` `End` | Jump to first/last asset |
| `Q` or `Esc` | Quit |

### Workflow

1. **Start the Dashboard**: `python run_tui.py`
2. **Review Assets**: Navigate through the asset list to see what's loaded
3. **Filter by Status**: Use left/right arrows to filter by risk level or pending status
4. **Run Analysis**: Press `R` to start AI analysis for pending assets
5. **Watch Progress**: See real-time updates as each asset completes
6. **View Details**: Use TAB to focus on the detail panel and scroll through analysis results
7. **Add New Data**: Add new CSV files and press `F5` to reload

## Dashboard Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│       🔒  VULNERABILITY RISK INTELLIGENCE DASHBOARD                 │
├─────────────────────────────────────────────────────────────────────┤
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │ Total    │ │ Critical │ │ High     │ │ Medium   │ │ Low      │ │
│ │ 23       │ │ 3        │ │ 8        │ │ 5        │ │ 7        │ │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│  [All (23)]  [Critical (3)]  [High (8)]  [Medium (5)]  [Low (7)]   │
├──────────────────────────────┬──────────────────────────────────────┤
│ # │ Hostname    │ Score │... │ IDENTITY                           │ │
│ 1 │ srv-web01   │  9.2  │... │ Asset ID: ASSET-001                │ │
│ 2 │ srv-sql01   │  8.7  │... │ Hostname: srv-web01                │ │
│ 3 │ dev-pc01    │  7.5  │... │ IP: 10.20.30.13                    │ │
│   │             │       │    │                                     │ │
│   │             │       │    │ RISK SCORE                          │ │
│   │             │       │    │ Risk Score: 9.2/10 ██████████      │ │
│   │             │       │    │ Risk Level: Critical                │ │
│   │             │       │    │                                     │ │
│   │             │       │    │ AI ANALYSIS                         │ │
│   │             │       │    │ Multiple critical vulnerabilities...│ │
└──────────────────────────────┴──────────────────────────────────────┘
│ R: Run Analysis  F5: Reload  ↑↓: Navigate  Q: Quit                │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Format

### Tenable CSV Requirements

Must include columns for asset identification:
- `DNS Name` or `IP Address`
- `Plugin`, `Plugin Name`, `Severity`
- `VPR`, `ACR` (vulnerability/asset criticality ratings)

### Splunk CSV Requirements

Must include columns for event identification:
- `Computer`, `host`, or `ComputerName`
- `EventCode` or `EventID`
- `_time` or `SystemTime`
- `Message` or `signature`

## AI Analysis

### Analysis Results

Each asset receives:
- **Risk Score** (0-10): Overall vulnerability risk
- **Risk Level**: Critical, High, Medium, or Low
- **Priority Level**: Remediation timeframe
- **AI Reason**: Detailed explanation of the risk assessment
- **Remediation**: Specific actions to address vulnerabilities
- **Tenable Analysis**: Vulnerability-specific details
- **Splunk Analysis**: Security log analysis and anomalies

### Result Caching

Analysis results are cached in `security_dashboard/data/ai_analysis_cache.json` using a fingerprint of:
- Asset name
- Tenable raw data
- Splunk raw data

If any of these change, the asset will be re-analyzed on the next run.

## Troubleshooting

### "DGX Spark Server not configured" Error

Set the endpoint URL:
```bash
$env:DGX_SPARK_SERVER_ENDPOINT_URL="http://your-endpoint"
```

### "No CSV files found" Warning

Add CSV files to the data directories:
- `security_dashboard/data/seed_data/tenable/*.csv`
- `security_dashboard/data/seed_data/splunk/*.csv`

### "Terminal too small" Error

Resize your terminal window to at least 70 columns × 30 rows.

### Analysis Not Starting

1. Check that the DGX endpoint is accessible
2. Verify pending assets exist (check the "Pending" filter tab)
3. Review terminal output for error messages

### Curses Import Error on Windows

Install windows-curses:
```bash
pip install windows-curses
```

## Architecture

### Components

- **`tui_dashboard.py`**: Main TUI application with curses rendering
- **`run_tui.py`**: Launcher script with dependency checks
- **`security_dashboard/data/datasets.py`**: Data loading and column filtering
- **`security_dashboard/analysis.py`**: Background AI analysis worker
- **`security_dashboard/services/dgx_spark_server_client.py`**: AI endpoint client
- **`security_dashboard/filters.py`**: Data filtering and status tracking

### Data Flow

```
CSV Files
   ↓
Load & Filter (datasets.py)
   ↓
Group by Hostname
   ↓
Apply Cache (if exists)
   ↓
TUI Display (tui_dashboard.py)
   ↓
User Presses 'R'
   ↓
Background Worker (analysis.py)
   ↓
AI Endpoint (dgx_spark_server_client.py)
   ↓
Update Assets Real-time
   ↓
Save to Cache
```

## Migration from Web Dashboard

The web dashboard has been archived to `archive_web_dashboard/`. See `archive_web_dashboard/README.md` for details on the old architecture and restoration instructions if needed.

### Key Improvements

| Feature | Web Dashboard | TUI Dashboard |
|---------|---------------|---------------|
| Startup Time | ~5-10 seconds | ~1-2 seconds |
| Memory Usage | ~200MB | ~50MB |
| Dependencies | dash, plotly, flask | pandas, curses, requests |
| Update Latency | 1-5 seconds (polling) | <200ms (direct) |
| SSH Compatible | ❌ No | ✅ Yes |
| Background Running | ❌ Blocks terminal | ✅ Can background |

## Performance

- **Startup**: Loads ~100 assets in <2 seconds
- **Analysis**: Processes assets in parallel (4 concurrent threads)
- **Updates**: Real-time with <200ms latency
- **Memory**: ~50MB typical usage
- **Token Reduction**: ~70% fewer tokens per asset vs. unfiltered

## License

Proprietary - Internal Use Only

## Support

For issues or questions, contact the security operations team.

---

**Version**: 2.0 (TUI Edition)  
**Last Updated**: June 12, 2026  
**Migration Date**: June 12, 2026
