#!/usr/bin/env python3
"""
Launcher script for the TUI Dashboard.
This script checks dependencies and launches the TUI.
"""
import sys
from pathlib import Path

# Check Python version
if sys.version_info < (3, 8):
    print("ERROR: Python 3.8 or higher is required")
    sys.exit(1)

# Check dependencies
missing_deps = []
try:
    import pandas
except ImportError:
    missing_deps.append("pandas")

try:
    import curses
except ImportError:
    missing_deps.append("windows-curses (on Windows)")

try:
    import requests
except ImportError:
    missing_deps.append("requests")

if missing_deps:
    print("ERROR: Missing required dependencies:")
    for dep in missing_deps:
        print(f"  - {dep}")
    print("\nInstall with: pip install -r requirements.txt")
    sys.exit(1)

# Check for data files
data_dir = Path(__file__).parent / "security_dashboard" / "data" / "seed_data"
tenable_dir = data_dir / "tenable"
splunk_dir = data_dir / "splunk"

if not tenable_dir.exists() or not splunk_dir.exists():
    print("WARNING: Data directories not found")
    print(f"  Tenable: {tenable_dir}")
    print(f"  Splunk: {splunk_dir}")
    print("\nPlease add CSV files to these directories.")

tenable_files = list(tenable_dir.glob("*.csv")) if tenable_dir.exists() else []
splunk_files = list(splunk_dir.glob("*.csv")) if splunk_dir.exists() else []

if not tenable_files and not splunk_files:
    print("WARNING: No CSV files found in data directories")
    print("The dashboard will start but may not show any data.")
    print("\nAdd Tenable CSV files to: security_dashboard/data/seed_data/tenable/")
    print("Add Splunk CSV files to: security_dashboard/data/seed_data/splunk/")
    response = input("\nContinue anyway? (y/n): ")
    if response.lower() != 'y':
        sys.exit(0)

# Check environment variables
import os

# Load .env file if it exists
env_file = Path(__file__).parent / ".env"
if env_file.exists():
    print(f"\nLoading environment from: {env_file}")
    with open(env_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                # Remove quotes if present
                value = value.strip('"').strip("'")
                os.environ[key] = value

dgx_endpoint = os.getenv("DGX_SPARK_SERVER_ENDPOINT_URL")
if not dgx_endpoint:
    print("\nWARNING: DGX_SPARK_SERVER_ENDPOINT_URL not set")
    print("AI analysis will not work without this endpoint.")
    print("Set it with: export DGX_SPARK_SERVER_ENDPOINT_URL=<your-endpoint>")
    print("Or add it to .env file in the project root")
    print("\nYou can still view existing cached analysis results.")

print("\n" + "="*70)
print("  VULNERABILITY RISK INTELLIGENCE DASHBOARD - TUI")
print("="*70)
if tenable_files:
    print(f"  Tenable files: {len(tenable_files)}")
if splunk_files:
    print(f"  Splunk files: {len(splunk_files)}")
if dgx_endpoint:
    print(f"  AI Endpoint: Configured")
else:
    print(f"  AI Endpoint: NOT CONFIGURED (AI analysis disabled)")
print("="*70)
print("\nStarting dashboard...\n")

# Launch TUI
try:
    from tui_dashboard import main
    main()
except KeyboardInterrupt:
    print("\n\nDashboard interrupted by user.")
except Exception as e:
    print(f"\n\nERROR: Dashboard crashed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
