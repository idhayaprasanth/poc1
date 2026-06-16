#!/usr/bin/env python3
"""
Launcher script for the TUI Dashboard.
This script checks dependencies and launches the TUI.
"""
import logging
import sys
from pathlib import Path

LOG_FILE = Path(__file__).parent / "tui_ai_analysis.log"
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")],
    force=True,
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Check Python version
if sys.version_info < (3, 8):
    logger.error("Python 3.8 or higher is required")
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
    logger.error("Missing required dependencies:")
    for dep in missing_deps:
        logger.error("  - %s", dep)
    logger.error("Install with: pip install -r requirements.txt")
    sys.exit(1)

# Check for data files
data_dir = Path(__file__).parent / "security_dashboard" / "data" / "seed_data"
tenable_dir = data_dir / "tenable"
splunk_dir = data_dir / "splunk"

if not tenable_dir.exists() or not splunk_dir.exists():
    logger.warning("Data directories not found")
    logger.warning("  Tenable: %s", tenable_dir)
    logger.warning("  Splunk: %s", splunk_dir)
    logger.warning("Please add CSV files to these directories.")

tenable_files = list(tenable_dir.glob("*.csv")) if tenable_dir.exists() else []
splunk_files = list(splunk_dir.glob("*.csv")) if splunk_dir.exists() else []

if not tenable_files and not splunk_files:
    logger.warning("No CSV files found in data directories")
    logger.warning("The dashboard will start but may not show any data.")
    logger.warning("Add Tenable CSV files to: security_dashboard/data/seed_data/tenable/")
    logger.warning("Add Splunk CSV files to: security_dashboard/data/seed_data/splunk/")
    response = input("\nContinue anyway? (y/n): ")
    if response.lower() != 'y':
        sys.exit(0)

# Check environment variables
import os

# Load .env file if it exists
env_file = Path(__file__).parent / ".env"
if env_file.exists():
    logger.info("Loading environment from: %s", env_file)
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
    logger.warning("DGX_SPARK_SERVER_ENDPOINT_URL not set")
    logger.warning("AI analysis will not work without this endpoint.")
    logger.warning("Set it with: export DGX_SPARK_SERVER_ENDPOINT_URL=<your-endpoint>")
    logger.warning("Or add it to .env file in the project root")
    logger.warning("You can still view existing cached analysis results.")

logger.info("=" * 70)
logger.info("  VULNERABILITY RISK INTELLIGENCE DASHBOARD - TUI")
logger.info("=" * 70)
if tenable_files:
    logger.info("  Tenable files: %s", len(tenable_files))
if splunk_files:
    logger.info("  Splunk files: %s", len(splunk_files))
if dgx_endpoint:
    logger.info("  AI Endpoint: Configured")
else:
    logger.info("  AI Endpoint: NOT CONFIGURED (AI analysis disabled)")
logger.info("=" * 70)
logger.info("Starting dashboard...")

# Launch TUI
try:
    from tui_dashboard import main
    main()
except KeyboardInterrupt:
    logger.info("Dashboard interrupted by user.")
except Exception as e:
    logger.exception("Dashboard crashed: %s", e)
    sys.exit(1)
