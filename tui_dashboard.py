#!/usr/bin/env python3
"""
=============================================================================
  VULNERABILITY RISK INTELLIGENCE DASHBOARD  —  Interactive TUI
=============================================================================
  Controls:
    R          Run AI analysis for pending assets
    ←  /  →    Navigate filter tabs
    ↑  /  ↓    Navigate asset list
    TAB        Toggle focus between list and detail panel
    PgUp/PgDn  Page through assets
    Home/End   Jump to first/last asset
    Q  /  Esc  Quit
=============================================================================
  COLOR SCHEME - Dark Cyberpunk Theme:
    - Background: BLACK throughout entire dashboard
    - Stats Panel: Stats boxes with colorful neon borders (green/red/yellow/cyan/magenta)
    - Asset List Section: CYAN neon borders (left panel)
    - Detail Panel Section: MAGENTA neon borders (right panel)
    - Title Bar: CYAN text on BLACK with line decoration
    - Filter Tabs: Active=white bg, Inactive=black bg with colored text
    - Risk Levels: RED=Critical, YELLOW=High, CYAN=Medium, GREEN=Low
    - Status: MAGENTA=Pending/Analyzing
    - Selected Item: WHITE text on BLUE highlight
=============================================================================
"""
import curses
import sys
import os
import platform
import threading
import time
import logging
from datetime import datetime
from pathlib import Path

# On Windows, windows-curses provides the curses module; on Linux it is built-in.
# No code change needed — just ensure windows-curses is installed on Windows only.
_PLATFORM = sys.platform          # "win32" | "linux" | "darwin"
_IS_WINDOWS = _PLATFORM == "win32"

try:
    import pandas as pd
except ImportError:
    print("Missing dependency: pandas\nRun: pip install pandas")
    sys.exit(1)

# Add project root to path for imports
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

from security_dashboard.config import load_env_file
from security_dashboard.data.datasets import build_merged_dataset, ensure_ai_analysis_columns
from security_dashboard.analysis import AnalysisBackgroundState, run_analysis_worker_thread
from security_dashboard.filters import analysis_pending_mask, analysis_completion_mask
from security_dashboard.services.dgx_spark_server_client import DGXSparkServerClient

# Load environment variables from .env file
load_env_file()

# Setup logging to file for AI analysis
LOG_FILE = project_root / "tui_ai_analysis.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, mode='w', encoding='utf-8'),
    ]
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
#  DEBUG: Log platform/environment at module import time
# ──────────────────────────────────────────────────────────────────────────────
logger.info("[DEBUG] ===== STARTUP ENVIRONMENT =====")
logger.info(f"[DEBUG] Python   : {sys.version}")
logger.info(f"[DEBUG] Platform : {platform.platform()}")
logger.info(f"[DEBUG] sys.platform: {sys.platform}")
logger.info(f"[DEBUG] TERM     : {os.environ.get('TERM', '<not set>')}")
logger.info(f"[DEBUG] COLORTERM: {os.environ.get('COLORTERM', '<not set>')}")
logger.info(f"[DEBUG] LANG     : {os.environ.get('LANG', '<not set>')}")
logger.info(f"[DEBUG] LC_ALL   : {os.environ.get('LC_ALL', '<not set>')}")
logger.info(f"[DEBUG] curses   : {curses.version if hasattr(curses, 'version') else 'unknown'}")
logger.info("[DEBUG] ==================================")

# ══════════════════════════════════════════════════════════════════════════════
#  COLOR PAIRS
# ══════════════════════════════════════════════════════════════════════════════
PAIR_CRIT = 1
PAIR_HIGH = 2
PAIR_MED = 3
PAIR_LOW = 4
PAIR_DIM = 5
PAIR_HEADER = 6
PAIR_SEL = 7
PAIR_TABA = 8
PAIR_TABI = 9
PAIR_BORDER = 10
PAIR_LABEL = 11
PAIR_WARN = 12
PAIR_BAR = 13
PAIR_WHITE = 14
PAIR_PENDING = 15
PAIR_STAT_BLUE = 16
PAIR_STAT_PURPLE = 17
PAIR_STAT_PINK = 18
PAIR_STAT_YELLOW = 19
PAIR_STAT_RED = 20
PAIR_STAT_GREEN = 21
PAIR_NAVY_BG = 22  # Navy blue background for entire dashboard
PAIR_STATS_SECTION = 23  # Color for stats panel section
PAIR_FILTER_SECTION = 24  # Color for filter bar section
PAIR_LIST_SECTION = 25  # Color for asset list section
PAIR_DETAIL_SECTION = 26  # Color for detail panel section
PAIR_TABLE_HEADER = 27  # Color for table column headers
PAIR_DETAIL_BG = 28  # Forest green background for detail panel
PAIR_DETAIL_WHITE = 29  # White text on forest green for detail panel
PAIR_DETAIL_DIM = 30  # Dim text on forest green for detail panel
PAIR_DETAIL_HEADER = 31  # Header text on forest green for detail panel
PAIR_DETAIL_CRIT = 32  # Critical text on forest green
PAIR_DETAIL_HIGH = 33  # High text on forest green
PAIR_DETAIL_MED = 34  # Medium text on forest green
PAIR_DETAIL_LOW = 35  # Low text on forest green
PAIR_DETAIL_PENDING = 36  # Pending text on forest green
PAIR_DETAIL_WARN = 37  # Warning text on forest green

LEVEL_PAIR = {
    "Critical": PAIR_CRIT,
    "High": PAIR_HIGH,
    "Medium": PAIR_MED,
    "Low": PAIR_LOW,
    "Pending": PAIR_PENDING,
}

FILTERS = ["All", "Critical", "High", "Medium", "Low", "Pending", "No Tenable Data", "No Splunk Data"]


def init_colors():
    """
    Initialize color pairs for the TUI with navy blue background theme.
    
    ==========================================================================
    CUSTOMIZATION GUIDE - Change colors here to customize the UI:
    ==========================================================================
    
    BACKGROUND COLOR:
    - Change BG_COLOR to any curses.COLOR_* (BLACK, RED, GREEN, YELLOW, 
      BLUE, MAGENTA, CYAN, WHITE) to change the overall background
    
    SECTION BORDERS:
    - PAIR_LIST_SECTION: Left panel (Asset List) border color - CYAN neon
    - PAIR_DETAIL_SECTION: Right panel (Detail) border color - MAGENTA neon
    - PAIR_BORDER: General border lines - CYAN neon
    
    RISK LEVELS:
    - PAIR_CRIT: Critical risk (default: RED)
    - PAIR_HIGH: High risk (default: YELLOW)
    - PAIR_MED: Medium risk (default: CYAN)
    - PAIR_LOW: Low risk (default: GREEN)
    
    OTHER UI ELEMENTS:
    - PAIR_HEADER: Title bar text (default: CYAN text on BLACK)
    - PAIR_SEL: Selected item highlight (default: WHITE on BLUE)
    - PAIR_PENDING: Pending analysis status (default: MAGENTA)
    - PAIR_TABLE_HEADER: Table column headers (default: WHITE on BLACK)
    
    ==========================================================================
    """
    curses.start_color()
    curses.use_default_colors()

    # DEBUG: log terminal color capabilities
    logger.info(f"[DEBUG] init_colors: COLORS={curses.COLORS} COLOR_PAIRS={curses.COLOR_PAIRS}")
    logger.info(f"[DEBUG] init_colors: has_colors={curses.has_colors()} can_change_color={curses.can_change_color()}")

    # ===== MAIN BACKGROUND COLOR - BLACK for dark cyberpunk aesthetic =====
    BG_COLOR = 17  # BLACK background for dark terminal look
    
    # ===== RISK LEVEL COLORS - Used for asset risk level display =====
    curses.init_pair(PAIR_CRIT, curses.COLOR_RED, BG_COLOR)  # Critical risk level (RED text)
    curses.init_pair(PAIR_HIGH, curses.COLOR_YELLOW, BG_COLOR)  # High risk level (YELLOW text)
    curses.init_pair(PAIR_MED, curses.COLOR_CYAN, BG_COLOR)  # Medium risk level (CYAN text)
    curses.init_pair(PAIR_LOW, curses.COLOR_GREEN, BG_COLOR)  # Low risk level (GREEN text)
    
    # ===== GENERAL UI COLORS =====
    curses.init_pair(PAIR_DIM, curses.COLOR_WHITE, BG_COLOR)  # Dimmed/secondary text
    curses.init_pair(PAIR_HEADER, curses.COLOR_CYAN, BG_COLOR)  # Title bar text (CYAN on BLACK - cyberpunk style)
    curses.init_pair(PAIR_SEL, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Selected item in asset list (WHITE on BLUE highlight)
    curses.init_pair(PAIR_TABA, curses.COLOR_BLACK, curses.COLOR_WHITE)  # Active filter tab (WHITE background)
    curses.init_pair(PAIR_TABI, curses.COLOR_WHITE, BG_COLOR)  # Inactive filter tabs
    curses.init_pair(PAIR_BORDER, curses.COLOR_CYAN, BG_COLOR)  # Generic border lines (CYAN neon)
    curses.init_pair(PAIR_LABEL, curses.COLOR_WHITE, 17)  # Labels in detail panel - forest green background
    curses.init_pair(PAIR_WARN, curses.COLOR_RED, BG_COLOR)  # Warning/error messages (RED text)
    curses.init_pair(PAIR_BAR, curses.COLOR_GREEN, BG_COLOR)  # Progress bars
    curses.init_pair(PAIR_WHITE, curses.COLOR_WHITE, BG_COLOR)  # White text on black background
    curses.init_pair(PAIR_PENDING, curses.COLOR_MAGENTA, BG_COLOR)  # Pending analysis status (MAGENTA text)
    
    # ===== STATS PANEL BOX COLORS - Top row stat boxes with neon borders =====
    curses.init_pair(PAIR_STAT_BLUE, curses.COLOR_BLUE, BG_COLOR)  # Blue accent (unused currently)
    curses.init_pair(PAIR_STAT_PURPLE, curses.COLOR_MAGENTA, BG_COLOR)  # Purple/Magenta - "Analyzed" count box
    curses.init_pair(PAIR_STAT_PINK, curses.COLOR_MAGENTA, BG_COLOR)  # Pink/Magenta accent
    curses.init_pair(PAIR_STAT_YELLOW, curses.COLOR_YELLOW, BG_COLOR)  # Yellow accent (unused currently)
    curses.init_pair(PAIR_STAT_RED, curses.COLOR_RED, BG_COLOR)  # Red - "Critical" count box
    curses.init_pair(PAIR_STAT_GREEN, curses.COLOR_GREEN, BG_COLOR)  # Green - "Total Assets" and "Low" count boxes
    
    # ===== BLACK BACKGROUND =====
    curses.init_pair(PAIR_NAVY_BG, curses.COLOR_WHITE, BG_COLOR)  # Black background with white text
    
    # ===== SECTION-SPECIFIC BORDER COLORS - Neon borders for cyberpunk look =====
    curses.init_pair(PAIR_STATS_SECTION, curses.COLOR_CYAN, BG_COLOR)  # Stats panel section (currently unused)
    curses.init_pair(PAIR_FILTER_SECTION, curses.COLOR_YELLOW, BG_COLOR)  # Filter bar section (currently unused)
    curses.init_pair(PAIR_LIST_SECTION, curses.COLOR_CYAN, BG_COLOR)  # LEFT PANEL: Asset list borders (CYAN neon)
    curses.init_pair(PAIR_DETAIL_SECTION, curses.COLOR_MAGENTA, BG_COLOR)  # RIGHT PANEL: Detail panel borders (MAGENTA neon)
    
    # ===== TABLE COLUMN HEADERS =====
    curses.init_pair(PAIR_TABLE_HEADER, curses.COLOR_WHITE, BG_COLOR)  # Table column headers (WHITE on BLACK)
    
    # ===== DETAIL PANEL BACKGROUND AND TEXT COLORS =====
    curses.init_pair(PAIR_DETAIL_BG, curses.COLOR_WHITE, 17)  # Forest green background for detail panel
    curses.init_pair(PAIR_DETAIL_WHITE, curses.COLOR_WHITE, 17)  # White text on forest green
    curses.init_pair(PAIR_DETAIL_DIM, curses.COLOR_WHITE, 17)  # Dim/secondary text on forest green
    curses.init_pair(PAIR_DETAIL_HEADER, curses.COLOR_CYAN, 17)  # Cyan headers on forest green
    curses.init_pair(PAIR_DETAIL_CRIT, curses.COLOR_RED, 17)  # Critical (red) on forest green
    curses.init_pair(PAIR_DETAIL_HIGH, curses.COLOR_YELLOW, 17)  # High (yellow) on forest green
    curses.init_pair(PAIR_DETAIL_MED, curses.COLOR_CYAN, 17)  # Medium (cyan) on forest green
    curses.init_pair(PAIR_DETAIL_LOW, curses.COLOR_GREEN, 17)  # Low (green) on forest green
    curses.init_pair(PAIR_DETAIL_PENDING, curses.COLOR_MAGENTA, 17)  # Pending (magenta) on forest green
    curses.init_pair(PAIR_DETAIL_WARN, curses.COLOR_RED, 17)  # Warning (red) on forest green


# ══════════════════════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════
def safe_addstr(win, y, x, text, attr=0):
    """Add string that silently ignores out-of-bounds writes."""
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w:
        return
    available = w - x
    if available <= 0:
        return
    text = text[:available]
    if y == h - 1:
        text = text[: w - x - 1]
    if not text:
        return
    try:
        win.addstr(y, x, text, attr)
    except curses.error:
        pass


def draw_box(win, title="", color_pair=PAIR_BORDER):
    """Draw a border around window with optional title."""
    h, w = win.getmaxyx()
    attr = curses.color_pair(color_pair)
    try:
        win.attron(attr)
        win.border(0, 0, 0, 0, 0, 0, 0, 0)
        win.attroff(attr)
    except curses.error as _exc:
        logger.error(
            f"[DEBUG] draw_box border FAILED — {_exc!r} | "
            f"win=({h},{w}) title={title!r} color_pair={color_pair}"
        )
    if title:
        t = f" {title} "
        x = max(1, (w - len(t)) // 2)
        safe_addstr(win, 0, x, t, curses.color_pair(PAIR_LABEL) | curses.A_BOLD)


def score_bar(score, width=10):
    """Return a bar string like '████░░░░░░' scaled to width."""
    filled = int(round(score / 10 * width))
    return "█" * filled + "░" * (width - filled)


# ══════════════════════════════════════════════════════════════════════════════
#  STATS PANEL
# ══════════════════════════════════════════════════════════════════════════════
def draw_stat_box(win, y, x, w, value, label, pair, label_color=None):
    """Draw a single stat box at (y, x) with given width."""
    h = 4
    if label_color is None:
        label_color = PAIR_DIM
    try:
        sub = win.derwin(h, w, y, x)
    except curses.error as _exc:
        logger.error(
            f"[DEBUG] draw_stat_box derwin FAILED — {_exc!r} | "
            f"derwin(h={h},w={w},y={y},x={x}) label={label!r}"
        )
        return
    sub.erase()
    attr = curses.color_pair(pair)
    try:
        sub.attron(attr)
        sub.border(0, 0, 0, 0, 0, 0, 0, 0)
        sub.attroff(attr)
    except curses.error:
        pass
    # left vertical accent bar
    try:
        sub.attron(attr | curses.A_BOLD)
        sub.addstr(1, 1, "│")
        sub.addstr(2, 1, "│")
        sub.attroff(attr | curses.A_BOLD)
    except curses.error:
        pass
    safe_addstr(sub, 1, 3, str(value), curses.A_BOLD)
    safe_addstr(sub, 2, 3, label[: w - 5], curses.color_pair(label_color) | curses.A_DIM)
    sub.noutrefresh()


def stats_panel_layout(W, n_boxes=8):
    """Return (box_w, per_row, n_rows) for the stats panel - FORCE SINGLE ROW."""
    # Calculate box width to fit all boxes in a single row
    gap = 1
    # Available width minus some margin
    available_width = W - 4
    # Calculate box width to fit all boxes in one row
    box_w = max(15, (available_width - (n_boxes - 1) * gap) // n_boxes)
    
    # Force single row layout
    per_row = n_boxes  # All boxes in one row
    n_rows = 1  # Single row only
    
    return box_w, per_row, n_rows


def draw_stats_panel(stdscr, stats, start_row=0):
    """Draw the top stats panel - ALL BOXES IN SINGLE ROW."""
    H, W = stdscr.getmaxyx()

    # Stats boxes configuration (removed correlated/uncorrelated cards)
    # Colors indicate: GREEN=Total, RED=Critical, YELLOW=High, CYAN=Medium, GREEN=Low, MAGENTA=Pending, PURPLE=Analyzed
    boxes = [
        (str(stats["n_total"]), "Total Assets", PAIR_STAT_GREEN),  # Total count - green
        (str(stats["n_critical"]), "Critical", PAIR_CRIT),  # Critical risk - red
        (str(stats["n_high"]), "High", PAIR_HIGH),  # High risk - yellow
        (str(stats["n_medium"]), "Medium", PAIR_MED),  # Medium risk - cyan
        (str(stats["n_low"]), "Low", PAIR_LOW),  # Low risk - green
        (str(stats["n_pending"]), "Pending", PAIR_PENDING),  # Pending analysis - magenta
        (str(stats["n_complete"]), "Analyzed", PAIR_STAT_PURPLE),  # Completed analysis - purple
    ]

    box_w, per_row, n_rows = stats_panel_layout(W, len(boxes))
    gap = 1
    x = 2  # Start with small margin
    y = start_row
    
    # Draw all boxes in single row
    for i, (value, label, pair) in enumerate(boxes):
        if x + box_w >= W - 2:  # Check if box fits
            break
        draw_stat_box(stdscr, y, x, box_w, value, label, pair)
        x += box_w + gap


# ══════════════════════════════════════════════════════════════════════════════
#  FILTER TAB BAR
# ══════════════════════════════════════════════════════════════════════════════
def draw_filter_bar(stdscr, active_idx, assets_all, row):
    """Draw the horizontal filter tab bar with scrolling support."""
    counts = {}
    for f in FILTERS[1:]:
        if f == "Pending":
            counts[f] = sum(1 for a in assets_all if a.get("status") in ("Pending", "Analyzing"))
        elif f == "No Tenable Data":
            counts[f] = sum(1 for a in assets_all if not a.get("has_tenable"))
        elif f == "No Splunk Data":
            counts[f] = sum(1 for a in assets_all if not a.get("has_splunk"))
        else:
            counts[f] = sum(1 for a in assets_all if a.get("risk_level") == f)
    counts["All"] = len(assets_all)

    stdscr.move(row, 0)
    stdscr.clrtoeol()
    
    W = stdscr.getmaxyx()[1]
    
    # Calculate which filters to show based on active index
    # Show active filter and neighbors
    visible_start = max(0, active_idx - 2)
    visible_end = min(len(FILTERS), visible_start + 6)
    
    # Adjust if we're at the end
    if visible_end == len(FILTERS) and len(FILTERS) > 6:
        visible_start = max(0, len(FILTERS) - 6)
    
    x = 2
    if visible_start > 0:
        safe_addstr(stdscr, row, x, " ◄ ", curses.color_pair(PAIR_DIM))
        x += 4
    
    for i in range(visible_start, visible_end):
        f = FILTERS[i]
        cnt = counts[f]
        label = f"  {f} ({cnt})  "
        if i == active_idx:
            attr = curses.color_pair(PAIR_TABA) | curses.A_BOLD
        else:
            pair = LEVEL_PAIR.get(f, PAIR_DIM)
            attr = curses.color_pair(pair)
        if x + len(label) + 10 >= W:  # Leave space for arrow
            break
        safe_addstr(stdscr, row, x, label, attr)
        x += len(label) + 1
    
    if visible_end < len(FILTERS):
        safe_addstr(stdscr, row, x, " ► ", curses.color_pair(PAIR_DIM))


# ══════════════════════════════════════════════════════════════════════════════
#  ASSET LIST
# ══════════════════════════════════════════════════════════════════════════════
def draw_asset_list(win, assets, sel_idx, scroll_off):
    """Render the asset list in the left window - ASSET LIST SECTION (cyan neon borders)."""
    logger.info(
        "[DEBUG] draw_asset_list ENTER assets=%s sel_idx=%s scroll_off=%s",
        len(assets),
        sel_idx,
        scroll_off,
    )
    win.erase()
    h, w = win.getmaxyx()
    # Set black background for asset list panel
    win.bkgd(' ', curses.color_pair(PAIR_NAVY_BG))
    draw_box(win, "Assets", PAIR_LIST_SECTION)  # Cyan neon borders for asset list section

    # DEBUG: temporary diagnostic text — confirms this window is rendered on screen
    _dbg_text = "ASSET PANEL WORKING"
    safe_addstr(win, 0, max(1, w - len(_dbg_text) - 2), _dbg_text,
                curses.color_pair(PAIR_WARN) | curses.A_BOLD)

    # Column header
    hdr = f"{'#':>3}  {'Hostname':<15}  {'Score':>5}  {'Risk Level':<10} IP Address"
    safe_addstr(win, 1, 1, hdr[: w - 2], curses.color_pair(PAIR_TABLE_HEADER) | curses.A_BOLD)

    list_h = h - 3
    visible = assets[scroll_off : scroll_off + list_h]

    for row_i, a in enumerate(visible):
        abs_idx = scroll_off + row_i
        y = row_i + 2

        status = a.get("status", "Unknown")
        if status == "Pending":
            pair = PAIR_PENDING
            level_str = "Pending"
        elif status == "Analyzing":
            pair = PAIR_PENDING
            level_str = "Analyzing..."
        else:
            pair = LEVEL_PAIR.get(a.get("risk_level", "Low"), PAIR_LOW)
            level_str = a.get("risk_level", "Low")[:10]

        is_sel = abs_idx == sel_idx

        rank = abs_idx + 1
        nb = a.get("asset_name", "unknown")[:15]
        score = a.get("risk_score", 0.0)
        score_str = f"{score:4.1f}" if score else " -- "
        ip = a.get("ip_address", "—")
        bar = score_bar(score, 6) if score else "      "

        if is_sel:
            sel_attr = curses.color_pair(PAIR_SEL) | curses.A_BOLD
            line = f" {rank:>3}  {nb:<15}  {score_str}  {bar}  {level_str:<10}  {ip}"
            safe_addstr(win, y, 1, line[: w - 2], sel_attr)
        else:
            base_attr = curses.color_pair(pair)
            white_attr = curses.color_pair(PAIR_WHITE) | curses.A_BOLD

            x = 1
            seg = f" {rank:>3}  "
            safe_addstr(win, y, x, seg, base_attr)
            x += len(seg)

            seg = f"{nb:<15}"
            safe_addstr(win, y, x, seg, white_attr)
            x += len(seg)

            seg = f"  {score_str}  {bar}  {level_str:<10}  "
            safe_addstr(win, y, x, seg, base_attr)
            x += len(seg)

            safe_addstr(win, y, x, ip, white_attr)

    # Scrollbar indicator - cyan to match asset list section
    if len(assets) > list_h:
        bar_top = int(scroll_off / max(1, len(assets)) * list_h)
        safe_addstr(win, bar_top + 2, w - 1, "█", curses.color_pair(PAIR_LIST_SECTION))

    win.noutrefresh()


# ══════════════════════════════════════════════════════════════════════════════
#  DETAIL PANEL
# ══════════════════════════════════════════════════════════════════════════════
def draw_detail(win, asset, scroll=0, focused=False):
    """Render the detailed info panel for the selected asset - DETAIL SECTION (magenta neon borders)."""
    logger.info(
        "[DEBUG] draw_detail ENTER asset=%s scroll=%s focused=%s",
        "None" if asset is None else asset.get("asset_name", "?"),
        scroll,
        focused,
    )
    win.erase()
    h, w = win.getmaxyx()
    # Set forest green background for detail panel
    win.bkgd(' ', curses.color_pair(PAIR_DETAIL_BG))

    # DEBUG: temporary diagnostic text — confirms this window is rendered on screen
    _dbg_text = "DETAIL PANEL WORKING"
    safe_addstr(win, 0, max(1, w - len(_dbg_text) - 2), _dbg_text,
                curses.color_pair(PAIR_WARN) | curses.A_BOLD)

    if asset is None:
        draw_box(win, "Detail", PAIR_DETAIL_SECTION)  # Magenta borders for detail section
        safe_addstr(
            win,
            h // 2,
            max(1, (w - 20) // 2),
            "← Select an asset",
            curses.color_pair(PAIR_DETAIL_DIM) | curses.A_DIM,
        )
        win.noutrefresh()
        return 0

    a = asset
    status = a.get("status", "Unknown")
    if status == "Pending":
        pair = PAIR_DETAIL_PENDING
    elif status == "Analyzing":
        pair = PAIR_DETAIL_PENDING
    else:
        # Map regular pairs to detail pairs
        risk_level = a.get("risk_level", "Low")
        if risk_level == "Critical":
            pair = PAIR_DETAIL_CRIT
        elif risk_level == "High":
            pair = PAIR_DETAIL_HIGH
        elif risk_level == "Medium":
            pair = PAIR_DETAIL_MED
        else:
            pair = PAIR_DETAIL_LOW

    # Estimate pad height
    pad_h = 60 + len(str(a.get("ai_reason", "")).split("\n"))
    pad_w = max(w, 1)
    try:
        pad = curses.newpad(pad_h, pad_w)
        # Set forest green background for the pad content
        pad.bkgd(' ', curses.color_pair(PAIR_DETAIL_BG))
        logger.info("[DEBUG] draw_detail: newpad(%s,%s) OK", pad_h, pad_w)
    except curses.error as _exc:
        logger.error(
            f"[DEBUG] draw_detail: newpad({pad_h},{pad_w}) FAILED — {_exc!r} — "
            f"falling back to win ({h},{w})"
        )
        pad = win

    def lbl(y, label, value, vpair=PAIR_DETAIL_DIM):
        lw = 18
        safe_addstr(
            pad, y, 2, f"{label:<{lw}}", curses.color_pair(PAIR_DETAIL_WHITE) | curses.A_BOLD
        )
        safe_addstr(pad, y, 2 + lw, str(value)[: w - lw - 4], curses.color_pair(vpair))

    def lbl_white(y, label, value):
        lw = 18
        safe_addstr(
            pad, y, 2, f"{label:<{lw}}", curses.color_pair(PAIR_DETAIL_WHITE) | curses.A_BOLD
        )
        safe_addstr(
            pad,
            y,
            2 + lw,
            str(value)[: w - lw - 4],
            curses.color_pair(PAIR_DETAIL_WHITE) | curses.A_BOLD,
        )

    def sep(y):
        # Separator line in detail panel - magenta to match detail section
        safe_addstr(pad, y, 1, "─" * (w - 2), curses.color_pair(PAIR_DETAIL_SECTION))

    row = 1

    # Identity
    safe_addstr(
        pad, row, 2, " IDENTITY ", curses.color_pair(PAIR_DETAIL_HEADER) | curses.A_BOLD
    )
    row += 1
    lbl_white(row, "Asset ID", a.get("asset_id", ""))
    row += 1
    lbl_white(row, "Hostname", a.get("asset_name", ""))
    row += 1
    lbl(row, "IP Address", a.get("ip_address", "—"))
    row += 1
    lbl(row, "Facing", a.get("facing", "Unknown"))
    row += 1
    
    # Correlation status
    has_tenable = a.get("has_tenable", False)
    has_splunk = a.get("has_splunk", False)
    if has_tenable and has_splunk:
        corr_status = "Correlated (Tenable + Splunk)"
        corr_pair = PAIR_DETAIL_LOW
    elif has_tenable and not has_splunk:
        corr_status = "No Splunk Data"
        corr_pair = PAIR_DETAIL_WARN
    elif has_splunk and not has_tenable:
        corr_status = "No Tenable Data"
        corr_pair = PAIR_DETAIL_WARN
    else:
        corr_status = "No Data"
        corr_pair = PAIR_DETAIL_WARN
    lbl(row, "Data Status", corr_status, corr_pair)
    row += 1
    sep(row)
    row += 1

    # Risk Score
    safe_addstr(
        pad, row, 2, " RISK SCORE ", curses.color_pair(PAIR_DETAIL_HEADER) | curses.A_BOLD
    )
    row += 1

    if status in ("Pending", "Analyzing"):
        lbl(row, "Status", status, PAIR_DETAIL_PENDING)
        row += 1
        if status == "Analyzing":
            safe_addstr(pad, row, 2, "⏳ AI analysis in progress...", curses.color_pair(PAIR_DETAIL_PENDING))
            row += 1
    else:
        score = a.get("risk_score", 0.0)
        bar_w = min(30, w - 24)
        bar_str = score_bar(score, bar_w) if score else ""
        score_line = f"{score:4.1f}/10  {bar_str}" if score else "Not analyzed"
        safe_addstr(
            pad, row, 2, "Risk Score        ", curses.color_pair(PAIR_DETAIL_WHITE) | curses.A_BOLD
        )
        safe_addstr(
            pad, row, 20, score_line[: w - 22], curses.color_pair(pair) | curses.A_BOLD
        )
        row += 1
        lbl(row, "Risk Level", a.get("risk_level", "Unknown"), pair)
        row += 1
        
        # Priority with timeframe
        priority = a.get("overall_priority_level", "Unknown")
        if priority == "Critical":
            priority_display = "P1 - Immediate (≤24h)"
        elif priority == "High":
            priority_display = "P2 - Urgent (≤7d)"
        elif priority == "Medium":
            priority_display = "P3 - Planned (≤30d)"
        elif priority == "Low":
            priority_display = "P4 - Monitor"
        else:
            priority_display = priority
        lbl(row, "Priority", priority_display, pair)
        row += 1

    sep(row)
    row += 1

    # AI Analysis
    if status not in ("Pending", "Analyzing"):
        safe_addstr(
            pad, row, 2, " AI ANALYSIS ", curses.color_pair(PAIR_DETAIL_HEADER) | curses.A_BOLD
        )
        row += 1

        ai_reason = str(a.get("ai_reason", "No analysis available"))
        for line in ai_reason.split("\n"):
            safe_addstr(pad, row, 2, line[: w - 4], curses.color_pair(PAIR_DETAIL_DIM))
            row += 1

        row += 1
        sep(row)
        row += 1

        # Remediation
        safe_addstr(
            pad, row, 2, " REMEDIATION ", curses.color_pair(PAIR_DETAIL_HEADER) | curses.A_BOLD
        )
        row += 1

        remediation = str(a.get("remediation", "No remediation provided"))
        for line in remediation.split("\n"):
            safe_addstr(pad, row, 2, line[: w - 4], curses.color_pair(PAIR_DETAIL_DIM))
            row += 1

    content_h = row + 1

    # Draw border on real window
    title_suffix = ""
    max_scroll = max(0, content_h - (h - 2))
    if max_scroll > 0:
        title_suffix = (
            f"  [{min(scroll, max_scroll)+1}-{min(scroll + (h-2), content_h)}/{content_h}]"
        )
    focus_tag = (
        "  [TAB to scroll]"
        if (max_scroll > 0 and not focused)
        else ("  [SCROLLING]" if focused else "")
    )
    title = f"  {a.get('asset_name', 'Asset')}  —  {a.get('risk_level', 'Unknown')}{title_suffix}{focus_tag}  "
    draw_box(win, title, PAIR_DETAIL_SECTION)  # Magenta borders for detail section

    # Copy visible slice of pad to window
    scroll = max(0, min(scroll, max_scroll))
    inner_h = h - 2
    inner_w = w - 2
    if pad is not win and inner_h > 0 and inner_w > 0:
        _dst_min_row = 1
        _dst_min_col = 1
        _dst_max_row = min(1 + inner_h - 1, h - 2)
        _dst_max_col = min(1 + inner_w - 1, w - 2)
        logger.info(
            f"[DEBUG] pad.overwrite: src_pad=({pad_h},{pad_w}) src_top_row={scroll} src_left_col=0 | "
            f"dst_win=({h},{w}) dst=({_dst_min_row},{_dst_min_col})->({_dst_max_row},{_dst_max_col})"
        )
        try:
            pad.overwrite(
                win,
                scroll,
                0,
                _dst_min_row,
                _dst_min_col,
                _dst_max_row,
                _dst_max_col,
            )
        except curses.error as _exc:
            logger.error(
                f"[DEBUG] pad.overwrite FAILED — {_exc!r} | "
                f"src_pad=({pad_h},{pad_w}) scroll={scroll} | "
                f"dst_win=({h},{w}) dst=({_dst_min_row},{_dst_min_col})->({_dst_max_row},{_dst_max_col}) | "
                f"inner_h={inner_h} inner_w={inner_w} max_scroll={max_scroll} content_h={content_h}"
            )
            raise  # re-raise for visibility

    # Scroll indicator - magenta to match detail section
    if max_scroll > 0:
        bar_h = max(1, int(inner_h * inner_h / content_h))
        bar_pos = int(scroll / max_scroll * (inner_h - bar_h)) if max_scroll else 0
        for i in range(bar_h):
            safe_addstr(
                win, 1 + bar_pos + i, w - 1, "█", curses.color_pair(PAIR_DETAIL_SECTION)
            )
        hint = "↑↓ scroll"
        safe_addstr(
            win,
            h - 1,
            max(2, w - len(hint) - 2),
            hint,
            curses.color_pair(PAIR_DETAIL_DIM) | curses.A_DIM,
        )

    win.noutrefresh()
    return content_h


# ══════════════════════════════════════════════════════════════════════════════
#  CONTROLS AND STATUS BAR
# ══════════════════════════════════════════════════════════════════════════════
def draw_controls_bar(stdscr, row, focus="list", analyzing=False):
    H, W = stdscr.getmaxyx()
    if analyzing:
        controls = "  AI Analysis Running...    F5 Reload Data    ↑ ↓ Navigate    Q / Esc Quit  "
    elif focus == "detail":
        controls = "  TAB Switch panel    ↑ ↓ Scroll details    R Run Analysis    F5 Reload    Q / Esc Quit  "
    else:
        controls = "  R Run Analysis    F5 Reload Data    ← → Filter tabs    ↑ ↓ Navigate    TAB Detail    Q / Esc Quit  "
    safe_addstr(
        stdscr,
        row,
        0,
        controls.ljust(W)[:W],
        curses.color_pair(PAIR_DIM) | curses.A_DIM,
    )


def draw_status(stdscr, filtered_count, total_count, filt_name, analysis_msg, row):
    H, W = stdscr.getmaxyx()
    # Truncate long messages to fit
    max_msg_len = W - 80  # Leave space for other info
    if len(analysis_msg) > max_msg_len:
        analysis_msg = analysis_msg[:max_msg_len - 3] + "..."
    
    status = (
        f"  Filter: {filt_name}   Showing: {filtered_count}/{total_count} assets   "
        f"{analysis_msg}   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  "
    )
    safe_addstr(
        stdscr, row, 0, status.ljust(W)[:W], curses.color_pair(PAIR_HEADER)
    )


# ══════════════════════════════════════════════════════════════════════════════
#  DATA MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
def load_data():
    """Load and prepare asset data."""
    df = build_merged_dataset()
    df = ensure_ai_analysis_columns(df)

    assets = []
    for idx, row in df.iterrows():
        # Check for tenable and splunk data
        tenable_raw = row.get("tenable_raw", "[]")
        splunk_raw = row.get("splunk_raw", "[]")
        has_tenable = tenable_raw and tenable_raw != "[]" and len(tenable_raw) > 2
        has_splunk = splunk_raw and splunk_raw != "[]" and len(splunk_raw) > 2
        
        # Determine status
        if pd.isna(row.get("ai_analysis_complete")) or not row.get("ai_analysis_complete"):
            status = "Pending"
            risk_level = "Unknown"
            risk_score = None
        else:
            status = "Complete"
            risk_level = row.get("risk_level", "Low")
            risk_score = row.get("risk_score")

        asset = {
            "asset_id": row.get("asset_id", ""),
            "asset_name": row.get("asset_name", "unknown"),
            "ip_address": row.get("ip_address", "—"),
            "facing": row.get("facing", "Unknown"),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "overall_priority_level": row.get("overall_priority_level"),
            "ai_reason": row.get("ai_reason"),
            "remediation": row.get("remediation"),
            "status": status,
            "df_index": idx,
            "has_tenable": has_tenable,
            "has_splunk": has_splunk,
        }
        assets.append(asset)

    # Sort: complete by score desc, then pending
    assets.sort(key=lambda x: (x["status"] == "Pending", -(x["risk_score"] or 0)))

    return df, assets


def compute_stats(assets):
    """Compute statistics for the stats panel."""
    total = len(assets)
    n_critical = sum(1 for a in assets if a.get("risk_level") == "Critical")
    n_high = sum(1 for a in assets if a.get("risk_level") == "High")
    n_medium = sum(1 for a in assets if a.get("risk_level") == "Medium")
    n_low = sum(1 for a in assets if a.get("risk_level") == "Low")
    # Include both Pending and Analyzing in pending count
    n_pending = sum(1 for a in assets if a.get("status") in ("Pending", "Analyzing"))
    n_complete = sum(1 for a in assets if a.get("status") == "Complete")
    
    # Calculate correlated vs non-correlated
    n_correlated = sum(1 for a in assets if a.get("has_tenable") and a.get("has_splunk"))
    n_non_correlated = total - n_correlated
    n_no_tenable = sum(1 for a in assets if not a.get("has_tenable"))
    n_no_splunk = sum(1 for a in assets if not a.get("has_splunk"))
    
    progress_pct = (n_complete / total * 100) if total > 0 else 0

    return {
        "n_total": total,
        "n_critical": n_critical,
        "n_high": n_high,
        "n_medium": n_medium,
        "n_low": n_low,
        "n_pending": n_pending,
        "n_complete": n_complete,
        "n_correlated": n_correlated,
        "n_non_correlated": n_non_correlated,
        "n_no_tenable": n_no_tenable,
        "n_no_splunk": n_no_splunk,
        "progress_pct": progress_pct,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN TUI LOOP
# ══════════════════════════════════════════════════════════════════════════════
def tui(stdscr, df_initial, assets_initial):
    """Main TUI event loop with dark cyberpunk black background theme."""
    init_colors()
    curses.curs_set(0)
    stdscr.keypad(True)
    stdscr.timeout(100)  # 100ms refresh for faster updates during analysis
    
    # Set black background for entire screen (cyberpunk aesthetic)
    stdscr.bkgd(' ', curses.color_pair(PAIR_NAVY_BG))

    # State
    df = df_initial
    assets_all = assets_initial
    filt_idx = 0
    sel_idx = 0
    scroll = 0
    detail_scroll = 0
    focus = "list"
    last_sel_key = None
    analysis_state = AnalysisBackgroundState()
    analysis_msg = ""
    reload_requested = False

    def filtered():
        f = FILTERS[filt_idx]
        if f == "All":
            return assets_all
        if f == "Pending":
            return [a for a in assets_all if a.get("status") in ("Pending", "Analyzing")]
        if f == "No Tenable Data":
            return [a for a in assets_all if not a.get("has_tenable")]
        if f == "No Splunk Data":
            return [a for a in assets_all if not a.get("has_splunk")]
        return [a for a in assets_all if a.get("risk_level") == f]

    def reload_data():
        nonlocal df, assets_all, analysis_msg, sel_idx, scroll, reload_requested
        try:
            analysis_msg = "Reloading data from CSV files..."
            new_df, new_assets = load_data()
            df = new_df
            assets_all = new_assets
            sel_idx = 0
            scroll = 0
            analysis_msg = f"Data reloaded: {len(assets_all)} assets"
            reload_requested = False
        except Exception as e:
            analysis_msg = f"ERROR: Failed to reload data - {str(e)}"
            reload_requested = False

    def start_analysis():
        nonlocal analysis_msg
        try:
            pending_assets = [a for a in assets_all if a.get("status") == "Pending"]
            if not pending_assets:
                analysis_msg = "No pending assets to analyze"
                logger.info("No pending assets to analyze")
                return

            client = DGXSparkServerClient()
            if not client.enabled():
                analysis_msg = "ERROR: DGX Spark Server not configured. Set DGX_SPARK_SERVER_ENDPOINT_URL"
                logger.error("DGX Spark Server not configured")
                return

            # Mark assets as analyzing
            for a in pending_assets:
                a["status"] = "Analyzing"

            analysis_msg = f"Starting AI analysis for {len(pending_assets)} assets..."
            logger.info("="*70)
            logger.info(f"Starting AI analysis for {len(pending_assets)} assets")
            logger.info(f"Assets: {', '.join([a['asset_name'] for a in pending_assets])}")
            logger.info("="*70)
            
            request_id = f"manual_{datetime.now().isoformat()}"
            initial_status = {
                "state": "running",
                "message": f"Analyzing {len(pending_assets)} assets...",
            }
            analysis_state.start_analysis(
                request_id, df.to_json(date_format="iso", orient="split"), initial_status
            )

            thread = threading.Thread(
                target=run_analysis_worker_thread,
                args=(request_id, df, 1, analysis_state),
                daemon=True,
            )
            analysis_state.set_thread(thread)
            thread.start()
        except Exception as e:
            analysis_msg = f"ERROR: Failed to start analysis - {str(e)}"
            logger.error(f"Failed to start analysis: {e}", exc_info=True)

    def update_from_analysis():
        """Update assets from analysis state."""
        nonlocal df, assets_all, analysis_msg, sel_idx
        try:
            running, request_id, df_json, status = analysis_state.get_state()
            
            # Update status message if available
            if status:
                analysis_msg = status.get("message", "")

            if df_json and isinstance(df_json, str) and len(df_json) > 0:
                try:
                    # Parse JSON with error handling
                    import json
                    from io import StringIO
                    # Use StringIO to parse JSON string properly
                    df_updated = pd.read_json(StringIO(df_json), orient="split")
                    
                    # Track which assets were just completed
                    newly_completed = []
                    updates_made = False
                    
                    # Update assets with latest analysis results
                    for asset in assets_all:
                        idx = asset["df_index"]
                        if idx in df_updated.index:
                            row = df_updated.loc[idx]
                            
                            # Check if this asset just completed
                            is_complete = bool(row.get("ai_analysis_complete"))
                            was_complete = asset["status"] == "Complete"
                            
                            if is_complete and not was_complete:
                                # Asset just completed
                                asset["status"] = "Complete"
                                risk_score = row.get("risk_score")
                                asset["risk_score"] = float(risk_score) if pd.notna(risk_score) else None
                                asset["risk_level"] = str(row.get("risk_level", "Low"))
                                asset["overall_priority_level"] = str(row.get("overall_priority_level", "Unknown"))
                                asset["ai_reason"] = str(row.get("ai_reason", ""))
                                asset["remediation"] = str(row.get("remediation", ""))
                                
                                score_str = f"({asset['risk_score']:.1f})" if asset['risk_score'] else ""
                                newly_completed.append(asset["asset_name"])
                                updates_made = True
                                logger.info(f"✓ Completed: {asset['asset_name']} - Risk: {asset['risk_level']} {score_str}")
                            elif is_complete and was_complete:
                                # Already complete, just update data in case it changed
                                risk_score = row.get("risk_score")
                                asset["risk_score"] = float(risk_score) if pd.notna(risk_score) else None
                                asset["risk_level"] = str(row.get("risk_level", "Low"))
                                asset["overall_priority_level"] = str(row.get("overall_priority_level", "Unknown"))
                                asset["ai_reason"] = str(row.get("ai_reason", ""))
                                asset["remediation"] = str(row.get("remediation", ""))
                    
                    # Update dataframe reference
                    df = df_updated
                    
                    if updates_made:
                        # Re-sort when assets complete
                        assets_all.sort(key=lambda x: (x["status"] in ("Pending", "Analyzing"), -(x["risk_score"] or 0)))
                        logger.info(f"TUI updated: {len(newly_completed)} asset(s) completed")
                        
                except (ValueError, json.JSONDecodeError) as e:
                    # JSON parsing error - ignore and wait for next update
                    logger.debug(f"JSON parse skipped (in progress): {str(e)[:100]}")
                except Exception as e:
                    analysis_msg = f"Update error (will retry): {str(e)[:50]}"
                    logger.error(f"Update failed: {e}", exc_info=True)

            # Check if analysis finished
            if not running and status and status.get("state") in ("complete", "warning"):
                # Analysis finished - reload data to get final results
                logger.info("Analysis finished, performing final data reload...")
                time.sleep(0.3)
                try:
                    new_df, new_assets = load_data()
                    df = new_df
                    assets_all = new_assets
                    sel_idx = min(sel_idx, len(assets_all) - 1) if assets_all else 0
                    logger.info(f"Final reload complete: {len(assets_all)} assets")
                    analysis_msg = "Analysis complete! All data updated."
                except Exception as e:
                    analysis_msg = f"WARNING: Could not reload final data - {str(e)[:50]}"
                    logger.error(f"Reload failed: {e}", exc_info=True)
                analysis_state.reset()
        except Exception as e:
            # Don't crash on update errors, just log and continue
            logger.error(f"Analysis update failed: {e}", exc_info=True)

    # DEBUG: frame counter used to throttle repetitive log lines
    _debug_frame = 0

    while True:
        _debug_frame += 1
        H, W = stdscr.getmaxyx()
        if H < 30 or W < 70:
            stdscr.erase()
            safe_addstr(
                stdscr,
                0,
                0,
                "Terminal too small — resize and try again.",
                curses.color_pair(PAIR_WARN),
            )
            stdscr.refresh()
            key = stdscr.getch()
            if key in (ord("q"), ord("Q"), 27):
                return
            continue

        # Handle data reload request
        if reload_requested:
            reload_data()
            continue

        # Update from analysis thread - ALWAYS check, even if not marked as running
        # This ensures we catch state changes immediately
        running, _, _, _ = analysis_state.get_state()
        update_from_analysis()

        vis_assets = filtered()
        if not vis_assets:
            sel_idx = 0
            scroll = 0
        else:
            sel_idx = max(0, min(sel_idx, len(vis_assets) - 1))

        # Layout - stats panel is now always single row (4 lines height)
        _, _, stats_n_rows = stats_panel_layout(W, 7)  # 7 boxes total (removed correlated/uncorrelated)
        stats_panel_h = stats_n_rows * 4  # Should be 1 * 4 = 4 lines

        title_row = 0
        stats_row = 1
        filter_row = stats_row + stats_panel_h
        pane_top = filter_row + 1
        controls_row = H - 2
        status_row = H - 1
        pane_bot = controls_row
        pane_h = pane_bot - pane_top

        left_w = min(64, W // 2)
        right_w = W - left_w
        # list_h defined early so the debug block below can reference it
        list_h = pane_h

        # DEBUG: log layout values on first frame and every 50 frames
        if _debug_frame == 1 or _debug_frame % 50 == 0:
            logger.info(
                f"[DEBUG] LAYOUT frame={_debug_frame}: "
                f"H={H} W={W} | "
                f"title_row={title_row} stats_row={stats_row} "
                f"stats_panel_h={stats_panel_h} filter_row={filter_row} | "
                f"pane_top={pane_top} pane_h={pane_h} pane_bot={pane_bot} | "
                f"left_w={left_w} right_w={right_w} list_h={list_h} | "
                f"controls_row={controls_row} status_row={status_row}"
            )
            # DEBUG: dimension bounds checks
            _errs = []
            if pane_top + list_h > H:
                _errs.append(f"LEFT_WIN y+h={pane_top}+{list_h}={pane_top+list_h} > H={H}")
            if left_w > W:
                _errs.append(f"LEFT_WIN x+w=0+{left_w}={left_w} > W={W}")
            if pane_top + pane_h > H:
                _errs.append(f"RIGHT_WIN y+h={pane_top}+{pane_h}={pane_top+pane_h} > H={H}")
            if left_w + right_w > W:
                _errs.append(f"RIGHT_WIN x+w={left_w}+{right_w}={left_w+right_w} > W={W}")
            if pane_h <= 0:
                _errs.append(f"pane_h={pane_h} is non-positive — window cannot be created")
            if list_h <= 0:
                _errs.append(f"list_h={list_h} is non-positive — window cannot be created")
            if _errs:
                for _e in _errs:
                    logger.error(f"[DEBUG] BOUNDS VIOLATION: {_e}")
            else:
                logger.info(
                    f"[DEBUG] BOUNDS OK: "
                    f"left_win({list_h},{left_w},y={pane_top},x=0) "
                    f"right_win({pane_h},{right_w},y={pane_top},x={left_w}) "
                    f"fits in terminal ({H}x{W})"
                )

        # Title bar - cyberpunk style with line decoration
        line = "═" * W
        safe_addstr(stdscr, title_row, 0, line, curses.color_pair(PAIR_BORDER))
        
        title = " VULNERABILITY RISK INTELLIGENCE DASHBOARD "
        x = max(0, (W - len(title)) // 2)
        safe_addstr(
            stdscr,
            title_row,
            x,
            title,
            curses.color_pair(PAIR_HEADER) | curses.A_BOLD
        )

        # Stats panel - always recompute to reflect current state
        stats = compute_stats(assets_all)
        draw_stats_panel(stdscr, stats, start_row=stats_row)

        # Filter tabs
        draw_filter_bar(stdscr, filt_idx, assets_all, filter_row)

        # Left pane - asset list
        if sel_idx < scroll:
            scroll = sel_idx
        elif sel_idx >= scroll + (list_h - 3):
            scroll = sel_idx - (list_h - 3) + 1
        scroll = max(0, scroll)

        # DEBUG: log newwin args before creation
        logger.info(
            f"[DEBUG] Creating left_win: newwin(nlines={list_h}, ncols={left_w}, "
            f"begin_y={pane_top}, begin_x=0) terminal=({H}x{W})"
        )
        try:
            left_win = curses.newwin(list_h, left_w, pane_top, 0)
        except curses.error as _exc:
            logger.error(
                f"[DEBUG] LEFT_WIN newwin FAILED — "
                f"args: nlines={list_h}, ncols={left_w}, begin_y={pane_top}, begin_x=0 | "
                f"terminal: H={H}, W={W} | error: {_exc!r}"
            )
            raise  # re-raise so the traceback is visible

        logger.info(
            "[DEBUG] Calling draw_asset_list: win_size=(%s,%s) assets=%s sel_idx=%s scroll=%s",
            list_h,
            left_w,
            len(vis_assets),
            sel_idx,
            scroll,
        )
        draw_asset_list(left_win, vis_assets, sel_idx, scroll)
        logger.info("[DEBUG] draw_asset_list returned")

        # Right pane - detail
        logger.info(
            f"[DEBUG] Creating right_win: newwin(nlines={pane_h}, ncols={right_w}, "
            f"begin_y={pane_top}, begin_x={left_w}) terminal=({H}x{W})"
        )
        try:
            right_win = curses.newwin(pane_h, right_w, pane_top, left_w)
        except curses.error as _exc:
            logger.error(
                f"[DEBUG] RIGHT_WIN newwin FAILED — "
                f"args: nlines={pane_h}, ncols={right_w}, begin_y={pane_top}, begin_x={left_w} | "
                f"terminal: H={H}, W={W} | error: {_exc!r}"
            )
            raise  # re-raise so the traceback is visible

        sel_asset = vis_assets[sel_idx] if vis_assets else None

        # Reset detail scroll when asset changes
        sel_key = (filt_idx, sel_idx)
        if sel_key != last_sel_key:
            detail_scroll = 0
            last_sel_key = sel_key

        logger.info(
            "[DEBUG] Calling draw_detail: win_size=(%s,%s) asset=%s scroll=%s focused=%s",
            pane_h,
            right_w,
            "None" if sel_asset is None else sel_asset.get("asset_name", "?"),
            detail_scroll,
            focus == "detail",
        )
        detail_content_h = draw_detail(right_win, sel_asset, detail_scroll, focus == "detail")
        logger.info("[DEBUG] draw_detail returned content_h=%s", detail_content_h)
        detail_visible_h = pane_h - 2
        detail_max_scroll = max(0, detail_content_h - detail_visible_h)
        detail_scroll = max(0, min(detail_scroll, detail_max_scroll))

        # Controls bar
        draw_controls_bar(stdscr, controls_row, focus, running)

        # Status bar - show accurate counts
        try:
            current_stats = compute_stats(assets_all)
            status_msg = analysis_msg if analysis_msg else f"Ready - {current_stats['n_complete']} analyzed, {current_stats['n_pending']} pending"
            # Sanitize message to prevent display issues
            status_msg = status_msg.replace('\n', ' ').replace('\r', ' ')
            draw_status(
                stdscr,
                len(vis_assets),
                len(assets_all),
                FILTERS[filt_idx],
                status_msg,
                status_row,
            )
        except Exception as e:
            # Fallback status if there's an error
            safe_addstr(stdscr, status_row, 0, f"Status Error: {str(e)[:50]}", curses.color_pair(PAIR_WARN))

        stdscr.noutrefresh()
        curses.doupdate()

        # Input
        key = stdscr.getch()

        if key in (ord("q"), ord("Q"), 27):  # Q / Esc → quit
            break
        elif key in (ord("r"), ord("R")) and not running:  # R → run analysis
            start_analysis()
        elif key == curses.KEY_F5 or key == 269:  # F5 → reload data (269 is F5 on some terminals)
            if not running:
                reload_requested = True
            else:
                analysis_msg = "Cannot reload while analysis is running"
        elif key in (ord("\t"), 9):  # Tab → toggle focus
            focus = "detail" if focus == "list" else "list"
        elif key == curses.KEY_LEFT:  # ← filter
            filt_idx = (filt_idx - 1) % len(FILTERS)
            sel_idx = 0
            scroll = 0
        elif key == curses.KEY_RIGHT:  # → filter
            filt_idx = (filt_idx + 1) % len(FILTERS)
            sel_idx = 0
            scroll = 0
        elif key == curses.KEY_UP:  # ↑
            if focus == "detail":
                detail_scroll = max(0, detail_scroll - 1)
            else:
                sel_idx = max(0, sel_idx - 1)
        elif key == curses.KEY_DOWN:  # ↓
            if focus == "detail":
                detail_scroll = min(detail_max_scroll, detail_scroll + 1)
            else:
                if vis_assets:
                    sel_idx = min(len(vis_assets) - 1, sel_idx + 1)
        elif key == curses.KEY_PPAGE:  # Page Up
            if focus == "detail":
                detail_scroll = max(0, detail_scroll - (detail_visible_h - 1))
            else:
                sel_idx = max(0, sel_idx - (list_h - 3))
        elif key == curses.KEY_NPAGE:  # Page Down
            if focus == "detail":
                detail_scroll = min(detail_max_scroll, detail_scroll + (detail_visible_h - 1))
            else:
                if vis_assets:
                    sel_idx = min(len(vis_assets) - 1, sel_idx + (list_h - 3))
        elif key == curses.KEY_HOME:  # Home
            if focus == "detail":
                detail_scroll = 0
            else:
                sel_idx = 0
                scroll = 0
        elif key == curses.KEY_END:  # End
            if focus == "detail":
                detail_scroll = detail_max_scroll
            else:
                if vis_assets:
                    sel_idx = len(vis_assets) - 1


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
def main():
    """Main entry point."""
    print("Loading data…", end=" ", flush=True)
    df, assets = load_data()
    print(f"{len(assets)} assets loaded.")
    print(f"\nAI Analysis logs will be written to: {LOG_FILE}")
    print("To monitor in real-time, open another terminal and run:")
    print(f"  powershell -Command \"Get-Content '{LOG_FILE}' -Wait -Tail 20\"")
    print("\nLaunching TUI…")
    logger.info("="*70)
    logger.info("TUI Dashboard Started")
    logger.info(f"Total assets loaded: {len(assets)}")
    logger.info("="*70)
    try:
        curses.wrapper(tui, df, assets)
    except KeyboardInterrupt:
        pass
    logger.info("Dashboard closed.")
    print("Dashboard closed.")


if __name__ == "__main__":
    main()
