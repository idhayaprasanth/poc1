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
"""
import curses
import sys
import threading
import time
import logging
from datetime import datetime
from pathlib import Path

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

LEVEL_PAIR = {
    "Critical": PAIR_CRIT,
    "High": PAIR_HIGH,
    "Medium": PAIR_MED,
    "Low": PAIR_LOW,
    "Pending": PAIR_PENDING,
}

FILTERS = ["All", "Critical", "High", "Medium", "Low", "Pending", "No Tenable Data", "No Splunk Data"]


def init_colors():
    """Initialize color pairs for the TUI."""
    curses.start_color()
    curses.use_default_colors()

    neon_enabled = bool(
        hasattr(curses, "can_change_color")
        and hasattr(curses, "init_color")
        and curses.can_change_color()
        and getattr(curses, "COLORS", 0) >= 256
    )

    if neon_enabled:
        neon_palette = {
            "CYAN": (0, 217, 255),
            "BLUE": (59, 130, 246),
            "PURPLE": (168, 85, 247),
            "PINK": (236, 72, 153),
            "RED": (255, 77, 77),
            "ORANGE": (255, 152, 0),
            "YELLOW": (255, 213, 79),
            "GREEN": (34, 197, 94),
            "TEAL": (6, 182, 212),
            "TEXT": (229, 231, 235),
            "MUTED": (148, 163, 184),
            "BLACK": (8, 10, 24),
            "WHITE": (248, 250, 252),
        }

        def rgb_to_curses(red, green, blue):
            return tuple(int(round(value * 1000 / 255)) for value in (red, green, blue))

        color_slots = {
            curses.COLOR_BLACK: "BLACK",
            curses.COLOR_RED: "RED",
            curses.COLOR_GREEN: "GREEN",
            curses.COLOR_YELLOW: "YELLOW",
            curses.COLOR_BLUE: "BLUE",
            curses.COLOR_MAGENTA: "PURPLE",
            curses.COLOR_CYAN: "CYAN",
            curses.COLOR_WHITE: "WHITE",
        }
        for color_number, color_name in color_slots.items():
            try:
                curses.init_color(color_number, *rgb_to_curses(*neon_palette[color_name]))
            except curses.error:
                pass

        try:
            extra_colors = {
                8: "ORANGE",
                9: "PINK",
                10: "TEAL",
                11: "TEXT",
                12: "MUTED",
            }
            for color_number, color_name in extra_colors.items():
                if color_number < curses.COLORS:
                    try:
                        curses.init_color(color_number, *rgb_to_curses(*neon_palette[color_name]))
                    except curses.error:
                        pass
        except Exception:
            pass

        neon_black = curses.COLOR_BLACK
        neon_text = 11
        neon_muted = 12
        neon_orange = 8
        neon_pink = 9
        neon_teal = 10

        pair_colors = {
            PAIR_CRIT: curses.COLOR_RED,
            PAIR_HIGH: neon_orange,
            PAIR_MED: neon_teal,
            PAIR_LOW: curses.COLOR_GREEN,
            PAIR_DIM: neon_muted,
            PAIR_HEADER: neon_teal,
            PAIR_SEL: neon_black,
            PAIR_TABA: neon_black,
            PAIR_TABI: neon_text,
            PAIR_BORDER: curses.COLOR_BLUE,
            PAIR_LABEL: neon_text,
            PAIR_WARN: neon_orange,
            PAIR_BAR: curses.COLOR_GREEN,
            PAIR_WHITE: neon_text,
            PAIR_PENDING: neon_pink,
            PAIR_STAT_BLUE: curses.COLOR_BLUE,
            PAIR_STAT_PURPLE: curses.COLOR_MAGENTA,
            PAIR_STAT_PINK: neon_pink,
            PAIR_STAT_YELLOW: curses.COLOR_YELLOW,
            PAIR_STAT_RED: curses.COLOR_RED,
            PAIR_STAT_GREEN: curses.COLOR_GREEN,
        }

        for pair_id, fg_color in pair_colors.items():
            bg_color = -1
            if pair_id == PAIR_HEADER:
                bg_color = neon_black
            elif pair_id in (PAIR_SEL, PAIR_TABA):
                fg_color, bg_color = neon_black, curses.COLOR_CYAN if pair_id == PAIR_SEL else curses.COLOR_WHITE
            try:
                curses.init_pair(pair_id, fg_color, bg_color)
            except curses.error:
                pass
        return

    curses.init_pair(PAIR_CRIT, curses.COLOR_RED, -1)
    curses.init_pair(PAIR_HIGH, curses.COLOR_YELLOW, -1)
    curses.init_pair(PAIR_MED, curses.COLOR_CYAN, -1)
    curses.init_pair(PAIR_LOW, curses.COLOR_GREEN, -1)
    curses.init_pair(PAIR_DIM, curses.COLOR_WHITE, -1)
    curses.init_pair(PAIR_HEADER, curses.COLOR_BLACK, curses.COLOR_WHITE)
    curses.init_pair(PAIR_SEL, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(PAIR_TABA, curses.COLOR_BLACK, curses.COLOR_WHITE)
    curses.init_pair(PAIR_TABI, curses.COLOR_WHITE, -1)
    curses.init_pair(PAIR_BORDER, curses.COLOR_BLUE, -1)
    curses.init_pair(PAIR_LABEL, curses.COLOR_WHITE, -1)
    curses.init_pair(PAIR_WARN, curses.COLOR_RED, -1)
    curses.init_pair(PAIR_BAR, curses.COLOR_GREEN, -1)
    curses.init_pair(PAIR_WHITE, curses.COLOR_WHITE, -1)
    curses.init_pair(PAIR_PENDING, curses.COLOR_MAGENTA, -1)
    curses.init_pair(PAIR_STAT_BLUE, curses.COLOR_BLUE, -1)
    curses.init_pair(PAIR_STAT_PURPLE, curses.COLOR_MAGENTA, -1)
    curses.init_pair(PAIR_STAT_PINK, curses.COLOR_MAGENTA, -1)
    curses.init_pair(PAIR_STAT_YELLOW, curses.COLOR_YELLOW, -1)
    curses.init_pair(PAIR_STAT_RED, curses.COLOR_RED, -1)
    curses.init_pair(PAIR_STAT_GREEN, curses.COLOR_GREEN, -1)


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
    except curses.error:
        pass
    if title:
        t = f" {title} "
        x = max(1, (w - len(t)) // 2)
        safe_addstr(win, 0, x, t, curses.color_pair(PAIR_HEADER) | curses.A_BOLD)


def draw_neon_box(win, title, border_pair, title_pair):
    """Draw a terminal-safe Unicode box with a colored border and title."""
    h, w = win.getmaxyx()
    if h <= 0 or w <= 0:
        return

    border_attr = curses.color_pair(border_pair)
    title_attr = curses.color_pair(title_pair) | curses.A_BOLD

    def safe_addch(y, x, ch, attr=0):
        if y < 0 or x < 0 or y >= h or x >= w:
            return
        try:
            win.addch(y, x, ch, attr)
        except curses.error:
            pass

    def safe_addstr_local(y, x, text, attr=0):
        if y < 0 or x < 0 or y >= h or x >= w:
            return
        try:
            available = w - x
            if available <= 0:
                return
            win.addstr(y, x, str(text)[:available], attr)
        except curses.error:
            pass

    if h == 1 or w == 1:
        safe_addstr_local(0, 0, str(title)[:w], title_attr)
        return

    tl, tr, bl, br = "┌", "┐", "└", "┘"
    hz, vt = "─", "│"

    for x in range(1, w - 1):
        safe_addch(0, x, hz, border_attr)
        safe_addch(h - 1, x, hz, border_attr)

    for y in range(1, h - 1):
        safe_addch(y, 0, vt, border_attr)
        safe_addch(y, w - 1, vt, border_attr)

    safe_addch(0, 0, tl, border_attr)
    safe_addch(0, w - 1, tr, border_attr)
    safe_addch(h - 1, 0, bl, border_attr)
    safe_addch(h - 1, w - 1, br, border_attr)

    title_text = f" {str(title).strip()} " if title is not None else " "
    available = max(0, w - 2)
    if available > 0:
        if len(title_text) > available:
            title_text = title_text[:available]
        title_x = max(1, (w - len(title_text)) // 2)
        safe_addstr_local(0, title_x, title_text, title_attr)


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
    except curses.error:
        return
    sub.erase()
    border_attr = curses.color_pair(pair)
    bg_attr = curses.color_pair(PAIR_BORDER)
    value_attr = curses.color_pair(pair) | curses.A_BOLD
    label_attr = curses.color_pair(label_color) | curses.A_DIM

    try:
        sub.bkgd(" ", curses.color_pair(PAIR_BORDER))
    except curses.error:
        pass

    try:
        sub.attron(bg_attr)
        sub.addstr(0, 0, "┌" + ("─" * max(0, w - 2)) + "┐")
        for row in range(1, h - 1):
            sub.addstr(row, 0, "│")
            if w > 1:
                sub.addstr(row, w - 1, "│")
        sub.addstr(h - 1, 0, "└" + ("─" * max(0, w - 2)) + "┘")
        sub.attroff(bg_attr)
    except curses.error:
        pass

    try:
        if w > 1:
            sub.attron(border_attr)
            sub.addstr(0, 0, "┌")
            if w > 2:
                sub.addstr(0, 1, "─" * (w - 2))
            if w > 1:
                sub.addstr(0, w - 1, "┐")
            for row in range(1, h - 1):
                sub.addstr(row, 0, "│")
                if w > 1:
                    sub.addstr(row, w - 1, "│")
            sub.addstr(h - 1, 0, "└")
            if w > 2:
                sub.addstr(h - 1, 1, "─" * (w - 2))
            if w > 1:
                sub.addstr(h - 1, w - 1, "┘")
            sub.attroff(border_attr)
    except curses.error:
        pass

    icon = "◉"
    inner_x = 2
    safe_addstr(sub, 1, inner_x, icon, curses.color_pair(pair) | curses.A_BOLD)
    safe_addstr(sub, 1, inner_x + 2, str(value), value_attr)
    safe_addstr(sub, 2, inner_x + 2, label[: max(0, w - inner_x - 4)], label_attr)
    sub.noutrefresh()


def stats_panel_layout(W, n_boxes=8):
    """Return (box_w, per_row, n_rows) for the stats panel."""
    box_w = max(18, min(24, (W - 6) // 4))
    gap = 1
    per_row = max(1, (W - 1) // (box_w + gap))
    n_rows = max(1, -(-n_boxes // per_row))
    return box_w, per_row, n_rows


def draw_stats_panel(stdscr, stats, start_row=0):
    """Draw the top stats panel."""
    H, W = stdscr.getmaxyx()

    boxes = [
        (str(stats["n_total"]), "Total Assets", PAIR_STAT_GREEN),
        # (str(stats["n_correlated"]), "Correlated", PAIR_STAT_BLUE),
        # (str(stats["n_non_correlated"]), "Non-Correlated", PAIR_STAT_YELLOW),
        (str(stats["n_critical"]), "Critical", PAIR_CRIT),
        (str(stats["n_high"]), "High", PAIR_HIGH),
        (str(stats["n_medium"]), "Medium", PAIR_MED),
        (str(stats["n_low"]), "Low", PAIR_LOW),
        (str(stats["n_pending"]), "Pending", PAIR_PENDING),
        (str(stats["n_complete"]), "Analyzed", PAIR_STAT_PURPLE),
    ]

    box_w, per_row, n_rows = stats_panel_layout(W, len(boxes))
    gap = 1
    x = 1
    y = start_row
    for i, (value, label, pair) in enumerate(boxes):
        if i > 0 and i % per_row == 0:
            x = 1
            y += 4
        if x + box_w >= W:
            continue
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
    """Render the asset list in the left window."""
    win.erase()
    h, w = win.getmaxyx()
    try:
        win.bkgd(" ", curses.color_pair(PAIR_HEADER))
    except curses.error:
        pass

    draw_neon_box(win, "Assets", PAIR_MED, PAIR_MED)

    # Column header
    hdr = f"{'#':>3}  {'Hostname':<15}  {'Score':>5}  {'Risk Level':<10} IP Address"
    if w > 2:
        header_attr = curses.color_pair(PAIR_BORDER) | curses.A_BOLD
        try:
            safe_addstr(win, 1, 1, " " * (w - 2), curses.color_pair(PAIR_HEADER))
            safe_addstr(win, 1, 1, hdr[: w - 2], header_attr)
        except curses.error:
            pass

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

    # Scrollbar indicator
    if len(assets) > list_h:
        scroll_track_attr = curses.color_pair(PAIR_DIM)
        scroll_thumb_attr = curses.color_pair(PAIR_MED) | curses.A_BOLD
        for row in range(2, h - 1):
            safe_addstr(win, row, w - 1, "░", scroll_track_attr)
        bar_h = max(1, int(list_h * list_h / max(1, len(assets))))
        max_scroll = max(1, len(assets) - list_h)
        bar_top = int((scroll_off / max_scroll) * max(1, list_h - bar_h))
        for i in range(bar_h):
            safe_addstr(win, 2 + bar_top + i, w - 1, "█", scroll_thumb_attr)

    win.noutrefresh()


# ══════════════════════════════════════════════════════════════════════════════
#  DETAIL PANEL
# ══════════════════════════════════════════════════════════════════════════════
def draw_detail(win, asset, scroll=0, focused=False):
    """Render the detailed info panel for the selected asset."""
    win.erase()
    h, w = win.getmaxyx()
    if asset is None:
        draw_neon_box(win, "Detail", PAIR_BORDER, PAIR_STAT_PURPLE)
        safe_addstr(
            win,
            h // 2,
            max(1, (w - 20) // 2),
            "← Select an asset",
            curses.color_pair(PAIR_DIM) | curses.A_DIM,
        )
        win.noutrefresh()
        return 0

    a = asset
    status = a.get("status", "Unknown")
    if status == "Pending":
        pair = PAIR_PENDING
    elif status == "Analyzing":
        pair = PAIR_PENDING
    else:
        pair = LEVEL_PAIR.get(a.get("risk_level", "Low"), PAIR_LOW)

    import json
    import textwrap

    def parse_raw_rows(value):
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                return parsed if isinstance(parsed, list) else []
            except Exception:
                return []
        return value if isinstance(value, list) else []

    def wrap_lines(text, width):
        text = str(text or "").strip()
        if not text:
            return [""]
        lines = []
        for paragraph in text.splitlines() or [""]:
            chunk = paragraph.strip()
            if not chunk:
                lines.append("")
            else:
                lines.extend(textwrap.wrap(chunk, width=width, break_long_words=True, break_on_hyphens=False) or [""])
        return lines or [""]

    def card_height(lines):
        return 3 + max(1, len(lines))

    def draw_card(start_row, title, border_pair, title_pair, lines):
        inner_left = 2
        inner_width = max(10, w - 4)
        top_width = max(2, inner_width)
        title_text = f" {title} "
        title_slice = title_text[: max(0, top_width - 2)]
        border_attr = curses.color_pair(border_pair)
        title_attr = curses.color_pair(title_pair) | curses.A_BOLD
        body_attr = curses.color_pair(PAIR_DIM)

        safe_addstr(pad, start_row, inner_left, "┌" + ("─" * max(0, top_width - 2)) + "┐", border_attr)
        if title_slice and top_width > 2:
            title_x = inner_left + max(1, (top_width - len(title_slice)) // 2)
            safe_addstr(pad, start_row, title_x, title_slice, title_attr)

        content_row = start_row + 1
        content_lines = lines or [""]
        for line in content_lines:
            safe_addstr(pad, content_row, inner_left, "│", border_attr)
            safe_addstr(pad, content_row, inner_left + 1, f" {line}"[: max(0, top_width - 2)], body_attr)
            safe_addstr(pad, content_row, inner_left + top_width - 1, "│", border_attr)
            content_row += 1

        safe_addstr(pad, content_row, inner_left, "└" + ("─" * max(0, top_width - 2)) + "┘", border_attr)
        return content_row + 1

    def kv_lines(items, label_width=16):
        rendered = []
        for label, value, value_pair in items:
            rendered.append((f"{label:<{label_width}} {value}", value_pair))
        return rendered

    def draw_kv_card(start_row, title, border_pair, title_pair, items):
        lines = []
        for label, value, value_pair in items:
            wrapped = wrap_lines(str(value), max(10, w - 24))
            if not wrapped:
                wrapped = [""]
            first_line = f"{label:<16} {wrapped[0]}"
            lines.append((first_line, value_pair))
            for extra in wrapped[1:]:
                lines.append((f"{'':<16} {extra}", value_pair))

        inner_left = 2
        inner_width = max(10, w - 4)
        top_width = max(2, inner_width)
        title_text = f" {title} "
        title_slice = title_text[: max(0, top_width - 2)]
        border_attr = curses.color_pair(border_pair)
        title_attr = curses.color_pair(title_pair) | curses.A_BOLD
        body_label_attr = curses.color_pair(PAIR_LABEL) | curses.A_BOLD

        safe_addstr(pad, start_row, inner_left, "┌" + ("─" * max(0, top_width - 2)) + "┐", border_attr)
        if title_slice and top_width > 2:
            title_x = inner_left + max(1, (top_width - len(title_slice)) // 2)
            safe_addstr(pad, start_row, title_x, title_slice, title_attr)

        content_row = start_row + 1
        for line, value_pair in lines or [("", PAIR_DIM)]:
            safe_addstr(pad, content_row, inner_left, "│", border_attr)
            label_part = line[:16]
            value_part = line[17:] if len(line) > 17 else ""
            safe_addstr(pad, content_row, inner_left + 1, f" {label_part:<16}", body_label_attr)
            safe_addstr(pad, content_row, inner_left + 18, value_part[: max(0, top_width - 20)], curses.color_pair(value_pair))
            safe_addstr(pad, content_row, inner_left + top_width - 1, "│", border_attr)
            content_row += 1

        safe_addstr(pad, content_row, inner_left, "└" + ("─" * max(0, top_width - 2)) + "┘", border_attr)
        return content_row + 1

    tenable_rows = parse_raw_rows(a.get("tenable_raw", []))
    splunk_rows = parse_raw_rows(a.get("splunk_raw", []))
    port_lines = []
    seen_ports = set()
    for source_rows in (tenable_rows, splunk_rows):
        for record in source_rows:
            if not isinstance(record, dict):
                continue
            port = record.get("Port") or record.get("port") or record.get("DestinationPort") or record.get("destination_port")
            protocol = record.get("Protocol") or record.get("protocol")
            service = record.get("Service") or record.get("service") or record.get("Plugin Name") or record.get("signature")
            if port in (None, "", "None"):
                continue
            key = (str(port), str(protocol or ""), str(service or ""))
            if key in seen_ports:
                continue
            seen_ports.add(key)
            port_text = str(port)
            if protocol:
                port_text = f"{port_text}/{protocol}"
            if service:
                port_text = f"{port_text} — {service}"
            port_lines.append(port_text)
            if len(port_lines) >= 5:
                break
        if len(port_lines) >= 5:
            break
    if not port_lines:
        port_lines = ["No open ports data available."]

    has_tenable = a.get("has_tenable", False)
    has_splunk = a.get("has_splunk", False)
    if has_tenable and has_splunk:
        corr_status = "Correlated (Tenable + Splunk)"
        corr_pair = PAIR_LOW
    elif has_tenable and not has_splunk:
        corr_status = "No Splunk Data"
        corr_pair = PAIR_WARN
    elif has_splunk and not has_tenable:
        corr_status = "No Tenable Data"
        corr_pair = PAIR_WARN
    else:
        corr_status = "No Data"
        corr_pair = PAIR_WARN

    score = a.get("risk_score", 0.0)
    risk_level = a.get("risk_level", "Unknown")
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

    ai_reason = str(a.get("ai_reason", "No analysis available"))
    remediation = str(a.get("remediation", "No remediation provided"))

    identity_items = [
        ("Asset ID", a.get("asset_id", ""), PAIR_WHITE),
        ("Hostname", a.get("asset_name", ""), PAIR_WHITE),
        ("IP Address", a.get("ip_address", "—"), PAIR_DIM),
        ("Facing", a.get("facing", "Unknown"), PAIR_DIM),
    ]
    status_items = [
        ("Data Status", corr_status, corr_pair),
        ("Tenable", "Available" if has_tenable else "Missing", PAIR_LOW if has_tenable else PAIR_WARN),
        ("Splunk", "Available" if has_splunk else "Missing", PAIR_LOW if has_splunk else PAIR_WARN),
    ]

    risk_lines = []
    if status in ("Pending", "Analyzing"):
        risk_lines.append(f"Status            {status}")
        if status == "Analyzing":
            risk_lines.append("⏳ AI analysis in progress...")
    else:
        score_bar_width = min(30, max(8, w - 24))
        bar_str = score_bar(score, score_bar_width) if score else ""
        score_line = f"{score:4.1f}/10  {bar_str}" if score else "Not analyzed"
        risk_lines.append(f"Risk Score        {score_line}")
        risk_lines.append(f"Risk Level        {risk_level}")
        risk_lines.append(f"Priority          {priority_display}")

    ai_lines = wrap_lines(ai_reason, max(10, w - 6)) if status not in ("Pending", "Analyzing") else [f"AI analysis not available while {status.lower()}."]
    remediation_lines = wrap_lines(remediation, max(10, w - 6))
    open_ports_lines = wrap_lines("\n".join(port_lines), max(10, w - 6))

    pad_h = (
        2
        + card_height([f"{k:<16} {v}" for k, v, _ in identity_items])
        + 1
        + card_height([f"{k:<16} {v}" for k, v, _ in status_items])
        + 1
        + card_height(risk_lines)
        + 1
        + card_height(ai_lines)
        + 1
        + card_height(remediation_lines)
        + 1
        + card_height(open_ports_lines)
        + 4
    )
    pad_w = max(w, 1)
    try:
        pad = curses.newpad(pad_h, pad_w)
    except curses.error:
        pad = win

    row = 1
    row = draw_kv_card(row, "Identity", PAIR_MED, PAIR_MED, identity_items)
    row += 1
    row = draw_kv_card(row, "Data Status", PAIR_STAT_PURPLE, PAIR_STAT_PURPLE, status_items)
    row += 1
    row = draw_card(row, "Risk Score", PAIR_CRIT, PAIR_CRIT, risk_lines)
    row += 1
    row = draw_card(row, "AI Analysis", PAIR_STAT_GREEN, PAIR_STAT_GREEN, ai_lines)
    row += 1
    row = draw_card(row, "Remediation", PAIR_STAT_PURPLE, PAIR_STAT_PURPLE, remediation_lines)
    row += 1
    row = draw_card(row, "Open Ports", PAIR_STAT_BLUE, PAIR_STAT_BLUE, open_ports_lines)

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
    draw_neon_box(win, title, pair, pair)

    # Copy visible slice of pad to window
    scroll = max(0, min(scroll, max_scroll))
    inner_h = h - 2
    inner_w = w - 2
    if pad is not win and inner_h > 0 and inner_w > 0:
        try:
            pad.overwrite(
                win,
                scroll,
                0,
                1,
                1,
                min(1 + inner_h - 1, h - 2),
                min(1 + inner_w - 1, w - 2),
            )
        except curses.error:
            pass

    # Scroll indicator
    if max_scroll > 0:
        bar_h = max(1, int(inner_h * inner_h / content_h))
        bar_pos = int(scroll / max_scroll * (inner_h - bar_h)) if max_scroll else 0
        for i in range(bar_h):
            safe_addstr(
                win, 1 + bar_pos + i, w - 1, "█", curses.color_pair(PAIR_BORDER)
            )
        hint = "↑↓ scroll"
        safe_addstr(
            win,
            h - 1,
            max(2, w - len(hint) - 2),
            hint,
            curses.color_pair(PAIR_DIM) | curses.A_DIM,
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

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filter_text = f"Filter: {filt_name}"
    showing_text = f"Showing: {filtered_count}/{total_count} assets"
    status_text = analysis_msg
    if status_text and not status_text.endswith(" "):
        status_text += " "

    try:
        stdscr.addstr(row, 0, " " * W, curses.color_pair(PAIR_BAR))
    except curses.error:
        pass

    x = 1
    segments = [
        (filter_text, curses.color_pair(PAIR_WHITE) | curses.A_BOLD),
        (" | ", curses.color_pair(PAIR_WHITE) | curses.A_BOLD),
        (showing_text, curses.color_pair(PAIR_WHITE) | curses.A_BOLD),
        (" | ", curses.color_pair(PAIR_WHITE) | curses.A_BOLD),
        (status_text, curses.color_pair(PAIR_WHITE)),
        (" | ", curses.color_pair(PAIR_WHITE) | curses.A_BOLD),
        (timestamp, curses.color_pair(PAIR_BAR) | curses.A_BOLD),
    ]

    for text, attr in segments:
        if x >= W:
            break
        safe_addstr(stdscr, row, x, text, attr)
        x += len(text)

    if x < W:
        safe_addstr(stdscr, row, x, " " * (W - x - 1), curses.color_pair(PAIR_BAR))


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
    """Main TUI event loop."""
    init_colors()
    curses.curs_set(0)
    stdscr.keypad(True)
    stdscr.timeout(100)  # 100ms refresh for faster updates during analysis

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

    while True:
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

        # Layout
        _, _, stats_n_rows = stats_panel_layout(W, 9)
        stats_panel_h = stats_n_rows * 4

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

        # Title bar
        title_text = "VULNERABILITY RISK INTELLIGENCE DASHBOARD"
        title_attr = curses.color_pair(PAIR_MED) | curses.A_BOLD
        line_attr = curses.color_pair(PAIR_MED)
        bg_attr = curses.color_pair(PAIR_HEADER)
        try:
            stdscr.addstr(title_row, 0, " " * W, bg_attr)
        except curses.error:
            pass
        if W >= 2:
            left_pad = 2
            right_pad = 2
            inner_width = max(0, W - left_pad - right_pad)
            title_block = f" {title_text} "
            if len(title_block) > inner_width:
                title_block = title_block[:inner_width]
            left_line = "─" * max(0, (inner_width - len(title_block)) // 2)
            right_line = "─" * max(0, inner_width - len(left_line) - len(title_block))
            safe_addstr(stdscr, title_row, 0, "╭", line_attr)
            safe_addstr(stdscr, title_row, 1, left_line, line_attr)
            safe_addstr(stdscr, title_row, 1 + len(left_line), title_block, title_attr)
            safe_addstr(stdscr, title_row, 1 + len(left_line) + len(title_block), right_line, line_attr)
            safe_addstr(stdscr, title_row, W - 1, "╮", line_attr)
        else:
            safe_addstr(stdscr, title_row, 0, title_text[:W], title_attr)

        # Stats panel - always recompute to reflect current state
        stats = compute_stats(assets_all)
        draw_stats_panel(stdscr, stats, start_row=stats_row)

        # Filter tabs
        draw_filter_bar(stdscr, filt_idx, assets_all, filter_row)

        # Left pane - asset list
        list_h = pane_h
        if sel_idx < scroll:
            scroll = sel_idx
        elif sel_idx >= scroll + (list_h - 3):
            scroll = sel_idx - (list_h - 3) + 1
        scroll = max(0, scroll)

        try:
            left_win = curses.newwin(list_h, left_w, pane_top, 0)
        except curses.error:
            stdscr.refresh()
            continue

        draw_asset_list(left_win, vis_assets, sel_idx, scroll)

        # Right pane - detail
        try:
            right_win = curses.newwin(pane_h, right_w, pane_top, left_w)
        except curses.error:
            stdscr.refresh()
            continue

        sel_asset = vis_assets[sel_idx] if vis_assets else None

        # Reset detail scroll when asset changes
        sel_key = (filt_idx, sel_idx)
        if sel_key != last_sel_key:
            detail_scroll = 0
            last_sel_key = sel_key

        detail_content_h = draw_detail(right_win, sel_asset, detail_scroll, focus == "detail")
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
