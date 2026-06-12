#!/usr/bin/env python3
"""
=============================================================================
  VULNERABILITY RISK INTELLIGENCE DASHBOARD  —  Interactive TUI
=============================================================================
  Controls:
    ←  /  →   Navigate filter tabs
    ↑  /  ↓   Navigate asset list
    B          Cycle background theme
    Q  /  Esc  Quit
=============================================================================
  Requirements:  pip install pandas
  (curses is part of Python stdlib on Linux/macOS;
   on Windows install windows-curses: pip install windows-curses)
=============================================================================
"""
import curses, sys, random, textwrap
from datetime import datetime, timedelta

try:
    import pandas as pd
except ImportError:
    print("Missing dependency: pandas\nRun: pip install pandas"); sys.exit(1)

# ─── Windows shim ────────────────────────────────────────────────────────────
try:
    import curses
except ImportError:
    print("curses not available. On Windows run:  pip install windows-curses")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
#  SAMPLE DATA
# ══════════════════════════════════════════════════════════════════════════════
HOSTS = [
    ("10.20.30.11","srv-dc01.corp.local",      "WIN-DC01",   "Server"),
    ("10.20.30.12","srv-sql01.corp.local",     "WIN-SQL01",  "Server"),
    ("10.20.30.13","srv-web01.corp.local",     "WIN-WEB01",  "Server"),
    ("10.20.30.14","srv-file01.corp.local",    "WIN-FILE01", "Server"),
    ("10.20.30.15","srv-exchange.corp.local",  "WIN-EXCH01", "Server"),
    ("10.20.30.16","srv-app01.corp.local",     "WIN-APP01",  "Server"),
    ("10.20.30.17","srv-backup.corp.local",    "WIN-BCK01",  "Server"),
    ("10.20.30.18","linux-web01.corp.local",   "LNX-WEB01",  "Server"),
    ("10.20.30.19","linux-db01.corp.local",    "LNX-DB01",   "Server"),
    ("10.20.30.20","linux-api01.corp.local",   "LNX-API01",  "Server"),
    ("10.20.30.21","dev-laptop01.corp.local",  "DEV-PC01",   "Workstation"),
    ("10.20.30.22","dev-laptop02.corp.local",  "DEV-PC02",   "Workstation"),
    ("10.20.30.23","hr-worksta.corp.local",    "HR-PC01",    "Workstation"),
    ("10.20.30.24","fin-worksta.corp.local",   "FIN-PC01",   "Workstation"),
    ("10.20.30.25","mgmt-srv.corp.local",      "MGMT-SRV01", "Server"),
    ("10.20.30.26","vpn-gw.corp.local",        "VPN-GW01",   "Network"),
    ("10.20.30.27","mon-srv.corp.local",       "MON-SRV01",  "Server"),
    ("10.20.30.28","legacy-2008.corp.local",   "LEGACY-01",  "Server"),
    ("10.20.30.29","prt-srv.corp.local",       "PRT-SRV01",  "Server"),
    ("10.20.30.30","test-vm01.corp.local",     "TEST-VM01",  "VM"),
    ("10.20.30.31","jump-host.corp.local",     "JUMP-HOST",  "Server"),
    ("10.20.30.32","ci-runner.corp.local",     "CI-RNR01",   "VM"),
    ("10.20.30.98","rogue-dev.corp.local",     "ROGUE-DEV",  "Unknown"),
    ("10.20.30.99","unknown-host.corp.local",  "UNKNWN-01",  "Unknown"),
]

# Extra hosts that exist ONLY in Tenable (no Splunk telemetry)
EXTRA_TENABLE_ONLY_HOSTS = [
    ("10.20.30.40","scan-only01.corp.local",   "SCAN-ONLY01","Server"),
    ("10.20.30.41","iot-cam01.corp.local",     "IOT-CAM01",  "IoT"),
]

# Extra hosts that exist ONLY in Splunk (no Tenable scan)
EXTRA_SPLUNK_ONLY_HOSTS = [
    ("10.20.30.50","shadow-it01.corp.local",   "SHADOW-IT01","Unknown"),
    ("10.20.30.51","new-vm05.corp.local",      "NEW-VM05",   "VM"),
]

VULNS = [
    (1207444,"SMBv1 Protocol Enabled",                    "Critical",9.8),
    (1190023,"RDP Encryption Level Insufficient",         "Critical",9.2),
    (1234567,"Log4Shell - Apache Log4j RCE",              "Critical",10.0),
    (1198001,"OpenSSL Heartbleed CVE-2014-0160",          "High",8.5),
    (1300001,"BlueKeep RDP Vulnerability",                "High",7.8),
    (1100044,"PrintNightmare - Print Spooler RCE",        "High",7.8),
    (1900077,"WannaCry EternalBlue MS17-010",             "High",7.3),
    (2400040,"Exchange ProxyLogon",                       "High",8.1),
    (1188018,"Toast Notifications on Lock Screen",        "High",    7.5),
    (1205118,"Interactive Logon Msg Not Configured",      "High",    7.2),
    (1400022,"Unquoted Service Path Priv Escalation",     "High",    7.8),
    (1600011,"Anonymous FTP Access Enabled",              "High",    7.5),
    (2200020,"Weak SSH Key Exchange Algorithms",          "High",    6.9),
    (2500050,"LocalAccount TokenFilterPolicy Misconfig",  "High",    7.1),
    (1500033,"SSL Certificate Expired",                   "Medium",  5.0),
    (1700099,"Default SNMP Community String",             "Medium",  5.3),
    (1800055,"SMB Signing Disabled",                      "Medium",  5.9),
    (2100010,"NTP Amplification Attack Vector",           "Medium",  4.8),
    (2000001,"Outdated .NET Framework 3.5",               "Low",     3.5),
    (2300030,"HTTP TRACE Method Enabled",                 "Low",     2.6),
]

SPLUNK_EVTS = [
    (4625,"Account failed logon",             "failure"),
    (4688,"New process created",              "success"),
    (4697,"Service installed",                "success"),
    (4720,"User account created",             "success"),
    (4732,"Member added to privileged group", "success"),
    (4776,"Credential validation failed",     "failure"),
    (7045,"New service installed",            "success"),
    (4698,"Scheduled task created",           "success"),
    (4663,"Object access attempt failed",     "failure"),
    (4657,"Registry value modified",          "success"),
    (4104,"PowerShell script executed",       "success"),
    (1102,"Audit log cleared",                "success"),
    (4648,"Explicit credential logon",        "success"),
    (4624,"Successful logon",                 "success"),
]

# ══════════════════════════════════════════════════════════════════════════════
#  DATA GENERATION & CORRELATION
# ══════════════════════════════════════════════════════════════════════════════
def gen_data(seed=42):
    random.seed(seed)
    t_rows, s_rows = [], []

    # Hosts present in BOTH Tenable and Splunk
    for ip, dns, nb, atype in HOSTS[:22]:
        acr = round(random.uniform(3.5, 9.8), 1)
        for pid, pname, sev, vpr in random.sample(VULNS, random.randint(3, 7)):
            t_rows.append({"IP Address": ip, "DNS Name": dns, "NetBIOS": nb,
                           "Asset Type": atype, "Plugin": pid, "Plugin Name": pname,
                           "Severity": sev, "VPR": vpr, "ACR": acr,
                           "Port": random.choice([0, 445, 3389, 80, 443, 22]),
                           "Protocol": "TCP"})

    base = datetime(2026, 5, 19, 8, 0, 0)
    for ip, dns, nb, atype in HOSTS:
        for _ in range(random.randint(5, 15)):
            eid, sig, res = random.choice(SPLUNK_EVTS)
            ts = base + timedelta(hours=random.randint(0, 47),
                                  minutes=random.randint(0, 59))
            s_rows.append({"Computer": dns, "host": nb.lower(), "IpAddress": ip,
                           "EventCode": eid, "signature": sig, "result": res,
                           "severity": random.choice(["info","low","medium","high","critical"]),
                           "_time": ts.isoformat()})

    # Tenable-only hosts (have vuln scans, no Splunk telemetry)
    for ip, dns, nb, atype in EXTRA_TENABLE_ONLY_HOSTS:
        acr = round(random.uniform(3.5, 9.8), 1)
        for pid, pname, sev, vpr in random.sample(VULNS, random.randint(2, 5)):
            t_rows.append({"IP Address": ip, "DNS Name": dns, "NetBIOS": nb,
                           "Asset Type": atype, "Plugin": pid, "Plugin Name": pname,
                           "Severity": sev, "VPR": vpr, "ACR": acr,
                           "Port": random.choice([0, 445, 3389, 80, 443, 22]),
                           "Protocol": "TCP"})

    # Splunk-only hosts (have telemetry, no Tenable scan)
    for ip, dns, nb, atype in EXTRA_SPLUNK_ONLY_HOSTS:
        for _ in range(random.randint(5, 15)):
            eid, sig, res = random.choice(SPLUNK_EVTS)
            ts = base + timedelta(hours=random.randint(0, 47),
                                  minutes=random.randint(0, 59))
            s_rows.append({"Computer": dns, "host": nb.lower(), "IpAddress": ip,
                           "EventCode": eid, "signature": sig, "result": res,
                           "severity": random.choice(["info","low","medium","high","critical"]),
                           "_time": ts.isoformat()})

    return pd.DataFrame(t_rows), pd.DataFrame(s_rows)


def correlate(df_t, df_s):
    tb = {}
    for _, r in df_t.iterrows():
        tb.setdefault(r["IP Address"], []).append(r)
    sb = {}
    for _, r in df_s.iterrows():
        sb.setdefault(r["IpAddress"], []).append(r)

    all_ips = set(tb) | set(sb)
    corr_ips     = set(tb) & set(sb)
    tenable_only = set(tb) - set(sb)   # has Tenable, no Splunk record
    splunk_only  = set(sb) - set(tb)   # has Splunk, no Tenable record

    assets = []
    for ip in sorted(all_ips):
        tr = tb.get(ip, [])
        sr = sb.get(ip, [])

        if tr:
            sevs = [r["Severity"] for r in tr]
            vprs = [float(r["VPR"]) for r in tr]
            nc = sevs.count("Critical"); nh = sevs.count("High")
            nm = sevs.count("Medium");   nl = sevs.count("Low")
            acr = float(tr[0]["ACR"]); max_vpr = max(vprs) if vprs else 0
            dns = str(tr[0]["DNS Name"]); nb_ = str(tr[0]["NetBIOS"])
            atype = str(tr[0]["Asset Type"])
            plugs = [r["Plugin Name"] for r in tr]
            ports = list({int(r["Port"]) for r in tr if int(r["Port"]) != 0})
        else:
            nc = nh = nm = nl = 0
            acr = 0.0; max_vpr = 0.0
            # derive identity from Splunk side
            dns = str(sr[0]["Computer"]) if sr else ip
            nb_ = str(sr[0]["host"]).upper() if sr else "UNKNOWN"
            atype = "Unknown"
            plugs = []
            ports = []

        fails  = sum(1 for r in sr if r["result"] == "failure")
        hisev  = sum(1 for r in sr if r["severity"] in ("high", "critical"))
        logclr = sum(1 for r in sr if r["EventCode"] == 1102)

        score = min(10.0, round(
            nc*2.5 + nh*1.4 + nm*0.6 + max_vpr*0.25 +
            (acr/10)*1.5 + fails*0.4 + hisev*0.2 + logclr*1.0, 1))

        if ip in corr_ips:
            level = ("Critical" if score >= 9 else "High" if score >= 7
                     else "Medium" if score >= 4 else "Low")
            corr_status = "Correlated"
        elif ip in tenable_only:
            level = "Unmatched"
            corr_status = "No Splunk Record Found"
        else:  # splunk_only
            level = "Unmatched"
            corr_status = "No Tenable Record Found"

        prio  = (1 if score >= 9 else 2 if score >= 7 else 3 if score >= 4 else 4)

        assets.append(dict(
            ip=ip, dns=dns, nb=nb_, atype=atype,
            nf=len(tr), ne=len(sr),
            nc=nc, nh=nh, nm=nm, nl=nl,
            max_vpr=max_vpr, acr=acr,
            fails=fails, hisev=hisev, logclr=logclr,
            plugs=plugs, ports=ports,
            score=score, level=level, prio=prio,
            corr_status=corr_status,
            has_tenable=bool(tr), has_splunk=bool(sr),
        ))

    # sort: correlated by score desc, then unmatched grouped at bottom
    assets.sort(key=lambda x: (x["level"] == "Unmatched", -x["score"]))

    stats = dict(
        n_total_assets=len(all_ips),
        n_correlated=len(corr_ips),
        n_tenable_rows=len(df_t),
        n_splunk_rows=len(df_s),
        n_tenable_only=len(tenable_only),
        n_splunk_only=len(splunk_only),
        n_non_correlatable=len(tenable_only) + len(splunk_only),
        n_critical=sum(1 for a in assets if a["level"] == "Critical"),
        n_high=sum(1 for a in assets if a["level"] == "High"),
        n_medium=sum(1 for a in assets if a["level"] == "Medium"),
        n_low=sum(1 for a in assets if a["level"] == "Low"),
    )
    return assets, stats


# ══════════════════════════════════════════════════════════════════════════════
#  COLOR PAIRS  (defined once in setup)
# ══════════════════════════════════════════════════════════════════════════════
# pair index → meaning
# 1  CRITICAL  red on black
# 2  HIGH      yellow on black
# 3  MEDIUM    cyan on black
# 4  LOW       green on black
# 5  DIM       white on black (normal text)
# 6  HEADER    black on white (inverted)
# 7  SELECTED  black on cyan  (highlighted row)
# 8  TAB_ACT   black on white (active filter tab)
# 9  TAB_IDLE  white on black (inactive filter tab)
# 10 BORDER    blue on black
# 11 LABEL     bright-white on black
# 12 WARN      red on black bold
# 13 BAR_FG    green on black (score bar fill)
# 14 WHITE     bright white on black (hostname / IP highlight)
# 15 UNMATCHED magenta on black (non-correlatable rows)
# 16 STAT_BLUE   blue box
# 17 STAT_PURPLE purple box
# 18 STAT_PINK   magenta/pink box
# 19 STAT_YELLOW yellow box
# 20 STAT_RED    red box
# 21 STAT_GREEN  green box

PAIR_CRIT  = 1
PAIR_HIGH  = 2
PAIR_MED   = 3
PAIR_LOW   = 4
PAIR_DIM   = 5
PAIR_HEADER= 6
PAIR_SEL   = 7
PAIR_TABA  = 8
PAIR_TABI  = 9
PAIR_BORDER= 10
PAIR_LABEL = 11
PAIR_WARN  = 12
PAIR_BAR   = 13
PAIR_WHITE = 14
PAIR_UNMATCHED = 15
PAIR_STAT_BLUE   = 16
PAIR_STAT_PURPLE = 17
PAIR_STAT_PINK   = 18
PAIR_STAT_YELLOW = 19
PAIR_STAT_RED    = 20
PAIR_STAT_GREEN  = 21

LEVEL_PAIR = {
    "Critical": PAIR_CRIT,
    "High":     PAIR_HIGH,
    "Medium":   PAIR_MED,
    "Low":      PAIR_LOW,
    "Unmatched": PAIR_UNMATCHED,
}

PRIO_LABEL = {1: "P1 ≤24h", 2: "P2 ≤7d", 3: "P3 ≤30d", 4: "P4 Next"}

# Filter tabs: standard severity levels + non-correlatable buckets
FILTERS = ["All", "Critical", "High", "Medium", "Low",
           "No Splunk Record Found", "No Tenable Record Found"]


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(PAIR_CRIT,   curses.COLOR_RED,     -1)
    curses.init_pair(PAIR_HIGH,   curses.COLOR_YELLOW,  -1)
    curses.init_pair(PAIR_MED,    curses.COLOR_CYAN,    -1)
    curses.init_pair(PAIR_LOW,    curses.COLOR_GREEN,   -1)
    curses.init_pair(PAIR_DIM,    curses.COLOR_WHITE,   -1)
    curses.init_pair(PAIR_HEADER, curses.COLOR_BLACK,   curses.COLOR_WHITE)
    curses.init_pair(PAIR_SEL,    curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(PAIR_TABA,   curses.COLOR_BLACK,   curses.COLOR_WHITE)
    curses.init_pair(PAIR_TABI,   curses.COLOR_WHITE,   -1)
    curses.init_pair(PAIR_BORDER, curses.COLOR_BLUE,    -1)
    curses.init_pair(PAIR_LABEL,  curses.COLOR_WHITE,   -1)
    curses.init_pair(PAIR_WARN,   curses.COLOR_RED,     -1)
    curses.init_pair(PAIR_BAR,    curses.COLOR_GREEN,   -1)
    curses.init_pair(PAIR_WHITE,  curses.COLOR_WHITE,   -1)
    curses.init_pair(PAIR_UNMATCHED, curses.COLOR_MAGENTA, -1)
    curses.init_pair(PAIR_STAT_BLUE,   curses.COLOR_BLUE,    -1)
    curses.init_pair(PAIR_STAT_PURPLE, curses.COLOR_MAGENTA, -1)
    curses.init_pair(PAIR_STAT_PINK,   curses.COLOR_MAGENTA, -1)
    curses.init_pair(PAIR_STAT_YELLOW, curses.COLOR_YELLOW,  -1)
    curses.init_pair(PAIR_STAT_RED,    curses.COLOR_RED,     -1)
    curses.init_pair(PAIR_STAT_GREEN,  curses.COLOR_GREEN,   -1)


# ══════════════════════════════════════════════════════════════════════════════
#  DRAW HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def safe_addstr(win, y, x, text, attr=0):
    """addstr that silently ignores out-of-bounds writes."""
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w:
        return
    available = w - x
    if available <= 0:
        return
    text = text[:available]
    if y == h - 1:
        text = text[:w - x - 1]
    if not text:
        return
    try:
        win.addstr(y, x, text, attr)
    except curses.error:
        pass


def draw_box(win, title="", color_pair=PAIR_BORDER):
    """Draw a simple border around win with an optional title."""
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


def score_bar(score, width=10):
    """Return a bar string like '████░░░░░░' scaled to width."""
    filled = int(round(score / 10 * width))
    return "█" * filled + "░" * (width - filled)


# ══════════════════════════════════════════════════════════════════════════════
#  TOP STATS PANEL  (matches reference image: bordered boxes with big numbers)
# ══════════════════════════════════════════════════════════════════════════════
def draw_stat_box(win, y, x, w, value, label, pair, label_color=None):
    """Draw a single rounded-style stat box at (y, x) with given width."""
    h = 4
    if label_color is None:
        label_color = PAIR_DIM
    try:
        sub = win.derwin(h, w, y, x)
    except curses.error:
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
    safe_addstr(sub, 2, 3, label[:w-5], curses.color_pair(label_color) | curses.A_DIM)
    sub.noutrefresh()


def stats_panel_layout(W, n_boxes=11):
    """Return (box_w, per_row, n_rows) for the stats panel given terminal width."""
    box_w = max(18, min(24, (W - 6) // 4))
    gap = 1
    per_row = max(1, (W - 1) // (box_w + gap))
    n_rows = max(1, -(-n_boxes // per_row))  # ceil division
    return box_w, per_row, n_rows


def draw_stats_panel(stdscr, stats, start_row=0):
    """Draw the top stats / logistics panel similar to the reference image."""
    H, W = stdscr.getmaxyx()

    boxes = [
        (str(stats["n_total_assets"]),    "Total Assets",      PAIR_STAT_GREEN),
        (str(stats["n_correlated"]),     "Correlated Assets", PAIR_STAT_BLUE),
        (str(stats["n_non_correlatable"]),"Non-Correlatable", PAIR_STAT_YELLOW),
        (str(stats["n_tenable_rows"]),   "Tenable Rows",      PAIR_STAT_PURPLE),
        (str(stats["n_splunk_rows"]),    "Splunk Rows",       PAIR_STAT_PINK),
        (str(stats["n_tenable_only"]),   "No Splunk Record",  PAIR_STAT_RED),
        (str(stats["n_splunk_only"]),    "No Tenable Record", PAIR_STAT_GREEN),
        (str(stats["n_critical"]),       "Critical Assets",   PAIR_CRIT),
        (str(stats["n_high"]),           "High Assets",       PAIR_HIGH),
        (str(stats["n_medium"]),         "Medium Assets",     PAIR_MED),
        (str(stats["n_low"]),            "Low Assets",        PAIR_LOW),
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


STATS_PANEL_BOX_COUNT = 11  # number of stat cards drawn in draw_stats_panel


# ══════════════════════════════════════════════════════════════════════════════
#  FILTER TAB BAR
# ══════════════════════════════════════════════════════════════════════════════
def draw_filter_bar(stdscr, active_idx, assets_all, row):
    """Draw the horizontal filter tab bar."""
    counts = {}
    for f in FILTERS[1:]:
        if f == "No Splunk Record Found":
            counts[f] = sum(1 for a in assets_all if a["corr_status"] == "No Splunk Record Found")
        elif f == "No Tenable Record Found":
            counts[f] = sum(1 for a in assets_all if a["corr_status"] == "No Tenable Record Found")
        else:
            counts[f] = sum(1 for a in assets_all if a["level"] == f)
    counts["All"] = len(assets_all)

    stdscr.move(row, 0)
    stdscr.clrtoeol()
    x = 2
    for i, f in enumerate(FILTERS):
        cnt = counts[f]
        label = f"  {f} ({cnt})  "
        if i == active_idx:
            attr = curses.color_pair(PAIR_TABA) | curses.A_BOLD
        else:
            pair = LEVEL_PAIR.get(f, PAIR_DIM)
            attr = curses.color_pair(pair)
        if x + len(label) >= stdscr.getmaxyx()[1]:
            break
        safe_addstr(stdscr, row, x, label, attr)
        x += len(label) + 1



# ══════════════════════════════════════════════════════════════════════════════
#  LEFT PANE — ASSET LIST
# ══════════════════════════════════════════════════════════════════════════════
def draw_asset_list(win, assets, sel_idx, scroll_off):
    """Render the filtered & sorted asset list in the left window."""
    win.erase()
    h, w = win.getmaxyx()
    draw_box(win, "Assets", PAIR_BORDER)

    # Column header (row 1 inside border)
    hdr = f"{'#':>3}  {'Hostname':<13}  {'Score':>5}  {'Level':<10} Priority IP Address"
    safe_addstr(win, 1, 1, hdr[:w-2], curses.color_pair(PAIR_HEADER) | curses.A_BOLD)

    list_h = h - 3         # rows available for asset rows (inside border, minus header)
    visible = assets[scroll_off: scroll_off + list_h]

    for row_i, a in enumerate(visible):
        abs_idx = scroll_off + row_i
        y = row_i + 2      # +2: border top + header row

        pair   = LEVEL_PAIR.get(a["level"], PAIR_UNMATCHED)
        is_sel = (abs_idx == sel_idx)

        rank = abs_idx + 1
        nb   = a["nb"][:13]
        score_str = f"{a['score']:4.1f}"
        if a["level"] == "Unmatched":
            level_str = a["corr_status"][:10]
        else:
            level_str = a["level"][:10]
        ip    = a["ip"]
        bar   = score_bar(a["score"], 6)

        if is_sel:
            sel_attr = curses.color_pair(PAIR_SEL) | curses.A_BOLD
            line = f" {rank:>3}  {nb:<13}  {score_str}  {bar}  {level_str:<10}  {ip}"
            safe_addstr(win, y, 1, line[:w-2], sel_attr)
        else:
            base_attr  = curses.color_pair(pair)
            white_attr = curses.color_pair(PAIR_WHITE) | curses.A_BOLD

            x = 1
            seg = f" {rank:>3}  "
            safe_addstr(win, y, x, seg, base_attr); x += len(seg)

            seg = f"{nb:<13}"
            safe_addstr(win, y, x, seg, white_attr); x += len(seg)

            seg = f"  {score_str}  {bar}  {level_str:<10}  "
            safe_addstr(win, y, x, seg, base_attr); x += len(seg)

            safe_addstr(win, y, x, ip, white_attr)

    # Scrollbar indicator
    if len(assets) > list_h:
        bar_top = int(scroll_off / max(1, len(assets)) * list_h)
        safe_addstr(win, bar_top + 2, w - 1, "█",
                    curses.color_pair(PAIR_BORDER))

    win.noutrefresh()


# ══════════════════════════════════════════════════════════════════════════════
#  RIGHT PANE — DETAIL PANEL
# ══════════════════════════════════════════════════════════════════════════════
def draw_detail(win, asset, scroll=0, focused=False):
    """Render the detailed info panel for the selected asset.

    The full content is drawn into an off-screen pad (which can be taller
    than the visible window) and then the visible window shows a
    vertically-scrolled slice of it, controlled by `scroll`.

    Returns the total content height (number of rows used in the pad),
    so the caller can clamp the scroll offset.
    """
    win.erase()
    h, w = win.getmaxyx()
    if asset is None:
        draw_box(win, "Detail", PAIR_BORDER)
        safe_addstr(win, h // 2, max(1, (w - 20) // 2),
                    "← Select an asset", curses.color_pair(PAIR_DIM) | curses.A_DIM)
        win.noutrefresh()
        return 0

    a    = asset
    pair = LEVEL_PAIR.get(a["level"], PAIR_UNMATCHED)

    # Estimate a generous pad height: base sections + one row per finding.
    pad_h = 60 + len(a["plugs"])
    pad_w = max(w, 1)
    try:
        pad = curses.newpad(pad_h, pad_w)
    except curses.error:
        pad = win

    def lbl(y, label, value, vpair=PAIR_DIM):
        lw = 16
        safe_addstr(pad, y, 2, f"{label:<{lw}}", curses.color_pair(PAIR_LABEL) | curses.A_BOLD)
        safe_addstr(pad, y, 2 + lw, str(value)[:w - lw - 4], curses.color_pair(vpair))

    def lbl_white(y, label, value):
        """Label with value displayed in WHITE (for hostname / IP)."""
        lw = 16
        safe_addstr(pad, y, 2, f"{label:<{lw}}", curses.color_pair(PAIR_LABEL) | curses.A_BOLD)
        safe_addstr(pad, y, 2 + lw, str(value)[:w - lw - 4],
                    curses.color_pair(PAIR_WHITE) | curses.A_BOLD)

    def sep(y):
        safe_addstr(pad, y, 1, "─" * (w - 2), curses.color_pair(PAIR_BORDER))

    row = 1

    # ── Identity ──────────────────────────────────────────────────────────────
    safe_addstr(pad, row, 2, " IDENTITY ", curses.color_pair(PAIR_HEADER) | curses.A_BOLD)
    row += 1
    lbl_white(row, "IP Address",  a["ip"])     ; row += 1
    lbl_white(row, "Hostname",    a["nb"])     ; row += 1
    lbl(row, "DNS Name",    a["dns"][:w-20]); row += 1
    lbl(row, "Asset Type",  a["atype"])      ; row += 1
    sep(row); row += 1

    # ── Correlation status (for unmatched assets) ───────────────────────────
    if a["level"] == "Unmatched":
        safe_addstr(pad, row, 2, " CORRELATION STATUS ",
                    curses.color_pair(PAIR_HEADER) | curses.A_BOLD)
        row += 1
        safe_addstr(pad, row, 2, f"⚠  {a['corr_status']}",
                    curses.color_pair(PAIR_UNMATCHED) | curses.A_BOLD)
        row += 1
        lbl(row, "Tenable Records", "Yes" if a["has_tenable"] else "No",
            PAIR_LOW if a["has_tenable"] else PAIR_WARN)
        row += 1
        lbl(row, "Splunk Records", "Yes" if a["has_splunk"] else "No",
            PAIR_LOW if a["has_splunk"] else PAIR_WARN)
        row += 1
        sep(row); row += 1

    # ── Risk Score ────────────────────────────────────────────────────────────
    safe_addstr(pad, row, 2, " RISK SCORE ", curses.color_pair(PAIR_HEADER) | curses.A_BOLD)
    row += 1

    bar_w   = min(30, w - 24)
    bar_str = score_bar(a["score"], bar_w)
    score_line = f"{a['score']:4.1f}/10  {bar_str}"
    safe_addstr(pad, row, 2, "Score           ",
                curses.color_pair(PAIR_LABEL) | curses.A_BOLD)
    safe_addstr(pad, row, 18, score_line[:w-20], curses.color_pair(pair) | curses.A_BOLD)
    row += 1

    lbl(row, "Level",    a["level"],            pair)        ; row += 1
    lbl(row, "Priority", PRIO_LABEL[a["prio"]], pair)        ; row += 1
    lbl(row, "Max VPR",  f"{a['max_vpr']:.1f}")              ; row += 1
    lbl(row, "ACR",      f"{a['acr']:.1f}")                  ; row += 1
    sep(row); row += 1

    # ── Vulnerability Counts ──────────────────────────────────────────────────
    safe_addstr(pad, row, 2, " VULNERABILITY COUNTS ",
                curses.color_pair(PAIR_HEADER) | curses.A_BOLD)
    row += 1

    safe_addstr(pad, row, 2,  f"Critical: {a['nc']}",
                curses.color_pair(PAIR_CRIT) | curses.A_BOLD)
    safe_addstr(pad, row, 18, f"High: {a['nh']}",
                curses.color_pair(PAIR_HIGH) | curses.A_BOLD)
    safe_addstr(pad, row, 28, f"Med: {a['nm']}",
                curses.color_pair(PAIR_MED))
    safe_addstr(pad, row, 38, f"Low: {a['nl']}",
                curses.color_pair(PAIR_LOW))
    row += 1
    lbl(row, "Total Findings", f"Tenable: {a['nf']}  |  Splunk events: {a['ne']}")
    row += 1
    sep(row); row += 1

    # ── Splunk Telemetry ──────────────────────────────────────────────────────
    safe_addstr(pad, row, 2, " SPLUNK TELEMETRY ",
                curses.color_pair(PAIR_HEADER) | curses.A_BOLD)
    row += 1
    lbl(row, "Login Failures", str(a["fails"]),
        PAIR_WARN if a["fails"] > 5 else PAIR_DIM)    ; row += 1
    lbl(row, "High-Sev Events", str(a["hisev"]),
        PAIR_WARN if a["hisev"] > 3 else PAIR_DIM)    ; row += 1
    if a["logclr"]:
        safe_addstr(pad, row, 2, f"⚠  AUDIT LOG CLEARED  ({a['logclr']}x)",
                    curses.color_pair(PAIR_WARN) | curses.A_BOLD)
        row += 1
    sep(row); row += 1

    # ── Open Ports ────────────────────────────────────────────────────────────
    safe_addstr(pad, row, 2, " OPEN PORTS ",
                curses.color_pair(PAIR_HEADER) | curses.A_BOLD)
    row += 1
    ports_str = "  ".join(str(p) for p in sorted(a["ports"])) or "—"
    safe_addstr(pad, row, 2, ports_str[:w-4], curses.color_pair(PAIR_DIM))
    row += 1
    sep(row); row += 1

    # ── Findings List ─────────────────────────────────────────────────────────
    safe_addstr(pad, row, 2, " FINDINGS ",
                curses.color_pair(PAIR_HEADER) | curses.A_BOLD)
    row += 1
    for i, plug in enumerate(a["plugs"], 1):
        prefix = f"  {i}. "
        max_plug = w - len(prefix) - 3
        safe_addstr(pad, row, 2, prefix + plug[:max_plug],
                    curses.color_pair(PAIR_DIM))
        row += 1

    content_h = row + 1   # total rows of content drawn

    # Draw the border/title on the real window first.
    title_suffix = ""
    max_scroll = max(0, content_h - (h - 2))
    if max_scroll > 0:
        title_suffix = f"  [{min(scroll, max_scroll)+1}-{min(scroll + (h-2), content_h)}/{content_h}]"
    focus_tag = "  [TAB to scroll]" if (max_scroll > 0 and not focused) else (
                "  [SCROLLING]" if focused else "")
    title = f"  {a['nb']}  —  {a['level'] if a['level'] != 'Unmatched' else a['corr_status']}{title_suffix}{focus_tag}  "
    draw_box(win, title, pair)

    # Copy the visible slice of the pad onto the real window (inside the border).
    scroll = max(0, min(scroll, max_scroll))
    inner_h = h - 2   # rows available inside top/bottom border
    inner_w = w - 2
    if pad is not win and inner_h > 0 and inner_w > 0:
        try:
            pad.overwrite(win, scroll, 0, 1, 1,
                           min(1 + inner_h - 1, h - 2), min(1 + inner_w - 1, w - 2))
        except curses.error:
            pass

    # Scroll indicator
    if max_scroll > 0:
        bar_h = max(1, int(inner_h * inner_h / content_h))
        bar_pos = int(scroll / max_scroll * (inner_h - bar_h)) if max_scroll else 0
        for i in range(bar_h):
            safe_addstr(win, 1 + bar_pos + i, w - 1, "█", curses.color_pair(PAIR_BORDER))
        hint = "↑↓ scroll"
        safe_addstr(win, h - 1, max(2, w - len(hint) - 2), hint,
                     curses.color_pair(PAIR_DIM) | curses.A_DIM)

    win.noutrefresh()
    return content_h


# ══════════════════════════════════════════════════════════════════════════════
#  CONTROLS BAR  (bottom)
# ══════════════════════════════════════════════════════════════════════════════
def draw_controls_bar(stdscr, row, focus="list"):
    H, W = stdscr.getmaxyx()
    if focus == "detail":
        controls = "  TAB Switch panel    ↑ ↓ Scroll details    PgUp/PgDn/Home/End    Q / Esc Quit  "
    else:
        controls = "  ← → Filter tabs    ↑ ↓ Navigate assets    TAB Detail panel    PgUp/PgDn/Home/End    Q / Esc Quit  "
    safe_addstr(stdscr, row, 0, controls.ljust(W)[:W],
                curses.color_pair(PAIR_DIM) | curses.A_DIM)


# ══════════════════════════════════════════════════════════════════════════════
#  STATUS BAR
# ══════════════════════════════════════════════════════════════════════════════
def draw_status(stdscr, filtered_count, total_count, filt_name, now_str, row):
    H, W = stdscr.getmaxyx()
    status = (f"  Filter: {filt_name}   Showing: {filtered_count}/{total_count} assets"
              f"   {now_str}  ")
    safe_addstr(stdscr, row, 0, status.ljust(W)[:W],
                curses.color_pair(PAIR_HEADER))


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN TUI LOOP
# ══════════════════════════════════════════════════════════════════════════════
def tui(stdscr, assets_all, stats):
    init_colors()
    curses.curs_set(0)
    stdscr.keypad(True)
    stdscr.timeout(200)          # ms — allows periodic refresh

    filt_idx = 0                  # index into FILTERS list
    sel_idx  = 0                  # selected row in filtered list
    scroll   = 0                  # scroll offset
    detail_scroll = 0             # scroll offset within detail panel
    focus = "list"                # "list" or "detail" — Tab toggles
    last_sel_key = None           # (filter, sel_idx) of asset shown last frame

    def filtered():
        f = FILTERS[filt_idx]
        if f == "All":
            return assets_all
        if f == "No Splunk Record Found":
            return [a for a in assets_all if a["corr_status"] == "No Splunk Record Found"]
        if f == "No Tenable Record Found":
            return [a for a in assets_all if a["corr_status"] == "No Tenable Record Found"]
        return [a for a in assets_all if a["level"] == f]

    while True:
        H, W = stdscr.getmaxyx()
        if H < 30 or W < 70:
            stdscr.erase()
            safe_addstr(stdscr, 0, 0, "Terminal too small — resize and try again.",
                        curses.color_pair(PAIR_WARN))
            stdscr.refresh()
            key = stdscr.getch()
            if key in (ord('q'), ord('Q'), 27):
                return
            continue

        vis_assets = filtered()
        if not vis_assets:
            sel_idx = 0; scroll = 0
        else:
            sel_idx  = max(0, min(sel_idx, len(vis_assets) - 1))

        # ── Layout ────────────────────────────────────────────────────────────
        # Row 0:               title bar
        # Row 1..stats_panel_h: stats / logistics panel
        # Row stats_panel_h+1:  filter tabs
        # Row stats_panel_h+2 .. H-3: panes
        # Row H-2:              controls bar
        # Row H-1:              status bar

        _, _, stats_n_rows = stats_panel_layout(W, STATS_PANEL_BOX_COUNT)
        stats_panel_h = stats_n_rows * 4

        title_row   = 0
        stats_row   = 1
        filter_row  = stats_row + stats_panel_h
        pane_top    = filter_row + 1
        controls_row = H - 2
        status_row   = H - 1
        pane_bot    = controls_row    # exclusive
        pane_h      = pane_bot - pane_top

        left_w  = min(64, W // 2)
        right_w = W - left_w

        # ── Title bar ─────────────────────────────────────────────────────────
        title_bar = " 🔒  VULNERABILITY RISK INTELLIGENCE DASHBOARD ".center(W)
        safe_addstr(stdscr, title_row, 0, title_bar[:W].ljust(W),
                    curses.color_pair(PAIR_HEADER) | curses.A_BOLD)

        # ── Stats / logistics panel ─────────────────────────────────────────────
        draw_stats_panel(stdscr, stats, start_row=stats_row)

        # ── Filter tabs ───────────────────────────────────────────────────────
        draw_filter_bar(stdscr, filt_idx, assets_all, filter_row)

        # ── Left pane ─────────────────────────────────────────────────────────
        list_h = pane_h
        # auto-scroll to keep sel_idx visible
        if sel_idx < scroll:
            scroll = sel_idx
        elif sel_idx >= scroll + (list_h - 3):
            scroll = sel_idx - (list_h - 3) + 1
        scroll = max(0, scroll)

        try:
            left_win = curses.newwin(list_h, left_w, pane_top, 0)
        except curses.error:
            stdscr.refresh(); continue

        draw_asset_list(left_win, vis_assets, sel_idx, scroll)

        # ── Right pane ────────────────────────────────────────────────────────
        try:
            right_win = curses.newwin(pane_h, right_w, pane_top, left_w)
        except curses.error:
            stdscr.refresh(); continue

        sel_asset = vis_assets[sel_idx] if vis_assets else None

        # Reset detail scroll whenever the selected asset changes
        sel_key = (filt_idx, sel_idx)
        if sel_key != last_sel_key:
            detail_scroll = 0
            last_sel_key = sel_key

        detail_content_h = draw_detail(right_win, sel_asset, detail_scroll, focus == "detail")
        detail_visible_h = pane_h - 2
        detail_max_scroll = max(0, detail_content_h - detail_visible_h)
        detail_scroll = max(0, min(detail_scroll, detail_max_scroll))

        # ── Controls bar ─────────────────────────────────────────────────────
        draw_controls_bar(stdscr, controls_row, focus)

        # ── Status bar ────────────────────────────────────────────────────────
        draw_status(stdscr, len(vis_assets), len(assets_all),
                    FILTERS[filt_idx], datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    status_row)

        stdscr.noutrefresh()
        curses.doupdate()

        # ── Input ─────────────────────────────────────────────────────────────
        key = stdscr.getch()

        if key in (ord('q'), ord('Q'), 27):          # Q / Esc → quit
            break
        elif key in (ord('\t'), 9):                   # Tab → toggle focus
            focus = "detail" if focus == "list" else "list"
        elif key == curses.KEY_LEFT:                  # ← filter
            filt_idx = (filt_idx - 1) % len(FILTERS)
            sel_idx = 0; scroll = 0
        elif key == curses.KEY_RIGHT:                 # → filter
            filt_idx = (filt_idx + 1) % len(FILTERS)
            sel_idx = 0; scroll = 0
        elif key == curses.KEY_UP:                    # ↑
            if focus == "detail":
                detail_scroll = max(0, detail_scroll - 1)
            else:
                sel_idx = max(0, sel_idx - 1)
        elif key == curses.KEY_DOWN:                  # ↓
            if focus == "detail":
                detail_scroll = min(detail_max_scroll, detail_scroll + 1)
            else:
                if vis_assets:
                    sel_idx = min(len(vis_assets) - 1, sel_idx + 1)
        elif key == curses.KEY_PPAGE:                 # Page Up
            if focus == "detail":
                detail_scroll = max(0, detail_scroll - (detail_visible_h - 1))
            else:
                sel_idx = max(0, sel_idx - (list_h - 3))
        elif key == curses.KEY_NPAGE:                 # Page Down
            if focus == "detail":
                detail_scroll = min(detail_max_scroll, detail_scroll + (detail_visible_h - 1))
            else:
                if vis_assets:
                    sel_idx = min(len(vis_assets) - 1, sel_idx + (list_h - 3))
        elif key == curses.KEY_HOME:                  # Home
            if focus == "detail":
                detail_scroll = 0
            else:
                sel_idx = 0; scroll = 0
        elif key == curses.KEY_END:                   # End
            if focus == "detail":
                detail_scroll = detail_max_scroll
            else:
                if vis_assets:
                    sel_idx = len(vis_assets) - 1


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
def main():
    print("Generating data…", end=" ", flush=True)
    df_t, df_s = gen_data()
    print(f"Tenable: {len(df_t)} rows  |  Splunk: {len(df_s)} rows")
    print("Correlating…", end=" ", flush=True)
    assets, stats = correlate(df_t, df_s)
    print(f"{stats['n_correlated']} correlated  |  "
          f"{stats['n_non_correlatable']} non-correlatable "
          f"(Tenable-only: {stats['n_tenable_only']}, "
          f"Splunk-only: {stats['n_splunk_only']})")
    print("Launching TUI…")
    curses.wrapper(tui, assets, stats)
    print("Dashboard closed.")


if __name__ == "__main__":
    main()