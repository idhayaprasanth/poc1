# Archived Web Dashboard Files

This folder contains the old web-based dashboard files that have been replaced by the TUI dashboard.

## Archived Files

- `app.py` - Web application entry point (Flask/Dash)
- `dashboard.py` - Main Dash application
- `layout.py` - Dash layout components
- `components.py` - Reusable Dash components
- `detail_panel.py` - Asset detail panel component
- `callbacks/` - Dash callback handlers

## New TUI Dashboard

The web dashboard has been replaced with a Terminal User Interface (TUI) dashboard.

**Run the new TUI dashboard:**
```bash
python run_tui.py
```

or

```bash
python tui_dashboard.py
```

## Key Differences

### Old Web Dashboard
- Required a web browser
- Used Dash/Plotly framework
- Flask server hosting
- Complex callback system
- Heavy dependencies (dash, plotly)

### New TUI Dashboard
- Runs directly in the terminal
- Uses curses for rendering
- Single process, no web server
- Real-time updates without polling
- Lightweight dependencies (pandas, windows-curses, requests)

## Migration Notes

The TUI dashboard retains all core functionality:
- ✅ Asset listing and filtering
- ✅ Risk score display
- ✅ AI analysis integration
- ✅ Real-time analysis progress
- ✅ Detailed asset information
- ✅ Splunk column filtering for optimized AI analysis

## Restoring Web Dashboard

If you need to restore the web dashboard:

1. Copy the files back to their original locations
2. Restore `callbacks/` to `security_dashboard/callbacks/`
3. Reinstall web dependencies: `pip install dash plotly`
4. Run: `python app.py`

Date Archived: 2026-06-12
