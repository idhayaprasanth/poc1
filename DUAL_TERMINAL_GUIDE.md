# Dual Terminal Setup Guide

Monitor AI analysis logs in real-time while running the TUI dashboard!

## Quick Start

### Terminal 1: Run the TUI Dashboard

```powershell
python run_tui.py
```

### Terminal 2: Monitor AI Analysis Logs

```powershell
.\monitor_logs.ps1
```

Or manually:

```powershell
Get-Content tui_ai_analysis.log -Wait -Tail 20
```

## What You'll See

### Terminal 1 (TUI Dashboard)
- Interactive dashboard with asset list
- Real-time progress updates
- Filter tabs and statistics
- Asset details panel

### Terminal 2 (Log Monitor)
- AI analysis start notifications
- Individual asset completion with risk scores
- Error messages if any occur
- Analysis progress tracking

## Log Output Examples

```
2026-06-12 09:45:23 - INFO - ======================================================================
2026-06-12 09:45:23 - INFO - Starting AI analysis for 93 assets
2026-06-12 09:45:23 - INFO - Assets: lll-mac-guptak1, lll-mac-santan1, lll-win-akandur...
2026-06-12 09:45:23 - INFO - ======================================================================
2026-06-12 09:45:28 - INFO - ✓ Completed: lll-mac-guptak1 - Risk: High (8.7)
2026-06-12 09:45:32 - INFO - ✓ Completed: lll-mac-santan1 - Risk: High (8.0)
2026-06-12 09:45:35 - INFO - ✓ Completed: lll-win-akandur - Risk: High (8.0)
```

## Color Coding (in monitor_logs.ps1)

- 🔴 **Red** - ERROR messages
- 🟡 **Yellow** - WARNING messages  
- 🟢 **Green** - ✓ Completed assets
- 🔵 **Cyan** - Analysis start messages
- ⚪ **White** - General info

## Workflow

1. **Start both terminals**
   - Terminal 1: TUI Dashboard
   - Terminal 2: Log Monitor

2. **Navigate in TUI**
   - Use arrow keys to browse assets
   - Press Tab to view details

3. **Trigger Analysis**
   - Press `R` in TUI to start analysis
   - Watch Terminal 2 for real-time progress

4. **Monitor Progress**
   - TUI shows overall stats and pending count
   - Logs show individual asset completions
   - Rows update immediately as they complete

## Tips

- **Keep logs visible** to see what AI is analyzing
- **Check for errors** in the log terminal
- **Log file location**: `tui_ai_analysis.log` in project root
- **Log resets** each time TUI starts (old logs are overwritten)

## Troubleshooting

### Log file not updating
- Make sure TUI is running
- Check that AI endpoint is configured
- Verify analysis was triggered with `R` key

### Monitor script not working
- Ensure PowerShell execution policy allows scripts:
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```

### Want to save logs
- Copy `tui_ai_analysis.log` before closing TUI
- Or redirect to another file:
  ```powershell
  Get-Content tui_ai_analysis.log -Wait -Tail 20 | Tee-Object analysis_session.log
  ```

## Advanced: Linux/Mac

For Linux or Mac, use tail:

```bash
tail -f tui_ai_analysis.log
```

Or with colors:

```bash
tail -f tui_ai_analysis.log | grep --color=always -E 'ERROR|WARNING|✓|$'
```
