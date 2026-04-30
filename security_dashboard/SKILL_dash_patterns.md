# Skill: Dash UI Patterns & Callbacks

**Use this skill when**: Adding new dashboard components, modifying callbacks, fixing state management issues, implementing filters/search, or styling UI elements.

## Dash Callback Architecture

POC1 uses **explicit callback decorators** (not chaining):

```python
from dash import dcc, html, callback, Input, Output, State, ctx, no_update

@callback(
    Output("detail-panel", "children"),
    Input("asset-table", "active_cell"),
    State("asset-table", "data"),
    State("asset-table", "columns")
)
def update_detail_panel(active_cell, data, columns):
    """Update detail panel when row is selected."""
    if not active_cell:
        return "Select an asset to view details"
    
    row_index = active_cell["row"]
    asset = data[row_index]
    
    return build_detail_panel(asset)
```

### Callback Rules

**DO**:
- Use `ctx.triggered_id` for multi-button handling
- Return `no_update` for conditional outputs
- Use `State` for non-reactive values
- Keep callbacks simple; move logic to helper functions

**DON'T**:
- Chain callbacks (Input → Output → Input again)
- Use clientside callbacks for complex logic
- Access `dcc.Store` components outside callbacks
- Return `None` for optional outputs (use `no_update` instead)

## Multi-Button Callback Pattern

```python
@callback(
    Output("message", "children"),
    Input("btn-analyze", "n_clicks"),
    Input("btn-export", "n_clicks"),
    Input("btn-clear", "n_clicks"),
)
def handle_buttons(analyze_clicks, export_clicks, clear_clicks):
    """Route to correct handler based on which button was clicked."""
    if ctx.triggered_id == "btn-analyze":
        return analyze_assets()
    elif ctx.triggered_id == "btn-export":
        return export_data()
    elif ctx.triggered_id == "btn-clear":
        return clear_cache()
    
    return "Ready"
```

## State Management: dcc.Store Pattern

```python
# In layout.py
dcc.Store(id="cache-store", data={})

# In dashboard.py - Load data on startup
@callback(
    Output("cache-store", "data"),
    Input("app", "id"),  # Triggers once on page load
)
def load_initial_data(_):
    """Load merged dataset and cache it in browser."""
    data = build_merged_dataset()
    # Convert DataFrame to JSON-serializable format
    return data.to_dict("records")

# Use cached data in other callbacks
@callback(
    Output("asset-table", "data"),
    Input("search-input", "value"),
    State("cache-store", "data")
)
def filter_table(search_term, cached_data):
    """Filter cached data without re-loading from disk."""
    df = pd.DataFrame(cached_data)
    if search_term:
        df = df[df["asset_name"].str.contains(search_term, case=False)]
    return df.to_dict("records")
```

## Component Patterns

### Reusable UI Components (layout.py)

```python
def build_kpi_card(label: str, value: int, color: str) -> html.Div:
    """Reusable KPI card component."""
    return html.Div([
        html.Div(label, className="kpi-label"),
        html.Div(value, className=f"kpi-value {color}"),
    ], className="kpi-card")

def build_detail_panel(asset: dict) -> html.Div:
    """Reusable detail panel component."""
    return html.Div([
        html.H3(f"Asset: {asset['asset_name']}"),
        html.P(f"Risk Score: {asset['risk_score']}"),
        # ... more fields
    ], className="detail-panel")
```

### Data Table with Filtering

```python
# In layout.py
dash_table.DataTable(
    id="asset-table",
    columns=[
        {"name": "Asset", "id": "asset_name", "type": "text"},
        {"name": "Risk", "id": "risk_level", "type": "text"},
        {"name": "Severity", "id": "vuln_severity", "type": "numeric"},
    ],
    data=[],
    filter_action="native",
    sort_action="native",
    page_action="native",
    page_size=20,
    style_cell={"textAlign": "left"},
    style_data_conditional=[
        {
            "if": {"column_id": "risk_level", "filter_query": '{risk_level} = "High"'},
            "backgroundColor": "#dc3545",
            "color": "white",
        },
        {
            "if": {"column_id": "risk_level", "filter_query": '{risk_level} = "Medium"'},
            "backgroundColor": "#ffc107",
        },
    ],
)
```

## Search & Filter Pattern

```python
@callback(
    Output("asset-table", "data"),
    Input("search-input", "value"),
    Input("risk-dropdown", "value"),
    State("cache-store", "data")
)
def filter_assets(search_term, risk_level, cached_data):
    """Multi-filter search: term + risk level."""
    df = pd.DataFrame(cached_data)
    
    # Search filter
    if search_term:
        df = df[
            df["asset_name"].str.contains(search_term, case=False, na=False) |
            df["vuln_name"].str.contains(search_term, case=False, na=False)
        ]
    
    # Risk level filter
    if risk_level and risk_level != "all":
        df = df[df["risk_level"] == risk_level]
    
    return df.to_dict("records")
```

## Styling with USWDS 3.0

**Location**: `security_dashboard/assets/dashboard_theme.css`

### Key Classes

```css
/* Card styling */
.dashboard-card {
    border: 1px solid #ccc;
    border-radius: 4px;
    padding: 16px;
    box-shadow: none;  /* Minimal shadow for clean look */
}

/* KPI styling */
.kpi-label {
    font-size: 12px;
    color: #666;
    text-transform: uppercase;
}

.kpi-value {
    font-size: 32px;
    font-weight: bold;
}

.kpi-value.high {
    color: #dc3545;  /* USWDS red */
}

.kpi-value.medium {
    color: #ffc107;  /* USWDS yellow */
}

.kpi-value.low {
    color: #28a745;  /* USWDS green */
}

/* Font: Source Sans 3 (Google Fonts) */
body {
    font-family: "Source Sans 3", sans-serif;
}
```

### When Adding Styles

1. Use USWDS color palette: https://designsystem.digital.gov/design-tokens/color/overview/
2. Keep shadows minimal (border-based design)
3. Use `rem` for responsive sizing (not `px`)
4. Add comments for non-obvious rules

## Conditional Rendering Pattern

```python
@callback(
    Output("error-alert", "style"),
    Input("dataset-load", "data")
)
def show_error_alert(dataset):
    """Show/hide error alert based on dataset state."""
    if dataset is None or len(dataset) == 0:
        return {"display": "block"}  # Show alert
    return {"display": "none"}  # Hide alert
```

## Loading States

```python
# Use dcc.Loading wrapper for async operations
dcc.Loading(
    id="loading-spinner",
    type="default",
    children=[
        html.Div(id="analysis-results")
    ]
)

@callback(
    Output("analysis-results", "children"),
    Input("btn-analyze", "n_clicks"),
    State("cache-store", "data")
)
def run_analysis(n_clicks, data):
    """Long-running operation shows spinner."""
    if not n_clicks:
        raise PreventUpdate
    
    # Expensive operation here
    results = sagemaker_client.generate_batch_analysis(data)
    
    return build_results_table(results)
```

## Chat Interface Pattern

```python
# Store conversation in dcc.Store
dcc.Store(id="chat-history", data=[])

# Display chat messages
def render_chat_messages(messages):
    """Render conversation history."""
    return [
        html.Div([
            html.Div(msg["role"].title(), className="chat-role"),
            html.Div(msg["content"], className="chat-message"),
        ], className="chat-bubble")
        for msg in messages
    ]

# Send message callback
@callback(
    Output("chat-history", "data"),
    Input("chat-send-btn", "n_clicks"),
    State("chat-input", "value"),
    State("chat-history", "data")
)
def send_chat_message(n_clicks, user_input, history):
    """Add user message, get AI response, update history."""
    if not n_clicks or not user_input:
        raise PreventUpdate
    
    history = history or []
    
    # Add user message
    history.append({"role": "user", "content": user_input})
    
    # Get AI response
    response = sagemaker_client.generate_security_answer(user_input, history)
    history.append({"role": "assistant", "content": response})
    
    return history
```

## Performance Tips

1. **Lazy Load Heavy Data**: Use `dcc.Store` to cache, don't reload on every callback
2. **Throttle Searches**: Add debounce on search input (interval-based filtering)
3. **Paginate Tables**: Use `page_size=20` instead of showing 1000 rows
4. **Avoid Re-renders**: Return `no_update` instead of None for unchanged outputs
5. **Precompute KPIs**: Calculate in data pipeline, don't compute in callback

## References

- [Dash Callbacks Documentation](https://dash.plotly.com/callback)
- [USWDS Design System](https://designsystem.digital.gov/)
- [Plotly Color Palettes](https://plotly.com/python/discrete-color/)
- `security_dashboard/layout.py`: UI component definitions
- `security_dashboard/dashboard.py`: Callback implementations
