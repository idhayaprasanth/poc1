"""
Theme and design tokens for the security dashboard.
Centralized color palette, card styles, and SVG icon definitions.
"""

import base64
from dash import html

# ── USWDS 3–aligned palette (light theme; designsystem.digital.gov tokens) ──
COLORS = {
    "bg": "#f0f0f0",
    "card": "#ffffff",
    "border": "#dfe1e2",
    "primary": "#005ea2",
    "primary_dark": "#1a4480",
    "primary_light": "#d9e8f6",
    "primary_lighter": "#e7f6f8",
    "text": "#1b1b1b",
    "text_muted": "#565c65",
    "high": "#b50909",
    "high_bg": "#f4e3db",
    "medium": "#c05600",
    "medium_bg": "#faf3d1",
    "low": "#008817",
    "low_bg": "#ecf3ec",
    "info_bg": "#e7f6f8",
    "focus": "#2491ff",
}

CARD_STYLE = {
    "background": COLORS["card"],
    "borderRadius": "4px",
    "padding": "24px",
    "border": f"1px solid {COLORS['border']}",
    "boxShadow": "0 2px 8px rgba(27, 27, 27, 0.06)",
}

PRIMARY_COLOR = COLORS["primary"]

# ── SVG Icon Definitions ──
CLOSE_SVG_STR = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6L6 18"/><path d="M6 6l12 12"/></svg>'

KPI_ICON_SVGS = {
    "assets": '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>',
    "high": '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l7 3v6c0 5-3 9-7 11-4-2-7-6-7-11V5l7-3z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>',
    "medium": '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/></svg>',
    "low": '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="M22 4L12 14.01l-3-3"/></svg>',
}


def svg_icon(svg_str: str, stroke_color: str, size: int = 20) -> html.Img:
    """
    Encode SVG string with dynamic stroke color and return as Dash Image component.
    
    Args:
        svg_str: SVG markup with 'stroke="currentColor"' placeholder
        stroke_color: Hex color to replace currentColor
        size: Icon size in pixels
    
    Returns:
        Dash html.Img component with base64-encoded SVG data URL
    """
    svg_str = svg_str.replace('stroke="currentColor"', f'stroke="{stroke_color}"')
    encoded = base64.b64encode(svg_str.encode("utf-8")).decode("utf-8")
    return html.Img(
        src=f"data:image/svg+xml;base64,{encoded}",
        style={"width": f"{size}px", "height": f"{size}px", "display": "block"},
    )


def get_close_svg() -> html.Img:
    """Get the close/dismiss SVG icon with primary color."""
    close_svg_colored = CLOSE_SVG_STR.replace('stroke="currentColor"', f'stroke="{PRIMARY_COLOR}"')
    close_encoded = base64.b64encode(close_svg_colored.encode('utf-8')).decode('utf-8')
    return html.Img(src=f"data:image/svg+xml;base64,{close_encoded}", style={"width": "20px", "height": "20px"})
