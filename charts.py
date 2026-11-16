"""Small SVG charts (no dependencies)."""

from __future__ import annotations

import html

from .models import SEVERITIES

SEV_COLORS = {
    "Critical": "#991b1b", "High": "#c2410c", "Medium": "#b45309",
    "Low": "#1d4ed8", "Info": "#475569",
}


def severity_bar_svg(counts: dict, width: int = 520) -> str:
    """Horizontal bar chart of findings per severity, with text labels (not colour only)."""
    peak = max([counts.get(s, 0) for s in SEVERITIES] + [1])
    row_h, left, right = 26, 78, 40
    bar_w = width - left - right
    height = row_h * len(SEVERITIES) + 8
    total = sum(counts.get(s, 0) for s in SEVERITIES)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
             f'width="{width}" role="img" aria-label="Findings by severity, {total} in total">']
    for i, sev in enumerate(SEVERITIES):
        n = counts.get(sev, 0)
        y = 4 + i * row_h
        w = max(3, int(bar_w * n / peak)) if n else 0
        parts.append(f'<text x="0" y="{y + 17}" font-size="13" fill="#1e293b">{html.escape(sev)}</text>')
        parts.append(f'<rect x="{left}" y="{y + 3}" width="{bar_w}" height="16" rx="3" fill="#e2e8f0"/>')
        if w:
            parts.append(f'<rect x="{left}" y="{y + 3}" width="{w}" height="16" rx="3" fill="{SEV_COLORS[sev]}"/>')
        parts.append(f'<text x="{left + bar_w + 8}" y="{y + 17}" font-size="13" font-weight="600" '
                     f'fill="#1e293b">{n}</text>')
    parts.append("</svg>")
    return "".join(parts)
