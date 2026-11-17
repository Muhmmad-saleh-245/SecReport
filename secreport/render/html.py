"""HTML renderer. Everything is escaped; links only for http(s) URLs."""

from __future__ import annotations

import html
import re

from ..charts import SEV_COLORS, severity_bar_svg

CSS = """
:root{--ink:#1e293b;--muted:#64748b;--line:#e2e8f0;--soft:#f1f5f9;--brand:#0f172a}
*{box-sizing:border-box}
body{font-family:"Segoe UI",system-ui,-apple-system,Arial,sans-serif;color:var(--ink);line-height:1.55;
 max-width:920px;margin:0 auto;padding:0 28px 60px;background:#fff}
.banner{background:var(--brand);color:#fff;text-align:center;letter-spacing:.22em;font-size:11px;
 padding:7px;margin:0 -28px}
.cover{padding:36px 0 18px;border-bottom:4px solid var(--brand);margin-bottom:22px}
.cover h1{font-size:30px;margin:0 0 4px;color:var(--brand)}
.cover .sub{font-size:18px;color:var(--muted);margin-bottom:14px}
.meta{display:grid;grid-template-columns:150px 1fr;gap:3px 12px;font-size:14px;margin:0}
.meta dt{color:var(--muted)}.meta dd{margin:0}
h2{font-size:21px;margin:34px 0 10px;padding-bottom:5px;border-bottom:2px solid var(--line);color:var(--brand)}
h3{font-size:17px;margin:0 0 8px;display:flex;gap:10px;align-items:flex-start;justify-content:space-between}
h4{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:14px 0 4px}
p{margin:6px 0}.small{font-size:12px;color:var(--muted)}
.sev{color:#fff;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700;white-space:nowrap}
.finding{border:1px solid var(--line);border-left:5px solid var(--muted);border-radius:8px;
 padding:14px 18px;margin:18px 0;break-inside:avoid-page}
table{border-collapse:collapse;width:100%;font-size:13px;margin:10px 0}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:var(--soft)}tr:nth-child(even) td{background:#fafcfe}
code,.mono{font-family:Consolas,Menlo,monospace;font-size:11.5px}
.note{padding:9px 12px;border-radius:6px;margin:10px 0;font-size:14px}
.note.draft{background:#fef3c7;border:1px solid #f59e0b}.note.info{background:#e0f2fe;border:1px solid #38bdf8}
.toc{background:var(--soft);border-radius:8px;padding:10px 20px;font-size:14px;margin:16px 0}
.toc ol{margin:4px 0;padding-left:20px;columns:2}
.chart{margin:12px 0}
ul{margin:4px 0 8px;padding-left:22px}
@media print{body{padding:0;max-width:none}.banner{position:fixed;top:0;left:0;right:0;margin:0}
 .cover{padding-top:40px}h2{break-after:avoid}.toc{display:none}}
@page{margin:16mm 14mm}
"""


def _e(text) -> str:
    return html.escape(str(text), quote=True)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "section"


def _link(url: str) -> str:
    if re.match(r"^https?://", url, re.I):
        return f'<a href="{_e(url)}" rel="noopener noreferrer" target="_blank">{_e(url)}</a>'
    return _e(url)


def render(blocks: list) -> str:
    h1s = [b["text"] for b in blocks if b["t"] == "h1"]
    cover = next((b for b in blocks if b["t"] == "cover"), {})
    out = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           "<meta name='robots' content='noindex'>",
           f"<title>{_e(cover.get('title', 'Report'))} - {_e(cover.get('client', ''))}</title>",
            f"<style>{CSS}</style></head><body style='--brand:{_e(cover.get('brand_color', '#0f172a'))}'>"]
    open_finding = False

    def close_finding():
        nonlocal open_finding
        if open_finding:
            out.append("</div>")
            open_finding = False

    for b in blocks:
        t = b["t"]
        if t != "h3" and open_finding and t in ("h1", "h2"):
            close_finding()
        if t == "cover":
            out.append(f"<div class='banner'>{_e(b['classification'])}</div><header class='cover'>")
            out.append("<div class='brand-row'>")
            if b.get("logo_data_uri"):
                out.append(f"<img class='brand-logo' src='{_e(b['logo_data_uri'])}' alt='Logo for {_e(b['brand_name'])}'>")
            out.append(f"<strong>{_e(b['brand_name'])}</strong></div>")
            out.append(f"<h1>{_e(b['title'])}</h1><div class='sub'>{_e(b['subtitle'])}</div><dl class='meta'>")
            for k, v in b["meta"]:
                out.append(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>")
            out.append("</dl></header>")
        elif t == "toc":
            if h1s:
                out.append("<nav class='toc'><b>Contents</b><ol>")
                out.extend(f"<li><a href='#{_slug(x)}'>{_e(x)}</a></li>" for x in h1s)
                out.append("</ol></nav>")
        elif t == "h1":
            out.append(f"<h2 id='{_slug(b['text'])}'>{_e(b['text'])}</h2>")
        elif t == "h2":
            out.append(f"<h3>{_e(b['text'])}</h3>")
        elif t == "h3":
            close_finding()
            color = SEV_COLORS.get(b.get("sev", ""), "#475569")
            out.append(f"<div class='finding' id='{_e(b.get('id', ''))}' style='border-left-color:{color}'>")
            open_finding = True
            badge = (f"<span class='sev' style='background:{color}'>{_e(b['sev'])}</span>"
                     if b.get("sev") else "")
            out.append(f"<h3><span>{_e(b['text'])}</span>{badge}</h3>")
        elif t == "label":
            out.append(f"<h4>{_e(b['text'])}</h4>")
        elif t == "p":
            cls = " class='small'" if b.get("small") else ""
            out.append(f"<p{cls}>{_e(b['text'])}</p>")
        elif t == "kv":
            out.append("<dl class='meta'>")
            for k, v in b["items"]:
                out.append(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>")
            out.append("</dl>")
        elif t == "ul":
            out.append("<ul>" + "".join(f"<li>{_e(i)}</li>" for i in b["items"]) + "</ul>")
        elif t == "refs":
            out.append("<ul>" + "".join(f"<li>{_link(i)}</li>" for i in b["items"]) + "</ul>")
        elif t == "table":
            mono = set(b.get("mono", []))
            out.append("<table><thead><tr>" + "".join(f"<th>{_e(h)}</th>" for h in b["headers"]) + "</tr></thead><tbody>")
            for row in b["rows"]:
                cells = []
                for i, c in enumerate(row):
                    if i in mono:
                        cells.append(f"<td><code>{_e(c)}</code></td>")
                    elif str(c) in SEV_COLORS and b["headers"][i] in ("Severity", "Priority", "Highest"):
                        cells.append(f"<td><span class='sev' style='background:{SEV_COLORS[str(c)]}'>{_e(c)}</span></td>")
                    else:
                        cells.append(f"<td>{_e(c)}</td>")
                out.append("<tr>" + "".join(cells) + "</tr>")
            out.append("</tbody></table>")
        elif t == "chart":
            out.append(f"<div class='chart'>{severity_bar_svg(b['counts'])}</div>")
        elif t == "note":
            out.append(f"<div class='note {_e(b.get('kind', 'info'))}'>{_e(b['text'])}</div>")
        elif t == "pagebreak":
            out.append("<div style='break-after:page'></div>")
    close_finding()
    out.append("</body></html>")
    return "".join(out)
