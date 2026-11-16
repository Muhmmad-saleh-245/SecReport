"""Markdown renderer. Escapes Markdown and HTML metacharacters in all content."""

from __future__ import annotations

import re

_SPECIAL = re.compile(r"([\\`*_{}\[\]<>#|])")


def esc(text) -> str:
    return _SPECIAL.sub(r"\\\1", str(text))


def _cell(text) -> str:
    return esc(str(text).replace("\r", "").replace("\n", " "))


def render(blocks: list) -> str:
    out = []
    for b in blocks:
        t = b["t"]
        if t == "cover":
            out.append(f"# {esc(b['title'])}\n")
            out.append(f"**Company:** {esc(b.get('brand_name', b.get('client', '')))}\n")
            out.append(f"**{esc(b['classification'])}**\n")
            out.extend(f"- **{esc(k)}:** {esc(v)}" for k, v in b["meta"])
            out.append("")
        elif t == "toc":
            continue
        elif t == "h1":
            out.append(f"\n## {esc(b['text'])}\n")
        elif t == "h2":
            out.append(f"\n### {esc(b['text'])}\n")
        elif t == "h3":
            sev = f" [{b['sev']}]" if b.get("sev") else ""
            out.append(f"\n### {esc(b['text'])}{sev}\n")
        elif t == "label":
            out.append(f"\n**{esc(b['text'])}**\n")
        elif t == "p":
            out.append(esc(b["text"]) + ("\n" if not b.get("small") else "\n"))
        elif t == "kv":
            out.extend(f"- **{esc(k)}:** {esc(v)}" for k, v in b["items"])
            out.append("")
        elif t in ("ul", "refs"):
            out.extend(f"- {esc(i)}" for i in b["items"])
            out.append("")
        elif t == "table":
            out.append("| " + " | ".join(esc(h) for h in b["headers"]) + " |")
            out.append("|" + "|".join("---" for _ in b["headers"]) + "|")
            mono = set(b.get("mono", []))
            for row in b["rows"]:
                out.append("| " + " | ".join(
                    (f"`{str(c).replace('`', '')}`" if i in mono else _cell(c)) for i, c in enumerate(row)) + " |")
            out.append("")
        elif t == "chart":
            out.append("| Severity | Count |\n|---|---|")
            out.extend(f"| {s} | {n} |" for s, n in b["counts"].items())
            out.append("")
        elif t == "note":
            out.append(f"> {esc(b['text'])}\n")
        elif t == "pagebreak":
            out.append("\n---\n")
    return "\n".join(out).rstrip() + "\n"
