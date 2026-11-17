"""Report facade: build blocks, render to a chosen format, write files."""

from __future__ import annotations

from pathlib import Path

from . import blocks as B
from .models import Engagement
from .redact import RedactionConfig
from .render import docx as docx_r
from .render import html as html_r
from .render import md as md_r
from .render import pdf as pdf_r

FORMATS = ("html", "md", "docx", "pdf", "json")
EXT = {"html": "html", "md": "md", "docx": "docx", "pdf": "pdf", "json": "json"}
MIME = {
    "html": "text/html; charset=utf-8", "md": "text/markdown; charset=utf-8",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pdf": "application/pdf", "json": "application/json",
}


def make_options(include_draft=False, redact=False, custom_terms=None, generated_at="") -> B.ReportOptions:
    cfg = RedactionConfig(custom_terms=list(custom_terms or [])) if redact else None
    return B.ReportOptions(include_draft=include_draft, redaction=cfg, generated_at=generated_at)


def render(eng: Engagement, fmt: str, options: B.ReportOptions | None = None, eng_dir=None) -> bytes:
    options = options or B.ReportOptions()
    if fmt not in FORMATS:
        raise ValueError(f"format must be one of {FORMATS}")
    blocks = B.build(eng, options, eng_dir)
    if fmt == "html":
        return html_r.render(blocks).encode("utf-8")
    if fmt == "md":
        return md_r.render(blocks).encode("utf-8")
    if fmt == "docx":
        return docx_r.render(blocks)
    if fmt == "json":
        import json
        return json.dumps(blocks, indent=2, ensure_ascii=False).encode("utf-8")
    # pdf
    html_text = html_r.render(blocks)
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        out = pdf_r.html_to_pdf(html_text, Path(tmp) / "r.pdf")
        return out.read_bytes()


def filename(eng: Engagement, fmt: str, redacted: bool = False) -> str:
    from .evidence import safe_name
    base = safe_name(f"{eng.report_type}_{eng.client}_{eng.name}")[:80]
    return f"{base}{'_REDACTED' if redacted else ''}.{EXT[fmt]}"


def write_reports(eng: Engagement, eng_dir, formats=("html", "md"), options=None) -> list:
    """Write reports into <eng_dir>/reports. Returns (written_paths, [(format, error_message)])."""
    out_dir = Path(eng_dir) / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    options = options or B.ReportOptions()
    written, errors = [], []
    for fmt in formats:
        try:
            data = render(eng, fmt, options, eng_dir)
        except pdf_r.PdfUnavailable as exc:
            errors.append((fmt, str(exc)))
            continue
        path = out_dir / filename(eng, fmt, bool(options.redaction))
        path.write_bytes(data)
        written.append(path)
    return written, errors
