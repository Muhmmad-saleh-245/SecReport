"""PDF export.

No PDF library is bundled (keeps the core dependency-free). Instead the HTML
report is printed to PDF by a browser or converter that is already installed.
Tried in order: Chrome/Chromium/Edge (headless), wkhtmltopdf. If none is found a
clear message explains the one-click fallback (open the HTML, Print > Save as PDF).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

CHROME_NAMES = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
                "chrome", "microsoft-edge", "msedge")
CHROME_PATHS = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
)


class PdfUnavailable(RuntimeError):
    pass


def find_chrome() -> str | None:
    for name in CHROME_NAMES:
        found = shutil.which(name)
        if found:
            return found
    for path in CHROME_PATHS:
        if os.path.isfile(path):
            return path
    return None


def available() -> str:
    """Return the name of the engine that will be used, or '' if none."""
    if find_chrome():
        return "chrome"
    if shutil.which("wkhtmltopdf"):
        return "wkhtmltopdf"
    return ""


def html_to_pdf(html_text: str, out_path) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    engine = available()
    if not engine:
        raise PdfUnavailable(
            "No PDF engine found. Install Google Chrome, Chromium or Edge (or wkhtmltopdf), "
            "or open the HTML report in a browser and use Print > Save as PDF.")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "report.html"
        src.write_text(html_text, encoding="utf-8")
        if engine == "chrome":
            cmd = [find_chrome(), "--headless", "--disable-gpu", "--no-sandbox",
                   "--no-pdf-header-footer", f"--user-data-dir={Path(tmp) / 'profile'}",
                   f"--print-to-pdf={out_path.resolve()}", src.as_uri()]
        else:
            cmd = ["wkhtmltopdf", "--quiet", "--enable-local-file-access",
                   "--page-size", "A4", str(src), str(out_path.resolve())]
        try:
            subprocess.run(cmd, check=True, timeout=120, capture_output=True)
        except subprocess.TimeoutExpired as exc:
            raise PdfUnavailable("PDF engine timed out") from exc
        except subprocess.CalledProcessError as exc:
            if not out_path.is_file() or out_path.stat().st_size == 0:
                raise PdfUnavailable(f"PDF engine failed: {exc.stderr.decode(errors='replace')[:300]}") from exc
    if not out_path.is_file() or out_path.stat().st_size == 0:
        raise PdfUnavailable("PDF engine produced no output")
    return out_path
