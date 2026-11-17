"""AI assist WITHOUT any network calls or API keys.

Workflow (works with any free AI chat such as Copilot Chat, ChatGPT, Gemini, Claude):
  1. build_prompt(finding)  -> text you paste into the AI chat
  2. paste the AI's JSON answer into parse_response(...)
  3. apply_response(...) copies the text into the finding as an AI-assisted DRAFT,
     which REVOKES any earlier approval. A human must review and approve again.

Why this design: AI tools sometimes invent facts, CVE numbers and links. The
prompt forbids that, parse_response drops unknown fields, and the approval gate
keeps a person responsible for every statement in the final report.
Client data is redacted from the prompt by default so it is not pasted into a
third-party service.
"""

from __future__ import annotations

import json
import re

from .models import Engagement, Finding
from .redact import RedactionConfig

EDITABLE = ("description", "impact", "remediation", "steps_to_reproduce")
MAX_FIELD = 4000

INSTRUCTIONS = """You are helping a security professional polish ONE finding for a client report.

RULES (important):
- Use ONLY the facts given below. Do not invent evidence, CVE numbers, versions, URLs, tools or test results.
- If a fact is missing, write "TODO: <what is missing>" instead of guessing.
- Plain, professional English. No marketing language. Keep each field under 150 words.
- Do not change the severity or scores. Do not add links.
- Reply with ONLY a JSON object with these keys: "description", "impact", "remediation", "steps_to_reproduce".
"""


def build_prompt(f: Finding, redact: bool = True, extra_terms=None) -> str:
    cfg = RedactionConfig(custom_terms=list(extra_terms or [])) if redact else None
    facts = {
        "title": f.title,
        "severity": f.severity,
        "weakness": f.cwe,
        "owasp": f.owasp,
        "affected_assets": f.affected_assets,
        "description": f.description,
        "impact": f.impact,
        "steps_to_reproduce": f.steps_to_reproduce,
        "remediation": f.remediation,
    }
    if cfg:
        facts = {k: (cfg.text(v) if isinstance(v, str) else [cfg.text(x) for x in v] if isinstance(v, list) else v)
                 for k, v in facts.items()}
    return INSTRUCTIONS + "\nFACTS:\n" + json.dumps(facts, indent=2, ensure_ascii=False) + "\n"


def parse_response(text: str) -> dict:
    """Extract the JSON object from an AI reply. Returns only the known text fields."""
    text = (text or "").strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.I)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("No JSON object found in the AI reply.")
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"The AI reply is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("The AI reply must be a JSON object.")
    out = {}
    for key in EDITABLE:
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            out[key] = val.strip()[:MAX_FIELD]
    if not out:
        raise ValueError("The AI reply contained none of: " + ", ".join(EDITABLE))
    return out


def warnings_for(reply: dict) -> list:
    """Flag things AI tends to invent so the reviewer looks at them."""
    warns = []
    blob = "\n".join(reply.values())
    if re.search(r"CVE-\d{4}-\d{3,}", blob):
        warns.append("The text mentions a CVE number. Verify it exists and applies.")
    if re.search(r"https?://", blob):
        warns.append("The text contains a link. Verify it before keeping it.")
    if "TODO" in blob:
        warns.append("The text still has TODO placeholders to fill in.")
    return warns


def apply_response(eng: Engagement, finding_id: str, text: str) -> tuple:
    """Apply a parsed AI reply as an AI-assisted draft. Returns (finding, warnings)."""
    reply = parse_response(text)
    f = eng.update_finding(finding_id, ai_assisted=True, **reply)
    return f, warnings_for(reply)
