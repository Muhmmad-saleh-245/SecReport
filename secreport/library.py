"""Reusable finding library.

Entries live in secreport/data/findings.json (plain JSON, easy to edit).
A user library at <workspace>/library.json is merged on top if it exists,
so you can add your own templates without touching the package.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import cvss, lookups
from .models import Engagement, Finding

BUILTIN = Path(__file__).parent / "data" / "findings.json"
PLACEHOLDER = "TODO"


def load(extra_path=None) -> list:
    entries = json.loads(BUILTIN.read_text(encoding="utf-8"))
    if extra_path and Path(extra_path).is_file():
        mine = json.loads(Path(extra_path).read_text(encoding="utf-8"))
        by_id = {e["id"]: e for e in entries}
        for e in mine:
            by_id[e["id"]] = e
        entries = list(by_id.values())
    return entries


def get(entry_id: str, extra_path=None) -> dict:
    for e in load(extra_path):
        if e["id"] == entry_id:
            return e
    raise KeyError(f"No library entry {entry_id!r}")


def validate_entry(entry: dict) -> list:
    problems = []
    for key in ("id", "kind", "title"):
        if not entry.get(key):
            problems.append(f"missing {key}")
    if entry.get("cvss_vector"):
        try:
            cvss.parse_vector(entry["cvss_vector"])
        except cvss.CvssError as exc:
            problems.append(f"{entry.get('id')}: {exc}")
    elif entry.get("manual_severity") not in ("Critical", "High", "Medium", "Low", "Info"):
        problems.append(f"{entry.get('id')}: needs a cvss_vector or a valid manual_severity")
    return problems


def instantiate(eng: Engagement, entry_id: str, assets, extra_path=None) -> Finding:
    """Copy a library entry into the engagement as a DRAFT finding.

    Every asset must pass the scope guard. Instance-specific fields still hold
    TODO placeholders that the tester must replace before approval.
    """
    entry = get(entry_id, extra_path)
    assets = [a.strip() for a in assets if a and a.strip()]
    for asset in assets:
        ok, why = eng.scope.check(asset)
        if not ok:
            raise PermissionError(f"Asset {asset!r} is not allowed ({why})")
    refs = lookups.reference_urls(entry.get("cwe", ""), entry.get("owasp", ""), entry.get("mitre", []))
    return eng.add_finding(
        entry["title"],
        cvss_vector=entry.get("cvss_vector", ""),
        manual_severity=entry.get("manual_severity", ""),
        cwe=entry.get("cwe", ""),
        owasp=lookups.owasp_label(entry.get("owasp", "")),
        mitre=list(entry.get("mitre", [])),
        affected_assets=assets,
        description=entry.get("description", ""),
        impact=entry.get("impact", ""),
        steps_to_reproduce=entry.get("steps_to_reproduce", ""),
        remediation=entry.get("remediation", ""),
        references=refs,
        sources=list(entry.get("sources", [])),
        source_reliability=entry.get("source_reliability", ""),
        info_credibility=entry.get("info_credibility", ""),
        tags=list(entry.get("tags", [])) + [f"library:{entry_id}"],
    )


def has_placeholders(f: Finding) -> bool:
    blob = "\n".join([f.description, f.impact, f.steps_to_reproduce, f.remediation] + f.sources)
    return PLACEHOLDER + ":" in blob
