"""Compare two engagements (for example the original test and the retest).

Findings are matched on a stable key: normalised title + CWE.
"""

from __future__ import annotations

import re

from .models import Engagement, Finding


def _key(f: Finding) -> str:
    return re.sub(r"\s+", " ", f.title.strip().lower()) + "|" + (f.cwe or "")


def _active(f: Finding) -> bool:
    return f.status in ("open",)


def compare(old: Engagement, new: Engagement, only_approved: bool = False) -> dict:
    """Group findings into: new, resolved (gone), fixed_status, persisting (still open),
    accepted (risk accepted in the new engagement) and severity_changed."""
    def pick(eng):
        return {_key(f): f for f in eng.findings if (f.approved or not only_approved)}
    a, b = pick(old), pick(new)
    result = {"new": [], "resolved": [], "persisting": [], "severity_changed": [],
              "fixed_status": [], "accepted": []}
    done = ("fixed", "verified")
    for k, f in b.items():
        if k not in a:
            result["new"].append(f)
            continue
        before = a[k]
        if f.status in done and before.status not in done:
            result["fixed_status"].append((before, f))
        elif f.status == "accepted":
            result["accepted"].append((before, f))
        elif _active(f):
            result["persisting"].append((before, f))
        if before.severity != f.severity:
            result["severity_changed"].append((before, f))
    for k, f in a.items():
        if k not in b:
            result["resolved"].append(f)
    return result


def summary_dict(res: dict) -> dict:
    """JSON-friendly summary used by the web UI."""
    def row(f):
        return {"id": f.id, "title": f.title, "severity": f.severity, "status": f.status}

    def pair(p):
        return {"old": row(p[0]), "new": row(p[1])}
    return {
        "new": [row(f) for f in res["new"]],
        "resolved": [row(f) for f in res["resolved"]],
        "persisting": [pair(p) for p in res["persisting"]],
        "severity_changed": [pair(p) for p in res["severity_changed"]],
        "fixed_status": [pair(p) for p in res["fixed_status"]],
        "accepted": [pair(p) for p in res["accepted"]],
    }


def to_text(res: dict) -> str:
    lines = []
    lines.append(f"New findings: {len(res['new'])}")
    lines += [f"  + {f.id} [{f.severity}] {f.title}" for f in res["new"]]
    lines.append(f"Resolved (no longer present): {len(res['resolved'])}")
    lines += [f"  - {f.id} [{f.severity}] {f.title}" for f in res["resolved"]]
    lines.append(f"Marked fixed/verified in the new engagement: {len(res['fixed_status'])}")
    lines += [f"  ~ {n.id} [{n.severity}] {n.title} ({n.status})" for _, n in res["fixed_status"]]
    lines.append(f"Risk accepted: {len(res['accepted'])}")
    lines += [f"  ? {n.id} [{n.severity}] {n.title}" for _, n in res["accepted"]]
    lines.append(f"Still open: {len(res['persisting'])}")
    lines += [f"  = {n.id} [{n.severity}] {n.title}" for _, n in res["persisting"]]
    lines.append(f"Severity changed: {len(res['severity_changed'])}")
    lines += [f"  ! {n.title}: {o.severity} -> {n.severity}" for o, n in res["severity_changed"]]
    return "\n".join(lines)
