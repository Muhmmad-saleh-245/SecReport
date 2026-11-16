"""Builds the report as a list of format-neutral "blocks".

The same blocks feed the HTML, Markdown, DOCX and PDF renderers, so every
format shows identical content. Each report type has its own template.

Block types (dicts with key "t"):
  cover(title, subtitle, classification, meta=[[k,v]..]) | toc | h1/h2(text)
  h3(text, sev, id) | label(text) | p(text) | kv(items) | ul(items) | refs(items)
  table(headers, rows, widths, mono=[col idx]) | chart(counts) | note(text, kind)
  pagebreak
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass

from . import branding, cvss40, lookups
from .models import REPORT_LABELS, SEVERITIES, Engagement
from .redact import RedactionConfig, apply as apply_redaction

OSINT_RELIABILITY = {
    "A": "Completely reliable", "B": "Usually reliable", "C": "Fairly reliable",
    "D": "Not usually reliable", "E": "Unreliable", "F": "Reliability cannot be judged",
}
OSINT_CREDIBILITY = {
    "1": "Confirmed by other sources", "2": "Probably true", "3": "Possibly true",
    "4": "Doubtful", "5": "Improbable", "6": "Truth cannot be judged",
}
TIMEFRAMES = {
    "Critical": "Immediately (within days)",
    "High": "Within 30 days",
    "Medium": "Within 90 days",
    "Low": "Next maintenance cycle",
    "Info": "For awareness",
}
RISK_PLAIN = {
    "Critical": "Critical: at least one issue could let an attacker seriously harm the business and should be fixed immediately.",
    "High": "High: serious weaknesses were found that should be fixed soon.",
    "Medium": "Medium: moderate weaknesses were found that should be planned into normal work.",
    "Low": "Low: only minor weaknesses or informational items were found.",
}
CVSS_BANDS = [["Critical", "9.0 - 10.0"], ["High", "7.0 - 8.9"], ["Medium", "4.0 - 6.9"],
              ["Low", "0.1 - 3.9"], ["Info", "0.0 / not scored"]]


@dataclass
class ReportOptions:
    include_draft: bool = False
    redaction: RedactionConfig | None = None
    generated_at: str = ""   # override for reproducible output/tests


# ---------------------------------------------------------------- helpers
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean(obj):
    """Remove control characters (NUL, VT, ...) from every string; keep newlines and tabs."""
    if isinstance(obj, str):
        return _CTRL.sub("", obj)
    if isinstance(obj, list):
        return [clean(x) for x in obj]
    if isinstance(obj, tuple):
        return tuple(clean(x) for x in obj)
    if isinstance(obj, dict):
        return {k: clean(v) for k, v in obj.items()}
    return obj


def paras(text: str) -> list:
    return [{"t": "p", "text": p.strip()} for p in (text or "").split("\n\n") if p.strip()]


def _rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


def select_findings(eng: Engagement, include_draft: bool) -> list:
    chosen = [f for f in eng.findings if include_draft or f.approved]
    return sorted(chosen, key=lambda f: (_rank(f.severity), -(f.score or 0), f.id))


def overall_risk(findings) -> str:
    present = {f.severity for f in findings}
    for sev in ("Critical", "High", "Medium"):
        if sev in present:
            return sev
    return "Low"


def _counts(findings) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    return counts


def _short_hash(h: str) -> str:
    return h[:12] + "..." if h else ""


def _size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0


def _evidence_for(eng: Engagement, findings) -> list:
    """Evidence tied to included findings, plus evidence tied to no finding.

    Evidence that belongs only to excluded (draft) findings is left out so a
    client copy never leaks material from unreviewed findings.
    """
    shown = {f.id for f in findings}
    out = []
    for e in eng.evidence:
        if not e.finding_ids or any(fid in shown for fid in e.finding_ids):
            out.append(e)
    return out


def _mitre_label(tid: str) -> str:
    name = lookups.mitre_name(tid)
    return f"{tid} {name}" if name else tid


def _asset_scope(eng: Engagement) -> list:
    s = eng.scope
    items = [
        ["Authorization reference", s.authorization_ref or "NOT RECORDED"],
        ["Testing window", f"{s.start_date or '?'} to {s.end_date or '?'}"],
        ["In scope", ", ".join(s.in_scope) or "none"],
        ["Out of scope", ", ".join(s.out_of_scope) or "none"],
    ]
    if s.rules_of_engagement:
        items.append(["Rules of engagement", s.rules_of_engagement])
    return [{"t": "kv", "items": items}]


def _summary_table(findings) -> dict:
    rows = [[f.id, f.title, f.severity, "" if f.score is None else f"{f.score}", f.status]
            for f in findings]
    return {"t": "table", "headers": ["ID", "Finding", "Severity", "CVSS", "Status"],
            "rows": rows, "widths": [0.08, 0.52, 0.14, 0.10, 0.16]}


def _evidence_table(evidence) -> list:
    if not evidence:
        return [{"t": "p", "text": "No evidence recorded."}]
    rows = [[e.id, e.filename, _size(e.size), e.sha256, ", ".join(e.finding_ids) or "-",
             e.description] for e in evidence]
    return [{"t": "table",
             "headers": ["ID", "File", "Size", "SHA-256", "Findings", "Description"],
             "rows": rows, "widths": [0.07, 0.15, 0.07, 0.36, 0.10, 0.25], "mono": [3]}]


def _remediation_roadmap(findings) -> list:
    actionable = [f for f in findings if f.status in ("open",) and f.remediation]
    if not actionable:
        return [{"t": "p", "text": "No open findings with remediation guidance."}]
    rows = [[f.severity, f.id, f.title, ", ".join(f.affected_assets) or "-",
             TIMEFRAMES.get(f.severity, "")] for f in actionable]
    return [
        {"t": "table", "headers": ["Priority", "ID", "Finding", "Affected", "Suggested timeframe"],
         "rows": rows, "widths": [0.11, 0.08, 0.33, 0.24, 0.24]},
        {"t": "p", "text": "Timeframes are suggestions. Adjust them to the client's own risk and patching policy."},
    ]


# ---------------------------------------------------------------- findings
def _meta_items(f, kind: str) -> list:
    items = [["Severity", f.severity]]
    if f.score is not None:
        label = cvss40.nomenclature(f.cvss_vector) if f.cvss_vector.startswith("CVSS:4.0/") else "CVSS 3.1"
        items.append([label, f"{f.score}  ({f.cvss_vector})"])
    if f.cwe:
        items.append(["Weakness", lookups.cwe_label(f.cwe)])
    if f.owasp:
        items.append(["OWASP", lookups.owasp_label(f.owasp)])
    if f.mitre:
        items.append(["MITRE ATT&CK", "; ".join(_mitre_label(t) for t in f.mitre)])
    if f.affected_assets:
        items.append(["Affected assets", ", ".join(f.affected_assets)])
    if kind == "osint" and (f.source_reliability or f.info_credibility):
        r, c = f.source_reliability, f.info_credibility
        items.append(["Source grade", f"{r or '?'}{c or '?'}  ({OSINT_RELIABILITY.get(r, 'not graded')}; "
                                      f"{OSINT_CREDIBILITY.get(c, 'not graded')})"])
    items.append(["Status", f.status])
    return items


def _evidence_line(f, ev_map) -> str:
    bits = []
    for eid in f.evidence_ids:
        e = ev_map.get(eid)
        bits.append(f"{eid} ({e.filename}, sha256 {_short_hash(e.sha256)})" if e else eid)
    return bits


def finding_blocks(f, ev_map: dict, kind: str) -> list:
    out = [{"t": "h3", "text": f"{f.id}: {f.title}", "sev": f.severity, "id": f.id}]
    if not f.approved:
        out.append({"t": "note", "kind": "draft", "text": "Not yet approved by a reviewer."})
    out.append({"t": "kv", "items": _meta_items(f, kind)})

    if kind == "bugbounty":
        sections = [("Summary", f.description), ("Steps to reproduce", f.steps_to_reproduce),
                    ("Impact", f.impact)]
        fix_label = "Suggested fix"
    elif kind == "osint":
        sections = [("Finding", f.description), ("Why it matters", f.impact)]
        fix_label = "Recommended action"
    else:
        sections = [("Description", f.description), ("Impact", f.impact),
                    ("Steps to reproduce", f.steps_to_reproduce)]
        fix_label = "Remediation"
    for label, text in sections:
        if (text or "").strip():
            out.append({"t": "label", "text": label})
            out.extend(paras(text))
    if kind == "osint" and f.sources:
        out.append({"t": "label", "text": "Sources"})
        out.append({"t": "ul", "items": list(f.sources)})
    if (f.remediation or "").strip():
        out.append({"t": "label", "text": fix_label})
        out.extend(paras(f.remediation))
    if f.evidence_ids:
        out.append({"t": "label", "text": "Supporting material" if kind == "bugbounty" else "Evidence"})
        out.append({"t": "ul", "items": _evidence_line(f, ev_map)})
    if f.references:
        out.append({"t": "label", "text": "References"})
        out.append({"t": "refs", "items": list(f.references)})
    if (f.retest_notes or "").strip():
        out.append({"t": "label", "text": "Retest notes"})
        out.extend(paras(f.retest_notes))
    if f.approved:
        out.append({"t": "p", "text": f"Reviewed and approved by {f.approved_by} on {f.approved_at}.",
                    "small": True})
    return out


# ---------------------------------------------------------------- templates
def _cover(eng: Engagement, opts: ReportOptions, generated: str, eng_dir=None) -> dict:
    meta = [["Engagement", eng.name], ["Client", eng.client],
            ["Prepared by", eng.tester or "N/A"], ["Generated", generated]]
    if eng.program:
        meta.insert(2, ["Program", eng.program])
    return {"t": "cover", "title": REPORT_LABELS[eng.report_type], "subtitle": eng.name,
            "classification": eng.classification, "meta": meta, "client": eng.client,
            "brand_name": eng.brand_name.strip() or eng.client,
            "brand_color": branding.validate_color(eng.brand_color),
            "logo_data_uri": branding.logo_data_uri(eng, eng_dir) if eng_dir is not None else ""}


def _front_notes(eng, findings, opts) -> list:
    out = []
    if opts.include_draft:
        out.append({"t": "note", "kind": "draft",
                    "text": "DRAFT: this report includes findings that a human reviewer has not approved yet."})
    if opts.redaction:
        out.append({"t": "note", "kind": "info",
                    "text": f"Redacted copy: {opts.redaction.describe()} were masked automatically. "
                            "Review before sharing; automatic redaction is not a guarantee."})
    if any(f.ai_assisted for f in findings):
        out.append({"t": "note", "kind": "info",
                    "text": "Some finding text was drafted with AI assistance. Each finding was reviewed "
                            "and approved by a named human reviewer before inclusion."})
    return out


def _exec_summary(eng, findings) -> list:
    counts = _counts(findings)
    out = [{"t": "h1", "text": "Executive Summary"}]
    out.extend(paras(eng.summary) or [{"t": "p", "text": "No summary provided."}])
    out.append({"t": "p", "text": f"Overall rating (highest finding severity): {overall_risk(findings)}."})
    out.append({"t": "chart", "counts": counts})
    return out


def _tail(eng, findings, evidence_blocks=True) -> list:
    out = []
    if (eng.recommendations or "").strip():
        out.append({"t": "h1", "text": "Recommendations"})
        out.extend(paras(eng.recommendations))
    if evidence_blocks:
        out.append({"t": "h1", "text": "Evidence Register"})
        out.extend(_evidence_table(_evidence_for(eng, findings)))
    return out


def _owasp_table(findings) -> list:
    rows = []
    for code, name in lookups.OWASP_2021.items():
        hits = [f for f in findings if lookups.owasp_code(f.owasp) == code]
        worst = min((f.severity for f in hits), key=_rank) if hits else "-"
        rows.append([f"{code} {name}", str(len(hits)), worst,
                     ", ".join(f.id for f in hits) or "-"])
    return [
        {"t": "table", "headers": ["OWASP Top 10 (2021) category", "Findings", "Highest", "IDs"],
         "rows": rows, "widths": [0.50, 0.12, 0.14, 0.24]},
        {"t": "p", "small": True,
         "text": "This table shows where findings were recorded. A zero does not by itself mean the "
                 "category was tested and found clean; see the methodology for what was covered."},
    ]


def build_webpentest(eng, findings, ev_map, opts) -> list:
    out = _exec_summary(eng, findings)
    out.append({"t": "h1", "text": "Scope and Authorization"})
    out.extend(_asset_scope(eng))
    out.append({"t": "h1", "text": "Methodology"})
    out.extend(paras(eng.methodology) or [{"t": "p", "text": "No methodology provided."}])
    out.append({"t": "h1", "text": "OWASP Top 10 Coverage"})
    out.extend(_owasp_table(findings))
    out.append({"t": "h1", "text": "Findings Overview"})
    out.append(_summary_table(findings) if findings else {"t": "p", "text": "No approved findings."})
    out.append({"t": "h1", "text": "Detailed Findings"})
    for f in findings:
        out.extend(finding_blocks(f, ev_map, "webpentest"))
    out.append({"t": "h1", "text": "Remediation Roadmap"})
    out.extend(_remediation_roadmap(findings))
    out.extend(_tail(eng, findings))
    out.append({"t": "h1", "text": "Appendix: Severity Scale"})
    out.append({"t": "table", "headers": ["Severity", "CVSS score"], "rows": CVSS_BANDS,
                "widths": [0.4, 0.6]})
    return out


def build_bugbounty(eng, findings, ev_map, opts) -> list:
    out = [{"t": "h1", "text": "Submission Overview"}]
    out.append({"t": "kv", "items": [["Program", eng.program or eng.client],
                                     ["Researcher", eng.tester or "N/A"],
                                     ["Reports in this document", str(len(findings))]]})
    out.extend(paras(eng.summary))
    out.append({"t": "chart", "counts": _counts(findings)})
    out.append({"t": "h1", "text": "Scope and Rules"})
    out.extend(_asset_scope(eng))
    if findings:
        out.append(_summary_table(findings))
    out.append({"t": "h1", "text": "Reports"})
    for f in findings:
        out.extend(finding_blocks(f, ev_map, "bugbounty"))
    out.extend(_tail(eng, findings))
    return out


def _osint_confidence(findings) -> list:
    graded = {}
    for f in findings:
        if f.source_reliability or f.info_credibility:
            key = f"{f.source_reliability or '?'}{f.info_credibility or '?'}"
            graded.setdefault(key, []).append(f.id)
    out = [{"t": "table", "headers": ["Grade", "Meaning", "Items"],
            "rows": [[k, f"{OSINT_RELIABILITY.get(k[0], 'not graded')}; "
                         f"{OSINT_CREDIBILITY.get(k[1], 'not graded')}", ", ".join(v)]
                     for k, v in sorted(graded.items())],
            "widths": [0.12, 0.58, 0.30]}] if graded else \
        [{"t": "p", "text": "No findings carry a source grade yet."}]
    legend_rows = [[k, v] for k, v in OSINT_RELIABILITY.items()]
    legend2 = [[k, v] for k, v in OSINT_CREDIBILITY.items()]
    out.append({"t": "label", "text": "Grading key: source reliability (letter)"})
    out.append({"t": "table", "headers": ["Letter", "Meaning"], "rows": legend_rows, "widths": [0.15, 0.85]})
    out.append({"t": "label", "text": "Grading key: information credibility (number)"})
    out.append({"t": "table", "headers": ["Number", "Meaning"], "rows": legend2, "widths": [0.15, 0.85]})
    return out


def build_osint(eng, findings, ev_map, opts) -> list:
    out = _exec_summary(eng, findings)
    if eng.objectives:
        out.append({"t": "h1", "text": "Collection Objectives"})
        out.append({"t": "ul", "items": list(eng.objectives)})
    out.append({"t": "h1", "text": "Scope and Authorization"})
    out.extend(_asset_scope(eng))
    out.append({"t": "p", "text": "Collection used publicly available sources only. No systems were "
                                  "accessed without authorization and no access controls were bypassed."})
    out.append({"t": "h1", "text": "Methodology"})
    out.extend(paras(eng.methodology) or [{"t": "p", "text": "No methodology provided."}])
    out.append({"t": "h1", "text": "Key Findings"})
    out.append(_summary_table(findings) if findings else {"t": "p", "text": "No approved findings."})
    out.append({"t": "h1", "text": "Detailed Findings"})
    for f in findings:
        out.extend(finding_blocks(f, ev_map, "osint"))
    if eng.entities:
        out.append({"t": "h1", "text": "Entities and Assets"})
        out.append({"t": "table", "headers": ["Name", "Type", "Confidence", "Notes"],
                    "rows": [[e.get("name", ""), e.get("type", ""), e.get("confidence", ""),
                              e.get("notes", "")] for e in eng.entities],
                    "widths": [0.28, 0.14, 0.14, 0.44]})
    if eng.timeline:
        out.append({"t": "h1", "text": "Timeline"})
        out.append(_timeline_table(eng, with_source=True))
    out.append({"t": "h1", "text": "Confidence Summary"})
    out.extend(_osint_confidence(findings))
    out.extend(_tail(eng, findings))
    return out


def _timeline_table(eng, with_source=False) -> dict:
    events = sorted(eng.timeline, key=lambda e: str(e.get("date", "")))
    if with_source:
        return {"t": "table", "headers": ["Date", "Event", "Detail", "Source"],
                "rows": [[e.get("date", ""), e.get("title", ""), e.get("detail", ""), e.get("source", "")]
                         for e in events], "widths": [0.14, 0.24, 0.40, 0.22]}
    return {"t": "table", "headers": ["Date / time", "Event", "Detail"],
            "rows": [[e.get("date", ""), e.get("title", ""), e.get("detail", "")] for e in events],
            "widths": [0.18, 0.27, 0.55]}


def build_redteam(eng, findings, ev_map, opts) -> list:
    out = _exec_summary(eng, findings)
    if eng.objectives:
        out.append({"t": "h1", "text": "Objectives"})
        out.append({"t": "ul", "items": list(eng.objectives)})
    out.append({"t": "h1", "text": "Scope and Rules of Engagement"})
    out.extend(_asset_scope(eng))
    out.append({"t": "h1", "text": "Methodology"})
    out.extend(paras(eng.methodology) or [{"t": "p", "text": "No methodology provided."}])
    if (eng.attack_narrative or "").strip():
        out.append({"t": "h1", "text": "Attack Narrative"})
        out.extend(paras(eng.attack_narrative))
    if eng.timeline:
        out.append({"t": "h1", "text": "Operation Timeline"})
        out.append(_timeline_table(eng))
    techniques = {}
    for f in findings:
        for t in f.mitre:
            techniques.setdefault(t, []).append(f.id)
    out.append({"t": "h1", "text": "MITRE ATT&CK Mapping"})
    if techniques:
        out.append({"t": "table", "headers": ["Technique", "Name", "Findings"],
                    "rows": [[t, lookups.mitre_name(t) or "(not in built-in list)", ", ".join(ids)]
                             for t, ids in sorted(techniques.items())],
                    "widths": [0.16, 0.54, 0.30]})
    else:
        out.append({"t": "p", "text": "No ATT&CK techniques mapped yet."})
    out.append({"t": "h1", "text": "Findings Overview"})
    out.append(_summary_table(findings) if findings else {"t": "p", "text": "No approved findings."})
    out.append({"t": "h1", "text": "Detailed Findings"})
    for f in findings:
        out.extend(finding_blocks(f, ev_map, "redteam"))
    out.append({"t": "h1", "text": "Detection and Response Gaps"})
    if eng.detection_gaps:
        out.append({"t": "ul", "items": list(eng.detection_gaps)})
    else:
        out.append({"t": "p", "text": "No detection or response gaps recorded."})
    out.append({"t": "h1", "text": "Remediation Roadmap"})
    out.extend(_remediation_roadmap(findings))
    out.extend(_tail(eng, findings))
    return out


def build_executive(eng, findings, ev_map, opts) -> list:
    risk = overall_risk(findings)
    out = [{"t": "h1", "text": "Overall Risk Posture"},
           {"t": "p", "text": RISK_PLAIN[risk]}]
    out.extend(paras(eng.summary))
    out.append({"t": "chart", "counts": _counts(findings)})
    out.append({"t": "h1", "text": "Top Risks in Plain Language"})
    top = findings[:3]
    if not top:
        out.append({"t": "p", "text": "No approved findings."})
    for i, f in enumerate(top, 1):
        out.append({"t": "h3", "text": f"{i}. {f.title}", "sev": f.severity, "id": f.id})
        if f.impact.strip():
            out.extend(paras(f.impact))
        if f.remediation.strip():
            out.append({"t": "p", "text": "What to do: " + f.remediation.strip().split("\n\n")[0]})
    out.append({"t": "h1", "text": "Recommended Priorities"})
    out.extend(_remediation_roadmap(findings))
    out.append({"t": "h1", "text": "Scope of the Work"})
    out.extend(_asset_scope(eng))
    if (eng.recommendations or "").strip():
        out.append({"t": "h1", "text": "Further Recommendations"})
        out.extend(paras(eng.recommendations))
    return out


BUILDERS = {
    "webpentest": build_webpentest, "bugbounty": build_bugbounty, "osint": build_osint,
    "redteam": build_redteam, "executive": build_executive,
}


def build(eng: Engagement, opts: ReportOptions | None = None, eng_dir=None) -> list:
    opts = opts or ReportOptions()
    generated = opts.generated_at or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    findings = select_findings(eng, opts.include_draft)
    ev_map = {e.id: e for e in eng.evidence}
    blocks = [_cover(eng, opts, generated, eng_dir)]
    blocks.extend(_front_notes(eng, findings, opts))
    blocks.append({"t": "toc"})
    blocks.extend(BUILDERS[eng.report_type](eng, findings, ev_map, opts))
    blocks = clean(blocks)
    if opts.redaction:
        blocks = apply_redaction(blocks, opts.redaction)
    return blocks
