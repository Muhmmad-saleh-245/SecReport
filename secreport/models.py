"""Core data model: Engagement, Finding, EvidenceItem.

Everything serialises to one engagement.json inside the engagement folder.
Loading is tolerant: unknown keys are ignored and missing keys get defaults,
so files written by older versions still open.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from . import cvss
from .scope import Scope

REPORT_TYPES = ("osint", "redteam", "webpentest", "bugbounty", "executive")
REPORT_LABELS = {
    "osint": "OSINT Intelligence Report",
    "redteam": "Red Team Assessment Report",
    "webpentest": "Web Application Penetration Test Report",
    "bugbounty": "Bug Bounty Report",
    "executive": "Executive Security Summary",
}
STATUSES = ("open", "fixed", "verified", "accepted")
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_ORDER = SEVERITIES  # kept for backward compatibility

RELIABILITY = "ABCDEF"   # OSINT source reliability
CREDIBILITY = "123456"   # OSINT information credibility

# Fields that, when edited, invalidate a previous human approval.
CONTENT_FIELDS = (
    "title", "cvss_vector", "manual_severity", "cwe", "owasp", "mitre",
    "affected_assets", "description", "impact", "steps_to_reproduce",
    "remediation", "references", "evidence_ids", "source_reliability",
    "info_credibility", "sources",
)


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def norm_cwe(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    m = re.fullmatch(r"(?i)(?:cwe)?[-\s]?(\d{1,5})", value)
    return f"CWE-{int(m.group(1))}" if m else value


def norm_mitre(value: str) -> str:
    return (value or "").strip().upper()


def _clean_list(values) -> list:
    return [str(v).strip() for v in (values or []) if str(v).strip()]


def _from_dict(cls, data: dict):
    names = {f.name for f in fields(cls)}
    return {k: v for k, v in (data or {}).items() if k in names}


@dataclass
class EvidenceItem:
    id: str
    filename: str
    stored_as: str
    sha256: str
    size: int
    description: str = ""
    added_at: str = ""
    finding_ids: list = field(default_factory=list)


@dataclass
class Finding:
    id: str
    title: str
    cvss_vector: str = ""
    manual_severity: str = ""          # used when there is no CVSS vector (e.g. OSINT info)
    cwe: str = ""                      # e.g. "CWE-89"
    owasp: str = ""                    # e.g. "A03:2021"
    mitre: list = field(default_factory=list)   # e.g. ["T1190"]
    affected_assets: list = field(default_factory=list)
    description: str = ""
    impact: str = ""
    steps_to_reproduce: str = ""
    remediation: str = ""
    references: list = field(default_factory=list)
    evidence_ids: list = field(default_factory=list)
    status: str = "open"
    source_reliability: str = ""       # OSINT: A-F
    info_credibility: str = ""         # OSINT: 1-6
    sources: list = field(default_factory=list)  # OSINT: where the data came from
    tags: list = field(default_factory=list)
    retest_notes: str = ""
    ai_assisted: bool = False          # text was drafted/improved with an AI tool
    approved: bool = False             # human review gate
    approved_by: str = ""
    approved_at: str = ""
    created_at: str = ""
    updated_at: str = ""

    @property
    def score(self) -> float | None:
        if not self.cvss_vector:
            return None
        return cvss.base_score(self.cvss_vector)

    @property
    def severity(self) -> str:
        if self.cvss_vector:
            sev = cvss.severity(cvss.base_score(self.cvss_vector))
            return "Info" if sev == "None" else sev
        return self.manual_severity if self.manual_severity in SEVERITIES else "Info"

    def normalise(self) -> None:
        self.title = (self.title or "").strip()
        self.cwe = norm_cwe(self.cwe)
        self.mitre = [norm_mitre(m) for m in _clean_list(self.mitre)]
        self.affected_assets = _clean_list(self.affected_assets)
        self.references = _clean_list(self.references)
        self.sources = _clean_list(self.sources)
        self.tags = _clean_list(self.tags)
        self.cvss_vector = (self.cvss_vector or "").strip()
        self.source_reliability = (self.source_reliability or "").strip().upper()
        self.info_credibility = (self.info_credibility or "").strip()

    def validate(self) -> list:
        problems = []
        if not (self.title or "").strip():
            problems.append("title is empty")
        if self.cvss_vector:
            try:
                cvss.parse_vector(self.cvss_vector)
            except cvss.CvssError as exc:
                problems.append(f"cvss_vector: {exc}")
        elif self.manual_severity and self.manual_severity not in SEVERITIES:
            problems.append(f"manual_severity must be one of {SEVERITIES}")
        if self.status not in STATUSES:
            problems.append(f"status must be one of {STATUSES}")
        if self.source_reliability and (len(self.source_reliability) != 1
                                        or self.source_reliability not in RELIABILITY):
            problems.append("source_reliability must be a single letter A-F")
        if self.info_credibility and (len(self.info_credibility) != 1
                                      or self.info_credibility not in CREDIBILITY):
            problems.append("info_credibility must be a single digit 1-6")
        return problems


@dataclass
class Engagement:
    name: str
    client: str
    report_type: str = "webpentest"
    tester: str = ""
    classification: str = "CONFIDENTIAL"
    brand_name: str = ""
    brand_color: str = "#0f172a"
    brand_logo_path: str = ""
    summary: str = ""
    methodology: str = ""
    scope: Scope = field(default_factory=Scope)
    findings: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    # Extra sections used by some report types
    objectives: list = field(default_factory=list)        # red team / osint
    timeline: list = field(default_factory=list)          # [{date,title,detail,source}]
    entities: list = field(default_factory=list)          # [{name,type,notes,confidence}]
    detection_gaps: list = field(default_factory=list)    # red team
    attack_narrative: str = ""                            # red team
    recommendations: str = ""
    program: str = ""                                     # bug bounty program / platform
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        if self.report_type not in REPORT_TYPES:
            raise ValueError(f"report_type must be one of {REPORT_TYPES}")
        if not (self.name or "").strip() or not (self.client or "").strip():
            raise ValueError("name and client are required")
        if not self.created_at:
            self.created_at = now_iso()

    # ---- findings -------------------------------------------------------
    def next_finding_id(self) -> str:
        nums = [int(m.group(1)) for f in self.findings
                if (m := re.fullmatch(r"F-(\d+)", f.id))]
        return f"F-{(max(nums) + 1 if nums else 1):03d}"

    def add_finding(self, title: str, **kwargs) -> Finding:
        finding = Finding(id=self.next_finding_id(), title=title,
                          created_at=now_iso(), **kwargs)
        finding.normalise()
        problems = finding.validate()
        if problems:
            raise ValueError("; ".join(problems))
        self.findings.append(finding)
        return finding

    def get_finding(self, finding_id: str) -> Finding:
        for f in self.findings:
            if f.id == finding_id:
                return f
        raise KeyError(f"No finding {finding_id}")

    def update_finding(self, finding_id: str, **changes) -> Finding:
        """Edit a finding. Changing reviewed content revokes its approval."""
        f = self.get_finding(finding_id)
        allowed = {fl.name for fl in fields(Finding)} - {
            "id", "approved", "approved_by", "approved_at", "created_at"}
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError(f"Cannot edit: {', '.join(sorted(unknown))}")
        before = {k: getattr(f, k) for k in CONTENT_FIELDS}
        backup = {k: getattr(f, k) for k in changes}
        for k, v in changes.items():
            setattr(f, k, v)
        f.normalise()
        problems = f.validate()
        if problems:
            for k, v in backup.items():  # roll back
                setattr(f, k, v)
            raise ValueError("; ".join(problems))
        after = {k: getattr(f, k) for k in CONTENT_FIELDS}
        if before != after and f.approved:
            f.approved, f.approved_by, f.approved_at = False, "", ""
        f.updated_at = now_iso()
        return f

    def delete_finding(self, finding_id: str) -> None:
        f = self.get_finding(finding_id)
        self.findings.remove(f)
        for e in self.evidence:
            if finding_id in e.finding_ids:
                e.finding_ids.remove(finding_id)

    def approve_finding(self, finding_id: str, reviewer: str) -> Finding:
        if not (reviewer or "").strip():
            raise ValueError("A reviewer name is required to approve a finding")
        f = self.get_finding(finding_id)
        f.approved, f.approved_by, f.approved_at = True, reviewer.strip(), now_iso()
        return f

    def unapprove_finding(self, finding_id: str) -> Finding:
        f = self.get_finding(finding_id)
        f.approved, f.approved_by, f.approved_at = False, "", ""
        return f

    def severity_counts(self, only_approved: bool = True) -> dict:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            if only_approved and not f.approved:
                continue
            counts[f.severity] += 1
        return counts

    def readiness(self) -> list:
        """Checklist used by the UI/CLI: list of (ok, message)."""
        checks = []
        s = self.scope
        checks.append((bool(s.authorization_ref.strip()), "Authorization reference recorded"))
        checks.append((bool(s.in_scope), "At least one in-scope target defined"))
        checks.append((not s.validate(), "Engagement dates are valid"))
        checks.append((bool(self.findings), "At least one finding exists"))
        drafts = [f for f in self.findings if not f.approved]
        checks.append((not drafts, f"All findings approved ({len(drafts)} still draft)"))
        checks.append((bool(self.summary.strip()), "Executive summary written"))
        missing_ev = [f.id for f in self.findings if f.severity in ("Critical", "High")
                      and not f.evidence_ids]
        checks.append((not missing_ev, "Critical/High findings have evidence"
                       + (f" (missing: {', '.join(missing_ev)})" if missing_ev else "")))
        return checks

    # ---- persistence ----------------------------------------------------
    def to_dict(self) -> dict:
        data = asdict(self)
        data["scope"] = self.scope.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Engagement":
        data = dict(data)
        scope = Scope.from_dict(data.pop("scope", {}))
        findings = [Finding(**_from_dict(Finding, f)) for f in data.pop("findings", [])]
        evidence = [EvidenceItem(**_from_dict(EvidenceItem, e)) for e in data.pop("evidence", [])]
        eng = cls(**_from_dict(cls, {k: v for k, v in data.items()
                                     if k not in ("scope", "findings", "evidence")}),
                  scope=scope)
        eng.findings, eng.evidence = findings, evidence
        return eng

    def save(self, directory) -> Path:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        self.updated_at = now_iso()
        path = directory / "engagement.json"
        tmp = directory / "engagement.json.tmp"
        tmp.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
                       encoding="utf-8")
        tmp.replace(path)
        return path

    @classmethod
    def load(cls, directory) -> "Engagement":
        path = Path(directory) / "engagement.json"
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
