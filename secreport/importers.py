"""Import results from other tools as DRAFT findings.

Supported (files you already produced with your own authorized testing):
  nuclei  JSONL / JSON array export
  zap     ZAP JSON report
  burp    Burp Suite XML issue export
  nmap    Nmap XML (-oX), one Info finding per host listing open ports
    nessus  Nessus XML report export
    sarif   SARIF 2.1.0 JSON log

This module only READS result files. It never connects to any target.

Safety:
  * Every affected asset passes the engagement scope guard. Out-of-scope
    items are skipped and reported, never imported.
  * Duplicates are merged (same title + CWE): assets are combined.
  * XML with entity declarations is rejected (entity-expansion attacks).
  * Everything imported is a draft and needs human approval.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from html import unescape
from urllib.parse import urlparse

from . import cvss, evidence, lookups
from .models import SEVERITIES, Engagement, norm_cwe

MAX_INPUT_BYTES = 20 * 1024 * 1024
MAX_ITEMS = 5000
MAX_ASSETS_PER_FINDING = 25
TOOLS = ("nuclei", "zap", "burp", "nmap", "nessus", "sarif")


class ImportError_(ValueError):
    """Raised for unreadable or unsafe input."""


@dataclass
class Candidate:
    title: str
    severity: str = "Info"
    description: str = ""
    remediation: str = ""
    cwe: str = ""
    cvss_vector: str = ""
    assets: list = field(default_factory=list)
    references: list = field(default_factory=list)
    raw: str = ""            # short raw evidence text
    tool: str = ""

    @property
    def key(self) -> str:
        return re.sub(r"\s+", " ", self.title.strip().lower()) + "|" + (self.cwe or "")


@dataclass
class ImportResult:
    created: list = field(default_factory=list)       # finding ids
    merged: list = field(default_factory=list)        # (finding id, new assets)
    skipped_scope: list = field(default_factory=list)  # (title, asset, reason)
    skipped_invalid: list = field(default_factory=list)
    total_items: int = 0

    def summary(self) -> str:
        return (f"{self.total_items} item(s) read: {len(self.created)} new draft finding(s), "
                f"{len(self.merged)} merged into existing, {len(self.skipped_scope)} out-of-scope skipped, "
                f"{len(self.skipped_invalid)} invalid skipped")


# ------------------------------------------------------------------ helpers
def _strip_html(text: str) -> str:
    text = re.sub(r"(?i)<br\s*/?>|</p>|</li>", "\n", text or "")
    text = re.sub(r"<[^>]+>", "", text)
    text = unescape(text)
    return re.sub(r"\n{3,}", "\n\n", re.sub(r"[ \t]+", " ", text)).strip()


def _sev(value: str) -> str:
    v = (value or "").strip().lower()
    return {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
            "info": "Info", "informational": "Info", "information": "Info"}.get(v, "Info")


def _trim(text: str, limit: int = 6000) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "\n... [truncated]"


def _safe_xml(text: str) -> ET.Element:
    if re.search(r"<!ENTITY", text, re.I):
        raise ImportError_("XML contains entity declarations; refusing to parse it.")
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        raise ImportError_(f"Invalid XML: {exc}") from exc


def _check_size(content) -> str:
    if isinstance(content, bytes):
        if len(content) > MAX_INPUT_BYTES:
            raise ImportError_("Input is larger than 20 MB")
        content = content.decode("utf-8", errors="replace")
    if len(content) > MAX_INPUT_BYTES:
        raise ImportError_("Input is larger than 20 MB")
    return content.lstrip("﻿")


def _cwe_from(value) -> str:
    value = str(value or "").strip()
    if value in ("", "0", "-1"):
        return ""
    return norm_cwe(value)


# ------------------------------------------------------------------ parsers
def parse_nuclei(content) -> list:
    text = _check_size(content).strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        records = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        records = []
        for n, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ImportError_(f"Line {n} is not valid JSON: {exc}") from exc
    out = []
    for r in records[:MAX_ITEMS]:
        if not isinstance(r, dict):
            continue
        info = r.get("info") or {}
        cls = info.get("classification") or {}
        cwe_ids = cls.get("cwe-id") or []
        if isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids]
        vec = (cls.get("cvss-metrics") or "").strip()
        if vec:
            try:
                cvss.parse_vector(vec)
            except cvss.CvssError:
                vec = ""
        refs = info.get("reference") or []
        refs = [refs] if isinstance(refs, str) else list(refs)
        asset = r.get("matched-at") or r.get("url") or r.get("host") or ""
        name = info.get("name") or r.get("template-id") or "Nuclei finding"
        desc = (info.get("description") or "").strip()
        extra = r.get("extracted-results")
        if extra:
            desc += ("\n\n" if desc else "") + "Extracted: " + ", ".join(map(str, extra))[:500]
        out.append(Candidate(
            title=str(name), severity=_sev(info.get("severity")), description=desc,
            remediation=(info.get("remediation") or "").strip(),
            cwe=_cwe_from(cwe_ids[0]) if cwe_ids else "", cvss_vector=vec,
            assets=[str(asset)] if asset else [], references=[str(x) for x in refs][:10],
            raw=_trim(json.dumps({k: r.get(k) for k in ("template-id", "matched-at", "type", "timestamp",
                                                         "matcher-name", "curl-command") if r.get(k)},
                                 indent=1)),
            tool="nuclei"))
    return out


def parse_zap(content) -> list:
    text = _check_size(content)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ImportError_(f"Not valid ZAP JSON: {exc}") from exc
    sites = data.get("site") if isinstance(data, dict) else None
    if isinstance(sites, dict):
        sites = [sites]
    if not isinstance(sites, list):
        raise ImportError_("This does not look like a ZAP JSON report (no 'site' list).")
    risk = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}
    out = []
    for site in sites:
        for alert in (site.get("alerts") or []):
            if len(out) >= MAX_ITEMS:
                break
            instances = alert.get("instances") or []
            assets = []
            for inst in instances:
                uri = inst.get("uri")
                if uri and uri not in assets:
                    assets.append(uri)
            if not assets and site.get("@name"):
                assets = [site["@name"]]
            refs = re.findall(r"https?://[^\s<]+", _strip_html(alert.get("reference", "")))
            out.append(Candidate(
                title=str(alert.get("alert") or alert.get("name") or "ZAP alert"),
                severity=risk.get(str(alert.get("riskcode")), "Info"),
                description=_strip_html(alert.get("desc", "")),
                remediation=_strip_html(alert.get("solution", "")),
                cwe=_cwe_from(alert.get("cweid")), assets=assets, references=refs[:10],
                raw=_trim(json.dumps([{k: i.get(k) for k in ("uri", "method", "param", "attack", "evidence")
                                       if i.get(k)} for i in instances[:20]], indent=1)),
                tool="zap"))
    return out


def parse_burp(content) -> list:
    root = _safe_xml(_check_size(content))
    if root.tag != "issues":
        raise ImportError_("This does not look like a Burp XML export (root must be <issues>).")
    out = []
    for issue in root.findall("issue")[:MAX_ITEMS]:
        def g(tag):
            el = issue.find(tag)
            return (el.text or "").strip() if el is not None and el.text else ""
        host, path = g("host"), g("path")
        asset = (host.rstrip("/") + path) if host else ""
        desc = _strip_html(g("issueBackground"))
        detail = _strip_html(g("issueDetail"))
        if detail:
            desc += ("\n\n" if desc else "") + detail
        cwe = ""
        m = re.search(r"CWE-(\d+)", g("vulnerabilityClassifications"))
        if m:
            cwe = norm_cwe(m.group(1))
        refs = re.findall(r"https?://[^\s<\"']+", g("references"))
        out.append(Candidate(
            title=g("name") or "Burp issue", severity=_sev(g("severity")), description=desc,
            remediation=_strip_html(g("remediationBackground")), cwe=cwe,
            assets=[asset] if asset else [], references=refs[:10],
            raw=_trim(f"location: {g('location')}\nconfidence: {g('confidence')}\ntype: {g('type')}"),
            tool="burp"))
    return out


def parse_nmap(content) -> list:
    root = _safe_xml(_check_size(content))
    if root.tag != "nmaprun":
        raise ImportError_("This does not look like Nmap XML (root must be <nmaprun>).")
    out = []
    for host in root.findall("host")[:MAX_ITEMS]:
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr = ""
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break
        name_el = host.find("hostnames/hostname")
        hostname = name_el.get("name", "") if name_el is not None else ""
        lines = []
        for port in host.findall("ports/port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = port.find("service")
            desc = ""
            if svc is not None:
                desc = " ".join(x for x in (svc.get("name"), svc.get("product"), svc.get("version")) if x)
            lines.append(f"{port.get('portid')}/{port.get('protocol')}  {desc}".rstrip())
        if not lines:
            continue
        asset = hostname or addr
        out.append(Candidate(
            title=f"Exposed network services on {asset}", severity="Info",
            description="The following ports were open when scanned:\n\n" + "\n".join(lines),
            remediation="Review each exposed service. Close or restrict anything that is not required.",
            assets=[a for a in (hostname, addr) if a][:1] or [asset], raw=_trim("\n".join(lines)),
            tool="nmap"))
    return out


def parse_nessus(content) -> list:
    root = _safe_xml(_check_size(content))
    if root.tag != "NessusClientData_v2":
        raise ImportError_("This does not look like a Nessus XML export (root must be <NessusClientData_v2>).")
    report = root.find("Report")
    if report is None:
        raise ImportError_("Nessus XML has no <Report> element.")
    out = []
    severity_by_number = {"0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
    for host in report.findall("ReportHost"):
        properties = {tag.get("name", "").lower(): (tag.text or "").strip()
                      for tag in host.findall("HostProperties/tag")}
        asset = properties.get("host-fqdn") or properties.get("host-ip") or host.get("name", "")
        for item in host.findall("ReportItem"):
            if len(out) >= MAX_ITEMS:
                return out

            def value(tag):
                child = item.find(tag)
                return (child.text or "").strip() if child is not None and child.text else ""

            title = item.get("pluginName") or item.get("pluginID") or "Nessus finding"
            synopsis = _strip_html(value("synopsis"))
            description = _strip_html(value("description"))
            if synopsis and synopsis not in description:
                description = synopsis + ("\n\n" + description if description else "")
            remediation = _strip_html(value("solution"))
            cwe_match = re.search(r"(?i)(?:CWE[-:]?\s*)?(\d+)", value("cwe"))
            cwe = _cwe_from(cwe_match.group(1)) if cwe_match else ""
            vector = ""
            for tag in ("cvss4_vector", "cvss3_vector", "cvss_vector"):
                candidate_vector = value(tag)
                if candidate_vector:
                    try:
                        cvss.parse_vector(candidate_vector)
                    except cvss.CvssError:
                        continue
                    vector = candidate_vector
                    break
            severity = severity_by_number.get(item.get("severity", ""), _sev(item.get("severity", "")))
            references = [url.strip() for node in item.findall("see_also")
                          for url in (node.text or "").splitlines() if url.strip()][:10]
            raw_data = {
                "plugin_id": item.get("pluginID", ""), "plugin_family": item.get("pluginFamily", ""),
                "port": item.get("port", ""), "protocol": item.get("protocol", ""),
                "service": item.get("svc_name", ""), "risk_factor": value("risk_factor"),
                "cve": [node.text for node in item.findall("cve") if node.text],
                "plugin_output": value("plugin_output"),
            }
            out.append(Candidate(title=str(title), severity=severity, description=description,
                                 remediation=remediation, cwe=cwe, cvss_vector=vector,
                                 assets=[asset] if asset else [], references=references,
                                 raw=_trim(json.dumps(raw_data, ensure_ascii=False, indent=1)), tool="nessus"))
    return out


def _sarif_text(value) -> str:
    if not isinstance(value, dict):
        return ""
    text = value.get("text") or value.get("markdown") or ""
    return text if isinstance(text, str) else ""


def _sarif_severity(level, properties) -> str:
    score = properties.get("security-severity") if isinstance(properties, dict) else None
    if isinstance(score, (str, int, float)):
        try:
            numeric = float(score)
        except (TypeError, ValueError):
            numeric = -1
        if 0 <= numeric <= 10:
            return ("Info" if numeric == 0 else "Low" if numeric < 4 else "Medium" if numeric < 7
                    else "High" if numeric < 9 else "Critical")
    return {"error": "High", "warning": "Medium", "note": "Info", "none": "Info"}.get(level, "Info")


def parse_sarif(content, default_asset: str = "") -> list:
    text = _check_size(content)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ImportError_(f"Not valid SARIF JSON: {exc}") from exc
    if not isinstance(data, dict) or data.get("version") != "2.1.0" or not isinstance(data.get("runs"), list):
        raise ImportError_("This does not look like a SARIF 2.1.0 log (expected version and runs).")

    default_asset = default_asset.strip() if isinstance(default_asset, str) else ""
    out = []
    for run in data["runs"]:
        if not isinstance(run, dict):
            continue
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        driver = driver if isinstance(driver, dict) else {}
        rules = driver.get("rules")
        rules = rules if isinstance(rules, list) else []
        rules_by_id = {rule.get("id"): rule for rule in rules if isinstance(rule, dict) and rule.get("id")}
        results = run.get("results")
        for result in results if isinstance(results, list) else []:
            if len(out) >= MAX_ITEMS:
                return out
            if not isinstance(result, dict):
                continue
            rule = rules_by_id.get(result.get("ruleId"))
            if rule is None and isinstance(result.get("ruleIndex"), int) and 0 <= result["ruleIndex"] < len(rules):
                rule = rules[result["ruleIndex"]]
            rule = rule if isinstance(rule, dict) else {}
            rule_properties = rule.get("properties")
            properties = dict(rule_properties) if isinstance(rule_properties, dict) else {}
            result_properties = result.get("properties")
            if isinstance(result_properties, dict):
                properties.update(result_properties)
            title = (_sarif_text(rule.get("shortDescription")) or rule.get("name") or result.get("ruleId")
                     or "SARIF result")
            message = _sarif_text(result.get("message"))
            description = _sarif_text(rule.get("fullDescription"))
            help_text = _sarif_text(rule.get("help"))
            if message:
                description = (description + "\n\n" if description else "") + message
            if not description:
                description = help_text
            cwe = ""
            tags = properties.get("tags") or []
            if isinstance(tags, list):
                for tag in tags:
                    match = re.search(r"(?i)\bCWE[-:]?\s*(\d+)\b", str(tag))
                    if match:
                        cwe = _cwe_from(match.group(1))
                        break
            assets = []
            locations = result.get("locations")
            for location in locations if isinstance(locations, list) else []:
                if not isinstance(location, dict):
                    continue
                physical = location.get("physicalLocation")
                if not isinstance(physical, dict):
                    continue
                artifact = physical.get("artifactLocation")
                if not isinstance(artifact, dict):
                    continue
                uri = artifact.get("uri")
                if isinstance(uri, str) and urlparse(uri).scheme.lower() in ("http", "https") and uri not in assets:
                    assets.append(uri)
            if not assets and default_asset.strip():
                assets = [default_asset.strip()]
            help_uri = rule.get("helpUri")
            refs = [help_uri] if isinstance(help_uri, str) and help_uri.startswith(("https://", "http://")) else []
            level = result.get("level", "warning")
            level = level if isinstance(level, str) else "warning"
            raw_data = {"ruleId": result.get("ruleId"), "level": level,
                        "locations": result.get("locations", []), "properties": properties}
            out.append(Candidate(title=str(title), severity=_sarif_severity(level, properties),
                                 description=_trim(description), remediation=_trim(help_text), cwe=cwe,
                                 assets=assets, references=refs, raw=_trim(json.dumps(raw_data, ensure_ascii=False, indent=1)),
                                 tool="sarif"))
    return out


PARSERS = {"nuclei": parse_nuclei, "zap": parse_zap, "burp": parse_burp, "nmap": parse_nmap,
           "nessus": parse_nessus, "sarif": parse_sarif}


def detect_tool(content) -> str:
    """Best-effort guess from the first bytes of a file."""
    head = (content[:4000] if isinstance(content, str) else content[:4000].decode("utf-8", "replace")).lstrip("﻿ \n\r\t")
    if "<nmaprun" in head:
        return "nmap"
    if head.startswith("<") and "<issues" in head:
        return "burp"
    if head.startswith("<") and "<NessusClientData_v2" in head:
        return "nessus"
    if head.startswith("{") and '"version"' in head and '"runs"' in head:
        return "sarif"
    if head.startswith("{") and '"site"' in head and ('"alerts"' in head or '"@name"' in head):
        return "zap"
    if head.startswith(("{", "[")) and ("template-id" in head or '"matched-at"' in head):
        return "nuclei"
    return ""


# ------------------------------------------------------------------ import
def import_candidates(eng: Engagement, eng_dir, candidates, tool: str = "") -> ImportResult:
    res = ImportResult(total_items=len(candidates))
    for cand in candidates:
        if not cand.title.strip():
            res.skipped_invalid.append(("(no title)", ""))
            continue
        allowed, blocked = [], []
        for asset in cand.assets or []:
            ok, why = eng.scope.check(asset)
            (allowed if ok else blocked).append((asset, why))
        if cand.assets and not allowed:
            res.skipped_scope.append((cand.title, blocked[0][0], blocked[0][1]))
            continue
        if not cand.assets:
            res.skipped_scope.append((cand.title, "(no asset)", "No target recorded, cannot check scope"))
            continue
        for asset, why in blocked:
            res.skipped_scope.append((cand.title, asset, why))
        assets = list(dict.fromkeys(a for a, _ in allowed))
        note = ""
        if len(assets) > MAX_ASSETS_PER_FINDING:
            note = f"\n\n(+{len(assets) - MAX_ASSETS_PER_FINDING} more affected URLs omitted; see evidence.)"
            shown = assets[:MAX_ASSETS_PER_FINDING]
        else:
            shown = assets

        existing = next((f for f in eng.findings if f"import-key:{cand.key}" in f.tags), None)
        if existing:
            new = [a for a in shown if a not in existing.affected_assets]
            if new:
                eng.update_finding(existing.id, affected_assets=existing.affected_assets + new)
                res.merged.append((existing.id, new))
            continue

        refs = list(cand.references)
        refs += [u for u in lookups.reference_urls(cand.cwe) if u not in refs]
        try:
            f = eng.add_finding(
                cand.title[:200], cvss_vector=cand.cvss_vector,
                manual_severity="" if cand.cvss_vector else cand.severity,
                cwe=cand.cwe, affected_assets=shown, description=(cand.description + note).strip(),
                remediation=cand.remediation, references=refs[:12],
                tags=[f"imported:{cand.tool or tool}", f"import-key:{cand.key}"])
        except ValueError as exc:
            res.skipped_invalid.append((cand.title, str(exc)))
            continue
        res.created.append(f.id)
        if cand.raw:
            evidence.add_text(eng, eng_dir, f"{cand.tool or tool}_{f.id}.txt", cand.raw,
                              f"Raw {cand.tool or tool} output for {f.id}", [f.id])
    return res


def run_import(eng: Engagement, eng_dir, tool: str, content, default_asset: str = "") -> ImportResult:
    if tool in ("", "auto"):
        tool = detect_tool(content)
        if not tool:
            raise ImportError_("Could not detect the tool. Choose it explicitly (nuclei, zap, burp, nmap, nessus, sarif).")
    if tool not in PARSERS:
        raise ImportError_(f"Unknown tool {tool!r}. Supported: {', '.join(TOOLS)}")
    candidates = PARSERS[tool](content, default_asset=default_asset) if tool == "sarif" else PARSERS[tool](content)
    return import_candidates(eng, eng_dir, candidates, tool)
