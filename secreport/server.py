"""Local web interface (standard library only).

Security model (this is a tool that handles client data, so it is strict):
  * Binds to loopback only (127.0.0.1 / localhost / ::1). Anything else is refused.
  * A random token is created on every start. The first visit uses the
    ?token=... link printed in the terminal, which sets an HttpOnly
    SameSite=Strict cookie. Without that cookie nothing is served.
  * Host header must match the bound address (blocks DNS-rebinding).
  * Writes need Content-Type: application/json, the X-Requested-With header and,
    when present, a same-origin Origin header (blocks cross-site requests).
  * App pages use a strict Content-Security-Policy (no inline scripts).
    Report previews are shown in a sandboxed iframe with their own CSP.
  * Engagement ids and evidence file names are validated, so paths cannot
    escape the workspace.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hmac
import json
import re
import secrets
import shutil
import threading
import webbrowser
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import ai, blocks, branding, cvss, cvss40, diff, evidence, importers, library, lookups, report
from .models import (REPORT_LABELS, REPORT_TYPES, RELIABILITY, CREDIBILITY, SEVERITIES, STATUSES,
                     Engagement, now_iso)
from .render import pdf as pdf_r
from .scope import Scope

WEB_DIR = Path(__file__).parent / "web"
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}
MAX_BODY = 80 * 1024 * 1024
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
LOOPBACK = {"127.0.0.1", "localhost", "::1"}

APP_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
           "connect-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'; "
           "frame-ancestors 'none'")
PREVIEW_CSP = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:"

FINDING_TEXT = ("title", "cvss_vector", "manual_severity", "cwe", "owasp", "description", "impact",
                "steps_to_reproduce", "remediation", "status", "source_reliability",
                "info_credibility", "retest_notes")
FINDING_LISTS = ("mitre", "affected_assets", "references", "sources")
ENGAGEMENT_TEXT = ("name", "client", "report_type", "tester", "classification", "summary", "methodology",
                   "attack_narrative", "recommendations", "program", "brand_name", "brand_color")
ENGAGEMENT_LISTS = ("objectives", "detection_gaps")
TIMELINE_KEYS = ("date", "title", "detail", "source")
ENTITY_KEYS = ("name", "type", "notes", "confidence")


class HttpError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class Response:
    def __init__(self, status=200, body=b"", headers=None):
        self.status, self.body, self.headers = status, body, headers or {}


def jresp(obj, status=200) -> Response:
    return Response(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                    {"Content-Type": "application/json; charset=utf-8"})


# ---------------------------------------------------------------- validation
def _str(value, field, limit=20000) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise HttpError(400, f"{field} must be text")
    if len(value) > limit:
        raise HttpError(400, f"{field} is too long (max {limit} characters)")
    return value


def _list(value, field, limit=2000, max_items=500) -> list:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > max_items:
        raise HttpError(400, f"{field} must be a list (max {max_items} items)")
    return [_str(v, field, limit).strip() for v in value if isinstance(v, str) and v.strip()]


def _dict_list(value, field, keys) -> list:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 500:
        raise HttpError(400, f"{field} must be a list (max 500 items)")
    out = []
    for item in value:
        if not isinstance(item, dict):
            raise HttpError(400, f"{field} entries must be objects")
        row = {k: _str(item.get(k, ""), f"{field}.{k}", 4000) for k in keys}
        if any(v.strip() for v in row.values()):
            out.append(row)
    return out


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")[:48]
    return s or "engagement"


class App:
    def __init__(self, workspace, token: str, allowed_hosts):
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.token = token
        self.allowed_hosts = set(allowed_hosts)
        self.lock = threading.RLock()
        self.user_library = self.workspace / "library.json"

    # ------------------------------------------------------------ storage
    def eng_dir(self, eid: str) -> Path:
        if not ID_RE.match(eid or ""):
            raise HttpError(404, "Unknown engagement")
        path = (self.workspace / eid).resolve()
        if path.parent != self.workspace or not (path / "engagement.json").is_file():
            raise HttpError(404, "Unknown engagement")
        return path

    def load(self, eid: str):
        path = self.eng_dir(eid)
        try:
            return Engagement.load(path), path
        except (ValueError, KeyError, TypeError) as exc:
            raise HttpError(500, f"Engagement file is damaged: {exc}") from exc

    def unique_id(self, base: str) -> str:
        base = _slug(base)
        cand, n = base, 2
        while (self.workspace / cand).exists():
            cand = f"{base}-{n}"
            n += 1
        return cand

    # ------------------------------------------------------------ serialisers
    @staticmethod
    def finding_json(f) -> dict:
        d = asdict(f)
        d["severity"], d["score"] = f.severity, f.score
        d["warnings"] = lookups.check_finding(f)
        d["placeholders"] = library.has_placeholders(f)
        return d

    def engagement_json(self, eid, eng) -> dict:
        d = eng.to_dict()
        d["id"] = eid
        d["findings"] = [self.finding_json(f) for f in eng.findings]
        d["counts_all"] = eng.severity_counts(False)
        d["counts_approved"] = eng.severity_counts(True)
        d["readiness"] = [{"ok": ok, "message": m} for ok, m in eng.readiness()]
        d["label"] = REPORT_LABELS[eng.report_type]
        return d

    def summary_json(self, eid, eng) -> dict:
        return {"id": eid, "name": eng.name, "client": eng.client, "report_type": eng.report_type,
                "label": REPORT_LABELS[eng.report_type], "updated_at": eng.updated_at or eng.created_at,
                "counts_all": eng.severity_counts(False), "counts_approved": eng.severity_counts(True),
                "drafts": sum(1 for f in eng.findings if not f.approved),
                "findings": len(eng.findings), "program": eng.program}

    # ------------------------------------------------------------ routes
    def meta(self):
        lib = []
        for e in library.load(self.user_library):
            sev = e.get("manual_severity") or cvss.severity(cvss.base_score(e["cvss_vector"]))
            lib.append({"id": e["id"], "kind": e["kind"], "title": e["title"],
                        "cwe": e.get("cwe", ""), "owasp": e.get("owasp", ""), "severity": sev,
                        "cvss_vector": e.get("cvss_vector", "")})
        return jresp({
            "library": lib, "cwe": lookups.CWE, "owasp": lookups.OWASP_2021, "mitre": lookups.MITRE,
            "report_types": [{"id": t, "label": REPORT_LABELS[t]} for t in REPORT_TYPES],
            "severities": SEVERITIES, "statuses": list(STATUSES),
            "reliability": blocks.OSINT_RELIABILITY, "credibility": blocks.OSINT_CREDIBILITY,
            "pdf_engine": pdf_r.available(), "formats": list(report.FORMATS),
            "importers": list(importers.TOOLS),
        })

    def score_cvss(self, query):
        vector = (query.get("vector") or [""])[0]
        try:
            details = cvss.describe(vector)
        except cvss.CvssError as exc:
            raise HttpError(400, f"invalid vector: {exc}") from exc
        details["label"] = cvss40.nomenclature(vector) if vector.startswith("CVSS:4.0/") else "CVSS 3.1"
        return jresp(details)

    def list_engagements(self):
        out = []
        for child in sorted(self.workspace.iterdir()):
            if child.is_dir() and (child / "engagement.json").is_file() and ID_RE.match(child.name):
                try:
                    out.append(self.summary_json(child.name, Engagement.load(child)))
                except (ValueError, KeyError, TypeError):
                    out.append({"id": child.name, "name": child.name, "client": "(damaged file)",
                                "report_type": "webpentest", "label": "", "updated_at": "",
                                "counts_all": {}, "counts_approved": {}, "drafts": 0,
                                "findings": 0, "program": "", "damaged": True})
        out.sort(key=lambda e: e.get("updated_at", ""), reverse=True)
        return jresp(out)

    def create_engagement(self, body):
        scope = self._scope_from(body.get("scope") or {})
        try:
            eng = Engagement(name=_str(body.get("name"), "name", 200).strip(),
                             client=_str(body.get("client"), "client", 200).strip(),
                             report_type=body.get("report_type") or "webpentest",
                             tester=_str(body.get("tester"), "tester", 200),
                             program=_str(body.get("program"), "program", 200), scope=scope)
        except ValueError as exc:
            raise HttpError(400, str(exc)) from exc
        with self.lock:
            eid = self.unique_id(eng.name)
            eng.save(self.workspace / eid)
        return jresp(self.engagement_json(eid, eng), 201)

    def _scope_from(self, data) -> Scope:
        if not isinstance(data, dict):
            raise HttpError(400, "scope must be an object")
        scope = Scope(in_scope=_list(data.get("in_scope"), "in_scope", 300),
                      out_of_scope=_list(data.get("out_of_scope"), "out_of_scope", 300),
                      start_date=_str(data.get("start_date"), "start_date", 10).strip(),
                      end_date=_str(data.get("end_date"), "end_date", 10).strip(),
                      authorization_ref=_str(data.get("authorization_ref"), "authorization_ref", 500),
                      rules_of_engagement=_str(data.get("rules_of_engagement"), "rules_of_engagement", 4000))
        problems = scope.validate()
        if problems:
            raise HttpError(400, "; ".join(problems))
        return scope

    def get_engagement(self, eid):
        eng, _ = self.load(eid)
        return jresp(self.engagement_json(eid, eng))

    def update_engagement(self, eid, body):
        with self.lock:
            eng, path = self.load(eid)
            for key in ENGAGEMENT_TEXT:
                if key in body:
                    val = _str(body[key], key, 50000)
                    if key == "report_type" and val not in REPORT_TYPES:
                        raise HttpError(400, f"report_type must be one of {list(REPORT_TYPES)}")
                    if key == "brand_color":
                        try:
                            val = branding.validate_color(val)
                        except branding.BrandingError as exc:
                            raise HttpError(400, str(exc)) from exc
                    if key in ("name", "client") and not val.strip():
                        raise HttpError(400, f"{key} cannot be empty")
                    setattr(eng, key, val)
            for key in ENGAGEMENT_LISTS:
                if key in body:
                    setattr(eng, key, _list(body[key], key))
            if "timeline" in body:
                eng.timeline = _dict_list(body["timeline"], "timeline", TIMELINE_KEYS)
            if "entities" in body:
                eng.entities = _dict_list(body["entities"], "entities", ENTITY_KEYS)
            if "scope" in body:
                eng.scope = self._scope_from(body["scope"])
            eng.save(path)
            return jresp(self.engagement_json(eid, eng))

    def set_brand_logo(self, eid, body):
        encoded = body.get("data_b64")
        if not isinstance(encoded, str):
            raise HttpError(400, "data_b64 must be text")
        if len(encoded) > (branding.MAX_LOGO_BYTES + 2) // 3 * 4:
            raise HttpError(413, "Logo file is larger than 2 MB")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HttpError(400, "Logo data is not valid base64") from exc
        with self.lock:
            eng, path = self.load(eid)
            try:
                eng.brand_logo_path = branding.save_logo(path, data)
            except branding.BrandingError as exc:
                raise HttpError(400, str(exc)) from exc
            eng.save(path)
        return jresp({"brand_logo_path": eng.brand_logo_path})

    def delete_brand_logo(self, eid):
        with self.lock:
            eng, path = self.load(eid)
            try:
                if eng.brand_logo_path:
                    branding.remove_logo(path, eng.brand_logo_path)
            except branding.BrandingError as exc:
                raise HttpError(400, str(exc)) from exc
            eng.brand_logo_path = ""
            eng.save(path)
        return jresp({"brand_logo_path": ""})

    def delete_engagement(self, eid, body):
        if body.get("confirm") != eid:
            raise HttpError(400, "Send {\"confirm\": \"<engagement id>\"} to delete")
        with self.lock:
            path = self.eng_dir(eid)
            shutil.rmtree(path)
        return jresp({"deleted": eid})

    def clone_retest(self, eid):
        with self.lock:
            eng, _ = self.load(eid)
            data = copy.deepcopy(eng.to_dict())
            new = Engagement.from_dict(data)
            new.name = f"{eng.name} (Retest)"
            new.evidence = []
            new.created_at = now_iso()
            for f in new.findings:
                f.evidence_ids = []
                f.approved, f.approved_by, f.approved_at = False, "", ""
                f.status = "open"
            nid = self.unique_id(new.name)
            new.save(self.workspace / nid)
        return jresp(self.engagement_json(nid, new), 201)

    # ---- findings
    def _finding_fields(self, body) -> dict:
        out = {}
        for k in FINDING_TEXT:
            if k in body:
                out[k] = _str(body[k], k, 20000).strip() if k not in ("description", "impact",
                                                                      "steps_to_reproduce", "remediation",
                                                                      "retest_notes") else _str(body[k], k, 20000)
        for k in FINDING_LISTS:
            if k in body:
                out[k] = _list(body[k], k)
        return out

    def _scope_gate(self, eng, assets):
        for asset in assets:
            ok, why = eng.scope.check(asset)
            if not ok:
                raise HttpError(403, f"Asset {asset!r} is not allowed: {why}")

    def create_finding(self, eid, body):
        with self.lock:
            eng, path = self.load(eid)
            if body.get("library_id"):
                try:
                    f = library.instantiate(eng, str(body["library_id"]),
                                            _list(body.get("affected_assets"), "affected_assets"),
                                            self.user_library)
                except KeyError as exc:
                    raise HttpError(404, exc.args[0]) from exc
                except PermissionError as exc:
                    raise HttpError(403, str(exc)) from exc
                except ValueError as exc:
                    raise HttpError(400, str(exc)) from exc
            else:
                fields = self._finding_fields(body)
                title = fields.pop("title", "")
                self._scope_gate(eng, fields.get("affected_assets", []))
                try:
                    f = eng.add_finding(title, **fields)
                except (ValueError, TypeError) as exc:
                    raise HttpError(400, str(exc)) from exc
            if "evidence_ids" in body:
                self._link_evidence(eng, f.id, body["evidence_ids"])
            eng.save(path)
            return jresp(self.finding_json(f), 201)

    def _link_evidence(self, eng, fid, ids):
        ids = _list(ids, "evidence_ids")
        known = {e.id for e in eng.evidence}
        ids = [i for i in ids if i in known]
        eng.update_finding(fid, evidence_ids=ids)
        for e in eng.evidence:
            if e.id in ids and fid not in e.finding_ids:
                e.finding_ids.append(fid)
            elif e.id not in ids and fid in e.finding_ids:
                e.finding_ids.remove(fid)

    def update_finding(self, eid, fid, body):
        with self.lock:
            eng, path = self.load(eid)
            try:
                current = eng.get_finding(fid)
            except KeyError as exc:
                raise HttpError(404, exc.args[0]) from exc
            fields = self._finding_fields(body)
            if "affected_assets" in fields:
                self._scope_gate(eng, [a for a in fields["affected_assets"] if a not in current.affected_assets])
            try:
                if fields:
                    eng.update_finding(fid, **fields)
                if "evidence_ids" in body:
                    self._link_evidence(eng, fid, body["evidence_ids"])
            except (ValueError, TypeError) as exc:
                raise HttpError(400, str(exc)) from exc
            eng.save(path)
            return jresp(self.finding_json(eng.get_finding(fid)))

    def delete_finding(self, eid, fid):
        with self.lock:
            eng, path = self.load(eid)
            try:
                eng.delete_finding(fid)
            except KeyError as exc:
                raise HttpError(404, exc.args[0]) from exc
            eng.save(path)
        return jresp({"deleted": fid})

    def approve(self, eid, fid, body, approve=True):
        with self.lock:
            eng, path = self.load(eid)
            try:
                f = eng.get_finding(fid)
                if approve:
                    if library.has_placeholders(f) and not body.get("force"):
                        raise HttpError(409, "This finding still has TODO placeholders. Fix them first.")
                    eng.approve_finding(fid, _str(body.get("reviewer"), "reviewer", 200))
                else:
                    eng.unapprove_finding(fid)
            except KeyError as exc:
                raise HttpError(404, exc.args[0]) from exc
            except ValueError as exc:
                raise HttpError(400, str(exc)) from exc
            eng.save(path)
            return jresp(self.finding_json(eng.get_finding(fid)))

    # ---- evidence
    def add_evidence(self, eid, body):
        name = _str(body.get("name"), "name", 200).strip()
        if not name:
            raise HttpError(400, "File name is required")
        try:
            data = base64.b64decode(body.get("data_b64") or "", validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HttpError(400, "File data is not valid base64") from exc
        if not data:
            raise HttpError(400, "File is empty")
        with self.lock:
            eng, path = self.load(eid)
            try:
                item = evidence.add_bytes(eng, path, name, data, _str(body.get("description"), "description", 2000),
                                          _list(body.get("finding_ids"), "finding_ids"))
            except KeyError as exc:
                raise HttpError(404, exc.args[0]) from exc
            except ValueError as exc:
                raise HttpError(413, str(exc)) from exc
            eng.save(path)
            return jresp(asdict(item), 201)

    def verify_evidence(self, eid):
        eng, path = self.load(eid)
        return jresp([{"id": i, "ok": ok, "detail": d} for i, ok, d in evidence.verify(eng, path)])

    def download_evidence(self, eid, evid):
        eng, path = self.load(eid)
        try:
            file = evidence.path_of(eng, path, evid)
        except KeyError as exc:
            raise HttpError(404, exc.args[0]) from exc
        except ValueError as exc:
            raise HttpError(400, str(exc)) from exc
        if not file.is_file():
            raise HttpError(404, "Evidence file is missing on disk")
        item = next(e for e in eng.evidence if e.id == evid)
        return Response(200, file.read_bytes(), {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": f'attachment; filename="{evidence.safe_name(item.filename)}"'})

    # ---- import / ai / report / diff
    def do_import(self, eid, body):
        tool = body.get("tool") or "auto"
        content = body.get("content")
        if not isinstance(content, str) or not content.strip():
            raise HttpError(400, "Paste or choose a results file first")
        with self.lock:
            eng, path = self.load(eid)
            try:
                res = importers.run_import(eng, path, tool, content,
                                           default_asset=_str(body.get("default_asset"), "default_asset", 500))
            except importers.ImportError_ as exc:
                raise HttpError(400, str(exc)) from exc
            eng.save(path)
        return jresp({"summary": res.summary(), "created": res.created,
                      "merged": [{"id": i, "assets": a} for i, a in res.merged],
                      "skipped_scope": [{"title": t, "asset": a, "reason": r} for t, a, r in res.skipped_scope],
                      "skipped_invalid": [{"title": t, "reason": r} for t, r in res.skipped_invalid]})

    def ai_prompt(self, eid, fid, body):
        eng, _ = self.load(eid)
        try:
            f = eng.get_finding(fid)
        except KeyError as exc:
            raise HttpError(404, exc.args[0]) from exc
        terms = _list(body.get("terms"), "terms", 200, 50)
        if body.get("redact", True):
            terms = terms + [eng.client]
        return jresp({"prompt": ai.build_prompt(f, redact=bool(body.get("redact", True)), extra_terms=terms)})

    def ai_apply(self, eid, fid, body):
        with self.lock:
            eng, path = self.load(eid)
            try:
                f, warns = ai.apply_response(eng, fid, _str(body.get("text"), "text", 60000))
            except KeyError as exc:
                raise HttpError(404, exc.args[0]) from exc
            except ValueError as exc:
                raise HttpError(400, str(exc)) from exc
            eng.save(path)
            return jresp({"finding": self.finding_json(f), "warnings": warns})

    def make_report(self, eid, query):
        eng, _ = self.load(eid)
        fmt = (query.get("format") or ["html"])[0]
        if fmt not in report.FORMATS:
            raise HttpError(400, f"format must be one of {list(report.FORMATS)}")
        redact = (query.get("redact") or ["0"])[0] == "1"
        terms = [t.strip() for t in (query.get("terms") or [""])[0].split(",") if t.strip()]
        opts = report.make_options(include_draft=(query.get("draft") or ["0"])[0] == "1",
                                   redact=redact, custom_terms=terms)
        try:
            data = report.render(eng, fmt, opts, eng_dir=self.eng_dir(eid))
        except pdf_r.PdfUnavailable as exc:
            raise HttpError(501, str(exc)) from exc
        headers = {"Content-Type": report.MIME[fmt]}
        if fmt == "html" and (query.get("inline") or ["0"])[0] == "1":
            headers["Content-Security-Policy"] = PREVIEW_CSP
            headers["X-Frame-Options"] = "SAMEORIGIN"
        else:
            headers["Content-Disposition"] = f'attachment; filename="{report.filename(eng, fmt, redact)}"'
        return Response(200, data, headers)

    def scope_check(self, eid, body):
        eng, _ = self.load(eid)
        targets = _list(body.get("targets"), "targets", 500, 100)
        out = []
        for t in targets:
            ok, why = eng.scope.check(t)
            out.append({"target": t, "allowed": ok, "reason": why})
        return jresp(out)

    def do_diff(self, body):
        a, b = str(body.get("a", "")), str(body.get("b", ""))
        old, _ = self.load(a)
        new, _ = self.load(b)
        return jresp(diff.summary_dict(diff.compare(old, new)))

    # ------------------------------------------------------------ dispatch
    def authorised(self, headers) -> bool:
        cookie = headers.get("Cookie", "")
        m = re.search(r"(?:^|;\s*)sr_token=([A-Za-z0-9_\-]+)", cookie)
        return bool(m) and hmac.compare_digest(m.group(1), self.token)

    def handle(self, method, raw_path, headers, body_bytes=b"") -> Response:
        try:
            return self._handle(method, raw_path, headers, body_bytes)
        except HttpError as exc:
            return jresp({"error": exc.message}, exc.status)
        except Exception as exc:  # never leak a traceback to the browser
            print(f"[internal error] {method} {urlparse(raw_path).path}: {exc!r}")
            return jresp({"error": "Internal error. See the terminal for details."}, 500)

    def _handle(self, method, raw_path, headers, body_bytes) -> Response:
        host = headers.get("Host", "")
        if host not in self.allowed_hosts:
            raise HttpError(403, "Bad Host header")
        url = urlparse(raw_path)
        path, query = url.path, parse_qs(url.query)

        # first visit: exchange the one-time link token for a cookie
        if method == "GET" and path == "/" and "token" in query:
            if hmac.compare_digest(query["token"][0], self.token):
                return Response(302, b"", {
                    "Location": "/", "Set-Cookie": f"sr_token={self.token}; HttpOnly; SameSite=Strict; Path=/"})
            raise HttpError(403, "Invalid token")
        if not self.authorised(headers):
            return Response(403, b"Open the full link that was printed in the terminal (it contains ?token=...).",
                            {"Content-Type": "text/plain; charset=utf-8"})

        if method == "GET" and path in STATIC:
            name, ctype = STATIC[path]
            return Response(200, (WEB_DIR / name).read_bytes(), {"Content-Type": ctype, "Content-Security-Policy": APP_CSP})
        if method == "GET" and path == "/favicon.ico":
            return Response(204)
        if not path.startswith("/api/"):
            raise HttpError(404, "Not found")

        body = {}
        if method in ("POST", "PUT", "DELETE"):
            if headers.get("X-Requested-With") != "secreport":
                raise HttpError(403, "Missing X-Requested-With header")
            origin = headers.get("Origin")
            if origin and urlparse(origin).netloc not in self.allowed_hosts:
                raise HttpError(403, "Cross-origin request refused")
            if body_bytes:
                if "application/json" not in headers.get("Content-Type", ""):
                    raise HttpError(415, "Content-Type must be application/json")
                try:
                    body = json.loads(body_bytes.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise HttpError(400, "Body is not valid JSON") from exc
                if not isinstance(body, dict):
                    raise HttpError(400, "Body must be a JSON object")

        seg = [s for s in path.split("/") if s][1:]   # drop "api"
        n = len(seg)
        if method == "GET":
            if seg == ["cvss"]:
                return self.score_cvss(query)
            if seg == ["meta"]:
                return self.meta()
            if seg == ["engagements"]:
                return self.list_engagements()
            if n == 2 and seg[0] == "e":
                return self.get_engagement(seg[1])
            if n == 3 and seg[0] == "e" and seg[2] == "report":
                return self.make_report(seg[1], query)
            if n == 3 and seg[0] == "e" and seg[2] == "verify":
                return self.verify_evidence(seg[1])
            if n == 4 and seg[0] == "e" and seg[2] == "evidence":
                return self.download_evidence(seg[1], seg[3])
        elif method == "POST":
            if seg == ["engagements"]:
                return self.create_engagement(body)
            if seg == ["diff"]:
                return self.do_diff(body)
            if n == 3 and seg[0] == "e":
                eid, action = seg[1], seg[2]
                if action == "findings":
                    return self.create_finding(eid, body)
                if action == "evidence":
                    return self.add_evidence(eid, body)
                if action == "import":
                    return self.do_import(eid, body)
                if action == "retest":
                    return self.clone_retest(eid)
                if action == "scope-check":
                    return self.scope_check(eid, body)
            if n == 4 and seg[0] == "e" and seg[2:] == ["branding", "logo"]:
                return self.set_brand_logo(seg[1], body)
            if n == 5 and seg[0] == "e" and seg[2] == "findings":
                eid, fid, action = seg[1], seg[3], seg[4]
                if action == "approve":
                    return self.approve(eid, fid, body, True)
                if action == "unapprove":
                    return self.approve(eid, fid, body, False)
                if action == "ai-prompt":
                    return self.ai_prompt(eid, fid, body)
                if action == "ai-apply":
                    return self.ai_apply(eid, fid, body)
        elif method == "PUT":
            if n == 2 and seg[0] == "e":
                return self.update_engagement(seg[1], body)
            if n == 4 and seg[0] == "e" and seg[2] == "findings":
                return self.update_finding(seg[1], seg[3], body)
        elif method == "DELETE":
            if n == 4 and seg[0] == "e" and seg[2:] == ["branding", "logo"]:
                return self.delete_brand_logo(seg[1])
            if n == 2 and seg[0] == "e":
                return self.delete_engagement(seg[1], body)
            if n == 4 and seg[0] == "e" and seg[2] == "findings":
                return self.delete_finding(seg[1], seg[3])
        raise HttpError(404, "Unknown API route")


# ---------------------------------------------------------------- HTTP glue
def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SecReport"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def _go(self, method):
            length = self.headers.get("Content-Length")
            body = b""
            if method in ("POST", "PUT", "DELETE"):
                if self.headers.get("Transfer-Encoding"):
                    self.close_connection = True      # body is left unread, so do not reuse the connection
                    return self._send(Response(411, b"Content-Length required"))
                try:
                    n = int(length or 0)
                except ValueError:
                    self.close_connection = True
                    return self._send(jresp({"error": "Bad Content-Length"}, 400))
                if n < 0 or n > MAX_BODY:
                    self.close_connection = True
                    return self._send(jresp({"error": "Request body too large"}, 413))
                body = self.rfile.read(n) if n else b""
            self._send(app.handle(method, self.path, dict(self.headers), body))

        def _send(self, r: Response):
            self.send_response(r.status)
            headers = {"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                       "Cache-Control": "no-store", "Cross-Origin-Resource-Policy": "same-origin"}
            headers.update(r.headers)
            if "Content-Security-Policy" not in headers:
                headers["Content-Security-Policy"] = "default-src 'none'"
            headers.setdefault("X-Frame-Options", "DENY")
            headers["Content-Length"] = str(len(r.body))
            if self.close_connection:
                headers["Connection"] = "close"
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(r.body)

        def do_GET(self): self._go("GET")
        def do_POST(self): self._go("POST")
        def do_PUT(self): self._go("PUT")
        def do_DELETE(self): self._go("DELETE")

        def log_message(self, fmt, *args):  # never log query strings (they hold the token)
            line = self.requestline.split("?")[0]
            print(f"  {self.command} {line.split(' ', 1)[-1]} -> {args[1] if len(args) > 1 else ''}")

    return Handler


def create_server(workspace, host="127.0.0.1", port=8765):
    if host not in LOOPBACK:
        raise ValueError("For safety the web interface only listens on 127.0.0.1 / localhost / ::1.")
    token = secrets.token_urlsafe(32)
    # port 0 means "pick one": the allowed Host values are filled in after binding
    app = App(workspace, token, [])
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    httpd.daemon_threads = True
    real_port = httpd.server_address[1]
    shown = "[::1]" if host == "::1" else host
    app.allowed_hosts = {f"{shown}:{real_port}", f"localhost:{real_port}", f"127.0.0.1:{real_port}"}
    return httpd, app, f"http://{shown}:{real_port}/?token={token}"


def serve(workspace, host="127.0.0.1", port=8765, open_browser=True):
    try:
        httpd, app, url = create_server(workspace, host, port)
    except (ValueError, OSError) as exc:
        raise SystemExit(f"Could not start the server: {exc}")
    print("SecReport web interface")
    print(f"  Workspace : {app.workspace}")
    print(f"  Open this : {url}")
    print("  (the link works for this session only; press Ctrl+C to stop)")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
