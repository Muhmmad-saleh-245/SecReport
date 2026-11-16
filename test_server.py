"""Web API: security checks, full workflow, and a real-socket smoke test."""

import base64
import contextlib
import http.client
import io
import json
import struct
import tempfile
import threading
import unittest
import zlib
from pathlib import Path

from secreport import report, server
from secreport.render import pdf as pdf_r

HOST = "127.0.0.1:8765"
TOKEN = "t" * 43


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def png_logo() -> bytes:
    def chunk(kind, body):
        return (len(body).to_bytes(4, "big") + kind + body
                + (zlib.crc32(kind + body) & 0xFFFFFFFF).to_bytes(4, "big"))

    header = struct.pack(">IIBBBBB", 2, 1, 8, 6, 0, 0, 0)
    image = zlib.compress(b"\x00" + b"\x00" * 8)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", image) + chunk(b"IEND", b""))


class ApiCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name) / "ws"
        self.app = server.App(self.ws, TOKEN, [HOST])

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, method, path, body=None, cookie=True, headers=None, raw=None):
        h = {"Host": HOST}
        if cookie:
            h["Cookie"] = f"sr_token={TOKEN}"
        if method in ("POST", "PUT", "DELETE"):
            h["X-Requested-With"] = "secreport"
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        payload = raw if raw is not None else (b"" if body is None else json.dumps(body).encode())
        return self.app.handle(method, path, h, payload)

    def ok(self, method, path, body=None, status=None, **kw):
        r = self.call(method, path, body, **kw)
        self.assertEqual(r.status, status or (201 if method == "POST" and path in ("/api/engagements",) else 200),
                         f"{method} {path}: {r.body[:300]!r}")
        return json.loads(r.body) if r.headers.get("Content-Type", "").startswith("application/json") else r

    def err(self, method, path, status, body=None, **kw):
        r = self.call(method, path, body, **kw)
        self.assertEqual(r.status, status, f"{method} {path}: {r.body[:300]!r}")
        return json.loads(r.body).get("error", "") if r.body.startswith(b"{") else r.body.decode()

    def make_engagement(self, **over):
        body = {"name": "Acme Q4", "client": "Acme Ltd", "report_type": "webpentest", "tester": "T",
                "scope": {"authorization_ref": "SOW-1", "in_scope": ["*.acme.test"], "out_of_scope": ["payments.acme.test"],
                          "start_date": "2026-01-01", "end_date": "2099-12-31"}}
        body.update(over)
        return self.ok("POST", "/api/engagements", body)["id"]


class SecurityTests(ApiCase):
    def test_authentication_and_headers(self):
        self.err("GET", "/api/meta", 403, cookie=False)
        self.err("GET", "/", 403, cookie=False)
        self.err("GET", "/api/meta", 403, headers={"Cookie": "sr_token=wrong"})
        self.err("GET", "/api/meta", 403, headers={"Host": "evil.com"})                 # DNS rebinding
        self.err("GET", "/api/meta", 403, headers={"Host": "127.0.0.1:9999"})

    def test_token_exchange(self):
        r = self.call("GET", f"/?token={TOKEN}", cookie=False)
        self.assertEqual(r.status, 302)
        cookie = r.headers["Set-Cookie"]
        for flag in ("HttpOnly", "SameSite=Strict", f"sr_token={TOKEN}"):
            self.assertIn(flag, cookie)
        self.err("GET", "/?token=nope", 403, cookie=False)

    def test_state_changing_requests_are_protected(self):
        body = {"name": "x", "client": "y"}
        self.err("POST", "/api/engagements", 403, body, headers={"X-Requested-With": ""})
        self.err("POST", "/api/engagements", 403, body, headers={"Origin": "http://evil.com"})
        self.err("POST", "/api/engagements", 415, body, headers={"Content-Type": "text/plain"})
        self.err("POST", "/api/engagements", 400, raw=b"{not json")
        self.err("POST", "/api/engagements", 400, raw=b"[1,2]")
        self.assertEqual(self.ok("POST", "/api/engagements", body, headers={"Origin": f"http://{HOST}"}, status=201)["name"], "x")

    def test_ids_cannot_traverse_paths(self):
        for bad in ("..", "%2e%2e", "a%2Fb", "UPPER", "x" * 80, ".hidden", "-x"):
            self.err("GET", f"/api/e/{bad}", 404)
        (self.ws.parent / "outside").mkdir()
        (self.ws.parent / "outside" / "engagement.json").write_text("{}")
        self.err("GET", "/api/e/..%2Foutside", 404)

    def test_static_files_are_whitelisted_and_have_csp(self):
        for path, ctype in (("/", "text/html"), ("/app.js", "javascript"), ("/style.css", "css")):
            r = self.call("GET", path)
            self.assertEqual(r.status, 200)
            self.assertIn(ctype, r.headers["Content-Type"])
            self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])
        self.err("GET", "/secreport/server.py", 404)
        self.err("GET", "/../server.py", 404)
        self.err("GET", "/web/app.js", 404)

    def test_internal_errors_do_not_leak_details(self):
        eid = self.make_engagement()
        (self.ws / eid / "engagement.json").write_text("{broken")
        with contextlib.redirect_stdout(io.StringIO()):
            msg = self.err("GET", f"/api/e/{eid}", 500)
        self.assertNotIn("Traceback", msg)
        listing = self.ok("GET", "/api/engagements")           # a damaged file must not break the list
        self.assertTrue(listing[0].get("damaged"))


class WorkflowTests(ApiCase):
    def test_sarif_api_uses_only_explicit_scoped_default_asset_for_local_paths(self):
        eid = self.make_engagement()
        sarif = json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fixture"}},
            "results": [{"ruleId": "local-rule", "level": "warning", "message": {"text": "Finding"},
                         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/main.py"}}}]}]}]})
        result = self.ok("POST", f"/api/e/{eid}/import", {"tool": "sarif", "content": sarif})
        self.assertEqual((result["created"], len(result["skipped_scope"])), ([], 1))
        result = self.ok("POST", f"/api/e/{eid}/import", {"tool": "sarif", "content": sarif,
                                                               "default_asset": "app.acme.test"})
        self.assertEqual(len(result["created"]), 1)
        finding = self.ok("GET", f"/api/e/{eid}")["findings"][0]
        self.assertEqual(finding["affected_assets"], ["app.acme.test"])
        self.assertFalse(finding["approved"])

    def test_cvss_v4_score_api_finding_and_report_label(self):
        eid = self.make_engagement()
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"
        result = self.ok("GET", f"/api/cvss?vector={vector}")
        self.assertEqual((result["score"], result["label"]), (9.3, "CVSS 4.0-BT"))
        self.err("GET", f"/api/cvss?vector={vector.replace('/AV:N/AC:L', '/AC:L/AV:N')}", 400)

        finding = self.ok("POST", f"/api/e/{eid}/findings",
                          {"title": "V4 scoring", "cvss_vector": vector}, status=201)
        self.assertEqual((finding["score"], finding["severity"]), (9.3, "Critical"))
        body = self.call("GET", f"/api/e/{eid}/report?format=html&draft=1").body
        self.assertIn(b"CVSS 4.0-BT", body)

    def test_client_branding_fields_and_logo_routes(self):
        eid = self.make_engagement()
        eng = self.ok("PUT", f"/api/e/{eid}", {"brand_name": "A & B", "brand_color": "#12ab34"})
        self.assertEqual((eng["brand_name"], eng["brand_color"]), ("A & B", "#12ab34"))
        self.err("PUT", f"/api/e/{eid}", 400, {"brand_color": "#fff; background:url(x)"})

        logo = png_logo()
        result = self.ok("POST", f"/api/e/{eid}/branding/logo", {"data_b64": b64(logo)})
        self.assertEqual(result["brand_logo_path"], "branding/logo.png")
        self.assertEqual((self.ws / eid / result["brand_logo_path"]).read_bytes(), logo)
        report_html = self.call("GET", f"/api/e/{eid}/report?format=html")
        self.assertEqual(report_html.status, 200)
        self.assertIn(b"data:image/png;base64,", report_html.body)
        self.assertIn(b"A &amp; B", report_html.body)

        svg = b64(b'<svg onload="alert(1)"></svg>')
        self.err("POST", f"/api/e/{eid}/branding/logo", 400, {"data_b64": svg})
        self.ok("DELETE", f"/api/e/{eid}/branding/logo")
        self.assertFalse((self.ws / eid / "branding" / "logo.png").exists())
        eng = self.ok("GET", f"/api/e/{eid}")
        self.assertEqual(eng["brand_logo_path"], "")

    def test_engagement_validation_and_update(self):
        self.err("POST", "/api/engagements", 400, {"name": "", "client": "c"})
        self.err("POST", "/api/engagements", 400, {"name": "n", "client": "c", "report_type": "nope"})
        self.err("POST", "/api/engagements", 400, {"name": "n", "client": "c", "scope": {"start_date": "yesterday"}})
        self.err("POST", "/api/engagements", 400, {"name": "n" * 300, "client": "c"})
        self.err("POST", "/api/engagements", 400, {"name": "n", "client": "c", "scope": {"in_scope": "not a list"}})
        eid = self.make_engagement()
        self.assertEqual(eid, "acme-q4")
        self.assertEqual(self.make_engagement(), "acme-q4-2")                       # unique ids
        d = self.ok("PUT", f"/api/e/{eid}", {"summary": "S", "report_type": "osint", "objectives": ["a", " ", "b"],
                                             "timeline": [{"date": "d", "title": "t", "detail": "", "source": ""}, {}],
                                             "entities": [{"name": "acme.test", "type": "Domain"}]})
        self.assertEqual((d["summary"], d["report_type"], d["objectives"]), ("S", "osint", ["a", "b"]))
        self.assertEqual(len(d["timeline"]), 1)
        self.err("PUT", f"/api/e/{eid}", 400, {"report_type": "bad"})
        self.err("PUT", f"/api/e/{eid}", 400, {"name": " "})
        self.err("PUT", f"/api/e/{eid}", 400, {"scope": {"start_date": "2026-12-01", "end_date": "2026-01-01"}})
        self.assertEqual(len(self.ok("GET", "/api/engagements")), 2)

    def test_findings_scope_approval_and_edit_flow(self):
        eid = self.make_engagement()
        base = f"/api/e/{eid}/findings"
        self.assertIn("not allowed", self.err("POST", base, 403, {"title": "x", "manual_severity": "Low", "affected_assets": ["evil.com"]}))
        self.err("POST", base, 403, {"title": "x", "manual_severity": "Low", "affected_assets": ["payments.acme.test"]})
        self.err("POST", base, 400, {"title": "", "manual_severity": "Low"})
        self.err("POST", base, 400, {"title": "x", "cvss_vector": "bad"})
        self.err("POST", base, 400, {"title": ["not text"]})
        f = self.ok("POST", base, {"title": "XSS", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                   "affected_assets": ["app.acme.test"], "cwe": "cwe 79", "mitre": ["T1189"],
                                   "approved": True, "id": "F-999"}, status=201)
        self.assertEqual((f["id"], f["score"], f["severity"], f["cwe"]), ("F-001", 6.1, "Medium", "CWE-79"))
        self.assertFalse(f["approved"], "approved must not be settable through create")
        self.err("POST", f"{base}/F-001/approve", 400, {"reviewer": " "})
        self.err("POST", f"{base}/F-404/approve", 404, {"reviewer": "R"})
        self.assertTrue(self.ok("POST", f"{base}/F-001/approve", {"reviewer": "Sam"})["approved"])
        r = self.ok("PUT", f"{base}/F-001", {"status": "fixed"})
        self.assertTrue(r["approved"])                                              # status change keeps approval
        r = self.ok("PUT", f"{base}/F-001", {"description": "new text"})
        self.assertFalse(r["approved"])                                             # content change revokes it
        self.err("PUT", f"{base}/F-001", 403, {"affected_assets": ["app.acme.test", "evil.com"]})
        self.err("PUT", f"{base}/F-001", 400, {"status": "weird"})
        self.err("PUT", f"{base}/F-001", 400, {"cvss_vector": "garbage"})
        self.ok("PUT", f"{base}/F-001", {"affected_assets": ["app.acme.test", "b.acme.test"]})
        self.err("PUT", f"{base}/F-404", 404, {"title": "x"})
        self.ok("DELETE", f"{base}/F-001")
        self.err("DELETE", f"{base}/F-001", 404)

    def test_library_and_placeholder_gate(self):
        eid = self.make_engagement()
        base = f"/api/e/{eid}/findings"
        self.err("POST", base, 403, {"library_id": "web-sqli", "affected_assets": ["evil.com"]})
        self.err("POST", base, 404, {"library_id": "nope", "affected_assets": ["a.acme.test"]})
        f = self.ok("POST", base, {"library_id": "web-sqli", "affected_assets": ["app.acme.test"]}, status=201)
        self.assertTrue(f["placeholders"])
        self.assertIn("TODO", self.err("POST", f"{base}/{f['id']}/approve", 409, {"reviewer": "R"}))
        self.ok("PUT", f"{base}/{f['id']}", {"steps_to_reproduce": "1. Open the page.\n\n2. Submit a quote."})
        self.assertTrue(self.ok("POST", f"{base}/{f['id']}/approve", {"reviewer": "R"})["approved"])
        self.assertFalse(self.ok("POST", f"{base}/{f['id']}/unapprove")["approved"])

    def test_evidence_upload_download_verify_and_links(self):
        eid = self.make_engagement()
        fid = self.ok("POST", f"/api/e/{eid}/findings", {"title": "T", "manual_severity": "Low"}, status=201)["id"]
        base = f"/api/e/{eid}/evidence"
        self.err("POST", base, 400, {"name": "a.txt", "data_b64": "!!!not base64!!!"})
        self.err("POST", base, 400, {"name": "a.txt", "data_b64": ""})
        self.err("POST", base, 400, {"name": "", "data_b64": b64(b"x")})
        self.err("POST", base, 404, {"name": "a.txt", "data_b64": b64(b"x"), "finding_ids": ["F-404"]})
        ev = self.ok("POST", base, {"name": "../../evil.txt", "data_b64": b64(b"proof"), "finding_ids": [fid],
                                    "description": "d"}, status=201)
        self.assertNotIn("..", ev["stored_as"])
        self.assertEqual(len(ev["sha256"]), 64)
        dl = self.call("GET", f"{base}/{ev['id']}")
        self.assertEqual(dl.body, b"proof")
        self.assertIn("attachment", dl.headers["Content-Disposition"])
        self.assertEqual(dl.headers["Content-Type"], "application/octet-stream")
        self.err("GET", f"{base}/E-404", 404)
        self.assertEqual(self.ok("GET", f"/api/e/{eid}/verify")[0]["ok"], True)
        (self.ws / eid / ev["stored_as"]).write_bytes(b"tampered")
        self.assertEqual(self.ok("GET", f"/api/e/{eid}/verify")[0]["ok"], False)
        # linking from the finding side keeps both directions in sync
        f = self.ok("PUT", f"/api/e/{eid}/findings/{fid}", {"evidence_ids": []})
        self.assertEqual(f["evidence_ids"], [])
        eng = self.ok("GET", f"/api/e/{eid}")
        self.assertEqual(eng["evidence"][0]["finding_ids"], [])
        f = self.ok("PUT", f"/api/e/{eid}/findings/{fid}", {"evidence_ids": [ev["id"], "E-404"]})
        self.assertEqual(f["evidence_ids"], [ev["id"]])

    def test_import_scope_check_ai_and_retest(self):
        eid = self.make_engagement()
        nuclei = "\n".join(json.dumps(x) for x in [
            {"template-id": "a", "info": {"name": "Exposed git", "severity": "medium"}, "matched-at": "https://app.acme.test/.git/config"},
            {"template-id": "b", "info": {"name": "Other", "severity": "high"}, "matched-at": "https://payments.acme.test/x"}])
        r = self.ok("POST", f"/api/e/{eid}/import", {"tool": "nuclei", "content": nuclei})
        self.assertEqual((len(r["created"]), len(r["skipped_scope"])), (1, 1))
        self.err("POST", f"/api/e/{eid}/import", 400, {"tool": "nuclei", "content": "   "})
        self.err("POST", f"/api/e/{eid}/import", 400, {"tool": "auto", "content": "hello"})
        checks = self.ok("POST", f"/api/e/{eid}/scope-check", {"targets": ["app.acme.test", "evil.com", "https://payments.acme.test"]}, status=200)
        self.assertEqual([c["allowed"] for c in checks], [True, False, False])
        prompt = self.ok("POST", f"/api/e/{eid}/findings/F-001/ai-prompt", {"redact": True})["prompt"]
        self.assertNotIn("Acme Ltd", prompt)
        self.assertIn("Do not invent", prompt)
        out = self.ok("POST", f"/api/e/{eid}/findings/F-001/ai-apply", {"text": '{"description": "Better text"}'})
        self.assertTrue(out["finding"]["ai_assisted"])
        self.err("POST", f"/api/e/{eid}/findings/F-001/ai-apply", 400, {"text": "no json"})
        self.ok("POST", f"/api/e/{eid}/findings/F-001/approve", {"reviewer": "R"})
        rt = self.ok("POST", f"/api/e/{eid}/retest", {}, status=201)
        self.assertEqual(rt["id"], "acme-q4-retest")
        self.assertFalse(rt["findings"][0]["approved"])
        self.assertEqual(rt["evidence"], [])
        d = self.ok("POST", "/api/diff", {"a": eid, "b": rt["id"]})
        self.assertEqual((len(d["new"]), len(d["resolved"]), len(d["persisting"])), (0, 0, 1))
        self.err("POST", "/api/diff", 404, {"a": eid, "b": "nope"})

    def test_reports_in_every_format(self):
        eid = self.make_engagement(report_type="osint")
        f = self.ok("POST", f"/api/e/{eid}/findings", {"title": "Exposed <b>thing</b>", "manual_severity": "Medium",
                                                       "affected_assets": ["app.acme.test"], "source_reliability": "B",
                                                       "info_credibility": "2", "sources": ["https://x.test"]}, status=201)
        self.ok("POST", f"/api/e/{eid}/findings/{f['id']}/approve", {"reviewer": "Rev"})
        self.ok("PUT", f"/api/e/{eid}", {"summary": "Contact bob@acme.test about 10.1.2.3"})
        html = self.call("GET", f"/api/e/{eid}/report?format=html&inline=1")
        self.assertEqual(html.status, 200)
        self.assertIn("sandbox", html.headers["Content-Security-Policy"])
        self.assertEqual(html.headers["X-Frame-Options"], "SAMEORIGIN")
        self.assertNotIn("Content-Disposition", html.headers)
        self.assertIn(b"&lt;b&gt;thing&lt;/b&gt;", html.body)
        for fmt, magic in (("html", b"<!doctype"), ("md", b"# "), ("docx", b"PK"), ("json", b"[")):
            r = self.call("GET", f"/api/e/{eid}/report?format={fmt}")
            self.assertEqual(r.status, 200, fmt)
            self.assertTrue(r.body.startswith(magic), fmt)
            self.assertIn("attachment", r.headers["Content-Disposition"])
        red = self.call("GET", f"/api/e/{eid}/report?format=md&redact=1&terms=Acme").body.decode()
        self.assertNotIn("10.1.2.3", red)
        self.assertNotIn("bob@", red)
        r = self.call("GET", f"/api/e/{eid}/report?format=pdf")
        if pdf_r.available():
            self.assertTrue(r.body.startswith(b"%PDF"))
        else:
            self.assertEqual(r.status, 501)
        self.err("GET", f"/api/e/{eid}/report?format=exe", 400)
        draft = self.ok("POST", f"/api/e/{eid}/findings", {"title": "Hidden draft", "manual_severity": "Low"}, status=201)
        self.assertNotIn(b"Hidden draft", self.call("GET", f"/api/e/{eid}/report?format=md").body)
        self.assertIn(b"Hidden draft", self.call("GET", f"/api/e/{eid}/report?format=md&draft=1").body)

    def test_delete_requires_confirmation(self):
        eid = self.make_engagement()
        self.err("DELETE", f"/api/e/{eid}", 400, {})
        self.err("DELETE", f"/api/e/{eid}", 400, {"confirm": "other"})
        self.assertTrue((self.ws / eid).exists())
        self.ok("DELETE", f"/api/e/{eid}", {"confirm": eid})
        self.assertFalse((self.ws / eid).exists())
        self.err("GET", f"/api/e/{eid}", 404)

    def test_meta_lists_library_and_lookups(self):
        meta = self.ok("GET", "/api/meta")
        self.assertGreaterEqual(len(meta["library"]), 35)
        self.assertIn("CWE-89", meta["cwe"])
        self.assertEqual([t["id"] for t in meta["report_types"]], list(report.REPORT_TYPES) if hasattr(report, "REPORT_TYPES") else [t["id"] for t in meta["report_types"]])
        self.assertEqual(len(meta["report_types"]), 5)


class SocketTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.httpd, self.app, self.url = server.create_server(Path(self.tmp.name) / "ws", "127.0.0.1", 0)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp.cleanup()

    def request(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r, data

    def test_full_round_trip_over_a_real_socket(self):
        token = self.url.split("token=")[1]
        r, _ = self.request("GET", "/api/meta")
        self.assertEqual(r.status, 403)
        r, _ = self.request("GET", f"/?token={token}")
        self.assertEqual(r.status, 302)
        cookie = r.getheader("Set-Cookie").split(";")[0]
        r, body = self.request("GET", "/", headers={"Cookie": cookie})
        self.assertEqual(r.status, 200)
        self.assertIn(b"SecReport", body)
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(r.getheader("Cache-Control"), "no-store")
        self.assertIn("frame-ancestors 'none'", r.getheader("Content-Security-Policy"))
        hdr = {"Cookie": cookie, "X-Requested-With": "secreport", "Content-Type": "application/json"}
        payload = json.dumps({"name": "Socket test", "client": "c"})
        r, body = self.request("POST", "/api/engagements", payload, hdr)
        self.assertEqual(r.status, 201)
        eid = json.loads(body)["id"]
        r, body = self.request("GET", f"/api/e/{eid}", headers={"Cookie": cookie})
        self.assertEqual(json.loads(body)["name"], "Socket test")
        r, _ = self.request("GET", "/api/meta", headers={"Cookie": cookie, "Host": "evil.com"})
        self.assertEqual(r.status, 403)

    def test_oversized_and_chunked_bodies_are_refused(self):
        token = self.url.split("token=")[1]
        r, _ = self.request("GET", f"/?token={token}")
        cookie = r.getheader("Set-Cookie").split(";")[0]
        hdr = {"Cookie": cookie, "X-Requested-With": "secreport", "Content-Type": "application/json"}
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.putrequest("POST", "/api/engagements")
        for k, v in dict(hdr, **{"Content-Length": str(server.MAX_BODY + 1)}).items():
            c.putheader(k, v)
        c.endheaders()
        self.assertEqual(c.getresponse().status, 413)
        c.close()
        r, _ = self.request("POST", "/api/engagements", body=iter([b"{}"]), headers=dict(hdr, **{"Transfer-Encoding": "chunked"}))
        self.assertEqual(r.status, 411)

    def test_the_secret_token_never_appears_in_logs(self):
        token = self.url.split("token=")[1]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.request("GET", f"/?token={token}")
            self.request("GET", f"/api/meta?token={token}")
        self.assertIn("GET", buf.getvalue())
        self.assertNotIn(token, buf.getvalue())
        self.assertNotIn("token=", buf.getvalue())

    def test_only_loopback_is_allowed(self):
        for host in ("0.0.0.0", "192.168.1.5", "example.com", ""):
            with self.assertRaises(ValueError):
                server.create_server(Path(self.tmp.name) / "x", host, 0)


if __name__ == "__main__":
    unittest.main()
