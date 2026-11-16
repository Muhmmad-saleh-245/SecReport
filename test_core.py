"""Core logic: CVSS, scope guard, models, evidence vault, library, lookups, redaction, diff, AI helper."""

import datetime as dt
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from secreport import ai, branding, cvss, diff, evidence, library, lookups
from secreport.models import Engagement, Finding
from secreport.redact import RedactionConfig
from secreport.scope import Scope

ROOT = Path(__file__).resolve().parent.parent


def make_eng(**kw):
    return Engagement(name="T", client="Acme", scope=Scope(
        in_scope=["*.acme.test", "10.0.0.0/24"], out_of_scope=["admin.acme.test"],
        authorization_ref="SOW-1"), **kw)


class CvssTests(unittest.TestCase):
    def test_known_scores(self):
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": (9.8, "Critical"),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": (6.1, "Medium"),
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": (6.5, "Medium"),
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": (0.0, "None"),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": (10.0, "Critical"),
            "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": (1.6, "Low"),
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": (7.8, "High"),
        }
        for vec, (score, sev) in cases.items():
            self.assertEqual(cvss.base_score(vec), score, vec)
            self.assertEqual(cvss.severity(score), sev)

    def test_bad_vectors(self):
        for bad in ("", "AV:N/AC:L", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
                    "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
            with self.assertRaises(cvss.CvssError, msg=bad):
                cvss.base_score(bad)

    def test_builder_roundtrip(self):
        m = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
        self.assertEqual(cvss.base_score(cvss.metrics_to_vector(m)), 9.8)

    def test_javascript_matches_python_for_every_combination(self):
        """The web UI recalculates scores in JavaScript. All 2592 vectors must match Python."""
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")
        src = (ROOT / "secreport" / "web" / "app.js").read_text(encoding="utf-8")
        a = src.index("// ------------------------------------------------------------------ CVSS 3.1")
        b = src.index("// ------------------------------------------------------------------ router")
        script = ("const window={};\n" + src[a:b] + "\n"
                  "const out=[];for(const AV of 'NALP')for(const AC of 'LH')for(const PR of 'NLH')for(const UI of 'NR')"
                  "for(const S of 'UC')for(const C of 'HLN')for(const I of 'HLN')for(const A of 'HLN')"
                  "out.push([`CVSS:3.1/AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}`,"
                  "cvssScore({AV,AC,PR,UI,S,C,I,A})]);console.log(JSON.stringify(out));")
        res = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr)
        rows = json.loads(res.stdout)
        self.assertEqual(len(rows), 2592)
        bad = [(v, js, cvss.base_score(v)) for v, js in rows if abs(js - cvss.base_score(v)) > 1e-9]
        self.assertEqual(bad, [], f"JS and Python disagree on {len(bad)} vectors, e.g. {bad[:3]}")


class Cvss40Tests(unittest.TestCase):
    def test_first_official_examples(self):
        cases = {
            "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 7.3,
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 7.7,
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U": 5.2,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N": 5.1,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A": 9.3,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N": 7.1,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:L/SA:H/E:U/MAV:A/R:U/V:C": 2.4,
        }
        for vector, expected in cases.items():
            with self.subTest(vector=vector):
                self.assertEqual(cvss.base_score(vector), expected)
                self.assertEqual(cvss.severity(expected), "Critical" if expected >= 9 else
                                 "High" if expected >= 7 else "Medium" if expected >= 4 else "Low")

    def test_parse_order_optional_metrics_and_round_trip(self):
        vector = ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                  "/E:A/CR:M/IR:L/AR:H/MAV:A/MAC:H/MAT:P/MPR:L/MUI:A/MVC:N/MVI:H/MVA:L"
                  "/MSC:L/MSI:S/MSA:H/S:P/AU:Y/R:A/V:D/RE:L/U:Red")
        self.assertEqual(cvss.metrics_to_vector(cvss.parse_vector(vector), version="4.0"), vector)
        self.assertEqual(cvss.parse_vector(vector)["U"], "Red")

    def test_invalid_vectors_are_rejected(self):
        valid = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        for bad in ("", "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                    valid + "/E:A/E:P", valid + "/ZZ:N", valid.replace("AV:N", "AV:F"),
                    valid.replace("/SA:N", "")):
            with self.subTest(vector=bad), self.assertRaises(cvss.CvssError):
                cvss.base_score(bad)


class BrandingValidationTests(unittest.TestCase):
    @staticmethod
    def png(width=2, height=1):
        import struct
        import zlib

        def chunk(kind, body):
            return (len(body).to_bytes(4, "big") + kind + body
                    + (zlib.crc32(kind + body) & 0xFFFFFFFF).to_bytes(4, "big"))

        header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
        image = zlib.compress(b"\x00" + b"\x00" * (width * 4) * height)
        return branding.PNG_SIGNATURE + chunk(b"IHDR", header) + chunk(b"IDAT", image) + chunk(b"IEND", b"")

    @staticmethod
    def jpeg():
        return (b"\xff\xd8" + b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x02\x01\x01\x11\x00"
                + b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x00\xff\xd9")

    def test_valid_png_and_color(self):
        self.assertEqual(branding.inspect_logo(self.png()), ("png", "image/png", 2, 1))
        self.assertEqual(branding.inspect_logo(self.jpeg()), ("jpg", "image/jpeg", 2, 1))
        self.assertEqual(branding.validate_color("#A1b2C3"), "#a1b2c3")

    def test_logo_is_saved_per_engagement_and_replaced_safely(self):
        with tempfile.TemporaryDirectory() as d:
            eng = make_eng()
            eng.brand_logo_path = branding.save_logo(d, self.png())
            eng.save(d)
            self.assertTrue((Path(d) / eng.brand_logo_path).is_file())
            self.assertTrue(branding.logo_data_uri(eng, d).startswith("data:image/png;base64,"))
            eng.brand_logo_path = branding.save_logo(d, self.jpeg())
            self.assertFalse((Path(d) / "branding" / "logo.png").exists())
            self.assertTrue(branding.logo_data_uri(eng, d).startswith("data:image/jpeg;base64,"))

    def test_rejects_svg_malformed_images_and_bad_colors(self):
        for data in (b'<svg onload="alert(1)"></svg>', self.png()[:-2], b"not an image"):
            with self.subTest(data=data[:16]), self.assertRaises(branding.BrandingError):
                branding.inspect_logo(data)
        for color in ("red", "#fff", "#123456; background:url(x)"):
            with self.subTest(color=color), self.assertRaises(branding.BrandingError):
                branding.validate_color(color)

    def test_logo_size_and_workspace_boundaries(self):
        old_limit = branding.MAX_LOGO_BYTES
        branding.MAX_LOGO_BYTES = 10
        try:
            with self.assertRaisesRegex(branding.BrandingError, "2 MB"):
                branding.inspect_logo(self.png())
        finally:
            branding.MAX_LOGO_BYTES = old_limit
        with tempfile.TemporaryDirectory() as d:
            eng = make_eng()
            eng.brand_logo_path = "branding/../../outside.png"
            with self.assertRaises(branding.BrandingError):
                branding.logo_data_uri(eng, d)

class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(in_scope=["*.acme.test", "10.0.0.0/24", "acme.test", "2001:db8::/64"],
                           out_of_scope=["admin.acme.test", "10.0.0.128/25"], authorization_ref="C-1",
                           start_date="2026-11-01", end_date="2026-11-30")
        self.day = dt.date(2026, 11, 15)

    def ok(self, t):
        return self.scope.check(t, self.day)[0]

    def test_allowed(self):
        for t in ("app.acme.test", "https://app.acme.test:8443/login?x=1", "acme.test", "10.0.0.55",
                  "APP.ACME.TEST", "app.acme.test.", "http://[2001:db8::5]:8080/", "10.0.0.0/26"):
            self.assertTrue(self.ok(t), t)

    def test_blocked(self):
        for t in ("admin.acme.test", "https://admin.acme.test/x", "evil-acme.test", "acme.test.evil.com",
                  "10.0.1.5", "10.0.0.200", "example.com", "", "   ", "10.0.0.0/23"):
            self.assertFalse(self.ok(t), t)

    def test_range_overlapping_out_of_scope_is_blocked(self):
        self.assertFalse(self.ok("10.0.0.0/24"))     # overlaps 10.0.0.128/25
        self.assertTrue(self.ok("10.0.0.0/25"))

    def test_url_tricks_cannot_fool_the_guard(self):
        self.assertFalse(self.ok("http://app.acme.test@evil.com/"))      # real host is evil.com
        self.assertFalse(self.ok("https://evil.com/?h=app.acme.test"))
        self.assertFalse(self.ok("https://evil.com/app.acme.test"))
        self.assertFalse(self.ok("http://app.acme.test.evil.com"))

    def test_dates_and_authorization(self):
        self.assertFalse(self.scope.check("app.acme.test", dt.date(2026, 12, 1))[0])
        self.assertFalse(self.scope.check("app.acme.test", dt.date(2026, 10, 1))[0])
        self.scope.authorization_ref = "  "
        self.assertFalse(self.ok("app.acme.test"))

    def test_bad_dates_do_not_crash(self):
        self.scope.start_date = "not-a-date"
        allowed, why = self.scope.check("app.acme.test", self.day)
        self.assertFalse(allowed)
        self.assertIn("YYYY-MM-DD", why)
        self.assertTrue(self.scope.validate())
        self.scope.start_date, self.scope.end_date = "2026-12-01", "2026-11-01"
        self.assertIn("end_date is before start_date", self.scope.validate())

    def test_from_dict_is_tolerant(self):
        s = Scope.from_dict({"in_scope": ["a.test"], "start_date": None})
        self.assertEqual(s.start_date, "")
        self.assertEqual(Scope.from_dict(None).in_scope, [])


class ModelTests(unittest.TestCase):
    def finding(self, eng, **kw):
        kw.setdefault("manual_severity", "Low")
        return eng.add_finding("Test finding", **kw)

    def test_ids_are_never_reused_after_delete(self):
        eng = make_eng()
        self.finding(eng); self.finding(eng); self.finding(eng)
        eng.delete_finding("F-002")
        self.assertEqual(self.finding(eng).id, "F-004")   # old code reused F-003 and collided

    def test_load_is_tolerant_of_old_and_unknown_fields(self):
        eng = make_eng()
        self.finding(eng)
        data = eng.to_dict()
        data["findings"][0]["field_from_the_future"] = 1
        data["findings"][0].pop("tags")
        data.pop("objectives")
        data["unknown"] = "x"
        again = Engagement.from_dict(data)
        self.assertEqual(again.findings[0].tags, [])
        self.assertEqual(again.objectives, [])

    def test_editing_content_revokes_approval_but_status_does_not(self):
        eng = make_eng()
        f = self.finding(eng)
        eng.approve_finding(f.id, "Reviewer")
        eng.update_finding(f.id, status="fixed")
        self.assertTrue(f.approved)
        eng.update_finding(f.id, description="changed after review")
        self.assertFalse(f.approved)
        self.assertEqual(f.approved_by, "")

    def test_failed_edit_rolls_back(self):
        eng = make_eng()
        f = self.finding(eng, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", manual_severity="")
        with self.assertRaises(ValueError):
            eng.update_finding(f.id, title="New", cvss_vector="garbage")
        self.assertEqual(f.title, "Test finding")
        self.assertEqual(f.score, 9.8)
        with self.assertRaises(ValueError):
            eng.update_finding(f.id, id="F-999")      # cannot rewrite identity or approval fields
        with self.assertRaises(ValueError):
            eng.update_finding(f.id, approved=True)

    def test_validation_rules(self):
        eng = make_eng()
        for kw in ({"title": ""}, {"cvss_vector": "x"}, {"manual_severity": "Huge"}, {"status": "weird"},
                   {"source_reliability": "AB"}, {"info_credibility": "9"}, {"source_reliability": "Z"}):
            with self.assertRaises(ValueError, msg=str(kw)):
                eng.add_finding(kw.pop("title", "T"), **kw)
        with self.assertRaises(ValueError):
            Engagement(name="", client="c")
        with self.assertRaises(ValueError):
            Engagement(name="n", client="c", report_type="nonsense")

    def test_severity_for_zero_score_is_info_not_none(self):
        eng = make_eng()
        f = self.finding(eng, cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", manual_severity="")
        self.assertEqual(f.severity, "Info")
        self.assertEqual(eng.severity_counts(False)["Info"], 1)

    def test_normalisation(self):
        eng = make_eng()
        f = self.finding(eng, cwe="cwe 89", mitre=[" t1190 ", ""], affected_assets=[" a.acme.test ", ""])
        self.assertEqual(f.cwe, "CWE-89")
        self.assertEqual(f.mitre, ["T1190"])
        self.assertEqual(f.affected_assets, ["a.acme.test"])

    def test_reviewer_required(self):
        eng = make_eng()
        f = self.finding(eng)
        for blank in ("", "   "):
            with self.assertRaises(ValueError):
                eng.approve_finding(f.id, blank)

    def test_save_load_roundtrip_and_atomic_write(self):
        eng = make_eng()
        self.finding(eng, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", manual_severity="")
        with tempfile.TemporaryDirectory() as d:
            eng.save(d)
            self.assertFalse((Path(d) / "engagement.json.tmp").exists())
            again = Engagement.load(d)
        self.assertEqual(again.findings[0].score, 6.1)

    def test_readiness_checklist(self):
        eng = make_eng()
        self.assertFalse(all(ok for ok, _ in eng.readiness()))
        f = self.finding(eng, manual_severity="Critical")
        eng.summary = "x"
        eng.approve_finding(f.id, "R")
        ev_check = [ok for ok, m in eng.readiness() if m.startswith("Critical/High findings have evidence")]
        self.assertEqual(ev_check, [False])
        self.assertIn("missing: F-001", [m for ok, m in eng.readiness() if "evidence" in m][0])


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "eng"
        self.eng = make_eng()
        self.eng.add_finding("F", manual_severity="Info")

    def tearDown(self):
        self.tmp.cleanup()

    def test_hash_and_tamper_detection(self):
        item = evidence.add_text(self.eng, self.dir, "proof.txt", "hello", "proof", ["F-001"])
        self.assertEqual(len(item.sha256), 64)
        self.assertEqual(self.eng.findings[0].evidence_ids, ["E-001"])
        self.assertTrue(all(ok for _, ok, _ in evidence.verify(self.eng, self.dir)))
        (self.dir / item.stored_as).write_text("tampered")
        self.assertEqual(evidence.verify(self.eng, self.dir)[0][1:], (False, "HASH MISMATCH, file was modified"))
        (self.dir / item.stored_as).unlink()
        self.assertEqual(evidence.verify(self.eng, self.dir)[0][2], "file missing")

    def test_hostile_file_names_cannot_escape_the_vault(self):
        for name in ("../../evil.txt", "..\\..\\evil.txt", "/etc/passwd", "a/b/c.txt", "..", "", "x" * 400):
            item = evidence.add_bytes(self.eng, self.dir, name, b"data")
            path = (self.dir / item.stored_as).resolve()
            self.assertIn((self.dir / "evidence").resolve(), path.parents, name)
            self.assertNotIn("..", item.filename)
        self.assertFalse((Path(self.tmp.name) / "evil.txt").exists())

    def test_tampered_json_path_is_refused(self):
        item = evidence.add_text(self.eng, self.dir, "a.txt", "x")
        item.stored_as = "../outside.txt"
        (self.dir / "evidence").parent.joinpath("outside.txt").write_text("secret")
        with self.assertRaises(ValueError):
            evidence.path_of(self.eng, self.dir, item.id)
        self.assertFalse(evidence.verify(self.eng, self.dir)[0][1])

    def test_ids_not_reused_and_unknown_finding_rejected(self):
        evidence.add_text(self.eng, self.dir, "a.txt", "1")
        evidence.add_text(self.eng, self.dir, "b.txt", "2")
        self.eng.evidence.pop(0)
        self.assertEqual(evidence.add_text(self.eng, self.dir, "c.txt", "3").id, "E-003")
        with self.assertRaises(KeyError):
            evidence.add_text(self.eng, self.dir, "d.txt", "4", finding_ids=["F-999"])
        self.assertEqual(len(self.eng.evidence), 2)

    def test_size_limit(self):
        old = evidence.MAX_EVIDENCE_BYTES
        evidence.MAX_EVIDENCE_BYTES = 10
        try:
            with self.assertRaises(ValueError):
                evidence.add_bytes(self.eng, self.dir, "big.bin", b"x" * 11)
        finally:
            evidence.MAX_EVIDENCE_BYTES = old


class LibraryAndLookupTests(unittest.TestCase):
    def test_library_is_valid_and_references_known_ids(self):
        entries = library.load()
        self.assertGreaterEqual(len(entries), 35)
        self.assertEqual(len({e["id"] for e in entries}), len(entries), "duplicate library ids")
        for e in entries:
            self.assertEqual(library.validate_entry(e), [], e["id"])
            if e.get("cwe"):
                self.assertIn(e["cwe"], lookups.CWE, e["id"])
            if e.get("owasp"):
                self.assertIn(lookups.owasp_code(e["owasp"]), lookups.OWASP_2021, e["id"])
            for t in e.get("mitre", []):
                self.assertIn(t, lookups.MITRE, e["id"])
        kinds = {e["kind"] for e in entries}
        self.assertEqual(kinds, {"web", "osint", "redteam"})

    def test_instantiate_enforces_scope_and_marks_draft(self):
        eng = make_eng()
        f = library.instantiate(eng, "web-sqli", ["app.acme.test"])
        self.assertFalse(f.approved)
        self.assertEqual((f.score, f.severity), (9.8, "Critical"))
        self.assertTrue(library.has_placeholders(f))
        self.assertTrue(all(u.startswith("https://") for u in f.references))
        for bad in ("evil.com", "admin.acme.test"):
            with self.assertRaises(PermissionError):
                library.instantiate(eng, "web-sqli", [bad])
        with self.assertRaises(KeyError):
            library.instantiate(eng, "nope", ["app.acme.test"])
        self.assertEqual(len(eng.findings), 1)

    def test_user_library_overrides_builtin(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "library.json"
            p.write_text(json.dumps([{"id": "web-sqli", "kind": "web", "title": "My SQLi", "manual_severity": "High"},
                                     {"id": "mine", "kind": "web", "title": "Mine", "manual_severity": "Low"}]))
            self.assertEqual(library.get("web-sqli", p)["title"], "My SQLi")
            self.assertEqual(library.get("mine", p)["title"], "Mine")

    def test_lookup_helpers(self):
        self.assertEqual(lookups.owasp_code("A3:2021 Injection"), "A03:2021")
        self.assertEqual(lookups.owasp_label("A03:2021"), "A03:2021 Injection")
        self.assertEqual(lookups.mitre_name("T1059.001"), "Command and Scripting Interpreter")
        urls = lookups.reference_urls("CWE-89", "A03:2021", ["T1059.001"])
        self.assertIn("https://attack.mitre.org/techniques/T1059/001/", urls)
        f = Finding(id="F-1", title="t", cwe="CWE-99999", owasp="A99:2021", mitre=["T1", "T9999"])
        self.assertEqual(len(lookups.check_finding(f)), 4)


class RedactionTests(unittest.TestCase):
    def test_masks_sensitive_values(self):
        cfg = RedactionConfig(custom_terms=["Project Falcon", "acme"])
        text = ("Host 192.168.1.20 and 2001:db8:0:0:0:0:0:1 mail bob@acme.test password=Hunter2 "
                "Authorization: Bearer abc.def-123 key AKIAABCDEFGHIJKLMNOP project falcon ACME")
        out = cfg.text(text)
        for secret in ("192.168.1.20", "2001:db8", "bob@", "Hunter2", "abc.def-123", "AKIAABCDEFGHIJKLMNOP",
                       "falcon", "ACME", "acme"):
            self.assertNotIn(secret.lower(), out.lower(), secret)
        self.assertGreaterEqual(cfg.stats["ips"], 2)

    def test_does_not_mangle_normal_text(self):
        cfg = RedactionConfig()
        for ok in ("Version 1.2.3 released", "Use TLS 1.3", "see section 4.5.6", "999.1.1.1 is not an IP",
                   "CVSS 9.8 (Critical)"):
            self.assertEqual(cfg.text(ok), ok)


class DiffTests(unittest.TestCase):
    def test_compare(self):
        old, new = make_eng(), make_eng()
        old.add_finding("SQL injection", manual_severity="High", cwe="CWE-89")
        old.add_finding("Open redirect", manual_severity="Low")
        old.add_finding("XSS", manual_severity="Medium")
        new.add_finding("SQL injection", manual_severity="High", cwe="CWE-89", status="verified")
        new.add_finding("XSS", manual_severity="High")
        new.add_finding("CSRF", manual_severity="Low")
        res = diff.compare(old, new)
        self.assertEqual([f.title for f in res["new"]], ["CSRF"])
        self.assertEqual([f.title for f in res["resolved"]], ["Open redirect"])
        self.assertEqual([n.title for _, n in res["fixed_status"]], ["SQL injection"])
        self.assertEqual([n.title for _, n in res["persisting"]], ["XSS"])
        self.assertEqual([(o.severity, n.severity) for o, n in res["severity_changed"]], [("Medium", "High")])
        self.assertIn("CSRF", diff.to_text(res))

    def test_accepted_and_verified_transitions_are_not_dropped(self):
        """Regression: accepted -> verified used to vanish from every section."""
        old, new = make_eng(), make_eng()
        old.add_finding("HSTS", manual_severity="Low", status="accepted")
        old.add_finding("Cookie flags", manual_severity="Low", status="accepted")
        old.add_finding("TLS", manual_severity="Medium", status="fixed")
        new.add_finding("HSTS", manual_severity="Low", status="verified")
        new.add_finding("Cookie flags", manual_severity="Low", status="accepted")
        new.add_finding("TLS", manual_severity="Medium", status="verified")
        res = diff.compare(old, new)
        self.assertEqual([n.title for _, n in res["fixed_status"]], ["HSTS"])
        self.assertEqual([n.title for _, n in res["accepted"]], ["Cookie flags"])
        listed = {n.title for k in ("fixed_status", "accepted", "persisting") for _, n in res[k]}
        self.assertEqual(listed, {"HSTS", "Cookie flags"})       # TLS was already done before, so no change to report


class AiHelperTests(unittest.TestCase):
    def test_prompt_masks_client_data(self):
        eng = make_eng()
        f = eng.add_finding("T", manual_severity="Low", affected_assets=["10.0.0.5"],
                            description="Contact admin@acme.test; password=Secret1 on 10.0.0.5")
        prompt = ai.build_prompt(f, redact=True, extra_terms=["Acme"])
        for leak in ("admin@acme", "Secret1", "10.0.0.5"):
            self.assertNotIn(leak, prompt)
        self.assertIn("Do not invent", prompt)
        self.assertIn("10.0.0.5", ai.build_prompt(f, redact=False))

    def test_parse_variants(self):
        good = '{"description": "d", "impact": "i"}'
        for reply in (good, f"```json\n{good}\n```", f"Sure! Here you go:\n{good}\nHope it helps."):
            self.assertEqual(ai.parse_response(reply), {"description": "d", "impact": "i"})
        out = ai.parse_response('{"description": "d", "severity": "Critical", "evil": "x"}')
        self.assertEqual(list(out), ["description"])       # unknown fields (e.g. severity) are dropped
        for bad in ("", "no json here", "{bad json}", "[1,2]", '{"unknown": "x"}', '{"description": "  "}'):
            with self.assertRaises(ValueError, msg=bad):
                ai.parse_response(bad)

    def test_apply_revokes_approval_and_flags_risky_text(self):
        eng = make_eng()
        f = eng.add_finding("T", manual_severity="Low")
        eng.approve_finding(f.id, "R")
        f2, warns = ai.apply_response(eng, f.id, '{"description": "See CVE-2024-12345 at https://x.test TODO: fix"}')
        self.assertTrue(f2.ai_assisted)
        self.assertFalse(f2.approved)
        self.assertEqual(len(warns), 3)


if __name__ == "__main__":
    unittest.main()
