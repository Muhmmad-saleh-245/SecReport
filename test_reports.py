"""Report generation for all 5 types and all formats, plus importers."""

import io
import json
import re
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from xml.dom import minidom
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "examples"))

from secreport import blocks, branding, evidence, importers, report  # noqa: E402
from secreport.models import Engagement  # noqa: E402
from secreport.render import pdf as pdf_r  # noqa: E402
from secreport.scope import Scope  # noqa: E402

PAYLOAD = '<script>alert(1)</script> & "quotes" <img src=x onerror=alert(2)>'


def workspace():
    import build_demos
    tmp = tempfile.TemporaryDirectory()
    ws = build_demos.main(Path(tmp.name) / "ws", make_reports=False)
    return tmp, ws


def png_logo():
    import struct
    import zlib

    def chunk(kind, body):
        return (len(body).to_bytes(4, "big") + kind + body
                + (zlib.crc32(kind + body) & 0xFFFFFFFF).to_bytes(4, "big"))

    header = struct.pack(">IIBBBBB", 2, 1, 8, 6, 0, 0, 0)
    image = zlib.compress(b"\x00" + b"\x00" * 8)
    return branding.PNG_SIGNATURE + chunk(b"IHDR", header) + chunk(b"IDAT", image) + chunk(b"IEND", b"")


class DemoReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.ws = workspace()
        cls.engs = {d.name: Engagement.load(d) for d in sorted(cls.ws.iterdir()) if d.is_dir()}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_all_five_types_exist(self):
        self.assertEqual({e.report_type for e in self.engs.values()},
                         {"osint", "redteam", "webpentest", "bugbounty", "executive"})

    def test_every_type_renders_in_every_text_format(self):
        for name, eng in self.engs.items():
            for fmt in ("html", "md", "docx", "json"):
                data = report.render(eng, fmt, report.make_options())
                self.assertGreater(len(data), 500, f"{name} {fmt}")

    def test_type_specific_sections(self):
        expect = {
            "osint-exposure": ["Collection Objectives", "Confidence Summary", "Entities and Assets", "Timeline", "Source grade"],
            "redteam-blue-lantern": ["Attack Narrative", "MITRE ATT&amp;CK Mapping", "Detection and Response Gaps", "Operation Timeline"],
            "webpentest-portal": ["OWASP Top 10 Coverage", "Remediation Roadmap", "Detailed Findings", "Severity Scale"],
            "bugbounty-submission": ["Submission Overview", "Steps to reproduce", "Reports"],
            "executive-summary": ["Overall Risk Posture", "Top Risks in Plain Language", "Recommended Priorities"],
        }
        for name, needles in expect.items():
            html = report.render(self.engs[name], "html", report.make_options()).decode()
            for n in needles:
                self.assertIn(n, html, f"{name} is missing {n!r}")

    def test_drafts_are_hidden_unless_requested_and_marked(self):
        eng = self.engs["webpentest-portal"]
        draft = next(f for f in eng.findings if not f.approved)
        heading = f"{draft.id}: {draft.title}"
        normal = report.render(eng, "md", report.make_options()).decode()
        self.assertNotIn(heading, normal)
        self.assertEqual(normal.count("Reviewed and approved by"), len(eng.findings) - 1)
        with_draft = report.render(eng, "md", report.make_options(include_draft=True)).decode()
        self.assertIn(heading, with_draft)
        self.assertIn("DRAFT", with_draft)

    def test_overall_rating_matches_the_text_of_the_summary(self):
        """Regression: a draft critical finding must not be mentioned as if it were reported."""
        eng = self.engs["webpentest-portal"]
        self.assertTrue(all(f.approved for f in eng.findings if f.severity in ("Critical", "High")))
        html = report.render(eng, "html", report.make_options()).decode()
        self.assertIn("Overall rating (highest finding severity): Critical", html)

    def test_evidence_of_draft_findings_is_not_leaked(self):
        eng = Engagement.from_dict(self.engs["webpentest-portal"].to_dict())
        draft = next(f for f in eng.findings if not f.approved)
        with tempfile.TemporaryDirectory() as d:
            evidence.add_text(eng, d, "secret_draft_notes.txt", "x", "only for the draft", [draft.id])
        out = report.render(eng, "html", report.make_options()).decode()
        self.assertNotIn("secret_draft_notes.txt", out)
        out = report.render(eng, "html", report.make_options(include_draft=True)).decode()
        self.assertIn("secret_draft_notes.txt", out)

    def test_docx_is_a_valid_word_file(self):
        for name, eng in self.engs.items():
            data = report.render(eng, "docx", report.make_options())
            z = zipfile.ZipFile(io.BytesIO(data))
            self.assertIsNone(z.testzip())
            for part in z.namelist():
                minidom.parseString(z.read(part))          # every part is well-formed XML
            self.assertIn("word/document.xml", z.namelist())
            try:
                import docx
            except ImportError:
                continue
            d = docx.Document(io.BytesIO(data))
            self.assertGreater(len(d.tables), 2, name)
            self.assertTrue(any("Acme" in p.text for p in d.paragraphs) or any("Acme" in c.text for t in d.tables for r in t.rows for c in r.cells))

    def test_pdf_when_an_engine_is_available(self):
        if not pdf_r.available():
            self.skipTest("no Chrome/Chromium/wkhtmltopdf installed")
        data = report.render(self.engs["osint-exposure"], "pdf", report.make_options())
        self.assertTrue(data.startswith(b"%PDF"))
        self.assertGreater(len(data), 5000)

    def test_report_files_are_written_with_safe_names(self):
        eng = self.engs["bugbounty-submission"]
        with tempfile.TemporaryDirectory() as d:
            written, errors = report.write_reports(eng, d, ("html", "md", "docx"))
            self.assertEqual(errors, [])
            self.assertEqual(len(written), 3)
            for p in written:
                self.assertEqual(p.parent, Path(d) / "reports")
                self.assertRegex(p.name, r"^[A-Za-z0-9._-]+$")

    def test_json_export_is_valid(self):
        data = json.loads(report.render(self.engs["executive-summary"], "json", report.make_options()))
        self.assertEqual(data[0]["t"], "cover")

    def test_client_branding_renders_across_formats(self):
        eng = Engagement(name="Q4 review", client="Client Ltd", brand_name="A & B Security",
                         brand_color="#125abc")
        with tempfile.TemporaryDirectory() as d:
            eng.brand_logo_path = branding.save_logo(d, png_logo())
            eng.save(d)
            loaded = Engagement.load(d)
            self.assertEqual(loaded.brand_name, "A & B Security")
            self.assertEqual(loaded.brand_color, "#125abc")

            html = report.render(loaded, "html", eng_dir=d).decode()
            self.assertIn("A &amp; B Security", html)
            self.assertIn("--brand:#125abc", html)
            self.assertIn("data:image/png;base64,", html)
            markdown = report.render(loaded, "md", eng_dir=d).decode()
            self.assertIn("A & B Security", markdown)

            docx = zipfile.ZipFile(io.BytesIO(report.render(loaded, "docx", eng_dir=d)))
            self.assertIn("word/media/logo.png", docx.namelist())
            document = docx.read("word/document.xml").decode()
            self.assertIn("<wp:inline", document)
            self.assertIn("125ABC", document)
            self.assertIn("A &amp; B Security", document)
            for name in docx.namelist():
                if name.endswith((".xml", ".rels")):
                    minidom.parseString(docx.read(name))

            def fake_pdf(html_text, out_path):
                self.assertIn("data:image/png;base64,", html_text)
                out_path = Path(out_path)
                out_path.write_bytes(b"%PDF-test")
                return out_path

            with mock.patch.object(pdf_r, "html_to_pdf", side_effect=fake_pdf):
                self.assertTrue(report.render(loaded, "pdf", eng_dir=d).startswith(b"%PDF"))


class HostileContentTests(unittest.TestCase):
    def make(self):
        eng = Engagement(name=PAYLOAD, client=PAYLOAD, report_type="webpentest", tester=PAYLOAD,
                         summary=PAYLOAD, methodology=PAYLOAD, recommendations=PAYLOAD, classification=PAYLOAD,
                         scope=Scope(in_scope=["*.acme.test"], authorization_ref=PAYLOAD))
        f = eng.add_finding(PAYLOAD, manual_severity="High", description=PAYLOAD + "\x00\x0b control chars",
                            impact=PAYLOAD, remediation=PAYLOAD, steps_to_reproduce=PAYLOAD,
                            references=["javascript:alert(1)", "https://ok.test/a?x=1&y=2"],
                            affected_assets=["a.acme.test"], cwe="CWE-79")
        eng.approve_finding(f.id, PAYLOAD)
        with tempfile.TemporaryDirectory() as d:
            evidence.add_text(eng, d, "x.txt", "data", PAYLOAD, [f.id])
        eng.timeline = [{"date": PAYLOAD, "title": PAYLOAD, "detail": PAYLOAD, "source": PAYLOAD}]
        return eng

    def test_html_never_contains_live_markup_from_data(self):
        from html.parser import HTMLParser

        class Collect(HTMLParser):
            def __init__(self):
                super().__init__()
                self.tags, self.attrs = [], []

            def handle_starttag(self, tag, attrs):
                self.tags.append(tag)
                self.attrs += [(tag, k, v) for k, v in attrs]

        html = report.render(self.make(), "html", report.make_options()).decode()
        c = Collect()
        c.feed(html)
        for bad in ("script", "img", "iframe", "object", "embed", "link"):
            self.assertNotIn(bad, c.tags)
        self.assertEqual([a for a in c.attrs if a[1].startswith("on")], [], "an event handler attribute leaked in")
        links = [a[2] for a in c.attrs if a[0] == "a" and a[1] == "href"]
        self.assertTrue(all(l.startswith(("https://", "http://", "#")) for l in links), links)
        self.assertIn("https://ok.test/a?x=1&y=2", links)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("javascript:alert(1)", html)           # shown as plain text only

    def test_control_characters_are_removed_from_every_format(self):
        eng = self.make()
        for fmt in ("html", "md", "json"):
            text = report.render(eng, fmt, report.make_options()).decode()
            self.assertNotRegex(text, "[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]", fmt)
            self.assertIn("control chars", text)

    def test_markdown_escapes_html_and_syntax(self):
        md = report.render(self.make(), "md", report.make_options()).decode()
        self.assertNotIn("<script>", md)
        self.assertIn("\\<script\\>", md)

    def test_docx_survives_control_characters_and_markup(self):
        data = report.render(self.make(), "docx", report.make_options())
        z = zipfile.ZipFile(io.BytesIO(data))
        for part in z.namelist():
            minidom.parseString(z.read(part))
        xml = z.read("word/document.xml").decode()
        self.assertNotIn("\x00", xml)
        self.assertNotIn("<script>", xml)


class RedactedReportTests(unittest.TestCase):
    def test_redaction_covers_every_format_and_every_field(self):
        eng = Engagement(name="Op Falcon", client="Acme Ltd", summary="Server 10.1.2.3 owned by bob@acme.test",
                         scope=Scope(in_scope=["10.1.2.3"], authorization_ref="SOW"), tester="Bob")
        f = eng.add_finding("Leak", manual_severity="High", affected_assets=["10.1.2.3"],
                            description="Found password=Hunter2 and key AKIAABCDEFGHIJKLMNOP on 10.1.2.3",
                            impact="Contact bob@acme.test", remediation="Rotate")
        eng.approve_finding(f.id, "R")
        with tempfile.TemporaryDirectory() as d:
            evidence.add_text(eng, d, "a.txt", "x", "dump from 10.1.2.3", [f.id])
        opts = report.make_options(redact=True, custom_terms=["Op Falcon", "Acme"])
        for fmt in ("html", "md", "docx", "json"):
            data = report.render(eng, fmt, opts)
            text = data.decode("utf-8", "ignore") if fmt != "docx" else zipfile.ZipFile(io.BytesIO(data)).read("word/document.xml").decode()
            for secret in ("10.1.2.3", "Hunter2", "AKIAABCDEFGHIJKLMNOP", "bob@acme", "Op Falcon", "Acme"):
                self.assertNotIn(secret, text, f"{secret} leaked in {fmt}")
            self.assertIn("REDACTED", text)
        self.assertIn("_REDACTED", report.filename(eng, "html", True))


class ImporterTests(unittest.TestCase):
    NUCLEI = "\n".join(json.dumps(x) for x in [
        {"template-id": "git", "info": {"name": "Git Config Exposure", "severity": "medium", "description": "d",
                                        "reference": ["https://x.test/a"], "classification": {"cwe-id": ["cwe-538"]}},
         "matched-at": "https://app.acme.test/.git/config", "type": "http"},
        {"template-id": "git", "info": {"name": "Git Config Exposure", "severity": "medium",
                                        "classification": {"cwe-id": ["cwe-538"]}}, "matched-at": "https://api.acme.test/.git/config"},
        {"template-id": "x", "info": {"name": "In out-of-scope host", "severity": "high"}, "matched-at": "https://admin.acme.test/x"},
        {"template-id": "y", "info": {"name": "Elsewhere", "severity": "low"}, "matched-at": "https://evil.example.com/"},
        {"template-id": "z", "info": {"name": "No target", "severity": "low"}},
    ])
    ZAP = json.dumps({"site": [{"@name": "https://app.acme.test", "alerts": [{
        "alert": "SQL Injection", "riskcode": "3", "cweid": "89", "desc": "<p>bad</p>", "solution": "<p>fix</p>",
        "reference": "<p>https://owasp.org/x</p>",
        "instances": [{"uri": "https://app.acme.test/s?q=1", "method": "GET", "param": "q"}]}]}]})
    BURP = ('<?xml version="1.0"?><!DOCTYPE issues [<!ELEMENT issues (issue*)>]><issues><issue><name>Cookie without HttpOnly</name>'
            '<host ip="1.2.3.4">https://app.acme.test</host><path>/login</path><severity>Low</severity><confidence>Firm</confidence>'
            '<issueBackground>&lt;p&gt;bg&lt;/p&gt;</issueBackground><remediationBackground>fix</remediationBackground>'
            '<vulnerabilityClassifications>&lt;a&gt;CWE-1004&lt;/a&gt;</vulnerabilityClassifications></issue></issues>')
    NMAP = ('<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port>'
            '<port protocol="tcp" portid="23"><state state="closed"/></port></ports></host>'
            '<host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host>'
            '<host><status state="down"/><address addr="10.0.0.9" addrtype="ipv4"/></host></nmaprun>')
    NESSUS = ('<?xml version="1.0"?><NessusClientData_v2><Report name="scan">'
              '<ReportHost name="192.0.2.10"><HostProperties><tag name="host-fqdn">app.acme.test</tag>'
              '</HostProperties><ReportItem port="443" protocol="tcp" svc_name="https" severity="3" '
              'pluginID="12345" pluginName="Example issue" pluginFamily="Web Servers">'
              '<synopsis>Short summary.</synopsis><description>Long detail.</description><solution>Apply a fix.</solution>'
              '<cwe>79</cwe><cvss3_vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N</cvss3_vector>'
              '<see_also>https://vendor.example/advisory</see_also><cve>CVE-2024-1234</cve>'
              '<plugin_output>Evidence text</plugin_output></ReportItem></ReportHost>'
              '<ReportHost name="admin.acme.test"><ReportItem port="80" protocol="tcp" svc_name="http" severity="2" '
              'pluginID="12345" pluginName="Example issue" pluginFamily="Web Servers"><cwe>79</cwe>'
              '</ReportItem></ReportHost></Report></NessusClientData_v2>')
    SARIF = json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Example analyzer", "rules": [{
        "id": "rule-xss", "name": "Potential XSS", "shortDescription": {"text": "Potential XSS"},
        "fullDescription": {"text": "Untrusted output is rendered."}, "help": {"text": "Encode output."},
        "helpUri": "https://vendor.example/fix", "properties": {"tags": ["security", "external/cwe/cwe-79"],
        "security-severity": "8.8"}}]}}, "results": [
        {"ruleId": "rule-xss", "level": "error", "message": {"text": "Found at the route."},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.js"}}}]},
        {"ruleId": "rule-xss", "level": "error", "message": {"text": "Found again."},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "https://app.acme.test/other.js"}}}]},
        {"ruleId": "rule-xss", "level": "warning", "message": {"text": "Out of scope."},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "https://admin.acme.test/app.js"}}}]}
    ]}]})

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.eng = Engagement(name="t", client="c", scope=Scope(
            in_scope=["*.acme.test", "10.0.0.0/24"], out_of_scope=["admin.acme.test"], authorization_ref="x"))

    def tearDown(self):
        self.tmp.cleanup()

    def run_import(self, tool, data, default_asset=""):
        return importers.run_import(self.eng, self.tmp.name, tool, data, default_asset=default_asset)

    def test_nuclei_scope_dedupe_and_idempotence(self):
        r = self.run_import("nuclei", self.NUCLEI)
        self.assertEqual(len(r.created), 1)
        self.assertEqual(len(r.skipped_scope), 3)          # out of scope, elsewhere, no target
        f = self.eng.findings[0]
        self.assertEqual(sorted(f.affected_assets), ["https://api.acme.test/.git/config", "https://app.acme.test/.git/config"])
        self.assertFalse(f.approved)
        self.assertEqual(f.cwe, "CWE-538")
        before = len(self.eng.findings), len(self.eng.evidence)
        r2 = self.run_import("nuclei", self.NUCLEI)         # importing the same file again changes nothing
        self.assertEqual((len(self.eng.findings), len(self.eng.evidence)), before)
        self.assertEqual((r2.created, r2.merged), ([], []))

    def test_zap_burp_nmap(self):
        self.assertEqual(len(self.run_import("zap", self.ZAP).created), 1)
        self.assertEqual(self.eng.findings[0].cwe, "CWE-89")
        self.assertEqual(self.eng.findings[0].severity, "High")
        self.assertEqual(len(self.run_import("burp", self.BURP).created), 1)
        self.assertEqual(self.eng.findings[1].cwe, "CWE-1004")
        r = self.run_import("nmap", self.NMAP)
        self.assertEqual(len(r.created), 1)                 # 192.168.1.1 is out of scope, 10.0.0.9 is down
        self.assertEqual(len(r.skipped_scope), 1)
        self.assertIn("22/tcp", self.eng.findings[2].description)
        self.assertNotIn("23/tcp", self.eng.findings[2].description)

    def test_nessus_scope_cvss_and_deduplication(self):
        self.assertEqual(importers.detect_tool(self.NESSUS), "nessus")
        result = self.run_import("nessus", self.NESSUS)
        self.assertEqual((len(result.created), len(result.skipped_scope)), (1, 1))
        finding = self.eng.findings[0]
        self.assertEqual((finding.cwe, finding.score, finding.affected_assets),
                         ("CWE-79", 8.2, ["app.acme.test"]))
        self.assertFalse(finding.approved)
        raw_path = evidence.path_of(self.eng, self.tmp.name, self.eng.evidence[0].id)
        self.assertIn("CVE-2024-1234", raw_path.read_text(encoding="utf-8"))
        again = self.run_import("nessus", self.NESSUS)
        self.assertEqual((again.created, again.merged), ([], []))

    def test_sarif_scope_default_asset_deduplication_and_detection(self):
        self.assertEqual(importers.detect_tool(self.SARIF), "sarif")
        result = self.run_import("sarif", self.SARIF, "app.acme.test")
        self.assertEqual((len(result.created), len(result.merged), len(result.skipped_scope)), (1, 1, 1))
        finding = self.eng.findings[0]
        self.assertEqual((finding.cwe, finding.severity, finding.affected_assets),
                         ("CWE-79", "High", ["app.acme.test", "https://app.acme.test/other.js"]))
        self.assertFalse(finding.approved)
        self.assertEqual(len(self.run_import("sarif", self.SARIF, "app.acme.test").created), 0)
        local_only = json.dumps({"version": "2.1.0", "runs": [{"results": [{"ruleId": "x", "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "src/only.js"}}}]}]}]})
        no_target = self.run_import("sarif", local_only)
        self.assertEqual(len(no_target.created), 0)
        self.assertEqual(no_target.skipped_scope[0][1], "(no asset)")

    def test_nessus_and_sarif_reject_unsafe_or_wrong_documents(self):
        unsafe = '<!DOCTYPE x [<!ENTITY e "expansion">]><NessusClientData_v2><Report>&e;</Report></NessusClientData_v2>'
        for tool, data in (("nessus", unsafe), ("nessus", "<other/>"),
                           ("sarif", json.dumps({"version": "1.0", "runs": []})),
                           ("sarif", "not json")):
            with self.subTest(tool=tool, data=data[:24]), self.assertRaises(importers.ImportError_):
                self.run_import(tool, data)
        malformed_optional_fields = json.dumps({"version": "2.1.0", "runs": [{"tool": "bad",
            "results": [{"ruleId": "x", "level": [], "properties": [], "locations": "bad"}]}]})
        self.assertEqual(len(importers.parse_sarif(malformed_optional_fields, "app.acme.test")), 1)

    def test_auto_detect(self):
        for tool, data in (("nuclei", self.NUCLEI), ("zap", self.ZAP), ("burp", self.BURP), ("nmap", self.NMAP)):
            self.assertEqual(importers.detect_tool(data), tool)
        self.assertEqual(importers.detect_tool("hello"), "")
        self.assertEqual(len(self.run_import("auto", self.ZAP).created), 1)

    def test_hostile_input_is_rejected_cleanly(self):
        bomb = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>'
        for tool, data in (("nmap", bomb), ("burp", bomb), ("nmap", "<not-xml"), ("nmap", "<other/>"),
                           ("zap", "not json"), ("zap", "[]"), ("nuclei", "{bad json\nmore"), ("auto", "plain text"),
                           ("unknown", "x"), ("zap", "x" * (importers.MAX_INPUT_BYTES + 1))):
            with self.assertRaises(importers.ImportError_, msg=f"{tool}: {data[:20]}"):
                self.run_import(tool, data)
        self.assertEqual(self.eng.findings, [])

    def test_imported_text_is_escaped_in_reports(self):
        nuclei = json.dumps({"template-id": "t", "info": {"name": PAYLOAD, "severity": "low", "description": PAYLOAD},
                             "matched-at": "https://app.acme.test/"})
        self.run_import("nuclei", nuclei)
        self.eng.approve_finding("F-001", "R")
        html = report.render(self.eng, "html", report.make_options()).decode()
        self.assertNotIn("<script>alert", html)


class BlocksTests(unittest.TestCase):
    def test_osint_grading_and_overall_risk(self):
        eng = Engagement(name="n", client="c", report_type="osint")
        f = eng.add_finding("A", manual_severity="Medium", source_reliability="B", info_credibility="2")
        self.assertEqual(blocks.overall_risk([f]), "Medium")
        self.assertEqual(blocks.overall_risk([]), "Low")
        out = blocks.build(eng, blocks.ReportOptions(include_draft=True))
        self.assertTrue(any(b["t"] == "table" and b["headers"][0] == "Grade" for b in out))


if __name__ == "__main__":
    unittest.main()
