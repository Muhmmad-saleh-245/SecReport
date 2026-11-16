"""Builds a demo workspace with one fictional engagement of every report type.

Everything uses reserved example domains (.test) and documentation IP ranges, and the
client "Acme Ltd" is fictional.

    python3 examples/build_demos.py            # creates ./demo_workspace
    python3 -m secreport serve --workspace demo_workspace
"""

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secreport import evidence, library, report  # noqa: E402
from secreport.models import Engagement  # noqa: E402
from secreport.scope import Scope  # noqa: E402

REVIEWER = "Priya Sharma (Senior Reviewer)"


def scope(*in_scope, out=(), auth="Signed Statement of Work SOW-2026-114"):
    return Scope(in_scope=list(in_scope), out_of_scope=list(out), start_date="2026-10-01",
                 end_date="2026-12-31", authorization_ref=auth,
                 rules_of_engagement="No denial-of-service. Business hours only. No real customer data.")


def lib(eng, entry_id, assets, **fields):
    """Instantiate a library finding, fill in the instance details, keep it a draft."""
    f = library.instantiate(eng, entry_id, assets)
    if fields:
        eng.update_finding(f.id, **fields)
    return f


def approve_all(eng, except_ids=()):
    for f in eng.findings:
        if f.id not in except_ids:
            eng.approve_finding(f.id, REVIEWER)


def save(eng, ws, name):
    d = ws / name
    eng.save(d)
    return d


def build_webpentest(ws):
    eng = Engagement(
        name="Acme Customer Portal Penetration Test", client="Acme Ltd (fictional)", report_type="webpentest",
        tester="Arjun Mehta, Offensive Security",
        summary=("Acme Ltd asked for an authorized security assessment of its customer portal before the "
                 "new billing module goes live.\n\nTesting found one critical SQL injection flaw in the search "
                 "function and an access control flaw that lets one customer read another customer's invoices. "
                 "Both should be fixed before release. The remaining issues are lower risk hardening items."),
        methodology=("Testing followed the OWASP Web Security Testing Guide against a staging copy of the portal. "
                     "Phases: mapping the application, authentication and session testing, access control testing, "
                     "input handling testing and configuration review. Automated results (Nuclei, ZAP) were "
                     "reviewed by hand; only confirmed issues are reported."),
        recommendations=("Add security testing to the release pipeline and fix critical findings before the billing "
                         "module is released. A retest of fixed items is recommended within 30 days."),
        scope=scope("*.acme.test", "acme.test", "203.0.113.0/28", out=["payments.acme.test"]))
    f1 = lib(eng, "web-sqli", ["portal.acme.test"],
             description="The q parameter of /search is concatenated into a SQL query without parameterisation. A single quote causes a database error and a boolean-based payload changed the number of results returned.",
             impact="An attacker can read customer records and, depending on database rights, modify data.",
             steps_to_reproduce="1. Sign in as a normal test user and open https://portal.acme.test/search.\n\n2. Submit the search term ' (single quote). The server returns a database syntax error (see E-001).\n\n3. Submit ' OR '1'='1 and observe that all records are returned instead of none.")
    f2 = lib(eng, "web-idor", ["portal.acme.test"],
             description="GET /api/invoices/{id} returns the invoice for any numeric id without checking that it belongs to the signed-in user.",
             impact="Any customer can read other customers' invoices, which contain names, addresses and amounts.",
             steps_to_reproduce="1. Sign in as test user A and request /api/invoices/1001 (own invoice).\n\n2. Change the id to 1002, which belongs to test user B. The invoice is returned (see E-002).")
    f3 = lib(eng, "web-xss-reflected", ["portal.acme.test"],
             description="The msg parameter of /error is written into the page without encoding.",
             impact="Script can run in a victim's session if they open a crafted link.",
             steps_to_reproduce="1. Open /error?msg=<b>test</b> and observe that the HTML is rendered.\n\n2. The page title and body both reflect the value unencoded.")
    f4 = lib(eng, "web-cookie-flags", ["portal.acme.test"],
             description="The session cookie is set without the HttpOnly and SameSite attributes.",
             steps_to_reproduce="1. Sign in and inspect the Set-Cookie header of the login response (see E-003).")
    f5 = lib(eng, "web-missing-hsts", ["www.acme.test"], description="Responses from www.acme.test do not include Strict-Transport-Security.")
    f6 = lib(eng, "web-weak-tls", ["203.0.113.5"],
             description="The server at 203.0.113.5 accepts TLS 1.0 connections.",
             steps_to_reproduce="1. Connect with a TLS 1.0 only client and observe that the handshake succeeds.")
    lib(eng, "web-verbose-errors", ["portal.acme.test"],
        description="Unhandled errors display a stack trace including file paths.",
        steps_to_reproduce="1. Request /search?page=abc and observe the stack trace.")   # left as DRAFT
    evidence.add_text(eng, ws / "_tmp", "sqli_response.txt",
                      "GET /search?q=%27 HTTP/1.1\nHost: portal.acme.test\n\nHTTP/1.1 500\n\nYou have an error in your SQL syntax near '''' at line 1",
                      "Server response to a single quote", [f1.id])
    evidence.add_text(eng, ws / "_tmp", "idor_response.json",
                      '{"invoice_id":1002,"customer":"Test User B","total":"120.00"}',
                      "Invoice of user B returned to user A", [f2.id])
    evidence.add_text(eng, ws / "_tmp", "login_headers.txt",
                      "HTTP/1.1 302\nSet-Cookie: SESSION=REDACTEDVALUE; Path=/; Secure",
                      "Login response headers", [f4.id])
    return eng, ["web-verbose-errors"]


def build_osint(ws):
    eng = Engagement(
        name="Acme External Exposure Review", client="Acme Ltd (fictional)", report_type="osint",
        tester="Neha Verma, Threat Intelligence",
        summary=("This review looked at what an outsider can learn about Acme Ltd from public sources only. "
                 "It found exposed credentials in public breach data, a leaked access key in a public code "
                 "repository and weak email authentication. No system was accessed."),
        methodology="Sources: public DNS and certificate transparency records, public code hosting search, breach notification services, company website and professional networking pages. All collection was passive. Each finding is graded for source reliability (A-F) and information credibility (1-6).",
        objectives=["Identify internet-facing assets that Acme may not be tracking",
                    "Find publicly exposed credentials or secrets",
                    "Assess how easily staff can be targeted by social engineering"],
        recommendations="Treat exposed secrets as compromised: rotate them first, then investigate. Set up continuous monitoring for new subdomains and breach exposures.",
        timeline=[{"date": "2026-10-05", "title": "Collection started", "detail": "Passive DNS and certificate review", "source": "crt.sh, passive DNS"},
                  {"date": "2026-10-09", "title": "Leaked key found", "detail": "Access key in a public repository commit", "source": "Public code hosting"},
                  {"date": "2026-10-12", "title": "Breach exposure confirmed", "detail": "12 staff e-mail addresses in a public breach collection", "source": "Breach notification service"}],
        entities=[{"name": "acme.test", "type": "Domain", "confidence": "High", "notes": "Primary domain"},
                  {"name": "old-portal.acme.test", "type": "Subdomain", "confidence": "Medium", "notes": "Appears unmaintained"},
                  {"name": "acme-corp.example", "type": "Domain", "confidence": "Low", "notes": "Look-alike registered by a third party"}],
        scope=scope("*.acme.test", "acme.test", auth="Client authorization letter 2026-09-30 (passive OSINT only)"))
    f = lib(eng, "osint-code-secrets", ["acme.test"],
            description="A cloud access key belonging to Acme was committed to a public repository and remained in the commit history.",
            impact="Anyone could use the key to reach the cloud account until it is revoked.",
            sources=["Public code hosting repository, commit from 2026-08-14 (collected 2026-10-09)"],
            source_reliability="B", info_credibility="2")
    lib(eng, "osint-leaked-credentials", ["acme.test"],
        description="12 e-mail addresses on the acme.test domain appear in a public breach collection together with passwords.",
        sources=["Breach notification service lookup (collected 2026-10-12)"], source_reliability="B", info_credibility="1")
    lib(eng, "osint-email-auth", ["acme.test"],
        description="The domain publishes an SPF record but no DMARC policy, so spoofed e-mail is not rejected.",
        sources=["Public DNS TXT records (collected 2026-10-05)"], source_reliability="A", info_credibility="1")
    lib(eng, "osint-subdomain-exposure", ["old-portal.acme.test"],
        description="old-portal.acme.test appears in certificate transparency logs and its web page has not changed since 2023.",
        sources=["Certificate transparency logs (collected 2026-10-05)"], source_reliability="A", info_credibility="3")
    lib(eng, "osint-lookalike-domains", ["acme.test"],
        description="acme-corp.example was registered by a third party two weeks ago and resolves to a parked page.",
        sources=["Public WHOIS and DNS data (collected 2026-10-12)"], source_reliability="B", info_credibility="3")
    lib(eng, "osint-employee-info", ["acme.test"],
        description="Staff names and job titles for the finance team are listed on professional networking sites.",
        sources=["Professional networking site search (collected 2026-10-10)"], source_reliability="C", info_credibility="2")   # DRAFT
    evidence.add_text(eng, ws / "_tmp", "repo_search_notes.txt",
                      "Search: org:acme-ltd AKIA\nResult: 1 file, commit a1b2c3d, key id redacted",
                      "Notes from the repository search", [f.id])
    return eng, ["osint-employee-info"]


def build_redteam(ws):
    eng = Engagement(
        name="Operation Blue Lantern", client="Acme Ltd (fictional)", report_type="redteam",
        tester="Red Team Alpha",
        summary=("The red team tested whether a realistic attacker could reach the finance file server and "
                 "whether Acme's security team would notice. The objective was reached in four days and was "
                 "not detected until the team reported it."),
        methodology="Intelligence-led exercise agreed with Acme's CISO. Phases: reconnaissance, phishing, initial access, privilege escalation, lateral movement and objective completion. All activity was logged and coordinated with a small white-cell team.",
        objectives=["Gain a foothold using social engineering", "Reach the finance file server", "Measure detection and response time"],
        attack_narrative="The team sent a pretext e-mail to 40 staff. Six opened it and two entered credentials into the test page. A valid account was used to sign in to the VPN, which allowed access to internal systems. A service account with excessive rights then provided access to the finance file server.\n\nNo alert was raised during VPN sign-in from a new location, remote service use between servers, or large file reads.",
        detection_gaps=["VPN sign-in from a new country did not alert", "Remote service use between servers produced no alert",
                        "Bulk file reads on the finance server were not monitored", "No one reviewed the pretext e-mail reports for 36 hours"],
        timeline=[{"date": "2026-11-02 09:10", "title": "Phishing e-mail sent", "detail": "40 recipients", "source": ""},
                  {"date": "2026-11-02 11:45", "title": "First credentials captured", "detail": "2 accounts", "source": ""},
                  {"date": "2026-11-03 14:20", "title": "VPN access gained", "detail": "Using a captured account", "source": ""},
                  {"date": "2026-11-05 10:05", "title": "Finance server reached", "detail": "Objective met", "source": ""},
                  {"date": "2026-11-06 16:00", "title": "Exercise ended", "detail": "Reported to white cell", "source": ""}],
        scope=scope("*.acme.test", "198.51.100.0/24", auth="Red team rules of engagement signed 2026-10-20"))
    lib(eng, "rt-phishing", ["mail.acme.test"], description="Six of 40 recipients opened the pretext e-mail and two entered credentials into the test page.")
    lib(eng, "rt-password-spraying", ["vpn.acme.test"], description="Three accounts accepted one of three common passwords on the VPN gateway.")
    lib(eng, "rt-excess-privileges", ["198.51.100.20"], description="A service account was a member of a group with write access to most file servers.")
    lib(eng, "rt-detection-gap", ["198.51.100.0/24"], description="Remote service use from the VPN pool to the file servers generated no alerts.")
    lib(eng, "rt-exfil-unmonitored", ["198.51.100.20"], description="A 200 MB test archive was uploaded to a web storage service without being flagged.")  # DRAFT
    return eng, ["rt-exfil-unmonitored"]


def build_bugbounty(ws):
    eng = Engagement(
        name="Acme Public Bug Bounty Submission", client="Acme Ltd (fictional)", report_type="bugbounty",
        program="Acme Vulnerability Disclosure Program (fictional)", tester="Researcher: sec_researcher_01",
        summary="Two issues found on in-scope assets while following the program rules. No customer data was accessed beyond the researcher's own test accounts, and testing was stopped as soon as each issue was confirmed.",
        scope=scope("*.acme.test", auth="https://acme.test/security/policy (public program policy)", out=["status.acme.test"]))
    lib(eng, "web-idor", ["app.acme.test"],
        description="PUT /api/profile/{id} updates the profile of the id in the URL without checking ownership.",
        impact="A user can change another user's name and e-mail address, which can lead to account takeover through password reset.",
        steps_to_reproduce="1. Create two test accounts, A and B.\n\n2. As A, send PUT /api/profile/<B's id> with a new display name.\n\n3. Sign in as B and observe the changed name.",
        remediation="Verify on the server that the id in the URL matches the signed-in user, or ignore the id and use the session.")
    lib(eng, "web-open-redirect", ["app.acme.test"],
        description="The next parameter of /login redirects to any URL after sign-in.",
        impact="Attackers can send victims a trusted-looking login link that lands on a malicious page.",
        steps_to_reproduce="1. Open https://app.acme.test/login?next=https://example.org.\n\n2. Sign in with a test account.\n\n3. The browser is redirected to https://example.org.")
    return eng, []


def build_executive(ws):
    eng = Engagement(
        name="Acme Security Summary Q4", client="Acme Ltd (fictional)", report_type="executive",
        tester="Security Assurance Team",
        summary=("This summary combines the results of the Q4 portal test, the external exposure review and the "
                 "red team exercise. The business should act first on the exposed access key, the customer "
                 "data access flaw and the lack of monitoring of VPN sign-ins."),
        recommendations="1. Rotate exposed secrets this week.\n\n2. Fix the invoice access flaw before the billing release.\n\n3. Fund 24x7 monitoring of VPN and file server activity.",
        scope=scope("*.acme.test", "acme.test"))
    lib(eng, "osint-code-secrets", ["acme.test"], impact="A cloud account key was public. Anyone could have used it to reach company data until it is revoked.",
        description="A cloud access key was found in a public code repository.")
    lib(eng, "web-idor", ["portal.acme.test"], impact="Any customer could read other customers' invoices, which is a data protection risk.",
        description="The invoice endpoint does not check who is asking.")
    lib(eng, "rt-detection-gap", ["acme.test"], impact="An attacker could move through the network for days without anyone noticing.",
        description="Remote access and file activity is not monitored.")
    lib(eng, "web-missing-hsts", ["www.acme.test"], description="A browser hardening setting is missing on the public website.")
    return eng, []


def main(out="demo_workspace", make_reports=True):
    ws = Path(out)
    if ws.exists():
        shutil.rmtree(ws)
    ws.mkdir()
    builders = [("webpentest-portal", build_webpentest), ("osint-exposure", build_osint),
                ("redteam-blue-lantern", build_redteam), ("bugbounty-submission", build_bugbounty),
                ("executive-summary", build_executive)]
    for name, fn in builders:
        eng, drafts = fn(ws)
        # evidence was written to a temp dir during build; move it to the engagement folder
        tmp = ws / "_tmp"
        target = ws / name
        target.mkdir(exist_ok=True)
        if tmp.exists():
            (target / "evidence").mkdir(exist_ok=True)
            for f in (tmp / "evidence").glob("*"):
                shutil.move(str(f), target / "evidence" / f.name)
            shutil.rmtree(tmp)
        draft_ids = {f.id for f in eng.findings if any(t == f"library:{d}" for t in f.tags for d in drafts)}
        approve_all(eng, draft_ids)
        if name == "webpentest-portal":
            eng.get_finding("F-005").status = "accepted"
        eng.save(target)
        print(f"built {name}: {len(eng.findings)} findings, {len(draft_ids)} left as draft")

    # a retest copy of the web pentest, with some findings fixed
    base = Engagement.load(ws / "webpentest-portal")
    retest = Engagement.from_dict(base.to_dict())
    retest.name = "Acme Customer Portal Penetration Test (Retest)"
    retest.evidence = []
    for f in retest.findings:
        f.evidence_ids = []
    for f in retest.findings:
        if f.title in ("SQL injection", "Missing HTTP Strict Transport Security (HSTS)"):
            retest.update_finding(f.id, status="verified", retest_notes="Retested on 2026-12-01: the issue is fixed.")
        elif f.title == "Reflected cross-site scripting (XSS)":
            retest.update_finding(f.id, retest_notes="Retested: still reproducible on /error.")
    approve_all(retest)
    retest.save(ws / "webpentest-portal-retest")
    print("built webpentest-portal-retest")

    if not make_reports:
        return ws
    # write sample report files for every type
    for d in sorted(p for p in ws.iterdir() if p.is_dir()):
        eng = Engagement.load(d)
        written, errors = report.write_reports(eng, d, ("html", "md", "docx", "pdf"), report.make_options())
        print(f"  {d.name}: " + ", ".join(p.name.rsplit('.', 1)[1] for p in written) + (f" (skipped: {[e[0] for e in errors]})" if errors else ""))
    return ws


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo_workspace")
