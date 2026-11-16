"""Command line interface.  Run:  python -m secreport --help

Typical flow:
  python -m secreport init eng1 --name "Acme Q4" --client "Acme Ltd" --type webpentest \\
      --auth-ref "SOW-123" --in-scope "*.acme.test" --start 2026-11-01 --end 2026-11-30
  python -m secreport finding from-library eng1 web-sqli --asset app.acme.test
  python -m secreport finding approve eng1 F-001 --reviewer "Your Name"
  python -m secreport report eng1 --format html docx pdf
  python -m secreport serve            # web interface at http://127.0.0.1:8765
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import ai, cvss, diff, evidence, importers, library, lookups, report
from .models import REPORT_TYPES, Engagement
from .scope import Scope


def _split(values):
    out = []
    for v in values or []:
        out.extend(x.strip() for x in v.split(",") if x.strip())
    return out


def _load(directory) -> Engagement:
    try:
        return Engagement.load(directory)
    except FileNotFoundError:
        sys.exit(f"No engagement found in {directory!r}. Create one with: python -m secreport init")
    except ValueError as exc:
        sys.exit(f"Could not read engagement: {exc}")


def _fail(msg):
    sys.exit(f"Error: {msg}")


# ----------------------------------------------------------------- commands
def cmd_init(a):
    path = Path(a.directory)
    if (path / "engagement.json").exists():
        _fail(f"engagement already exists in {path}")
    scope = Scope(in_scope=_split(a.in_scope), out_of_scope=_split(a.out_of_scope),
                  start_date=a.start or "", end_date=a.end or "",
                  authorization_ref=a.auth_ref or "", rules_of_engagement=a.roe or "")
    problems = scope.validate()
    if problems:
        _fail("; ".join(problems))
    try:
        eng = Engagement(name=a.name, client=a.client, report_type=a.type, tester=a.tester or "",
                         summary=a.summary or "", scope=scope, program=a.program or "")
    except ValueError as exc:
        _fail(str(exc))
    eng.save(path)
    print(f"Created engagement in {path}")
    if not scope.authorization_ref:
        print("WARNING: no authorization reference set. Scope checks fail until you add one (--auth-ref).")


def cmd_show(a):
    eng = _load(a.directory)
    print(f"{eng.name}  |  {eng.client}  |  {eng.report_type}")
    print("Findings by severity (approved only):", eng.severity_counts(True))
    print("Findings by severity (all):          ", eng.severity_counts(False))
    print("\nReadiness checklist:")
    for ok, msg in eng.readiness():
        print(f"  [{'x' if ok else ' '}] {msg}")


def cmd_scope(a):
    eng = _load(a.directory)
    code = 0
    for target in a.targets:
        ok, why = eng.scope.check(target)
        print(f"{'ALLOWED' if ok else 'BLOCKED'}  {target}  ({why})")
        code |= 0 if ok else 1
    sys.exit(code)


def cmd_cvss(a):
    try:
        info = cvss.describe(a.vector)
    except cvss.CvssError as exc:
        _fail(f"invalid vector: {exc}")
    print(f"Score: {info['score']}  Severity: {info['severity']}")


def cmd_library_list(a):
    for e in library.load():
        if a.kind and e["kind"] != a.kind:
            continue
        sev = e.get("manual_severity") or cvss.severity(cvss.base_score(e["cvss_vector"]))
        print(f"{e['id']:<28} {e['kind']:<8} {sev:<9} {e['title']}")


def cmd_finding_add(a):
    eng = _load(a.directory)
    assets = _split(a.asset)
    for asset in assets:
        ok, why = eng.scope.check(asset)
        if not ok:
            _fail(f"asset {asset!r} is not allowed ({why})")
    try:
        f = eng.add_finding(
            a.title, cvss_vector=a.vector or "", manual_severity=a.severity or "", cwe=a.cwe or "",
            owasp=a.owasp or "", mitre=_split(a.mitre), affected_assets=assets,
            description=a.desc or "", impact=a.impact or "", steps_to_reproduce=a.steps or "",
            remediation=a.fix or "", source_reliability=a.reliability or "",
            info_credibility=a.credibility or "", sources=_split(a.source))
    except ValueError as exc:
        _fail(f"invalid finding: {exc}")
    eng.save(a.directory)
    for w in lookups.check_finding(f):
        print("Note:", w)
    print(f"Added {f.id}: {f.title} [{f.severity}] (draft, needs approval)")


def cmd_finding_from_library(a):
    eng = _load(a.directory)
    try:
        f = library.instantiate(eng, a.library_id, _split(a.asset))
    except (KeyError, PermissionError, ValueError) as exc:
        _fail(str(exc.args[0] if exc.args else exc))
    eng.save(a.directory)
    print(f"Added {f.id}: {f.title} [{f.severity}] as a draft.")
    if library.has_placeholders(f):
        print("It still contains TODO placeholders. Edit them before approving.")


def cmd_finding_approve(a):
    eng = _load(a.directory)
    try:
        f = eng.get_finding(a.finding_id)
        if library.has_placeholders(f) and not a.force:
            _fail(f"{f.id} still has TODO placeholders. Fix them or use --force.")
        eng.approve_finding(a.finding_id, a.reviewer)
    except (KeyError, ValueError) as exc:
        _fail(str(exc.args[0] if exc.args else exc))
    eng.save(a.directory)
    print(f"Approved {a.finding_id} by {a.reviewer}")


def cmd_finding_unapprove(a):
    eng = _load(a.directory)
    try:
        eng.unapprove_finding(a.finding_id)
    except KeyError as exc:
        _fail(exc.args[0])
    eng.save(a.directory)
    print(f"{a.finding_id} is a draft again")


def cmd_finding_list(a):
    eng = _load(a.directory)
    for f in eng.findings:
        flag = "approved" if f.approved else "DRAFT"
        print(f"{f.id}  {f.severity:<9} {flag:<8} {f.status:<9} {f.title}")


def cmd_evidence_add(a):
    eng = _load(a.directory)
    try:
        item = evidence.add_file(eng, a.directory, a.file, a.desc or "", _split(a.finding))
    except (FileNotFoundError, KeyError, ValueError) as exc:
        _fail(str(exc.args[0] if exc.args else exc))
    eng.save(a.directory)
    print(f"{item.id} stored, sha256={item.sha256}")


def cmd_evidence_verify(a):
    eng = _load(a.directory)
    bad = 0
    for eid, ok, detail in evidence.verify(eng, a.directory):
        print(f"{'OK  ' if ok else 'FAIL'} {eid} {detail}")
        bad += 0 if ok else 1
    sys.exit(1 if bad else 0)


def cmd_import(a):
    eng = _load(a.directory)
    try:
        content = Path(a.file).read_bytes()
        res = importers.run_import(eng, a.directory, a.tool, content, default_asset=a.asset or "")
    except (OSError, importers.ImportError_) as exc:
        _fail(str(exc))
    eng.save(a.directory)
    print(res.summary())
    for title, asset, why in res.skipped_scope:
        print(f"  skipped (scope): {title} -> {asset} ({why})")


def cmd_report(a):
    eng = _load(a.directory)
    if not a.draft and not any(f.approved for f in eng.findings):
        print("Note: no approved findings yet. Add --draft to preview with drafts included.")
    for ok, msg in eng.readiness():
        if not ok and not a.draft:
            print(f"Heads up: {msg}")
    opts = report.make_options(include_draft=a.draft, redact=a.redact, custom_terms=_split(a.redact_term))
    written, errors = report.write_reports(eng, a.directory, a.format, opts)
    for p in written:
        print("Wrote", p)
    for fmt, err in errors:
        print(f"Could not make {fmt}: {err}")
    if opts.redaction:
        print("Redaction counts:", opts.redaction.stats, "(read the output before sharing it)")
    sys.exit(1 if errors else 0)


def cmd_diff(a):
    print(diff.to_text(diff.compare(_load(a.old), _load(a.new))))


def cmd_ai_prompt(a):
    eng = _load(a.directory)
    try:
        f = eng.get_finding(a.finding_id)
    except KeyError as exc:
        _fail(exc.args[0])
    print(ai.build_prompt(f, redact=not a.no_redact, extra_terms=_split(a.redact_term)))


def cmd_ai_apply(a):
    eng = _load(a.directory)
    try:
        text = Path(a.file).read_text(encoding="utf-8") if a.file else sys.stdin.read()
        f, warns = ai.apply_response(eng, a.finding_id, text)
    except (OSError, KeyError, ValueError) as exc:
        _fail(str(exc.args[0] if exc.args else exc))
    eng.save(a.directory)
    print(f"Updated {f.id} as AI-assisted draft. Approval was cleared; review then approve again.")
    for w in warns:
        print("Check:", w)


def cmd_lint(a):
    eng = _load(a.directory)
    warnings = []
    for f in eng.findings:
        warnings += lookups.check_finding(f)
        if library.has_placeholders(f):
            warnings.append(f"{f.id}: still has TODO placeholders")
    if not warnings:
        print("No warnings.")
    for w in warnings:
        print("-", w)


def cmd_serve(a):
    from . import server
    server.serve(a.workspace, a.host, a.port, open_browser=not a.no_browser)


def build_parser():
    p = argparse.ArgumentParser(prog="secreport", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create an engagement folder")
    s.add_argument("directory")
    s.add_argument("--name", required=True)
    s.add_argument("--client", required=True)
    s.add_argument("--type", choices=REPORT_TYPES, default="webpentest")
    s.add_argument("--tester"); s.add_argument("--summary"); s.add_argument("--program")
    s.add_argument("--auth-ref"); s.add_argument("--roe")
    s.add_argument("--in-scope", action="append"); s.add_argument("--out-of-scope", action="append")
    s.add_argument("--start"); s.add_argument("--end")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("show", help="summary and readiness checklist"); s.add_argument("directory")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("scope", help="check targets against the scope")
    s.add_argument("directory"); s.add_argument("targets", nargs="+"); s.set_defaults(func=cmd_scope)

    s = sub.add_parser("cvss", help="score a CVSS 3.1 or 4.0 vector"); s.add_argument("vector")
    s.set_defaults(func=cmd_cvss)

    lib = sub.add_parser("library").add_subparsers(dest="sub", required=True)
    s = lib.add_parser("list"); s.add_argument("--kind", choices=("web", "osint", "redteam"))
    s.set_defaults(func=cmd_library_list)

    fin = sub.add_parser("finding").add_subparsers(dest="sub", required=True)
    s = fin.add_parser("add"); s.add_argument("directory"); s.add_argument("--title", required=True)
    for opt in ("vector", "severity", "cwe", "owasp", "desc", "impact", "steps", "fix",
                "reliability", "credibility"):
        s.add_argument(f"--{opt}")
    s.add_argument("--mitre", action="append"); s.add_argument("--asset", action="append")
    s.add_argument("--source", action="append"); s.set_defaults(func=cmd_finding_add)
    s = fin.add_parser("from-library"); s.add_argument("directory"); s.add_argument("library_id")
    s.add_argument("--asset", action="append", required=True); s.set_defaults(func=cmd_finding_from_library)
    s = fin.add_parser("approve"); s.add_argument("directory"); s.add_argument("finding_id")
    s.add_argument("--reviewer", required=True); s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_finding_approve)
    s = fin.add_parser("unapprove"); s.add_argument("directory"); s.add_argument("finding_id")
    s.set_defaults(func=cmd_finding_unapprove)
    s = fin.add_parser("list"); s.add_argument("directory"); s.set_defaults(func=cmd_finding_list)

    ev = sub.add_parser("evidence").add_subparsers(dest="sub", required=True)
    s = ev.add_parser("add"); s.add_argument("directory"); s.add_argument("file")
    s.add_argument("--finding", action="append"); s.add_argument("--desc"); s.set_defaults(func=cmd_evidence_add)
    s = ev.add_parser("verify"); s.add_argument("directory"); s.set_defaults(func=cmd_evidence_verify)

    s = sub.add_parser("import", help="import scanner result files as draft findings")
    s.add_argument("directory"); s.add_argument("file")
    s.add_argument("--tool", choices=("auto",) + importers.TOOLS, default="auto")
    s.add_argument("--asset", help="default scoped target for SARIF results with local file paths")
    s.set_defaults(func=cmd_import)

    s = sub.add_parser("report", help="generate reports"); s.add_argument("directory")
    s.add_argument("--format", nargs="+", choices=report.FORMATS, default=["html", "docx"])
    s.add_argument("--draft", action="store_true", help="include unapproved findings")
    s.add_argument("--redact", action="store_true", help="mask IPs, emails, secrets in the output")
    s.add_argument("--redact-term", action="append", help="extra word/name to mask (repeatable)")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("diff", help="compare original test and retest")
    s.add_argument("old"); s.add_argument("new"); s.set_defaults(func=cmd_diff)

    s = sub.add_parser("ai-prompt", help="make a prompt to paste into any AI chat")
    s.add_argument("directory"); s.add_argument("finding_id")
    s.add_argument("--no-redact", action="store_true"); s.add_argument("--redact-term", action="append")
    s.set_defaults(func=cmd_ai_prompt)
    s = sub.add_parser("ai-apply", help="apply an AI reply (JSON) as an AI-assisted draft")
    s.add_argument("directory"); s.add_argument("finding_id")
    s.add_argument("--file", help="file with the AI reply (default: read stdin)"); s.set_defaults(func=cmd_ai_apply)

    s = sub.add_parser("lint", help="warn about unknown CWE/OWASP/MITRE IDs and TODOs")
    s.add_argument("directory"); s.set_defaults(func=cmd_lint)

    s = sub.add_parser("serve", help="start the local web interface")
    s.add_argument("--workspace", default="workspace"); s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765); s.add_argument("--no-browser", action="store_true")
    s.set_defaults(func=cmd_serve)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
