# SecReport

One platform that turns authorized security work into professional client reports:
**OSINT, Red Team, Web Pentest, Bug Bounty, and an Executive Summary.**

It is a **documentation and reporting tool**. It never scans or attacks anything. It only reads result
files you already have, and every target must pass an authorization and scope check.

Python 3.10+ (tested on 3.13), **no packages to install**. Works on Windows, macOS and Linux
(tested on Linux only; see "Known limits").

## Start in 30 seconds
```bash
python3 examples/build_demos.py                       # optional: 6 demo engagements with all report types
python3 -m secreport serve --workspace demo_workspace # opens the web interface
```
The terminal prints a link with a one-time token. Open that full link. (Windows: double-click `start_windows.bat`,
Mac/Linux: `./start.sh`.)

## What it does
| Area | Features |
|---|---|
| Report types | OSINT (source grading A-F / 1-6, timeline, entities), Red Team (narrative, MITRE ATT&CK table, detection gaps), Web Pentest (OWASP Top 10 table, roadmap), Bug Bounty (platform-style reports), Executive Summary (plain language) |
| Formats | HTML, Word (.docx), PDF, Markdown, JSON |
| Safety | Authorization reference required, in/out-of-scope guard (domains, wildcards, IPs, CIDR, dates), out-of-scope always wins |
| Quality | Human approval gate, TODO-placeholder gate, evidence SHA-256 vault with tamper check, readiness checklist |
| Branding | Per-engagement company name, brand colour and PNG/JPEG logo (2 MB max) in HTML, Word and PDF reports |
| Speed | 41 reusable findings (web, OSINT, red team), CVSS 3.1 and 4.0 scoring, CWE / OWASP / MITRE lookups |
| Import | Nuclei, ZAP, Burp XML, Nmap XML, Nessus XML and SARIF 2.1.0 as **draft** findings (scope-checked, de-duplicated) |
| Client copies | Redaction mode (IPs, e-mails, secrets, your own words), retest copy, original-vs-retest comparison |
| AI help | Makes a prompt for any free AI chat and reads the reply back as an AI-assisted draft that needs approval again. No API keys, no network calls |
| Web UI | Dashboard, finding editor with live CVSS, evidence upload, import, report preview, light/dark, mobile friendly |

## Command line
```bash
python3 -m secreport init eng1 --name "Acme Q4" --client "Acme Ltd" --type webpentest \
   --auth-ref "SOW-123" --in-scope "*.acme.test" --start 2026-11-01 --end 2026-11-30
python3 -m secreport library list
python3 -m secreport cvss "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
python3 -m secreport finding from-library eng1 web-sqli --asset app.acme.test
python3 -m secreport import eng1 nuclei_results.jsonl
python3 -m secreport import eng1 results.sarif --tool sarif --asset app.acme.test
python3 -m secreport finding approve eng1 F-001 --reviewer "Your Name"
python3 -m secreport report eng1 --format html docx pdf --redact --redact-term "Acme"
python3 -m secreport diff eng_original eng_retest
python3 -m secreport --help
```

## Tests
```bash
python3 -m unittest discover -s tests       # 76 tests, a few seconds
```
Includes a check that the JavaScript CVSS calculator in the UI matches the Python one for all 2,592 vectors.

## Security model of the web interface
Listens on 127.0.0.1 only; random per-run token in an HttpOnly SameSite=Strict cookie; Host and Origin checks;
JSON-only writes with a custom header; strict Content-Security-Policy; report preview in a sandboxed iframe;
engagement ids and evidence names validated against path traversal; token never written to logs.

## Known limits (honest list)
- **Not a scanner.** Findings come from you or from imported tool files.
- CVSS **3.1 only** (no 4.0 yet). The CWE / OWASP / MITRE tables are curated subsets; unknown IDs only produce a warning. Confirm important IDs on the official sites.
- The finding library is a set of **starting templates**. Always check them against your own evidence.
- Redaction is pattern based: read the output before sending it.
- PDF needs Google Chrome, Chromium or Edge (or wkhtmltopdf) installed. Without it, use HTML/Word and Print > Save as PDF.
- Word files were validated with python-docx and LibreOffice, not with Microsoft Word itself.
- Tested on Linux with Python 3.13. Windows/macOS paths for finding Chrome are included but untested.
- Client logo / colour branding is not included yet. Only the classification label (e.g. CONFIDENTIAL) is configurable.
- Single user, local use. There is no login system or multi-user sharing.

Use only on systems you own or have written permission to test.

CVSS v4.0 scoring follows FIRST's published specification and reference calculator data. Scores are labelled with
their metric groups (CVSS-B, CVSS-BT, CVSS-BE or CVSS-BTE); share the vector alongside the score.
For SARIF logs containing local file paths rather than absolute HTTP(S) artifact URIs, provide `--asset` (or the
web form's default target). The supplied target is still checked against the engagement scope.
