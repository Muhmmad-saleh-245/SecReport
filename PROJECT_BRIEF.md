# PROJECT BRIEF: SecReport

Use this file to restore context in a new chat or to brief Copilot / any AI assistant before extending the project.

## Goal
One platform that produces professional client/company reports for OSINT, Red Team, Web Pentest, Bug Bounty and an
Executive Summary. Chain: Engagement -> Scope -> Findings -> Evidence -> Report.

## Status
Phases 1-5 are built and tested. See README.md for the feature list and known limits.

## Hard rules (do not break these when extending)
1. Documentation and reporting only. It must never scan, attack or send traffic to a target.
2. An authorization reference and scope are required. Out-of-scope always beats in-scope. Every asset (manual, library, import) passes `Scope.check`.
3. Findings are drafts until a named human approves them. Editing reviewed content revokes approval. TODO placeholders block approval.
4. Everything rendered is escaped (HTML, Markdown, DOCX). Imported/AI text is untrusted.
5. Evidence keeps SHA-256, names are sanitised, paths cannot leave the vault.
6. The core uses the Python standard library only. Optional tools (Chrome for PDF) are detected, never required.
7. The web server stays loopback-only with token cookie, Host/Origin checks and strict CSP.
8. AI helpers never call a network service. They only build prompts and parse pasted replies.
9. Every new feature needs unit tests. Run `python3 -m unittest discover -s tests` after each step.
10. Do not invent library functions, CWE/CVE/ATT&CK IDs or URLs. Verify against official sources.

## Layout
secreport/  models scope cvss evidence lookups library importers redact diff ai blocks report charts server cli
secreport/render/  html md docx pdf       secreport/data/findings.json (41 templates)
secreport/web/  index.html app.js style.css      tests/  test_core test_reports test_server      examples/build_demos.py

## Ideas for a next phase (not built)
- Custom report templates and a user-editable finding library in the UI
- More importers (OpenVAS, Burp JSON)
- Report signing / watermark, and a read-only client portal export
- Optional login and multi-user review workflow

## Prompt to give an AI assistant before extending it
```
You are extending "SecReport", a Python security REPORTING platform (documentation only; it must never attack or scan).
Read PROJECT_BRIEF.md and README.md first, then read every file in secreport/ and tests/ before changing anything.
Keep every hard rule in PROJECT_BRIEF.md. Do not rewrite working modules; extend them in small steps.
Show me a short plan first. After each step run `python3 -m unittest discover -s tests`, fix failures, and tell me what
changed and what you were unsure about. Do not invent APIs, IDs or URLs; say when you are not sure.
TASK: <describe the next feature, for example "add logo and brand colour support to the HTML, DOCX and PDF output">
```
