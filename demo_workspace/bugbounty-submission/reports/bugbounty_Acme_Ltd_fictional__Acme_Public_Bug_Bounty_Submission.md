# Bug Bounty Report

**Company:** Acme Ltd (fictional)

**CONFIDENTIAL**

- **Engagement:** Acme Public Bug Bounty Submission
- **Client:** Acme Ltd (fictional)
- **Program:** Acme Vulnerability Disclosure Program (fictional)
- **Prepared by:** Muhammad Saleh, Cybersecurity Researcher
- **Generated:** 2026-11-17 08:20 UTC


## Submission Overview

- **Program:** Acme Vulnerability Disclosure Program (fictional)
- **Researcher:** Muhammad Saleh, Cybersecurity Researcher
- **Reports in this document:** 2

Two issues found on in-scope assets while following the program rules. No customer data was accessed beyond the researcher's own test accounts, and testing was stopped as soon as each issue was confirmed.

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 2 |
| Low | 0 |
| Info | 0 |


## Scope and Rules

- **Authorization reference:** https://acme.test/security/policy (public program policy)
- **Testing window:** 2026-10-01 to 2026-12-31
- **In scope:** \*.acme.test
- **Out of scope:** status.acme.test
- **Rules of engagement:** No denial-of-service. Business hours only. No real customer data.

| ID | Finding | Severity | CVSS | Status |
|---|---|---|---|---|
| F-001 | Insecure direct object reference (IDOR) | Medium | 6.5 | open |
| F-002 | Open redirect | Medium | 6.1 | open |


## Reports


### F-001: Insecure direct object reference (IDOR) [Medium]

- **Severity:** Medium
- **CVSS 3.1:** 6.5  (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
- **Weakness:** CWE-639: Authorization Bypass Through User-Controlled Key
- **OWASP:** A01:2021 Broken Access Control
- **Affected assets:** app.acme.test
- **Status:** open


**Summary**

PUT /api/profile/\{id\} updates the profile of the id in the URL without checking ownership.


**Steps to reproduce**

1. Create two test accounts, A and B.

2. As A, send PUT /api/profile/\<B's id\> with a new display name.

3. Sign in as B and observe the changed name.


**Impact**

A user can change another user's name and e-mail address, which can lead to account takeover through password reset.


**Suggested fix**

Verify on the server that the id in the URL matches the signed-in user, or ignore the id and use the session.


**References**

- https://cwe.mitre.org/data/definitions/639.html
- https://owasp.org/Top10/A01\_2021-Broken\_Access\_Control/

Reviewed and approved by Priya Sharma (Senior Reviewer) on 2026-11-17T08:20:33+00:00.


### F-002: Open redirect [Medium]

- **Severity:** Medium
- **CVSS 3.1:** 6.1  (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
- **Weakness:** CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
- **OWASP:** A01:2021 Broken Access Control
- **MITRE ATT&CK:** T1566 Phishing
- **Affected assets:** app.acme.test
- **Status:** open


**Summary**

The next parameter of /login redirects to any URL after sign-in.


**Steps to reproduce**

1. Open https://app.acme.test/login?next=https://example.org.

2. Sign in with a test account.

3. The browser is redirected to https://example.org.


**Impact**

Attackers can send victims a trusted-looking login link that lands on a malicious page.


**Suggested fix**

Redirect only to an allow-list of known destinations or to relative paths.


**References**

- https://cwe.mitre.org/data/definitions/601.html
- https://owasp.org/Top10/A01\_2021-Broken\_Access\_Control/
- https://attack.mitre.org/techniques/T1566/

Reviewed and approved by Priya Sharma (Senior Reviewer) on 2026-11-17T08:20:33+00:00.


## Evidence Register

No evidence recorded.
