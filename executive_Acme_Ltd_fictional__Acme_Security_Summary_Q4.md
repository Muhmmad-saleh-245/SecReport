# Executive Security Summary

**CONFIDENTIAL**

- **Engagement:** Acme Security Summary Q4
- **Client:** Acme Ltd (fictional)
- **Prepared by:** Security Assurance Team
- **Generated:** 2026-11-13 23:23 UTC


## Overall Risk Posture

High: serious weaknesses were found that should be fixed soon.

This summary combines the results of the Q4 portal test, the external exposure review and the red team exercise. The business should act first on the exposed access key, the customer data access flaw and the lack of monitoring of VPN sign-ins.

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 1 |
| Medium | 2 |
| Low | 1 |
| Info | 0 |


## Top Risks in Plain Language


### 1. Secrets exposed in a public code repository [High]

A cloud account key was public. Anyone could have used it to reach company data until it is revoked.

What to do: Revoke and rotate the exposed secrets, remove them from history, and add secret scanning to the development workflow.


### 2. Insecure direct object reference (IDOR) [Medium]

Any customer could read other customers' invoices, which is a data protection risk.

What to do: Enforce object-level authorisation on every request on the server side and avoid relying on hard-to-guess identifiers as protection.


### 3. Lateral movement not detected [Medium]

An attacker could move through the network for days without anyone noticing.

What to do: Improve endpoint and network telemetry, tune detections for remote service use and rehearse the response.


## Recommended Priorities

| Priority | ID | Finding | Affected | Suggested timeframe |
|---|---|---|---|---|
| High | F-001 | Secrets exposed in a public code repository | acme.test | Within 30 days |
| Medium | F-002 | Insecure direct object reference (IDOR) | portal.acme.test | Within 90 days |
| Medium | F-003 | Lateral movement not detected | acme.test | Within 90 days |
| Low | F-004 | Missing HTTP Strict Transport Security (HSTS) | www.acme.test | Next maintenance cycle |

Timeframes are suggestions. Adjust them to the client's own risk and patching policy.


## Scope of the Work

- **Authorization reference:** Signed Statement of Work SOW-2026-114
- **Testing window:** 2026-10-01 to 2026-12-31
- **In scope:** \*.acme.test, acme.test
- **Out of scope:** none
- **Rules of engagement:** No denial-of-service. Business hours only. No real customer data.


## Further Recommendations

1. Rotate exposed secrets this week.

2. Fix the invoice access flaw before the billing release.

3. Fund 24x7 monitoring of VPN and file server activity.
