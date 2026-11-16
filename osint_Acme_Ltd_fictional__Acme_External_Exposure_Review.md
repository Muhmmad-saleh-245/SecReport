# OSINT Intelligence Report

**CONFIDENTIAL**

- **Engagement:** Acme External Exposure Review
- **Client:** Acme Ltd (fictional)
- **Prepared by:** Neha Verma, Threat Intelligence
- **Generated:** 2026-11-13 23:23 UTC


## Executive Summary

This review looked at what an outsider can learn about Acme Ltd from public sources only. It found exposed credentials in public breach data, a leaked access key in a public code repository and weak email authentication. No system was accessed.

Overall rating (highest finding severity): High.

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 2 |
| Medium | 2 |
| Low | 1 |
| Info | 0 |


## Collection Objectives

- Identify internet-facing assets that Acme may not be tracking
- Find publicly exposed credentials or secrets
- Assess how easily staff can be targeted by social engineering


## Scope and Authorization

- **Authorization reference:** Client authorization letter 2026-09-30 (passive OSINT only)
- **Testing window:** 2026-10-01 to 2026-12-31
- **In scope:** \*.acme.test, acme.test
- **Out of scope:** none
- **Rules of engagement:** No denial-of-service. Business hours only. No real customer data.

Collection used publicly available sources only. No systems were accessed without authorization and no access controls were bypassed.


## Methodology

Sources: public DNS and certificate transparency records, public code hosting search, breach notification services, company website and professional networking pages. All collection was passive. Each finding is graded for source reliability (A-F) and information credibility (1-6).


## Key Findings

| ID | Finding | Severity | CVSS | Status |
|---|---|---|---|---|
| F-001 | Secrets exposed in a public code repository | High |  | open |
| F-002 | Organisation credentials found in public breach data | High |  | open |
| F-003 | Weak or missing email authentication (SPF/DKIM/DMARC) | Medium |  | open |
| F-005 | Look-alike domains registered | Medium |  | open |
| F-004 | Forgotten or unmonitored subdomains | Low |  | open |


## Detailed Findings


### F-001: Secrets exposed in a public code repository [High]

- **Severity:** High
- **Weakness:** CWE-798: Use of Hard-coded Credentials
- **MITRE ATT&CK:** T1593 Search Open Websites/Domains
- **Affected assets:** acme.test
- **Source grade:** B2  (Usually reliable; Probably true)
- **Status:** open


**Finding**

A cloud access key belonging to Acme was committed to a public repository and remained in the commit history.


**Why it matters**

Anyone could use the key to reach the cloud account until it is revoked.


**Sources**

- Public code hosting repository, commit from 2026-08-14 (collected 2026-10-09)


**Recommended action**

Revoke and rotate the exposed secrets, remove them from history, and add secret scanning to the development workflow.


**Evidence**

- E-001 (repo\_search\_notes.txt, sha256 c7b98b04fcb2...)


**References**

- https://cwe.mitre.org/data/definitions/798.html
- https://attack.mitre.org/techniques/T1593/

Reviewed and approved by Priya Sharma (Senior Reviewer) on 2026-11-13T23:23:11+00:00.


### F-002: Organisation credentials found in public breach data [High]

- **Severity:** High
- **MITRE ATT&CK:** T1589 Gather Victim Identity Information
- **Affected assets:** acme.test
- **Source grade:** B1  (Usually reliable; Confirmed by other sources)
- **Status:** open


**Finding**

12 e-mail addresses on the acme.test domain appear in a public breach collection together with passwords.


**Why it matters**

Reused passwords may let attackers sign in to company services.


**Sources**

- Breach notification service lookup (collected 2026-10-12)


**Recommended action**

Force password resets for affected accounts, enforce multi-factor authentication and monitor breach notifications.


**References**

- https://attack.mitre.org/techniques/T1589/

Reviewed and approved by Priya Sharma (Senior Reviewer) on 2026-11-13T23:23:11+00:00.


### F-003: Weak or missing email authentication (SPF/DKIM/DMARC) [Medium]

- **Severity:** Medium
- **MITRE ATT&CK:** T1566 Phishing
- **Affected assets:** acme.test
- **Source grade:** A1  (Completely reliable; Confirmed by other sources)
- **Status:** open


**Finding**

The domain publishes an SPF record but no DMARC policy, so spoofed e-mail is not rejected.


**Why it matters**

Attackers may be able to send spoofed email that appears to come from the organisation.


**Sources**

- Public DNS TXT records (collected 2026-10-05)


**Recommended action**

Publish SPF and DKIM records and move DMARC to an enforcing policy after monitoring.


**References**

- https://attack.mitre.org/techniques/T1566/

Reviewed and approved by Priya Sharma (Senior Reviewer) on 2026-11-13T23:23:11+00:00.


### F-005: Look-alike domains registered [Medium]

- **Severity:** Medium
- **MITRE ATT&CK:** T1583 Acquire Infrastructure
- **Affected assets:** acme.test
- **Source grade:** B3  (Usually reliable; Possibly true)
- **Status:** open


**Finding**

acme-corp.example was registered by a third party two weeks ago and resolves to a parked page.


**Why it matters**

Look-alike domains can be used for phishing or brand abuse.


**Sources**

- Public WHOIS and DNS data (collected 2026-10-12)


**Recommended action**

Monitor new registrations, consider defensive registrations and use takedown procedures where abuse is confirmed.


**References**

- https://attack.mitre.org/techniques/T1583/

Reviewed and approved by Priya Sharma (Senior Reviewer) on 2026-11-13T23:23:11+00:00.


### F-004: Forgotten or unmonitored subdomains [Low]

- **Severity:** Low
- **MITRE ATT&CK:** T1596 Search Open Technical Databases
- **Affected assets:** old-portal.acme.test
- **Source grade:** A3  (Completely reliable; Possibly true)
- **Status:** open


**Finding**

old-portal.acme.test appears in certificate transparency logs and its web page has not changed since 2023.


**Why it matters**

Neglected hosts widen the attack surface and can be taken over if DNS records dangle.


**Sources**

- Certificate transparency logs (collected 2026-10-05)


**Recommended action**

Maintain an asset inventory, remove stale DNS records and retire unused hosts.


**References**

- https://attack.mitre.org/techniques/T1596/

Reviewed and approved by Priya Sharma (Senior Reviewer) on 2026-11-13T23:23:11+00:00.


## Entities and Assets

| Name | Type | Confidence | Notes |
|---|---|---|---|
| acme.test | Domain | High | Primary domain |
| old-portal.acme.test | Subdomain | Medium | Appears unmaintained |
| acme-corp.example | Domain | Low | Look-alike registered by a third party |


## Timeline

| Date | Event | Detail | Source |
|---|---|---|---|
| 2026-10-05 | Collection started | Passive DNS and certificate review | crt.sh, passive DNS |
| 2026-10-09 | Leaked key found | Access key in a public repository commit | Public code hosting |
| 2026-10-12 | Breach exposure confirmed | 12 staff e-mail addresses in a public breach collection | Breach notification service |


## Confidence Summary

| Grade | Meaning | Items |
|---|---|---|
| A1 | Completely reliable; Confirmed by other sources | F-003 |
| A3 | Completely reliable; Possibly true | F-004 |
| B1 | Usually reliable; Confirmed by other sources | F-002 |
| B2 | Usually reliable; Probably true | F-001 |
| B3 | Usually reliable; Possibly true | F-005 |


**Grading key: source reliability (letter)**

| Letter | Meaning |
|---|---|
| A | Completely reliable |
| B | Usually reliable |
| C | Fairly reliable |
| D | Not usually reliable |
| E | Unreliable |
| F | Reliability cannot be judged |


**Grading key: information credibility (number)**

| Number | Meaning |
|---|---|
| 1 | Confirmed by other sources |
| 2 | Probably true |
| 3 | Possibly true |
| 4 | Doubtful |
| 5 | Improbable |
| 6 | Truth cannot be judged |


## Recommendations

Treat exposed secrets as compromised: rotate them first, then investigate. Set up continuous monitoring for new subdomains and breach exposures.


## Evidence Register

| ID | File | Size | SHA-256 | Findings | Description |
|---|---|---|---|---|---|
| E-001 | repo\_search\_notes.txt | 73 B | `c7b98b04fcb24db8ccccf36a151c44f306b811c17be6c706df9baf19cd2c1f4b` | F-001 | Notes from the repository search |
