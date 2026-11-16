# Red Team Assessment Report

**CONFIDENTIAL**

- **Engagement:** Operation Blue Lantern
- **Client:** Acme Ltd (fictional)
- **Prepared by:** Red Team Alpha
- **Generated:** 2026-11-13 23:23 UTC


## Executive Summary

The red team tested whether a realistic attacker could reach the finance file server and whether Acme's security team would notice. The objective was reached in four days and was not detected until the team reported it.

Overall rating (highest finding severity): High.

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 2 |
| Medium | 2 |
| Low | 0 |
| Info | 0 |


## Objectives

- Gain a foothold using social engineering
- Reach the finance file server
- Measure detection and response time


## Scope and Rules of Engagement

- **Authorization reference:** Red team rules of engagement signed 2026-10-20
- **Testing window:** 2026-10-01 to 2026-12-31
- **In scope:** \*.acme.test, 198.51.100.0/24
- **Out of scope:** none
- **Rules of engagement:** No denial-of-service. Business hours only. No real customer data.


## Methodology

Intelligence-led exercise agreed with Acme's CISO. Phases: reconnaissance, phishing, initial access, privilege escalation, lateral movement and objective completion. All activity was logged and coordinated with a small white-cell team.


## Attack Narrative

The team sent a pretext e-mail to 40 staff. Six opened it and two entered credentials into the test page. A valid account was used to sign in to the VPN, which allowed access to internal systems. A service account with excessive rights then provided access to the finance file server.

No alert was raised during VPN sign-in from a new location, remote service use between servers, or large file reads.


## Operation Timeline

| Date / time | Event | Detail |
|---|---|---|
| 2026-11-02 09:10 | Phishing e-mail sent | 40 recipients |
| 2026-11-02 11:45 | First credentials captured | 2 accounts |
| 2026-11-03 14:20 | VPN access gained | Using a captured account |
| 2026-11-05 10:05 | Finance server reached | Objective met |
| 2026-11-06 16:00 | Exercise ended | Reported to white cell |


## MITRE ATT&CK Mapping

| Technique | Name | Findings |
|---|---|---|
| T1021 | Remote Services | F-004 |
| T1068 | Exploitation for Privilege Escalation | F-003 |
| T1078 | Valid Accounts | F-002, F-003 |
| T1110 | Brute Force | F-002 |
| T1566 | Phishing | F-001 |


## Findings Overview

| ID | Finding | Severity | CVSS | Status |
|---|---|---|---|---|
| F-002 | Valid accounts obtained by password spraying | High |  | open |
| F-003 | Excessive privileges on user and service accounts | High |  | open |
| F-001 | Staff susceptible to phishing | Medium |  | open |
| F-004 | Lateral movement not detected | Medium |  | open |


## Detailed Findings


### F-002: Valid accounts obtained by password spraying [High]

- **Severity:** High
- **MITRE ATT&CK:** T1110 Brute Force; T1078 Valid Accounts
- **Affected assets:** vpn.acme.test
- **Status:** open


**Description**

Three accounts accepted one of three common passwords on the VPN gateway.


**Impact**

Attackers can gain initial access without exploiting software.


**Remediation**

Enforce multi-factor authentication, block common passwords and alert on spray patterns.


**References**

- https://attack.mitre.org/techniques/T1110/
- https://attack.mitre.org/techniques/T1078/

Reviewed and approved by Priya Sharma (Senior Reviewer) on 2026-11-13T23:23:11+00:00.


### F-003: Excessive privileges on user and service accounts [High]

- **Severity:** High
- **MITRE ATT&CK:** T1068 Exploitation for Privilege Escalation; T1078 Valid Accounts
- **Affected assets:** 198.51.100.20
- **Status:** open


**Description**

A service account was a member of a group with write access to most file servers.


**Impact**

Compromise of one account can lead to wide control.


**Remediation**

Apply least privilege, review group membership regularly and protect privileged accounts with tiering.


**References**

- https://attack.mitre.org/techniques/T1068/
- https://attack.mitre.org/techniques/T1078/

Reviewed and approved by Priya Sharma (Senior Reviewer) on 2026-11-13T23:23:11+00:00.


### F-001: Staff susceptible to phishing [Medium]

- **Severity:** Medium
- **MITRE ATT&CK:** T1566 Phishing
- **Affected assets:** mail.acme.test
- **Status:** open


**Description**

Six of 40 recipients opened the pretext e-mail and two entered credentials into the test page.


**Impact**

Phishing is a realistic initial access route into the organisation.


**Remediation**

Run regular awareness training, add easy reporting for suspicious email and strengthen email filtering.


**References**

- https://attack.mitre.org/techniques/T1566/

Reviewed and approved by Priya Sharma (Senior Reviewer) on 2026-11-13T23:23:11+00:00.


### F-004: Lateral movement not detected [Medium]

- **Severity:** Medium
- **MITRE ATT&CK:** T1021 Remote Services
- **Affected assets:** 198.51.100.0/24
- **Status:** open


**Description**

Remote service use from the VPN pool to the file servers generated no alerts.


**Impact**

Attackers can spread through the network without being noticed.


**Remediation**

Improve endpoint and network telemetry, tune detections for remote service use and rehearse the response.


**References**

- https://attack.mitre.org/techniques/T1021/

Reviewed and approved by Priya Sharma (Senior Reviewer) on 2026-11-13T23:23:11+00:00.


## Detection and Response Gaps

- VPN sign-in from a new country did not alert
- Remote service use between servers produced no alert
- Bulk file reads on the finance server were not monitored
- No one reviewed the pretext e-mail reports for 36 hours


## Remediation Roadmap

| Priority | ID | Finding | Affected | Suggested timeframe |
|---|---|---|---|---|
| High | F-002 | Valid accounts obtained by password spraying | vpn.acme.test | Within 30 days |
| High | F-003 | Excessive privileges on user and service accounts | 198.51.100.20 | Within 30 days |
| Medium | F-001 | Staff susceptible to phishing | mail.acme.test | Within 90 days |
| Medium | F-004 | Lateral movement not detected | 198.51.100.0/24 | Within 90 days |

Timeframes are suggestions. Adjust them to the client's own risk and patching policy.


## Evidence Register

No evidence recorded.
