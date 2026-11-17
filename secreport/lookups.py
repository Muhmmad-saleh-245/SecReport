"""Reference tables: CWE, OWASP Top 10 (2021) and MITRE ATT&CK (Enterprise).

These are CURATED SUBSETS of the most commonly used entries, not the full
databases. Unknown IDs are reported as warnings (never blocked), so you can
still use an ID that is not listed here. Always confirm against the official
sites before sending a report to a client:
  https://cwe.mitre.org   https://owasp.org/Top10/   https://attack.mitre.org
"""

from __future__ import annotations

import re

OWASP_2021 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)",
}

OWASP_URLS = {
    "A01:2021": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "A02:2021": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "A03:2021": "https://owasp.org/Top10/A03_2021-Injection/",
    "A04:2021": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    "A05:2021": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "A06:2021": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "A07:2021": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "A08:2021": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    "A09:2021": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    "A10:2021": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
}

CWE = {
    "CWE-16": "Configuration",
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
    "CWE-98": "Improper Control of Filename for Include/Require Statement in PHP Program",
    "CWE-117": "Improper Output Neutralization for Logs",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-209": "Generation of Error Message Containing Sensitive Information",
    "CWE-259": "Use of Hard-coded Password",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-384": "Session Fixation",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-444": "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-538": "Insertion of Sensitive Information into Externally-Accessible File or Directory",
    "CWE-548": "Exposure of Information Through Directory Listing",
    "CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-778": "Insufficient Logging",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-916": "Use of Password Hash With Insufficient Computational Effort",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-942": "Permissive Cross-domain Security Policy with Untrusted Domains",
    "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
    "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
    "CWE-1104": "Use of Unmaintained Third Party Components",
    "CWE-1275": "Sensitive Cookie with Improper SameSite Attribute",
    "CWE-1321": "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
}

MITRE_TACTICS = {
    "TA0043": "Reconnaissance", "TA0042": "Resource Development", "TA0001": "Initial Access",
    "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion", "TA0006": "Credential Access", "TA0007": "Discovery",
    "TA0008": "Lateral Movement", "TA0009": "Collection", "TA0011": "Command and Control",
    "TA0010": "Exfiltration", "TA0040": "Impact",
}

MITRE = {
    "T1003": "OS Credential Dumping",
    "T1005": "Data from Local System",
    "T1018": "Remote System Discovery",
    "T1021": "Remote Services",
    "T1027": "Obfuscated Files or Information",
    "T1036": "Masquerading",
    "T1040": "Network Sniffing",
    "T1041": "Exfiltration Over C2 Channel",
    "T1046": "Network Service Discovery",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1053": "Scheduled Task/Job",
    "T1055": "Process Injection",
    "T1056": "Input Capture",
    "T1057": "Process Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1068": "Exploitation for Privilege Escalation",
    "T1069": "Permission Groups Discovery",
    "T1070": "Indicator Removal",
    "T1071": "Application Layer Protocol",
    "T1078": "Valid Accounts",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1087": "Account Discovery",
    "T1090": "Proxy",
    "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1112": "Modify Registry",
    "T1114": "Email Collection",
    "T1133": "External Remote Services",
    "T1134": "Access Token Manipulation",
    "T1135": "Network Share Discovery",
    "T1136": "Create Account",
    "T1189": "Drive-by Compromise",
    "T1190": "Exploit Public-Facing Application",
    "T1195": "Supply Chain Compromise",
    "T1199": "Trusted Relationship",
    "T1204": "User Execution",
    "T1213": "Data from Information Repositories",
    "T1218": "System Binary Proxy Execution",
    "T1482": "Domain Trust Discovery",
    "T1486": "Data Encrypted for Impact",
    "T1498": "Network Denial of Service",
    "T1499": "Endpoint Denial of Service",
    "T1505": "Server Software Component",
    "T1530": "Data from Cloud Storage",
    "T1539": "Steal Web Session Cookie",
    "T1547": "Boot or Logon Autostart Execution",
    "T1550": "Use Alternate Authentication Material",
    "T1552": "Unsecured Credentials",
    "T1555": "Credentials from Password Stores",
    "T1556": "Modify Authentication Process",
    "T1557": "Adversary-in-the-Middle",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1560": "Archive Collected Data",
    "T1562": "Impair Defenses",
    "T1565": "Data Manipulation",
    "T1566": "Phishing",
    "T1567": "Exfiltration Over Web Service",
    "T1574": "Hijack Execution Flow",
    "T1583": "Acquire Infrastructure",
    "T1584": "Compromise Infrastructure",
    "T1589": "Gather Victim Identity Information",
    "T1590": "Gather Victim Network Information",
    "T1591": "Gather Victim Org Information",
    "T1592": "Gather Victim Host Information",
    "T1593": "Search Open Websites/Domains",
    "T1594": "Search Victim-Owned Websites",
    "T1595": "Active Scanning",
    "T1596": "Search Open Technical Databases",
    "T1597": "Search Closed Sources",
    "T1598": "Phishing for Information",
}

_OWASP_CODE = re.compile(r"(?i)\bA(\d{1,2}):(\d{4})\b")
_MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def owasp_code(value: str) -> str:
    """Pull 'A03:2021' out of text like 'A03:2021 Injection'."""
    m = _OWASP_CODE.search(value or "")
    return f"A{int(m.group(1)):02d}:{m.group(2)}" if m else ""


def owasp_label(value: str) -> str:
    code = owasp_code(value)
    if code in OWASP_2021:
        return f"{code} {OWASP_2021[code]}"
    return value or ""


def cwe_label(value: str) -> str:
    name = CWE.get(value)
    return f"{value}: {name}" if name else (value or "")


def mitre_name(tid: str) -> str:
    base = (tid or "").split(".")[0]
    return MITRE.get(base, "")


def check_finding(f) -> list:
    """Return warnings for IDs that are not in the curated tables."""
    warnings = []
    if f.cwe and f.cwe not in CWE:
        warnings.append(f"{f.id}: {f.cwe} is not in the built-in CWE list (verify at cwe.mitre.org)")
    if f.owasp:
        code = owasp_code(f.owasp)
        if code not in OWASP_2021:
            warnings.append(f"{f.id}: OWASP value {f.owasp!r} is not a Top 10 2021 category")
    for t in f.mitre:
        if not _MITRE_ID.match(t):
            warnings.append(f"{f.id}: {t!r} is not a valid ATT&CK technique ID format")
        elif t.split(".")[0] not in MITRE:
            warnings.append(f"{f.id}: {t} is not in the built-in ATT&CK list (verify at attack.mitre.org)")
    return warnings


def reference_urls(cwe: str = "", owasp: str = "", mitre=()) -> list:
    """Official reference URLs for the given IDs (only well-known URL patterns)."""
    urls = []
    m = re.fullmatch(r"CWE-(\d+)", cwe or "")
    if m:
        urls.append(f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html")
    code = owasp_code(owasp)
    if code in OWASP_URLS:
        urls.append(OWASP_URLS[code])
    for t in mitre or ():
        if _MITRE_ID.match(t):
            urls.append("https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/")
    return urls
