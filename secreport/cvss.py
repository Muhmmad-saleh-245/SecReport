"""CVSS v3.1 base score calculator (standard library only).

Vector example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Reference: FIRST CVSS v3.1 specification, section 7 (base equations).
"""

from __future__ import annotations

import math

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class CvssError(ValueError):
    """Raised when a vector string is invalid."""


def roundup(value: float) -> float:
    """CVSS 3.1 Roundup: smallest number, to 1 decimal, >= value."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict:
    if isinstance(vector, str) and vector.startswith("CVSS:4.0/"):
        from . import cvss40
        try:
            return cvss40.parse_vector(vector)
        except CvssError:
            raise
    parts = vector.strip().split("/")
    if not parts or not parts[0].startswith("CVSS:3."):
        raise CvssError("Vector must start with CVSS:3.1/ (or CVSS:3.0/)")
    metrics = {}
    for part in parts[1:]:
        if ":" not in part:
            raise CvssError(f"Bad metric: {part!r}")
        key, val = part.split(":", 1)
        if key in metrics:
            raise CvssError(f"Duplicate metric: {key}")
        metrics[key] = val
    missing = [m for m in REQUIRED if m not in metrics]
    if missing:
        raise CvssError("Missing metrics: " + ", ".join(missing))
    checks = {
        "AV": AV, "AC": AC, "PR": PR_UNCHANGED, "UI": UI,
        "S": {"U": 0, "C": 0}, "C": CIA, "I": CIA, "A": CIA,
    }
    for key, allowed in checks.items():
        if metrics[key] not in allowed:
            raise CvssError(f"Invalid value {metrics[key]!r} for {key}")
    return metrics


def base_score(vector: str) -> float:
    if isinstance(vector, str) and vector.startswith("CVSS:4.0/"):
        from . import cvss40
        return cvss40.base_score(vector)
    m = parse_vector(vector)
    changed = m["S"] == "C"
    pr = (PR_CHANGED if changed else PR_UNCHANGED)[m["PR"]]
    iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * AV[m["AV"]] * AC[m["AC"]] * pr * UI[m["UI"]]
    if impact <= 0:
        return 0.0
    if changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def severity(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def describe(vector: str) -> dict:
    score = base_score(vector)
    return {"vector": vector, "score": score, "severity": severity(score)}


def metrics_to_vector(metrics: dict, version="3.1") -> str:
    """Build a CVSS:3.1 vector string from a dict like {"AV": "N", ...}."""
    if version == "4.0":
        from . import cvss40
        return cvss40.metrics_to_vector(metrics)
    if version != "3.1":
        raise CvssError("Version must be 3.1 or 4.0")
    vector = "CVSS:3.1/" + "/".join(f"{k}:{metrics[k]}" for k in REQUIRED if k in metrics)
    parse_vector(vector)  # validates
    return vector
