"""CVSS v4.0 vector parsing and scoring using FIRST's offline reference tables."""

from __future__ import annotations

import json
import math
from itertools import product
from pathlib import Path

from .cvss import CvssError

BASE_METRICS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
THREAT_METRICS = ("E",)
ENVIRONMENTAL_METRICS = ("CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI",
                         "MVC", "MVI", "MVA", "MSC", "MSI", "MSA")
SUPPLEMENTAL_METRICS = ("S", "AU", "R", "V", "RE", "U")
METRIC_ORDER = BASE_METRICS + THREAT_METRICS + ENVIRONMENTAL_METRICS + SUPPLEMENTAL_METRICS
METRIC_VALUES = {
    "AV": ("N", "A", "L", "P"), "AC": ("L", "H"), "AT": ("N", "P"),
    "PR": ("N", "L", "H"), "UI": ("N", "P", "A"),
    "VC": ("H", "L", "N"), "VI": ("H", "L", "N"), "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"), "SI": ("H", "L", "N"), "SA": ("H", "L", "N"),
    "E": ("X", "A", "P", "U"), "CR": ("X", "H", "M", "L"),
    "IR": ("X", "H", "M", "L"), "AR": ("X", "H", "M", "L"),
    "MAV": ("X", "N", "A", "L", "P"), "MAC": ("X", "L", "H"),
    "MAT": ("X", "N", "P"), "MPR": ("X", "N", "L", "H"),
    "MUI": ("X", "N", "P", "A"), "MVC": ("X", "H", "L", "N"),
    "MVI": ("X", "H", "L", "N"), "MVA": ("X", "H", "L", "N"),
    "MSC": ("X", "H", "L", "N"), "MSI": ("X", "S", "H", "L", "N"),
    "MSA": ("X", "S", "H", "L", "N"), "S": ("X", "N", "P"),
    "AU": ("X", "N", "Y"), "R": ("X", "A", "U", "I"),
    "V": ("X", "D", "C"), "RE": ("X", "L", "M", "H"),
    "U": ("X", "Clear", "Green", "Amber", "Red"),
}
SCORE_METRICS = ("AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA",
                 "CR", "IR", "AR", "E")
LEVELS = {
    "AV": {"N": 0, "A": 1, "L": 2, "P": 3}, "PR": {"N": 0, "L": 1, "H": 2},
    "UI": {"N": 0, "P": 1, "A": 2}, "AC": {"L": 0, "H": 1}, "AT": {"N": 0, "P": 1},
    "VC": {"H": 0, "L": 1, "N": 2}, "VI": {"H": 0, "L": 1, "N": 2},
    "VA": {"H": 0, "L": 1, "N": 2}, "SC": {"H": 1, "L": 2, "N": 3},
    "SI": {"S": 0, "H": 1, "L": 2, "N": 3}, "SA": {"S": 0, "H": 1, "L": 2, "N": 3},
    "CR": {"H": 0, "M": 1, "L": 2}, "IR": {"H": 0, "M": 1, "L": 2},
    "AR": {"H": 0, "M": 1, "L": 2}, "E": {"A": 0, "P": 1, "U": 2},
}
DATA = json.loads((Path(__file__).parent / "data" / "cvss40_lookup.json").read_text(encoding="utf-8"))


def parse_vector(vector: str) -> dict:
    if not isinstance(vector, str):
        raise CvssError("CVSS v4.0 vector must be text")
    parts = vector.strip().split("/")
    if not parts or parts[0] != "CVSS:4.0":
        raise CvssError("Vector must start with CVSS:4.0/")
    metrics = {}
    last_index = -1
    for part in parts[1:]:
        if ":" not in part:
            raise CvssError(f"Bad metric: {part!r}")
        key, value = part.split(":", 1)
        if key not in METRIC_VALUES:
            raise CvssError(f"Unknown CVSS v4.0 metric: {key}")
        if key in metrics:
            raise CvssError(f"Duplicate metric: {key}")
        index = METRIC_ORDER.index(key)
        if index <= last_index:
            raise CvssError("CVSS v4.0 metrics must follow the specified order")
        if value not in METRIC_VALUES[key]:
            raise CvssError(f"Invalid value {value!r} for {key}")
        metrics[key] = value
        last_index = index
    missing = [key for key in BASE_METRICS if key not in metrics]
    if missing:
        raise CvssError("Missing metrics: " + ", ".join(missing))
    return metrics


def metrics_to_vector(metrics: dict) -> str:
    unknown = set(metrics) - set(METRIC_VALUES)
    if unknown:
        raise CvssError("Unknown CVSS v4.0 metrics: " + ", ".join(sorted(unknown)))
    vector = "CVSS:4.0" + "".join(f"/{key}:{metrics[key]}" for key in METRIC_ORDER if key in metrics)
    parse_vector(vector)
    return vector


def nomenclature(vector: str) -> str:
    metrics = parse_vector(vector)
    suffix = "B"
    if metrics.get("E") not in (None, "X"):
        suffix += "T"
    if any(metrics.get(key) not in (None, "X") for key in ENVIRONMENTAL_METRICS):
        suffix += "E"
    return f"CVSS 4.0-{suffix}"


def _metric(metrics: dict, key: str) -> str:
    value = metrics.get(key, "X")
    if key == "E" and value == "X":
        return "A"
    if key in ("CR", "IR", "AR") and value == "X":
        return "H"
    modified = metrics.get("M" + key)
    return modified if modified not in (None, "X") else value


def _macrovector(metrics: dict) -> tuple[int, int, int, int, int, int]:
    m = lambda key: _metric(metrics, key)
    av, pr, ui = m("AV"), m("PR"), m("UI")
    eq1 = 0 if (av, pr, ui) == ("N", "N", "N") else 1 if "N" in (av, pr, ui) and av != "P" else 2
    eq2 = 0 if m("AC") == "L" and m("AT") == "N" else 1
    vc, vi, va = m("VC"), m("VI"), m("VA")
    eq3 = 0 if vc == "H" and vi == "H" else 1 if "H" in (vc, vi, va) else 2
    sc, si, sa = m("SC"), m("SI"), m("SA")
    eq4 = 0 if "S" in (si, sa) else 1 if "H" in (sc, si, sa) else 2
    eq5 = {"A": 0, "P": 1, "U": 2}[m("E")]
    cr, ir, ar = m("CR"), m("IR"), m("AR")
    eq6 = 0 if ((cr == "H" and vc == "H") or (ir == "H" and vi == "H")
                or (ar == "H" and va == "H")) else 1
    return eq1, eq2, eq3, eq4, eq5, eq6


def _fragment_metrics(fragment: str) -> dict:
    return {key: value for item in fragment.strip("/").split("/")
            if item for key, value in [item.split(":", 1)]}


def _composed_maxima(key: tuple[int, ...]) -> list[dict]:
    eq1, eq2, eq3, eq4, eq5, eq6 = key
    maxima = DATA["max_composed"]
    fragments = (
        maxima["eq1"][str(eq1)], maxima["eq2"][str(eq2)],
        maxima["eq3"][str(eq3)][str(eq6)], maxima["eq4"][str(eq4)],
        maxima["eq5"][str(eq5)],
    )
    return [{key: value for part in combination for key, value in _fragment_metrics(part).items()}
            for combination in product(*fragments)]


def _lower_macro_scores(key: tuple[int, ...]) -> list[tuple[str, float | None]]:
    eq1, eq2, eq3, eq4, eq5, eq6 = key
    scores = DATA["lookup"]
    lowers = [
        ("eq1", scores.get("".join(map(str, (eq1 + 1, eq2, eq3, eq4, eq5, eq6))))),
        ("eq2", scores.get("".join(map(str, (eq1, eq2 + 1, eq3, eq4, eq5, eq6))))),
        ("eq4", scores.get("".join(map(str, (eq1, eq2, eq3, eq4 + 1, eq5, eq6)))),),
        ("eq5", scores.get("".join(map(str, (eq1, eq2, eq3, eq4, eq5 + 1, eq6)))),),
    ]
    if (eq3, eq6) == (0, 0):
        candidates = (scores.get("".join(map(str, (eq1, eq2, eq3, eq4, eq5, eq6 + 1)))),
                     scores.get("".join(map(str, (eq1, eq2, eq3 + 1, eq4, eq5, eq6)))))
        lower = max((value for value in candidates if value is not None), default=None)
    elif (eq3, eq6) in ((0, 1), (1, 0)):
        lower = scores.get("".join(map(str, (eq1, eq2, 1, eq4, eq5, 1))))
    elif (eq3, eq6) == (1, 1):
        lower = scores.get("".join(map(str, (eq1, eq2, 2, eq4, eq5, 1))))
    else:
        lower = scores.get("".join(map(str, (eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1))))
    lowers.insert(2, ("eq3eq6", lower))
    return lowers


def base_score(vector: str) -> float:
    metrics = parse_vector(vector)
    m = lambda key: _metric(metrics, key)
    if all(m(key) == "N" for key in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    key = _macrovector(metrics)
    lookup_key = "".join(map(str, key))
    try:
        score = DATA["lookup"][lookup_key]
    except KeyError as exc:
        raise CvssError(f"No CVSS v4.0 score is defined for macrovector {lookup_key}") from exc

    distances = None
    for maximum in _composed_maxima(key):
        candidate = {metric: maximum[metric] for metric in SCORE_METRICS}
        candidate_distances = {
            metric: LEVELS[metric][m(metric)] - LEVELS[metric][candidate[metric]]
            for metric in SCORE_METRICS
        }
        if all(distance >= 0 for distance in candidate_distances.values()):
            distances = candidate_distances
            break
    if distances is None:
        raise CvssError(f"Could not resolve a maximum vector for macrovector {lookup_key}")

    current_distances = {
        "eq1": sum(distances[k] for k in ("AV", "PR", "UI")),
        "eq2": sum(distances[k] for k in ("AC", "AT")),
        "eq3eq6": sum(distances[k] for k in ("VC", "VI", "VA", "CR", "IR", "AR")),
        "eq4": sum(distances[k] for k in ("SC", "SI", "SA")),
        "eq5": 0,
    }
    depths = DATA["max_severity"]
    depth_values = {
        "eq1": depths["eq1"][str(key[0])], "eq2": depths["eq2"][str(key[1])],
        "eq3eq6": depths["eq3eq6"][str(key[2])][str(key[5])],
        "eq4": depths["eq4"][str(key[3])], "eq5": depths["eq5"][str(key[4])],
    }
    adjustments = []
    for group, lower_score in _lower_macro_scores(key):
        if lower_score is not None:
            adjustments.append((score - lower_score) * current_distances[group] / depth_values[group])
    if adjustments:
        score -= sum(adjustments) / len(adjustments)
    return math.floor(max(0.0, min(10.0, score)) * 10 + 0.500000001) / 10